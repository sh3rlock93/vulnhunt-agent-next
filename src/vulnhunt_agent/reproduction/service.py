"""Independent Reproducer orchestration with two clean sandbox executions."""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Callable

from ..domain.schemas import (
    Evidence,
    EvidenceKind,
    OracleResult,
    ReproductionSpec,
)
from ..domain.states import FindingState
from ..infrastructure.artifacts import ArtifactStore
from ..infrastructure.sqlite_repository import (
    SqliteRepository,
    TaskLeaseLostError,
)
from ..sandbox.base import SandboxBackend, SandboxJob
from .oracles import evaluate_oracle


class ReproductionStatus(StrEnum):
    IN_PROGRESS = "in_progress"
    REPRODUCED = "reproduced"
    FAILED = "failed"
    FLAKY = "flaky"
    ENVIRONMENT_BLOCKED = "environment_blocked"


@dataclass(frozen=True)
class ReproductionOutcome:
    reproduction_id: str
    status: ReproductionStatus
    evidence: tuple[Evidence, ...] = ()
    error: str = ""


class ReproducerService:
    def __init__(
        self,
        repository: SqliteRepository,
        artifacts: ArtifactStore,
        backend: SandboxBackend,
        *,
        worker_id: str | None = None,
        lease_seconds: int = 120,
        clock: Callable[[], datetime] | None = None,
    ):
        self.repository = repository
        self.artifacts = artifacts
        self.backend = backend
        self.worker_id = worker_id or f"reproducer-{uuid.uuid4().hex[:16]}"
        self.lease_seconds = lease_seconds
        self.clock = clock or (lambda: datetime.now(UTC))

    async def reproduce(self, spec: ReproductionSpec) -> ReproductionOutcome:
        spec = ReproductionSpec.model_validate(spec)
        run = self.repository.get_run(spec.run_id)
        finding = self.repository.get_candidate(spec.candidate_id)
        if run is None:
            raise KeyError(f"unknown run: {spec.run_id}")
        if finding is None or finding.run_id != spec.run_id:
            raise KeyError(f"candidate does not belong to run: {spec.candidate_id}")
        if run.source_snapshot != spec.source_snapshot:
            raise ValueError("reproduction snapshot does not match the run")
        if (
            finding.poc is None
            or finding.poc.artifact != spec.poc_artifact
            or finding.poc.setup_argvs != spec.setup_argvs
            or finding.poc.argv != spec.argv
            or finding.poc.cwd != spec.cwd
        ):
            raise ValueError("reproduction PoC does not match the candidate")

        task_payload = spec.model_dump(mode="json")
        task_created = self.repository.ensure_task(
            spec.run_id,
            "reproduction",
            spec.reproduction_id,
            payload=task_payload,
        )
        if not task_created:
            stored_task = next(
                (
                    task
                    for task in self.repository.list_tasks(spec.run_id)
                    if task["task_type"] == "reproduction"
                    and task["task_key"] == spec.reproduction_id
                ),
                None,
            )
            if stored_task is None or stored_task["payload"] != task_payload:
                raise ValueError("reproduction_id is already bound to another job")
        existing = self._group_evidence(spec)
        if finding.state is FindingState.REPRODUCED and _is_deterministic(existing, spec):
            return ReproductionOutcome(
                reproduction_id=spec.reproduction_id,
                status=ReproductionStatus.REPRODUCED,
                evidence=tuple(existing),
            )
        if finding.state is FindingState.ENVIRONMENT_BLOCKED and not task_created:
            raise ValueError(
                "environment-blocked reproduction requires a new reproduction_id to retry"
            )
        if finding.state not in {
            FindingState.POC_READY,
            FindingState.ENVIRONMENT_BLOCKED,
            FindingState.REPRODUCTION_PENDING,
        }:
            raise ValueError(
                f"candidate is not reproducible from state {finding.state.value}"
            )
        lease_seconds = max(
            self.lease_seconds,
            (len(spec.setup_argvs) + 1) * spec.timeout_seconds + 30,
        )
        lease = self.repository.acquire_task_lease(
            spec.run_id,
            "reproduction",
            spec.reproduction_id,
            worker_id=self.worker_id,
            lease_seconds=lease_seconds,
            now=self.clock(),
        )
        if lease is None:
            return ReproductionOutcome(
                reproduction_id=spec.reproduction_id,
                status=ReproductionStatus.IN_PROGRESS,
                evidence=tuple(existing),
                error="reproduction task is leased by another worker or already terminal",
            )
        if finding.state in {FindingState.POC_READY, FindingState.ENVIRONMENT_BLOCKED}:
            self.repository.transition_finding(
                spec.candidate_id,
                FindingState.REPRODUCTION_PENDING,
                idempotency_key=f"{spec.reproduction_id}:pending",
                reason="independent reproduction started",
            )

        evidence_by_attempt = {item.attempt: item for item in existing}
        try:
            for attempt in range(1, spec.attempts + 1):
                if attempt in evidence_by_attempt:
                    continue
                lease = self.repository.heartbeat_task_lease(
                    lease,
                    lease_seconds=lease_seconds,
                    now=self.clock(),
                )
                attempt_evidence = await self._execute_attempt(spec, attempt)
                self.repository.save_evidence(attempt_evidence)
                evidence_by_attempt[attempt] = attempt_evidence
        except Exception as exc:
            try:
                self.repository.finish_task_lease_and_transition_finding(
                    lease,
                    status=ReproductionStatus.ENVIRONMENT_BLOCKED.value,
                    candidate_id=spec.candidate_id,
                    target=FindingState.ENVIRONMENT_BLOCKED,
                    idempotency_key=f"{spec.reproduction_id}:environment-blocked",
                    reason=str(exc)[:500],
                    error=str(exc),
                    now=self.clock(),
                )
            except TaskLeaseLostError:
                return ReproductionOutcome(
                    reproduction_id=spec.reproduction_id,
                    status=ReproductionStatus.IN_PROGRESS,
                    evidence=tuple(
                        item for _, item in sorted(evidence_by_attempt.items())
                    ),
                    error="worker lost the reproduction task lease",
                )
            return ReproductionOutcome(
                reproduction_id=spec.reproduction_id,
                status=ReproductionStatus.ENVIRONMENT_BLOCKED,
                evidence=tuple(
                    item for _, item in sorted(evidence_by_attempt.items())
                ),
                error=str(exc),
            )

        try:
            lease = self.repository.heartbeat_task_lease(
                lease,
                lease_seconds=lease_seconds,
                now=self.clock(),
            )
        except TaskLeaseLostError:
            return ReproductionOutcome(
                reproduction_id=spec.reproduction_id,
                status=ReproductionStatus.IN_PROGRESS,
                evidence=tuple(
                    item for _, item in sorted(evidence_by_attempt.items())
                ),
                error="worker lost the reproduction task lease",
            )
        group_evidence = tuple(
            item for _, item in sorted(evidence_by_attempt.items())
        )
        self.repository.attach_candidate_evidence(
            spec.candidate_id, tuple(item.evidence_id for item in group_evidence)
        )
        if _is_deterministic(list(group_evidence), spec):
            state = FindingState.REPRODUCED
            status = ReproductionStatus.REPRODUCED
        elif any(
            item.oracle and item.oracle.result == "passed"
            for item in group_evidence
        ):
            state = FindingState.UNCLEAR
            status = ReproductionStatus.FLAKY
        else:
            state = FindingState.REJECTED
            status = ReproductionStatus.FAILED
        self.repository.finish_task_lease_and_transition_finding(
            lease,
            status=status.value,
            candidate_id=spec.candidate_id,
            target=state,
            idempotency_key=f"{spec.reproduction_id}:result",
            reason=f"independent reproduction result: {status.value}",
            now=self.clock(),
        )
        return ReproductionOutcome(
            reproduction_id=spec.reproduction_id,
            status=status,
            evidence=group_evidence,
        )

    async def _execute_attempt(
        self, spec: ReproductionSpec, attempt: int
    ) -> Evidence:
        execution = await self.backend.execute(
            SandboxJob(
                image=spec.image,
                source_tar=self.artifacts.path_for(spec.source_snapshot),
                poc_file=self.artifacts.path_for(spec.poc_artifact),
                poc_path=spec.poc_path,
                setup_argvs=spec.setup_argvs,
                argv=spec.argv,
                cwd=spec.cwd,
                env=spec.env,
                timeout_seconds=spec.timeout_seconds,
                capture_files=spec.capture_files,
            )
        )
        stdout = self.artifacts.put_text(execution.result.stdout)
        stderr = self.artifacts.put_text(execution.result.stderr)
        self.repository.register_artifact(stdout)
        self.repository.register_artifact(stderr)
        captured = {
            path: self.artifacts.put_bytes(content)
            for path, content in sorted((execution.result.captured_files or {}).items())
        }
        for artifact in captured.values():
            self.repository.register_artifact(artifact)
        setup_succeeded = all(
            item.exit_code == 0 and not item.timed_out
            for item in execution.setup_results
        )
        oracle = (
            evaluate_oracle(spec.oracle, execution.result)
            if setup_succeeded
            else _failed_oracle(spec)
        )
        return Evidence(
            evidence_id=_evidence_id(spec, attempt),
            run_id=spec.run_id,
            candidate_id=spec.candidate_id,
            kind=EvidenceKind.REPRODUCTION,
            producer="reproducer",
            reproduction_group=spec.reproduction_id,
            attempt=attempt,
            source_snapshot=spec.source_snapshot,
            image_digest=execution.image_digest,
            setup_commands=spec.setup_argvs,
            command=spec.argv,
            exit_code=execution.result.exit_code,
            timed_out=execution.result.timed_out,
            duration_ms=execution.result.duration_ms,
            stdout_artifact=stdout.digest,
            stderr_artifact=stderr.digest,
            oracle=oracle,
            artifact_ids=tuple(item.digest for item in captured.values()),
            captured_artifacts={
                path: artifact.digest for path, artifact in captured.items()
            },
        )

    def _group_evidence(self, spec: ReproductionSpec) -> list[Evidence]:
        return sorted(
            (
                item
                for item in self.repository.list_candidate_evidence(spec.candidate_id)
                if item.reproduction_group == spec.reproduction_id
            ),
            key=lambda item: item.attempt or 0,
        )


def _evidence_id(spec: ReproductionSpec, attempt: int) -> str:
    identity = "\0".join(
        [spec.run_id, spec.candidate_id, spec.reproduction_id, str(attempt)]
    )
    digest = hashlib.sha256(identity.encode()).hexdigest()[:26]
    return f"ev_repro_{digest}"


def _is_deterministic(
    evidence: list[Evidence], spec: ReproductionSpec
) -> bool:
    if len(evidence) != spec.attempts:
        return False
    attempt_ids = {item.attempt for item in evidence}
    image_digests = {item.image_digest for item in evidence}
    return (
        attempt_ids == set(range(1, spec.attempts + 1))
        and len(image_digests) == 1
        and all(
            item.run_id == spec.run_id
            and item.candidate_id == spec.candidate_id
            and item.reproduction_group == spec.reproduction_id
            and item.source_snapshot == spec.source_snapshot
            and item.setup_commands == spec.setup_argvs
            and item.command == spec.argv
            and not item.timed_out
            and item.oracle is not None
            and item.oracle.result == "passed"
            for item in evidence
        )
    )


def _failed_oracle(spec: ReproductionSpec) -> OracleResult:
    return OracleResult(
        type=spec.oracle.type.value,
        expression="setup command failed",
        result="failed",
    )
