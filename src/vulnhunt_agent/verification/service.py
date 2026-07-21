"""End-to-end promotion from Hunter candidates to strict verified reports."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from ..domain.compat import candidate_from_legacy
from ..domain.schemas import (
    CandidateFinding,
    ConsensusStatus,
    PocSpec,
    ReproductionSpec,
    ReproductionVariantRequest,
)
from ..domain.states import RUN_SEQUENCE, FindingState, RunState
from ..infrastructure.artifacts import ArtifactStore
from ..infrastructure.sqlite_repository import SqliteRepository
from ..reporting.service import StrictReportService
from ..reproduction.service import ReproducerService
from ..reproduction.variants import (
    LLMVariantCompiler,
    ReproductionVariantExecutor,
    VariantCompiler,
)
from ..reviewing.agent import EvidenceReviewerAgent
from ..reviewing.service import EvidenceReviewCoordinator
from ..sandbox.base import SandboxBackend
from .recipe import CompiledRecipe, RecipeDecision, validate_recorded_recipe


@dataclass(frozen=True)
class _HunterFinding:
    raw: dict
    task_key: str
    recipe: RecipeDecision


@dataclass(frozen=True)
class VerificationSummary:
    candidates: int
    recipes_accepted: int
    recipes_rejected: int
    states: dict[str, int]
    reports: int
    variants_executed: int = 0
    variants_failed: int = 0
    automatic_rereviews: int = 0
    errors: tuple[str, ...] = ()


class VerifiedPipelineService:
    def __init__(
        self,
        repository: SqliteRepository,
        artifacts: ArtifactStore,
        backend: SandboxBackend,
        reviewers: list[EvidenceReviewerAgent],
        *,
        output_root: Path,
        variant_compiler: VariantCompiler | None = None,
    ):
        self.repository = repository
        self.artifacts = artifacts
        self.backend = backend
        self.reviewers = reviewers
        self.output_root = output_root
        self.variant_compiler = variant_compiler

    async def verify(
        self,
        *,
        run_id: str,
        run_dir: Path,
        image: str,
    ) -> VerificationSummary:
        run = self.repository.get_run(run_id)
        if run is None or run.source_snapshot is None:
            raise ValueError("verified pipeline requires an immutable run snapshot")
        grouped = self._group_findings(run_id, run_dir)
        accepted = sum(1 for item in grouped.values() if item.recipe.recipe)
        rejected = sum(
            1
            for item in grouped.values()
            if item.raw.get("status") == "confirmed" and item.recipe.recipe is None
        )
        errors: list[str] = []

        self._advance_run(run_id, RunState.REPRODUCING)
        candidates = []
        for fingerprint, item in sorted(grouped.items()):
            finding = self._save_candidate(run_id, fingerprint, item)
            candidates.append(finding.candidate_id)
            recipe = item.recipe.recipe
            if recipe is None:
                continue
            try:
                finding = self._attach_poc(finding.candidate_id, recipe)
                if not image:
                    if finding.state is FindingState.POC_READY:
                        self.repository.transition_finding(
                            finding.candidate_id,
                            FindingState.ENVIRONMENT_BLOCKED,
                            idempotency_key="verified:no-prepared-image",
                            reason="no prepared image is available for reproduction",
                        )
                    continue
                if finding.state is FindingState.POC_READY:
                    await ReproducerService(
                        self.repository, self.artifacts, self.backend
                    ).reproduce(ReproductionSpec(
                        reproduction_id=f"repro-{finding.candidate_id}-v1",
                        run_id=run_id,
                        candidate_id=finding.candidate_id,
                        source_snapshot=run.source_snapshot,
                        image=image,
                        poc_artifact=finding.poc.artifact,
                        poc_path=recipe.poc_relative,
                        setup_argvs=recipe.setup_argvs,
                        argv=recipe.argv,
                        cwd=recipe.cwd,
                        oracle=recipe.oracle,
                        attempts=2,
                        timeout_seconds=recipe.timeout,
                    ))
            except Exception as exc:
                errors.append(f"{finding.candidate_id}: reproduction: {exc}")

        self._advance_run(run_id, RunState.REVIEWING)
        coordinator = EvidenceReviewCoordinator(self.repository, self.artifacts)
        compiler = self.variant_compiler
        if compiler is None and self.reviewers:
            compiler = LLMVariantCompiler(self.reviewers[0].client)
        variant_executor = (
            ReproductionVariantExecutor(
                self.repository,
                self.artifacts,
                self.backend,
                compiler,
            )
            if compiler is not None
            else None
        )
        variants_executed = 0
        variants_failed = 0
        automatic_rereviews = 0
        for candidate_id in candidates:
            finding = self.repository.get_candidate(candidate_id)
            if finding is None or finding.state is not FindingState.REPRODUCED:
                continue
            try:
                decision = await coordinator.review(candidate_id, self.reviewers)
                for _ in range(2):
                    if decision.status is not ConsensusStatus.VARIANT_REQUESTED:
                        break
                    request = self._variant_request(run_id, candidate_id)
                    if request is None or variant_executor is None:
                        raise RuntimeError("variant request has no available executor")
                    execution = await variant_executor.execute(request)
                    if execution.outcome.status.value == "in_progress":
                        break
                    variants_executed += 1
                    if execution.outcome.error:
                        variants_failed += 1
                        errors.append(
                            f"{candidate_id}: variant {request.request_id}: "
                            f"{execution.outcome.error}"
                        )
                        break
                    automatic_rereviews += 1
                    decision = await coordinator.review(candidate_id, self.reviewers)
            except Exception as exc:
                errors.append(f"{candidate_id}: review: {exc}")

        self._advance_run(run_id, RunState.REPORTING)
        reports = 0
        reporter = StrictReportService(self.repository, self.artifacts)
        for candidate_id in candidates:
            finding = self.repository.get_candidate(candidate_id)
            if finding is None:
                continue
            if finding.state is FindingState.REVIEWER_VERIFIED:
                try:
                    reporter.materialize(
                        self.output_root,
                        run_id=run_id,
                        candidate_id=candidate_id,
                    )
                    reports += 1
                except Exception as exc:
                    errors.append(f"{candidate_id}: report: {exc}")
            elif finding.state is FindingState.REPORTABLE:
                reports += 1

        self._advance_run(run_id, RunState.COMPLETED)
        state_counts = Counter(
            item.state.value
            for item in self.repository.list_candidates(run_id)
        )
        return VerificationSummary(
            candidates=len(candidates),
            recipes_accepted=accepted,
            recipes_rejected=rejected,
            states=dict(sorted(state_counts.items())),
            reports=reports,
            variants_executed=variants_executed,
            variants_failed=variants_failed,
            automatic_rereviews=automatic_rereviews,
            errors=tuple(errors),
        )

    def _variant_request(
        self,
        run_id: str,
        candidate_id: str,
    ) -> ReproductionVariantRequest | None:
        tasks = [
            task for task in self.repository.list_tasks(run_id)
            if task["task_type"] == "reproduction_variant"
            and task["payload"].get("candidate_id") == candidate_id
        ]
        if not tasks:
            return None
        active = [
            task for task in tasks if task["status"] in {"pending", "running"}
        ]
        selected = (active or tasks)[-1]
        return ReproductionVariantRequest.model_validate(selected["payload"])

    def _group_findings(
        self,
        run_id: str,
        run_dir: Path,
    ) -> dict[str, _HunterFinding]:
        grouped: dict[str, _HunterFinding] = {}
        hunters_root = run_dir / "hunters"
        if not hunters_root.exists():
            return grouped
        for findings_path in sorted(hunters_root.glob("*/hunts/*/findings.json")):
            payload = json.loads(findings_path.read_text())
            pocs_root = findings_path.parent / "pocs"
            relative = findings_path.relative_to(run_dir).as_posix()
            for raw in payload.get("findings", []):
                task_key = relative
                seed = candidate_from_legacy(raw, run_id=run_id, task_key=task_key)
                item = _HunterFinding(
                    raw=raw,
                    task_key=task_key,
                    recipe=validate_recorded_recipe(raw, payload, pocs_root),
                )
                previous = grouped.get(seed.fingerprint)
                if previous is None or (
                    previous.recipe.recipe is None and item.recipe.recipe is not None
                ):
                    grouped[seed.fingerprint] = item
        return grouped

    def _save_candidate(
        self,
        run_id: str,
        fingerprint: str,
        item: _HunterFinding,
    ):
        task_key = f"verified:{fingerprint}"
        seed = candidate_from_legacy(
            item.raw,
            run_id=run_id,
            task_key=task_key,
        )
        candidate_id = _candidate_id(run_id, fingerprint)
        initial = seed.model_copy(update={
            "candidate_id": candidate_id,
            "task_key": task_key,
            "state": FindingState.HYPOTHESIS,
            "evidence_ids": (),
            "poc": None,
        })
        existing = self.repository.get_candidate(candidate_id)
        if existing is not None:
            if _immutable_candidate_data(existing) != _immutable_candidate_data(initial):
                raise ValueError(
                    f"verified candidate changed during replay: {candidate_id}"
                )
            finding = existing
        else:
            finding, _ = self.repository.save_candidate(initial)
        if finding.state is FindingState.HYPOTHESIS:
            finding = self.repository.transition_finding(
                finding.candidate_id,
                FindingState.STATICALLY_SUPPORTED,
                idempotency_key="verified:statically-supported",
                reason="validated Hunter candidate imported into V2",
            )
        return finding

    def _attach_poc(self, candidate_id: str, recipe: CompiledRecipe):
        finding = self.repository.get_candidate(candidate_id)
        if finding is None:
            raise KeyError(candidate_id)
        if finding.poc is None:
            artifact = self.artifacts.put_file(
                recipe.poc_path,
                "text/plain; charset=utf-8",
            )
            self.repository.register_artifact(artifact)
            finding = self.repository.attach_candidate_poc(
                candidate_id,
                PocSpec(
                    artifact=artifact.digest,
                    setup_argvs=recipe.setup_argvs,
                    argv=recipe.argv,
                    cwd=recipe.cwd,
                ),
            )
        if finding.state is FindingState.STATICALLY_SUPPORTED:
            finding = self.repository.transition_finding(
                candidate_id,
                FindingState.POC_READY,
                idempotency_key="verified:poc-ready",
                reason="recorded recipe matched Hunter tool execution",
            )
        return finding

    def _advance_run(self, run_id: str, target: RunState) -> None:
        run = self.repository.get_run(run_id)
        if run is None or run.state not in RUN_SEQUENCE:
            return
        current = RUN_SEQUENCE.index(run.state)
        desired = RUN_SEQUENCE.index(target)
        for state in RUN_SEQUENCE[current + 1 : desired + 1]:
            run = self.repository.transition_run(
                run_id,
                state,
                idempotency_key=f"verified:{state.value}",
                reason="verified finding pipeline",
            )


def _candidate_id(run_id: str, fingerprint: str) -> str:
    digest = hashlib.sha256(f"{run_id}\0{fingerprint}".encode()).hexdigest()[:26]
    return f"cand_verified_{digest}"


def _immutable_candidate_data(finding: CandidateFinding) -> dict:
    return finding.model_dump(exclude={
        "state",
        "evidence_ids",
        "poc",
        "created_at",
        "updated_at",
    })
