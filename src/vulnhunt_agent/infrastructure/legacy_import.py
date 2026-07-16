"""One-way importer from the original filesystem RunStore into V2 storage."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from ..domain.compat import candidate_from_legacy
from ..domain.schemas import RunRecord
from ..domain.states import RUN_SEQUENCE, FindingState, RunState
from .artifacts import ArtifactStore
from .sqlite_repository import SqliteRepository


@dataclass(frozen=True)
class ImportSummary:
    run_id: str
    tasks_created: int = 0
    findings_created: int = 0
    findings_deduplicated: int = 0
    artifacts_registered: int = 0
    already_imported: bool = False


class LegacyRunImporter:
    def __init__(self, repository: SqliteRepository, artifacts: ArtifactStore):
        self.repository = repository
        self.artifacts = artifacts

    def import_run(self, run_dir: Path) -> ImportSummary:
        run_dir = run_dir.resolve()
        if not run_dir.is_dir():
            raise FileNotFoundError(run_dir)
        run_id = run_dir.name
        if self.repository.has_legacy_import(run_id):
            return ImportSummary(run_id=run_id, already_imported=True)

        config = _read_json(run_dir / "config.json", default={})
        desired_run_state = _infer_run_state(run_dir)
        run = self.repository.get_run(run_id)
        if run is None:
            run = self.repository.save_run(
                RunRecord(
                    run_id=run_id,
                    source_url=str(config.get("repo_source") or "") or None,
                    source_ref=str(config.get("ref") or "") or None,
                    config=config,
                )
            )
        run = self._advance_legacy_run(run.state, desired_run_state, run_id)

        tasks_created = 0
        queue_path = run_dir / "hunters" / "_queue.json"
        queue = _read_json(queue_path, default={"tasks": []})
        for task in queue.get("tasks", []):
            file_path = str(task.get("file") or "unknown")
            if self.repository.ensure_task(
                run_id,
                "hunt_file",
                file_path,
                status=str(task.get("status") or "pending"),
                payload=task,
            ):
                tasks_created += 1

        findings_created = 0
        findings_deduplicated = 0
        artifact_count = 0
        for path in sorted((run_dir / "hunters").glob("*/hunts/*/findings.json")):
            relative = path.relative_to(run_dir)
            raw_result = _read_json(path, default={"findings": []})
            artifact = self.artifacts.put_json(raw_result)
            self.repository.register_artifact(artifact)
            artifact_count += 1
            task_key = str(relative.parent).replace("\\", "/")
            self.repository.ensure_task(
                run_id,
                "hunter",
                task_key,
                status="done",
                payload={"legacy_artifact": artifact.digest},
            )
            for raw_finding in raw_result.get("findings", []):
                candidate = candidate_from_legacy(
                    raw_finding,
                    run_id=run_id,
                    task_key=task_key,
                )
                desired_state = candidate.state
                initial = candidate.model_copy(update={"state": FindingState.HYPOTHESIS})
                stored, created = self.repository.save_candidate(initial)
                self._advance_legacy_finding(stored.candidate_id, desired_state, task_key)
                if created:
                    findings_created += 1
                else:
                    findings_deduplicated += 1

        for path in sorted(run_dir.glob("steps/*.json")):
            artifact = self.artifacts.put_file(path, "application/json")
            self.repository.register_artifact(artifact)
            artifact_count += 1

        summary = ImportSummary(
            run_id=run_id,
            tasks_created=tasks_created,
            findings_created=findings_created,
            findings_deduplicated=findings_deduplicated,
            artifacts_registered=artifact_count,
        )
        self.repository.record_legacy_import(run_id, run_dir, asdict(summary))
        return summary

    def _advance_legacy_run(
        self, current: RunState, desired: RunState, run_id: str
    ) -> RunRecord:
        if current not in RUN_SEQUENCE or desired not in RUN_SEQUENCE:
            run = self.repository.get_run(run_id)
            assert run is not None
            return run
        current_index = RUN_SEQUENCE.index(current)
        desired_index = RUN_SEQUENCE.index(desired)
        run = self.repository.get_run(run_id)
        assert run is not None
        for target in RUN_SEQUENCE[current_index + 1 : desired_index + 1]:
            run = self.repository.transition_run(
                run_id,
                target,
                idempotency_key=f"legacy-import:run:{target.value}",
                reason="legacy RunStore inferred state",
            )
        return run

    def _advance_legacy_finding(
        self, candidate_id: str, desired: FindingState, task_key: str
    ) -> None:
        targets = (FindingState.STATICALLY_SUPPORTED, FindingState.POC_READY)
        if desired not in targets:
            return
        for target in targets[: targets.index(desired) + 1]:
            self.repository.transition_finding(
                candidate_id,
                target,
                idempotency_key=f"legacy-import:{task_key}:{target.value}",
                reason="conservative legacy finding conversion",
            )


def _read_json(path: Path, *, default: dict) -> dict:
    if not path.exists():
        return default
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _infer_run_state(run_dir: Path) -> RunState:
    steps = run_dir / "steps"
    if (steps / "hunt.json").exists():
        return RunState.COMPLETED
    if (run_dir / "hunters" / "_queue.json").exists():
        return RunState.HUNTING
    if (steps / "sandbox_prepare.json").exists():
        return RunState.BUILDING
    if (steps / "file_selector.json").exists():
        return RunState.PLANNING
    if (steps / "rank.json").exists() or (steps / "filter.json").exists():
        return RunState.INDEXING
    return RunState.CREATED
