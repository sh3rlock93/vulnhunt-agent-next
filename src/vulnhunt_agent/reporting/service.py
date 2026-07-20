"""Final report materialization guarded by the strict evidence policy."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from ..domain.states import FindingState
from ..infrastructure.artifacts import ArtifactStore
from ..infrastructure.sqlite_repository import SqliteRepository
from .policy import StrictReportPolicy


@dataclass(frozen=True)
class ReportBundle:
    report_path: Path
    provenance_path: Path


class StrictReportService:
    def __init__(
        self,
        repository: SqliteRepository,
        artifacts: ArtifactStore,
        policy: StrictReportPolicy | None = None,
    ):
        self.repository = repository
        self.artifacts = artifacts
        self.policy = policy or StrictReportPolicy()

    def materialize(
        self,
        output_root: Path,
        *,
        run_id: str,
        candidate_id: str,
        reviewer: str,
        markdown: str,
    ) -> ReportBundle:
        run = self.repository.get_run(run_id)
        finding = self.repository.get_candidate(candidate_id)
        if run is None:
            raise KeyError(f"unknown run: {run_id}")
        if finding is None or finding.run_id != run_id:
            raise KeyError(f"candidate does not belong to run: {candidate_id}")
        evidence = self.repository.list_candidate_evidence(candidate_id)
        verdict = next(
            (
                item
                for item in self.repository.list_verdicts(candidate_id)
                if item.reviewer == reviewer
            ),
            None,
        )
        if verdict is None:
            raise KeyError(f"unknown reviewer verdict: {reviewer}")
        self._verify_artifacts(run.source_snapshot, finding.poc.artifact if finding.poc else None)
        for item in evidence:
            self._verify_artifacts(
                item.stdout_artifact,
                item.stderr_artifact,
                *item.artifact_ids,
                *item.captured_artifacts.values(),
            )
        policy_finding = (
            finding.model_copy(update={"state": FindingState.REVIEWER_VERIFIED})
            if finding.state is FindingState.REPORTABLE
            else finding
        )
        promoted = self.policy.promote(
            policy_finding,
            run_snapshot=run.source_snapshot,
            evidence=evidence,
            verdict=verdict,
        )
        if finding.state is not FindingState.REPORTABLE:
            promoted = self.repository.transition_finding(
                candidate_id,
                FindingState.REPORTABLE,
                idempotency_key=f"report:{self.policy.version}:{reviewer}",
                reason=f"report policy {self.policy.version} passed",
            )
        slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", promoted.candidate_id).strip("-")
        report_dir = output_root / "reports" / (slug or "finding")
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.md"
        provenance_path = report_dir / "provenance.json"
        report_path.write_text(markdown)
        provenance_path.write_text(
            json.dumps(
                {
                    "policy": self.policy.version,
                    "run_id": run.run_id,
                    "candidate_id": promoted.candidate_id,
                    "source_snapshot": run.source_snapshot,
                    "evidence_ids": list(promoted.evidence_ids),
                    "reviewer": verdict.reviewer,
                    "verdict": verdict.verdict.value,
                    "cvss_vector": verdict.cvss_vector,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return ReportBundle(report_path=report_path, provenance_path=provenance_path)

    def _verify_artifacts(self, *digests: str | None) -> None:
        for digest in digests:
            if digest is not None:
                self.artifacts.read_bytes(digest)
