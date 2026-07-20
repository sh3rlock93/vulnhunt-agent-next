"""Consensus-gated Markdown, canonical JSON, and SARIF materialization."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from ..domain.states import FindingState
from ..infrastructure.artifacts import ArtifactStore
from ..infrastructure.sqlite_repository import SqliteRepository
from ..reviewing.consensus import decide_consensus
from .exporters import build_canonical_report, render_markdown
from .policy import StrictReportPolicy
from .sarif import build_sarif


@dataclass(frozen=True)
class ReportBundle:
    report_path: Path
    json_path: Path
    sarif_path: Path
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
        reviewer: str | None = None,
        markdown: str | None = None,
    ) -> ReportBundle:
        # `reviewer` and `markdown` remain accepted for API compatibility.
        # Export content is derived only from validated domain data.
        del reviewer, markdown
        run = self.repository.get_run(run_id)
        finding = self.repository.get_candidate(candidate_id)
        if run is None:
            raise KeyError(f"unknown run: {run_id}")
        if finding is None or finding.run_id != run_id:
            raise KeyError(f"candidate does not belong to run: {candidate_id}")
        candidate_evidence = self.repository.list_candidate_evidence(candidate_id)
        evidence = [
            item for item in candidate_evidence
            if item.evidence_id in finding.evidence_ids
        ]
        verdicts = self.repository.list_verdicts(candidate_id)
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
            verdicts=verdicts,
        )
        consensus = decide_consensus(policy_finding, verdicts, evidence)
        if finding.state is not FindingState.REPORTABLE:
            reviewer_key = "-".join(consensus.reviewers)
            promoted = self.repository.transition_finding(
                candidate_id,
                FindingState.REPORTABLE,
                idempotency_key=f"report:{self.policy.version}:{reviewer_key}",
                reason=f"report policy {self.policy.version} passed",
            )
        canonical = build_canonical_report(
            run=run,
            finding=promoted,
            evidence=evidence,
            verdicts=verdicts,
            consensus=consensus,
            policy=self.policy,
        )
        markdown_content = render_markdown(canonical)
        sarif = build_sarif(canonical)
        provenance = {
            "policy": self.policy.version,
            "run_id": run.run_id,
            "candidate_id": promoted.candidate_id,
            "source_snapshot": run.source_snapshot,
            "evidence_ids": list(promoted.evidence_ids),
            "reviewers": list(consensus.reviewers),
            "verdict": consensus.verdict.value if consensus.verdict else None,
            "cvss_vector": consensus.cvss_vector,
            "cwe_id": consensus.cwe_id,
        }

        slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", promoted.candidate_id).strip("-")
        report_dir = output_root / "reports" / (slug or "finding")
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.md"
        json_path = report_dir / "report.json"
        sarif_path = report_dir / "report.sarif"
        provenance_path = report_dir / "provenance.json"
        _write_deterministic(report_path, markdown_content)
        _write_deterministic(json_path, _pretty_json(canonical))
        _write_deterministic(sarif_path, _pretty_json(sarif))
        _write_deterministic(provenance_path, _pretty_json(provenance))
        for path, media_type in (
            (report_path, "text/markdown; charset=utf-8"),
            (json_path, "application/json"),
            (sarif_path, "application/sarif+json"),
            (provenance_path, "application/json"),
        ):
            self.repository.register_artifact(self.artifacts.put_file(path, media_type))
        return ReportBundle(
            report_path=report_path,
            json_path=json_path,
            sarif_path=sarif_path,
            provenance_path=provenance_path,
        )

    def _verify_artifacts(self, *digests: str | None) -> None:
        for digest in digests:
            if digest is not None:
                self.artifacts.read_bytes(digest)


def _pretty_json(value: object) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def _write_deterministic(path: Path, content: str) -> None:
    if path.exists():
        if path.read_text() != content:
            raise ValueError(f"report output already exists with different content: {path}")
        return
    path.write_text(content)
