"""Canonical report model plus deterministic JSON/Markdown rendering."""
from __future__ import annotations

from typing import Any

from ..core import cvss
from ..domain.schemas import (
    CandidateFinding,
    ConsensusDecision,
    Evidence,
    ReviewVerdict,
    RunRecord,
)
from ..reviewing.consensus import CONSENSUS_POLICY_VERSION
from .policy import StrictReportPolicy


def build_canonical_report(
    *,
    run: RunRecord,
    finding: CandidateFinding,
    evidence: list[Evidence],
    verdicts: list[ReviewVerdict],
    consensus: ConsensusDecision,
    policy: StrictReportPolicy,
) -> dict[str, Any]:
    score = cvss.base_score(consensus.cvss_vector)
    reproductions = [
        {
            "evidence_id": item.evidence_id,
            "reproduction_group": item.reproduction_group,
            "attempt": item.attempt,
            "image_digest": item.image_digest,
            "setup_commands": [list(command) for command in item.setup_commands],
            "command": list(item.command),
            "exit_code": item.exit_code,
            "timed_out": item.timed_out,
            "duration_ms": item.duration_ms,
            "oracle": item.oracle.model_dump(mode="json") if item.oracle else None,
            "stdout_artifact": item.stdout_artifact,
            "stderr_artifact": item.stderr_artifact,
            "captured_artifacts": item.captured_artifacts,
            "execution_subject": item.execution_subject.value,
            "provenance_policy": item.provenance_policy,
            "clean_environment_id": item.clean_environment_id,
            "target_binary": item.target_binary,
            "linked_target_artifacts": list(item.linked_target_artifacts),
            "sanitizer_failure_class": item.sanitizer_failure_class,
            "sanitizer_frames": [
                frame.model_dump(mode="json") for frame in item.sanitizer_frames
            ],
            "target_source_reached": item.target_source_reached,
        }
        for item in evidence
        if (
            item.evidence_id in finding.evidence_ids
            and item.kind.value == "reproduction"
        )
    ]
    return {
        "schema_version": 2,
        "run": {
            "run_id": run.run_id,
            "repository_url": run.source_url,
            "source_ref": run.source_ref,
            "source_snapshot": run.source_snapshot,
            "scan_scope": {
                "mode": run.config.get("scan_scope_mode", "full"),
                "include_paths": run.config.get("scan_scope_include_paths", []),
                "exclude_paths": run.config.get("scan_scope_exclude_paths", []),
                "repository_complete": (
                    run.config.get("scan_scope_mode", "full") == "full"
                ),
            },
        },
        "finding": {
            "candidate_id": finding.candidate_id,
            "fingerprint": finding.fingerprint,
            "title": finding.title,
            "weakness": finding.weakness,
            "entrypoint": finding.entrypoint.model_dump(mode="json"),
            "sink": finding.sink.model_dump(mode="json") if finding.sink else None,
            "dataflow": [item.model_dump(mode="json") for item in finding.dataflow],
            "preconditions": [
                item.model_dump(mode="json") for item in finding.preconditions
            ],
            "attacker_capability": finding.attacker_capability,
            "impact": list(finding.impact),
            "confidence": finding.confidence,
        },
        "classification": {
            "cwe_id": consensus.cwe_id,
            "cvss_vector": consensus.cvss_vector,
            "cvss_score": score,
            "severity": cvss.severity(score),
        },
        "reproduction": reproductions,
        "reviews": [
            {
                "reviewer": item.reviewer,
                "model_id": item.model_id,
                "prompt_version": item.prompt_version,
                "verdict": item.verdict.value,
                "notes": item.notes,
                "cvss_vector": item.cvss_vector,
                "cwe_id": item.cwe_id,
                "evidence_ids": list(item.evidence_ids),
            }
            for item in sorted(verdicts, key=lambda value: value.reviewer)
        ],
        "provenance": {
            "policy_version": policy.version,
            "consensus_version": CONSENSUS_POLICY_VERSION,
            "reviewers": list(consensus.reviewers),
            "evidence_ids": list(finding.evidence_ids),
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    finding = report["finding"]
    classification = report["classification"]
    lines = [
        f"# {finding['title']}",
        "",
        (
            f"**{classification['cwe_id']} · CVSS {classification['cvss_score']:.1f} "
            f"({classification['severity']}) · `{classification['cvss_vector']}`**"
        ),
        "",
        "## Summary",
        "",
        f"- Candidate: `{finding['candidate_id']}`",
        f"- Attacker capability: {finding['attacker_capability']}",
        f"- Impact: {'; '.join(finding['impact'])}",
        "",
        "## Affected code",
        "",
        f"- Entry: `{_location(finding['entrypoint'])}`",
    ]
    if finding["sink"]:
        lines.append(f"- Sink: `{_location(finding['sink'])}`")
    if finding["dataflow"]:
        lines.append(
            "- Data flow: "
            + " → ".join(f"`{_location(item)}`" for item in finding["dataflow"])
        )
    lines.extend(["", "## Preconditions", ""])
    lines.extend(
        f"- [{item['kind']}] {item['description']}"
        for item in finding["preconditions"]
    )
    lines.extend(["", "## Reproduction evidence", ""])
    for item in report["reproduction"]:
        oracle = item["oracle"] or {}
        lines.extend([
            f"### `{item['evidence_id']}` (attempt {item['attempt']})",
            "",
            f"- Image: `{item['image_digest']}`",
        ])
        for command in item.get("setup_commands", []):
            lines.append(f"- Setup: `{' '.join(command)}`")
        lines.extend([
            f"- Trigger: `{' '.join(item['command'])}`",
            f"- Execution subject: `{item['execution_subject']}`; "
            f"target source reached: `{item['target_source_reached']}`",
            f"- Sanitizer failure: `{item['sanitizer_failure_class'] or 'none'}`",
            f"- Exit: `{item['exit_code']}`; timed out: `{item['timed_out']}`",
            (
                f"- Oracle: `{oracle.get('expression') or oracle.get('type', '')}` "
                f"→ **{oracle.get('result', 'unknown')}**"
            ),
            "",
        ])
    lines.extend(["## Review consensus", ""])
    for review in report["reviews"]:
        citations = ", ".join(f"`{item}`" for item in review["evidence_ids"])
        lines.append(
            f"- **{review['reviewer']}** ({review['verdict']}): "
            f"{review['notes']} Evidence: {citations}"
        )
    lines.extend([
        "",
        "## Provenance",
        "",
        f"- Source snapshot: `{report['run']['source_snapshot']}`",
        f"- Scan scope: `{report['run']['scan_scope']['mode']}`; "
        f"repository complete: `{report['run']['scan_scope']['repository_complete']}`",
        f"- Report policy: `{report['provenance']['policy_version']}`",
        f"- Consensus policy: `{report['provenance']['consensus_version']}`",
        "- Evidence IDs: "
        + ", ".join(f"`{item}`" for item in report["provenance"]["evidence_ids"]),
        "",
    ])
    return "\n".join(lines)


def _location(location: dict) -> str:
    suffix = f"-{location['end_line']}" if location.get("end_line") else ""
    symbol = f" ({location['symbol']})" if location.get("symbol") else ""
    return f"{location['path']}:{location['line']}{suffix}{symbol}"
