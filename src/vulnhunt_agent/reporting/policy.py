"""Code-enforced policy for promoting a finding to reportable."""
from __future__ import annotations

from dataclasses import dataclass

from ..domain.schemas import CandidateFinding, Evidence, EvidenceKind, ReviewVerdict
from ..domain.states import FindingState, require_finding_transition
from ..reproduction.provenance import (
    actual_target_group_agrees,
    requires_actual_target,
)
from ..reviewing.consensus import decide_consensus


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reasons: tuple[str, ...] = ()


class StrictReportPolicy:
    """Require independent, snapshot-matched reproduction before reporting."""

    version = "strict-v3"

    def evaluate(
        self,
        finding: CandidateFinding,
        *,
        run_snapshot: str | None,
        evidence: list[Evidence],
        verdicts: list[ReviewVerdict],
    ) -> PolicyDecision:
        reasons: list[str] = []
        require_target = requires_actual_target(finding)
        if finding.state is not FindingState.REVIEWER_VERIFIED:
            reasons.append("finding is not reviewer_verified")
        if not run_snapshot:
            reasons.append("run has no immutable source snapshot")
        consensus = decide_consensus(finding, verdicts, evidence)
        if consensus.status.value != "verified":
            reasons.append(
                "review consensus is not verified"
                + (": " + "; ".join(consensus.reasons) if consensus.reasons else "")
            )
        if not finding.preconditions:
            reasons.append("structured preconditions are missing")

        by_id = {item.evidence_id: item for item in evidence}
        missing_ids = [item for item in finding.evidence_ids if item not in by_id]
        if missing_ids:
            reasons.append("referenced evidence is missing: " + ", ".join(sorted(missing_ids)))

        reproductions = [
            by_id[evidence_id]
            for evidence_id in finding.evidence_ids
            if evidence_id in by_id and by_id[evidence_id].kind is EvidenceKind.REPRODUCTION
        ]
        if not reproductions:
            reasons.append("independent reproduction evidence is missing")
        else:
            groups: dict[str, list[Evidence]] = {}
            for item in reproductions:
                if item.reproduction_group:
                    groups.setdefault(item.reproduction_group, []).append(item)
            if not any(
                _valid_reproduction_group(
                    items,
                    run_id=finding.run_id,
                    candidate_id=finding.candidate_id,
                    run_snapshot=run_snapshot,
                    require_actual_target=require_target,
                )
                for items in groups.values()
            ):
                reasons.append(
                    "no deterministic two-attempt reproduction matches the run snapshot"
                )
                if require_target:
                    reasons.append(
                        "memory-safety reproduction did not execute the prepared target "
                        "in two clean matching attempts"
                    )

        return PolicyDecision(allowed=not reasons, reasons=tuple(reasons))

    def promote(
        self,
        finding: CandidateFinding,
        *,
        run_snapshot: str | None,
        evidence: list[Evidence],
        verdicts: list[ReviewVerdict],
    ) -> CandidateFinding:
        decision = self.evaluate(
            finding,
            run_snapshot=run_snapshot,
            evidence=evidence,
            verdicts=verdicts,
        )
        if not decision.allowed:
            raise ValueError("strict report policy blocked finding: " + "; ".join(decision.reasons))
        require_finding_transition(finding.state, FindingState.REPORTABLE)
        return finding.model_copy(update={"state": FindingState.REPORTABLE})


def _valid_reproduction_group(
    evidence: list[Evidence],
    *,
    run_id: str,
    candidate_id: str,
    run_snapshot: str | None,
    require_actual_target: bool = False,
) -> bool:
    if len(evidence) < 2:
        return False
    attempts = {item.attempt for item in evidence}
    images = {item.image_digest for item in evidence}
    setup_commands = {item.setup_commands for item in evidence}
    commands = {item.command for item in evidence}
    deterministic = (
        attempts == set(range(1, len(evidence) + 1))
        and len(images) == 1
        and len(setup_commands) == 1
        and len(commands) == 1
        and all(
            item.run_id == run_id
            and item.candidate_id == candidate_id
            and item.producer == "reproducer"
            and item.source_snapshot == run_snapshot
            and not item.timed_out
            and item.oracle is not None
            and item.oracle.result == "passed"
            for item in evidence
        )
    )
    if not deterministic:
        return False
    return not require_actual_target or actual_target_group_agrees(evidence)
