"""Code-enforced policy for promoting a finding to reportable."""
from __future__ import annotations

from dataclasses import dataclass

from ..domain.schemas import CandidateFinding, Evidence, EvidenceKind, ReviewVerdict, Verdict
from ..domain.states import FindingState, require_finding_transition


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reasons: tuple[str, ...] = ()


class StrictReportPolicy:
    """Require independent, snapshot-matched reproduction before reporting."""

    version = "strict-v1"

    def evaluate(
        self,
        finding: CandidateFinding,
        *,
        run_snapshot: str | None,
        evidence: list[Evidence],
        verdict: ReviewVerdict | None,
    ) -> PolicyDecision:
        reasons: list[str] = []
        if finding.state is not FindingState.REVIEWER_VERIFIED:
            reasons.append("finding is not reviewer_verified")
        if not run_snapshot:
            reasons.append("run has no immutable source snapshot")
        if verdict is None:
            reasons.append("review verdict is missing")
        elif verdict.candidate_id != finding.candidate_id:
            reasons.append("review verdict belongs to another finding")
        elif verdict.verdict is not Verdict.REAL:
            reasons.append("review verdict is not real")
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
            valid_reproduction = any(
                item.run_id == finding.run_id
                and item.producer == "reproducer"
                and item.source_snapshot == run_snapshot
                and item.oracle is not None
                and item.oracle.result == "passed"
                for item in reproductions
            )
            if not valid_reproduction:
                reasons.append("no passed reproduction matches the run snapshot")

        return PolicyDecision(allowed=not reasons, reasons=tuple(reasons))

    def promote(
        self,
        finding: CandidateFinding,
        *,
        run_snapshot: str | None,
        evidence: list[Evidence],
        verdict: ReviewVerdict | None,
    ) -> CandidateFinding:
        decision = self.evaluate(
            finding,
            run_snapshot=run_snapshot,
            evidence=evidence,
            verdict=verdict,
        )
        if not decision.allowed:
            raise ValueError("strict report policy blocked finding: " + "; ".join(decision.reasons))
        require_finding_transition(finding.state, FindingState.REPORTABLE)
        return finding.model_copy(update={"state": FindingState.REPORTABLE})
