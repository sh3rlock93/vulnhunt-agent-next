"""Code-enforced review consensus policy."""
from __future__ import annotations

from ..core.cvss import base_score
from ..domain.schemas import (
    CandidateFinding,
    ConsensusDecision,
    ConsensusStatus,
    Evidence,
    EvidenceKind,
    ReviewVerdict,
    Verdict,
)

CONSENSUS_POLICY_VERSION = "consensus-v1"
_DUAL_REVIEW_THRESHOLD = 7.0


def decide_consensus(
    finding: CandidateFinding,
    verdicts: list[ReviewVerdict],
    evidence: list[Evidence],
) -> ConsensusDecision:
    ordered = sorted(verdicts, key=lambda item: item.reviewer)
    reviewers = tuple(item.reviewer for item in ordered)
    if not ordered:
        return ConsensusDecision(
            candidate_id=finding.candidate_id,
            status=ConsensusStatus.NEEDS_SECOND_REVIEW,
            reasons=("no review verdict exists",),
        )
    if any(item.candidate_id != finding.candidate_id for item in ordered):
        raise ValueError("consensus received a verdict for another candidate")

    verdict_kinds = {item.verdict for item in ordered}
    if len(verdict_kinds) != 1 or Verdict.UNCLEAR in verdict_kinds:
        return ConsensusDecision(
            candidate_id=finding.candidate_id,
            status=ConsensusStatus.DISAGREEMENT,
            reviewers=reviewers,
            reasons=("reviewers do not agree on one conclusive verdict",),
        )
    only_verdict = next(iter(verdict_kinds))
    if only_verdict is Verdict.FALSE_POSITIVE:
        return ConsensusDecision(
            candidate_id=finding.candidate_id,
            status=ConsensusStatus.REJECTED,
            reviewers=reviewers,
            verdict=Verdict.FALSE_POSITIVE,
        )

    vectors = {item.cvss_vector for item in ordered}
    cwes = {item.cwe_id for item in ordered}
    if len(vectors) != 1 or len(cwes) != 1:
        return ConsensusDecision(
            candidate_id=finding.candidate_id,
            status=ConsensusStatus.DISAGREEMENT,
            reviewers=reviewers,
            reasons=("reviewers disagree on CVSS or CWE classification",),
        )

    valid_reproduction_ids = _valid_reproduction_evidence_ids(
        finding, evidence
    )
    uncited = [
        item.reviewer
        for item in ordered
        if not set(item.evidence_ids).issubset(valid_reproduction_ids)
        or not set(item.evidence_ids)
    ]
    if uncited:
        return ConsensusDecision(
            candidate_id=finding.candidate_id,
            status=ConsensusStatus.DISAGREEMENT,
            reviewers=reviewers,
            reasons=("review verdict lacks valid reproduction citations: " + ", ".join(uncited),),
        )

    vector = next(iter(vectors))
    if base_score(vector) >= _DUAL_REVIEW_THRESHOLD:
        configurations = {
            (item.model_id, item.prompt_version) for item in ordered
        }
        if len(reviewers) < 2 or len(configurations) < 2:
            return ConsensusDecision(
                candidate_id=finding.candidate_id,
                status=ConsensusStatus.NEEDS_SECOND_REVIEW,
                reviewers=reviewers,
                verdict=Verdict.REAL,
                cvss_vector=vector,
                cwe_id=next(iter(cwes)),
                evidence_ids=tuple(sorted(set().union(
                    *(set(item.evidence_ids) for item in ordered)
                ))),
                reasons=(
                    "high/critical findings require two distinct model/prompt "
                    "reviewer configurations",
                ),
            )

    cited = tuple(sorted(set().union(*(set(item.evidence_ids) for item in ordered))))
    return ConsensusDecision(
        candidate_id=finding.candidate_id,
        status=ConsensusStatus.VERIFIED,
        reviewers=reviewers,
        verdict=Verdict.REAL,
        cvss_vector=vector,
        cwe_id=next(iter(cwes)),
        evidence_ids=cited,
    )


def _valid_reproduction_evidence_ids(
    finding: CandidateFinding, evidence: list[Evidence]
) -> set[str]:
    groups: dict[str, list[Evidence]] = {}
    for item in evidence:
        if (
            item.evidence_id in finding.evidence_ids
            and item.kind is EvidenceKind.REPRODUCTION
            and item.reproduction_group
        ):
            groups.setdefault(item.reproduction_group, []).append(item)
    valid: set[str] = set()
    for items in groups.values():
        attempts = {item.attempt for item in items}
        if (
            len(items) >= 2
            and attempts == set(range(1, len(items) + 1))
            and len({item.image_digest for item in items}) == 1
            and len({item.command for item in items}) == 1
            and all(
                item.run_id == finding.run_id
                and item.candidate_id == finding.candidate_id
                and item.oracle is not None
                and item.oracle.result == "passed"
                and not item.timed_out
                for item in items
            )
        ):
            valid.update(item.evidence_id for item in items)
    return valid
