"""Review orchestration that separates model judgment from execution authority."""
from __future__ import annotations

import hashlib
import json

from ..domain.schemas import (
    ConsensusDecision,
    ConsensusStatus,
    Evidence,
    EvidenceKind,
    ReproductionVariantRequest,
    ReviewVerdict,
    Verdict,
)
from ..domain.states import FindingState
from ..infrastructure.artifacts import ArtifactStore
from ..infrastructure.sqlite_repository import SqliteRepository
from .agent import EvidenceReviewerAgent, ReviewProposal
from .classification import normalize_cwe
from .consensus import CONSENSUS_POLICY_VERSION, decide_consensus
from .packet import EvidenceReviewPacketBuilder


class EvidenceReviewCoordinator:
    def __init__(self, repository: SqliteRepository, artifacts: ArtifactStore):
        self.repository = repository
        self.artifacts = artifacts
        self.packet_builder = EvidenceReviewPacketBuilder(repository, artifacts)

    async def review(
        self,
        candidate_id: str,
        reviewers: list[EvidenceReviewerAgent],
    ) -> ConsensusDecision:
        if not reviewers:
            raise ValueError("at least one Reviewer is required")
        packet = self.packet_builder.build(candidate_id)
        finding = packet.candidate
        for agent in reviewers:
            existing = next(
                (
                    verdict
                    for verdict in self.repository.list_verdicts(candidate_id)
                    if verdict.reviewer == agent.reviewer
                ),
                None,
            )
            if existing is None:
                proposal = await agent.review(packet)
                if proposal.variant_request is not None:
                    request = self._variant_request(finding, agent, proposal)
                    self.request_variant(request)
                    return ConsensusDecision(
                        candidate_id=candidate_id,
                        status=ConsensusStatus.VARIANT_REQUESTED,
                        reviewers=(agent.reviewer,),
                        verdict=proposal.verdict,
                        evidence_ids=proposal.evidence_ids,
                        reasons=(proposal.variant_request.rationale,),
                    )
                self.repository.save_verdict(
                    self._to_verdict(finding, agent, proposal)
                )

            decision = decide_consensus(
                finding,
                self.repository.list_verdicts(candidate_id),
                self.repository.list_candidate_evidence(candidate_id),
            )
            if decision.status is not ConsensusStatus.NEEDS_SECOND_REVIEW:
                return self._finalize(finding.state, decision)
        return decide_consensus(
            finding,
            self.repository.list_verdicts(candidate_id),
            self.repository.list_candidate_evidence(candidate_id),
        )

    def request_variant(self, request: ReproductionVariantRequest) -> None:
        request = ReproductionVariantRequest.model_validate(request)
        finding = self.repository.get_candidate(request.candidate_id)
        if finding is None or finding.run_id != request.run_id:
            raise KeyError("variant request candidate does not belong to the run")
        groups = {
            item.reproduction_group
            for item in self.repository.list_candidate_evidence(request.candidate_id)
            if item.kind is EvidenceKind.REPRODUCTION
        }
        if request.base_reproduction_group not in groups:
            raise ValueError("variant request references an unknown reproduction group")
        payload = request.model_dump(mode="json")
        created = self.repository.ensure_task(
            request.run_id,
            "reproduction_variant",
            request.request_id,
            payload=payload,
        )
        if not created:
            stored = next(
                (
                    task for task in self.repository.list_tasks(request.run_id)
                    if task["task_type"] == "reproduction_variant"
                    and task["task_key"] == request.request_id
                ),
                None,
            )
            if stored is None or stored["payload"] != payload:
                raise ValueError("variant request ID is already bound to another request")

    def _to_verdict(
        self,
        finding,
        agent: EvidenceReviewerAgent,
        proposal: ReviewProposal,
    ) -> ReviewVerdict:
        cwe = ""
        if proposal.verdict is Verdict.REAL:
            cwe = normalize_cwe(proposal.cwe_id or finding.weakness)
        return ReviewVerdict(
            candidate_id=finding.candidate_id,
            verdict=proposal.verdict,
            notes=proposal.notes,
            cvss_vector=proposal.cvss_vector,
            cwe_id=cwe,
            evidence_ids=proposal.evidence_ids,
            reviewer=agent.reviewer,
            model_id=agent.model_id,
            prompt_version=agent.configuration_id,
        )

    def _variant_request(self, finding, agent, proposal) -> ReproductionVariantRequest:
        variant = proposal.variant_request
        if variant is None:
            raise ValueError("variant proposal is missing")
        groups = sorted({
            item.reproduction_group
            for item in self.repository.list_candidate_evidence(finding.candidate_id)
            if item.kind is EvidenceKind.REPRODUCTION and item.reproduction_group
        })
        if not groups:
            raise ValueError("no reproduction group is available for a variant")
        identity = "\0".join((
            finding.run_id,
            finding.candidate_id,
            agent.reviewer,
            variant.variant_type.value,
            variant.requested_change,
        ))
        return ReproductionVariantRequest(
            request_id="variant-" + hashlib.sha256(identity.encode()).hexdigest()[:20],
            run_id=finding.run_id,
            candidate_id=finding.candidate_id,
            reviewer=agent.reviewer,
            base_reproduction_group=groups[0],
            variant_type=variant.variant_type,
            rationale=variant.rationale,
            requested_change=variant.requested_change,
        )

    def _finalize(
        self, current_state: FindingState, decision: ConsensusDecision
    ) -> ConsensusDecision:
        if current_state is not FindingState.REPRODUCED:
            return decision
        if decision.status is ConsensusStatus.VERIFIED:
            self._persist_consensus_evidence(decision)
            self.repository.transition_finding(
                decision.candidate_id,
                FindingState.REVIEWER_VERIFIED,
                idempotency_key=f"{CONSENSUS_POLICY_VERSION}:verified",
                reason="evidence-aware review consensus verified",
            )
        elif decision.status is ConsensusStatus.REJECTED:
            self.repository.transition_finding(
                decision.candidate_id,
                FindingState.REJECTED,
                idempotency_key=f"{CONSENSUS_POLICY_VERSION}:rejected",
                reason="review consensus rejected candidate",
            )
        elif decision.status is ConsensusStatus.DISAGREEMENT:
            self.repository.transition_finding(
                decision.candidate_id,
                FindingState.UNCLEAR,
                idempotency_key=f"{CONSENSUS_POLICY_VERSION}:disagreement",
                reason="reviewer disagreement requires human review",
            )
        return decision

    def _persist_consensus_evidence(self, decision: ConsensusDecision) -> None:
        finding = self.repository.get_candidate(decision.candidate_id)
        if finding is None:
            raise KeyError(decision.candidate_id)
        payload = decision.model_dump(mode="json")
        artifact = self.artifacts.put_json(payload)
        self.repository.register_artifact(artifact)
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:24]
        evidence_id = f"ev_review_{digest}"
        existing = {
            item.evidence_id: item
            for item in self.repository.list_candidate_evidence(decision.candidate_id)
        }
        if evidence_id not in existing:
            self.repository.save_evidence(Evidence(
                evidence_id=evidence_id,
                run_id=finding.run_id,
                candidate_id=finding.candidate_id,
                kind=EvidenceKind.REVIEW,
                producer=CONSENSUS_POLICY_VERSION,
                artifact_ids=(artifact.digest,),
            ))
        self.repository.attach_candidate_evidence(
            decision.candidate_id, (evidence_id,)
        )
