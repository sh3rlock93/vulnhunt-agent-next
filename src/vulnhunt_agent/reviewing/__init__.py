"""Evidence-aware review, consensus, and reproduction-variant requests."""

from .agent import EvidenceReviewerAgent, ReviewProposal, VariantProposal
from .consensus import CONSENSUS_POLICY_VERSION, decide_consensus
from .packet import EvidenceReviewPacket, EvidenceReviewPacketBuilder
from .service import EvidenceReviewCoordinator

__all__ = [
    "CONSENSUS_POLICY_VERSION",
    "EvidenceReviewCoordinator",
    "EvidenceReviewPacket",
    "EvidenceReviewPacketBuilder",
    "EvidenceReviewerAgent",
    "ReviewProposal",
    "VariantProposal",
    "decide_consensus",
]
