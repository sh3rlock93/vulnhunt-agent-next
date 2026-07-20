"""Build integrity-checked, redacted evidence packets for Reviewers."""
from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict

from ..domain.schemas import CandidateFinding, EvidenceKind, OracleResult
from ..domain.states import FindingState
from ..infrastructure.artifacts import ArtifactStore
from ..infrastructure.sqlite_repository import SqliteRepository
from .classification import ALLOWED_CWES

_EXCERPT_LIMIT = 4_000
_REDACTIONS = (
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password)\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


class PacketEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    kind: EvidenceKind
    producer: str
    reproduction_group: str | None = None
    attempt: int | None = None
    source_snapshot: str | None = None
    image_digest: str | None = None
    command: tuple[str, ...] = ()
    exit_code: int | None = None
    timed_out: bool = False
    oracle: OracleResult | None = None
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    artifact_ids: tuple[str, ...] = ()


class EvidenceReviewPacket(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    candidate: CandidateFinding
    repository_url: str | None = None
    source_ref: str | None = None
    source_snapshot: str
    evidence: tuple[PacketEvidence, ...]
    allowed_cwes: tuple[str, ...]


class EvidenceReviewPacketBuilder:
    def __init__(self, repository: SqliteRepository, artifacts: ArtifactStore):
        self.repository = repository
        self.artifacts = artifacts

    def build(self, candidate_id: str) -> EvidenceReviewPacket:
        finding = self.repository.get_candidate(candidate_id)
        if finding is None:
            raise KeyError(f"unknown candidate: {candidate_id}")
        if finding.state not in {
            FindingState.REPRODUCED,
            FindingState.REVIEWER_VERIFIED,
            FindingState.REPORTABLE,
        }:
            raise ValueError(
                f"evidence review requires a reproduced candidate, got {finding.state.value}"
            )
        run = self.repository.get_run(finding.run_id)
        if run is None or run.source_snapshot is None:
            raise ValueError("evidence review requires an immutable run snapshot")

        by_id = {
            item.evidence_id: item
            for item in self.repository.list_candidate_evidence(candidate_id)
        }
        missing = sorted(set(finding.evidence_ids) - set(by_id))
        if missing:
            raise ValueError("candidate references missing evidence: " + ", ".join(missing))

        packet_evidence = tuple(
            self._packet_item(by_id[evidence_id])
            for evidence_id in finding.evidence_ids
        )
        if not any(item.kind is EvidenceKind.REPRODUCTION for item in packet_evidence):
            raise ValueError("evidence review requires independent reproduction evidence")
        return EvidenceReviewPacket(
            candidate=finding,
            repository_url=run.source_url,
            source_ref=run.source_ref,
            source_snapshot=run.source_snapshot,
            evidence=packet_evidence,
            allowed_cwes=tuple(sorted(ALLOWED_CWES)),
        )

    def _packet_item(self, evidence) -> PacketEvidence:
        artifacts = tuple(dict.fromkeys((
            *evidence.artifact_ids,
            *evidence.captured_artifacts.values(),
        )))
        for digest in artifacts:
            self.artifacts.read_bytes(digest)
        return PacketEvidence(
            evidence_id=evidence.evidence_id,
            kind=evidence.kind,
            producer=evidence.producer,
            reproduction_group=evidence.reproduction_group,
            attempt=evidence.attempt,
            source_snapshot=evidence.source_snapshot,
            image_digest=evidence.image_digest,
            command=evidence.command,
            exit_code=evidence.exit_code,
            timed_out=evidence.timed_out,
            oracle=evidence.oracle,
            stdout_excerpt=self._read_excerpt(evidence.stdout_artifact),
            stderr_excerpt=self._read_excerpt(evidence.stderr_artifact),
            artifact_ids=artifacts,
        )

    def _read_excerpt(self, digest: str | None) -> str:
        if digest is None:
            return ""
        text = self.artifacts.read_bytes(digest).decode(errors="replace")
        for pattern in _REDACTIONS:
            text = pattern.sub(r"\1[REDACTED]" if pattern.groups else "[REDACTED]", text)
        return text[:_EXCERPT_LIMIT]
