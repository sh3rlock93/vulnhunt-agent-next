"""Pydantic V2 models for persisted security-analysis data."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .states import FindingState, RunState

SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
CVSS31_PATTERN = (
    r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/"
    r"C:[HLN]/I:[HLN]/A:[HLN]$"
)


def utc_now() -> datetime:
    return datetime.now(UTC)


class DomainModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        revalidate_instances="always",
        str_strip_whitespace=True,
    )


class CodeLocation(DomainModel):
    path: str = Field(min_length=1)
    line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    symbol: str | None = None

    @model_validator(mode="after")
    def validate_location(self) -> "CodeLocation":
        path = PurePosixPath(self.path.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("code path must be relative and may not traverse parents")
        if self.end_line is not None and self.end_line < self.line:
            raise ValueError("end_line must not be before line")
        return self


class Precondition(DomainModel):
    kind: str = Field(min_length=1)
    description: str = Field(min_length=1)
    required: bool = True


class OracleResult(DomainModel):
    type: str = Field(min_length=1)
    expression: str | None = None
    result: str = Field(pattern=r"^(passed|failed)$")


class PocSpec(DomainModel):
    artifact: str = Field(pattern=SHA256_PATTERN)
    argv: tuple[str, ...] = Field(min_length=1)
    cwd: str = "."

    @model_validator(mode="after")
    def validate_cwd(self) -> "PocSpec":
        cwd = PurePosixPath(self.cwd.replace("\\", "/"))
        if cwd.is_absolute() or ".." in cwd.parts:
            raise ValueError("PoC cwd must stay inside the workspace")
        if any(not arg for arg in self.argv):
            raise ValueError("PoC argv entries may not be empty")
        return self


class EvidenceKind(StrEnum):
    SOURCE = "source"
    SANDBOX_EXECUTION = "sandbox_execution"
    REPRODUCTION = "reproduction"
    REVIEW = "review"
    LEGACY_ARTIFACT = "legacy_artifact"


class Evidence(DomainModel):
    evidence_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    kind: EvidenceKind
    producer: str = Field(min_length=1)
    source_snapshot: str | None = Field(default=None, pattern=SHA256_PATTERN)
    image_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    command: tuple[str, ...] = ()
    exit_code: int | None = None
    stdout_artifact: str | None = Field(default=None, pattern=SHA256_PATTERN)
    stderr_artifact: str | None = Field(default=None, pattern=SHA256_PATTERN)
    oracle: OracleResult | None = None
    artifact_ids: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_reproduction_contract(self) -> "Evidence":
        if self.kind is EvidenceKind.REPRODUCTION:
            required = {
                "source_snapshot": self.source_snapshot,
                "image_digest": self.image_digest,
                "command": self.command,
                "exit_code": self.exit_code,
                "stdout_artifact": self.stdout_artifact,
                "stderr_artifact": self.stderr_artifact,
                "oracle": self.oracle,
            }
            missing = [name for name, value in required.items() if value is None or value == ()]
            if missing:
                raise ValueError(
                    "reproduction evidence is missing required fields: " + ", ".join(missing)
                )
        if any(not arg for arg in self.command):
            raise ValueError("evidence command entries may not be empty")
        return self


class CandidateFinding(DomainModel):
    candidate_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    task_key: str = Field(min_length=1)
    title: str = Field(min_length=1)
    weakness: str = Field(min_length=1)
    state: FindingState = FindingState.HYPOTHESIS
    entrypoint: CodeLocation
    sink: CodeLocation | None = None
    dataflow: tuple[CodeLocation, ...] = ()
    preconditions: tuple[Precondition, ...] = ()
    attacker_capability: str = Field(min_length=1)
    impact: tuple[str, ...] = Field(min_length=1)
    evidence_ids: tuple[str, ...] = ()
    poc: PocSpec | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @property
    def fingerprint(self) -> str:
        identity = {
            "weakness": self.weakness.casefold(),
            "entrypoint": [self.entrypoint.path, self.entrypoint.line],
            "sink": [self.sink.path, self.sink.line] if self.sink else None,
        }
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()


class Verdict(StrEnum):
    REAL = "real"
    FALSE_POSITIVE = "false_positive"
    UNCLEAR = "unclear"


class ReviewVerdict(DomainModel):
    candidate_id: str = Field(min_length=1)
    verdict: Verdict
    notes: str = Field(min_length=1)
    cvss_vector: str = ""
    reviewer: str = Field(min_length=1)
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_cvss_contract(self) -> "ReviewVerdict":
        if self.verdict is Verdict.REAL:
            if not self.cvss_vector:
                raise ValueError("real verdict requires a CVSS 3.1 vector")
            import re

            if re.fullmatch(CVSS31_PATTERN, self.cvss_vector) is None:
                raise ValueError("invalid CVSS 3.1 vector")
        elif self.cvss_vector:
            raise ValueError("non-real verdict must not carry a CVSS vector")
        return self


class RunRecord(DomainModel):
    run_id: str = Field(min_length=1)
    state: RunState = RunState.CREATED
    source_url: str | None = None
    source_ref: str | None = None
    source_snapshot: str | None = Field(default=None, pattern=SHA256_PATTERN)
    config: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ArtifactRef(DomainModel):
    digest: str = Field(pattern=SHA256_PATTERN)
    size: int = Field(ge=0)
    media_type: str = Field(min_length=1)
