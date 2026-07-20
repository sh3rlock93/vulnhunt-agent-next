"""Pydantic V2 models for persisted security-analysis data."""
from __future__ import annotations

import hashlib
import json
import re
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


class OracleType(StrEnum):
    EXIT_CODE = "exit_code"
    STDOUT_REGEX = "stdout_regex"
    STDERR_REGEX = "stderr_regex"
    COMBINED_REGEX = "combined_regex"
    FILE_SHA256 = "file_sha256"


class OracleSpec(DomainModel):
    type: OracleType
    expected_exit_code: int | None = None
    pattern: str | None = Field(default=None, min_length=1, max_length=512)
    path: str | None = None
    expected_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_oracle_fields(self) -> "OracleSpec":
        if self.type is OracleType.EXIT_CODE:
            if self.expected_exit_code is None:
                raise ValueError("exit-code oracle requires expected_exit_code")
            if any(value is not None for value in (self.pattern, self.path, self.expected_sha256)):
                raise ValueError("exit-code oracle contains fields for another oracle type")
        elif self.type in {
            OracleType.STDOUT_REGEX,
            OracleType.STDERR_REGEX,
            OracleType.COMBINED_REGEX,
        }:
            if not self.pattern:
                raise ValueError("regex oracle requires pattern")
            if any(
                value is not None
                for value in (self.expected_exit_code, self.path, self.expected_sha256)
            ):
                raise ValueError("regex oracle contains fields for another oracle type")
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"invalid oracle regex: {exc}") from exc
        elif self.type is OracleType.FILE_SHA256:
            if not self.path or not self.expected_sha256:
                raise ValueError("file oracle requires path and expected_sha256")
            if self.expected_exit_code is not None or self.pattern is not None:
                raise ValueError("file oracle contains fields for another oracle type")
            _validate_relative_path(self.path, label="oracle file")
            if PurePosixPath(self.path) == PurePosixPath("."):
                raise ValueError("oracle file must identify a file")
        return self


class PocSpec(DomainModel):
    artifact: str = Field(pattern=SHA256_PATTERN)
    argv: tuple[str, ...] = Field(min_length=1, max_length=256)
    cwd: str = "."

    @model_validator(mode="after")
    def validate_cwd(self) -> "PocSpec":
        cwd = PurePosixPath(self.cwd.replace("\\", "/"))
        if cwd.is_absolute() or ".." in cwd.parts:
            raise ValueError("PoC cwd must stay inside the workspace")
        if any(not arg or "\0" in arg for arg in self.argv):
            raise ValueError("PoC argv entries may not be empty or contain NUL")
        return self


class ReproductionSpec(DomainModel):
    reproduction_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    source_snapshot: str = Field(pattern=SHA256_PATTERN)
    image: str = Field(min_length=1)
    poc_artifact: str = Field(pattern=SHA256_PATTERN)
    poc_path: str = Field(min_length=1)
    argv: tuple[str, ...] = Field(min_length=1, max_length=256)
    cwd: str = "."
    env: dict[str, str] = Field(default_factory=dict, max_length=32)
    oracle: OracleSpec
    attempts: int = Field(default=2, ge=2, le=5)
    timeout_seconds: int = Field(default=60, ge=1, le=600)
    capture_files: tuple[str, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def validate_reproduction_spec(self) -> "ReproductionSpec":
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}", self.image) is None:
            raise ValueError("invalid Docker image reference")
        _validate_relative_path(self.poc_path, label="PoC path")
        if PurePosixPath(self.poc_path) == PurePosixPath("."):
            raise ValueError("PoC path must identify a file")
        _validate_relative_path(self.cwd, label="reproduction cwd")
        for path in self.capture_files:
            _validate_relative_path(path, label="capture path")
            if PurePosixPath(path) == PurePosixPath("."):
                raise ValueError("capture path must identify a file")
        if any(not arg or "\0" in arg for arg in self.argv):
            raise ValueError("reproduction argv entries may not be empty or contain NUL")
        for key, value in self.env.items():
            if re.fullmatch(r"[A-Z_][A-Z0-9_]*", key) is None:
                raise ValueError(f"invalid environment variable name: {key}")
            if "\0" in value:
                raise ValueError(f"environment variable contains NUL: {key}")
        if (
            self.oracle.type is OracleType.FILE_SHA256
            and self.oracle.path not in self.capture_files
        ):
            raise ValueError("file oracle path must be included in capture_files")
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
    candidate_id: str | None = None
    kind: EvidenceKind
    producer: str = Field(min_length=1)
    reproduction_group: str | None = None
    attempt: int | None = Field(default=None, ge=1)
    source_snapshot: str | None = Field(default=None, pattern=SHA256_PATTERN)
    image_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    command: tuple[str, ...] = ()
    exit_code: int | None = None
    timed_out: bool = False
    duration_ms: int | None = Field(default=None, ge=0)
    stdout_artifact: str | None = Field(default=None, pattern=SHA256_PATTERN)
    stderr_artifact: str | None = Field(default=None, pattern=SHA256_PATTERN)
    oracle: OracleResult | None = None
    artifact_ids: tuple[str, ...] = ()
    captured_artifacts: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_reproduction_contract(self) -> "Evidence":
        if self.kind is EvidenceKind.REPRODUCTION:
            required = {
                "candidate_id": self.candidate_id,
                "reproduction_group": self.reproduction_group,
                "attempt": self.attempt,
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
            if self.producer != "reproducer":
                raise ValueError("reproduction evidence must be produced by reproducer")
        if any(not arg for arg in self.command):
            raise ValueError("evidence command entries may not be empty")
        for digest in self.artifact_ids:
            if re.fullmatch(SHA256_PATTERN, digest) is None:
                raise ValueError(f"evidence has invalid artifact digest: {digest}")
        for path, digest in self.captured_artifacts.items():
            _validate_relative_path(path, label="captured artifact")
            if re.fullmatch(SHA256_PATTERN, digest) is None:
                raise ValueError(f"captured artifact has invalid digest: {path}")
        if (
            self.kind is EvidenceKind.REPRODUCTION
            and set(self.captured_artifacts.values()) != set(self.artifact_ids)
        ):
            raise ValueError(
                "reproduction artifact_ids must exactly match captured artifacts"
            )
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


class SourceFileEntry(DomainModel):
    path: str = Field(min_length=1)
    size: int = Field(ge=0)
    mode: int = Field(ge=0, le=0o777)
    digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_source_path(self) -> "SourceFileEntry":
        _validate_relative_path(self.path, label="source file")
        return self


class SourceManifest(DomainModel):
    schema_version: int = 1
    source_url: str | None = None
    resolved_ref: str | None = None
    files: tuple[SourceFileEntry, ...]
    excluded_paths: tuple[str, ...] = ()


class SourceSnapshot(DomainModel):
    snapshot_artifact: str = Field(pattern=SHA256_PATTERN)
    manifest_artifact: str = Field(pattern=SHA256_PATTERN)
    file_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)


def _validate_relative_path(value: str, *, label: str) -> None:
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must be relative and may not traverse parents")
