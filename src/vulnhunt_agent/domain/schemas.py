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
CWE_PATTERN = r"^CWE-[1-9][0-9]{0,4}$"


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
    setup_argvs: tuple[tuple[str, ...], ...] = Field(default=(), max_length=16)
    argv: tuple[str, ...] = Field(min_length=1, max_length=256)
    cwd: str = "."

    @model_validator(mode="after")
    def validate_cwd(self) -> "PocSpec":
        cwd = PurePosixPath(self.cwd.replace("\\", "/"))
        if cwd.is_absolute() or ".." in cwd.parts:
            raise ValueError("PoC cwd must stay inside the workspace")
        _validate_command(self.argv, label="PoC argv")
        for command in self.setup_argvs:
            _validate_command(command, label="PoC setup argv")
        return self


class ReproductionSpec(DomainModel):
    reproduction_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    source_snapshot: str = Field(pattern=SHA256_PATTERN)
    image: str = Field(min_length=1)
    poc_artifact: str = Field(pattern=SHA256_PATTERN)
    poc_path: str = Field(min_length=1)
    setup_argvs: tuple[tuple[str, ...], ...] = Field(default=(), max_length=16)
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
        _validate_command(self.argv, label="reproduction argv")
        for command in self.setup_argvs:
            _validate_command(command, label="reproduction setup argv")
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


class ExecutionSubject(StrEnum):
    PREPARED_BINARY = "prepared_binary"
    LINKED_TARGET_HARNESS = "linked_target_harness"
    STANDALONE_MODEL = "standalone_model"
    UNKNOWN = "unknown"


class SanitizerFrame(DomainModel):
    index: int = Field(ge=0)
    function: str = ""
    path: str = Field(min_length=1)
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    in_target: bool = False

    @model_validator(mode="after")
    def validate_frame(self) -> "SanitizerFrame":
        if "\0" in self.function or "\0" in self.path:
            raise ValueError("sanitizer frame may not contain NUL")
        return self


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
    setup_commands: tuple[tuple[str, ...], ...] = ()
    command: tuple[str, ...] = ()
    exit_code: int | None = None
    timed_out: bool = False
    duration_ms: int | None = Field(default=None, ge=0)
    stdout_artifact: str | None = Field(default=None, pattern=SHA256_PATTERN)
    stderr_artifact: str | None = Field(default=None, pattern=SHA256_PATTERN)
    oracle: OracleResult | None = None
    artifact_ids: tuple[str, ...] = ()
    captured_artifacts: dict[str, str] = Field(default_factory=dict)
    execution_subject: ExecutionSubject = ExecutionSubject.UNKNOWN
    provenance_policy: str | None = None
    clean_environment_id: str | None = None
    target_binary: str | None = None
    linked_target_artifacts: tuple[str, ...] = ()
    sanitizer_failure_class: str | None = None
    sanitizer_frames: tuple[SanitizerFrame, ...] = ()
    target_source_reached: bool = False
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
        if self.command:
            _validate_command(self.command, label="evidence command")
        for command in self.setup_commands:
            _validate_command(command, label="evidence setup command")
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
        provenance_strings = (
            self.provenance_policy,
            self.clean_environment_id,
            self.target_binary,
            self.sanitizer_failure_class,
            *self.linked_target_artifacts,
        )
        if any(value is not None and "\0" in value for value in provenance_strings):
            raise ValueError("execution provenance may not contain NUL")
        if (
            self.execution_subject is ExecutionSubject.PREPARED_BINARY
            and not self.target_binary
        ):
            raise ValueError("prepared-binary evidence requires target_binary")
        if (
            self.execution_subject is ExecutionSubject.LINKED_TARGET_HARNESS
            and not self.linked_target_artifacts
        ):
            raise ValueError(
                "linked-target-harness evidence requires linked_target_artifacts"
            )
        if self.execution_subject is ExecutionSubject.STANDALONE_MODEL:
            if self.target_source_reached:
                raise ValueError("standalone model cannot claim target source execution")
        if self.target_source_reached and (
            self.execution_subject
            not in {
                ExecutionSubject.PREPARED_BINARY,
                ExecutionSubject.LINKED_TARGET_HARNESS,
            }
            or not any(frame.in_target for frame in self.sanitizer_frames)
        ):
            raise ValueError(
                "target source execution requires prepared target sanitizer frames"
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


class ConsensusStatus(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    DISAGREEMENT = "disagreement"
    NEEDS_SECOND_REVIEW = "needs_second_review"
    VARIANT_REQUESTED = "variant_requested"


class ReproductionVariantType(StrEnum):
    SAFE_INPUT = "safe_input"
    CONFIG_TOGGLE = "config_toggle"
    FIXED_REVISION = "fixed_revision"
    ALTERNATE_TRIGGER = "alternate_trigger"


class ReviewVerdict(DomainModel):
    candidate_id: str = Field(min_length=1)
    verdict: Verdict
    notes: str = Field(min_length=1)
    cvss_vector: str = ""
    cwe_id: str = ""
    evidence_ids: tuple[str, ...] = Field(default=(), max_length=128)
    reviewer: str = Field(min_length=1)
    model_id: str = ""
    prompt_version: str = "evidence-review-v1"
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_cvss_contract(self) -> "ReviewVerdict":
        if self.verdict is Verdict.REAL:
            if not self.cvss_vector:
                raise ValueError("real verdict requires a CVSS 3.1 vector")
            import re

            if re.fullmatch(CVSS31_PATTERN, self.cvss_vector) is None:
                raise ValueError("invalid CVSS 3.1 vector")
            if re.fullmatch(CWE_PATTERN, self.cwe_id) is None:
                raise ValueError("real verdict requires a valid CWE identifier")
            if not self.evidence_ids:
                raise ValueError("real verdict requires cited evidence IDs")
        elif self.cvss_vector or self.cwe_id:
            raise ValueError("non-real verdict must not carry CVSS or CWE classification")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("review evidence IDs must be unique")
        return self


class ConsensusDecision(DomainModel):
    candidate_id: str = Field(min_length=1)
    status: ConsensusStatus
    reviewers: tuple[str, ...] = ()
    verdict: Verdict | None = None
    cvss_vector: str = ""
    cwe_id: str = ""
    evidence_ids: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()


class ReproductionVariantRequest(DomainModel):
    request_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    reviewer: str = Field(min_length=1)
    base_reproduction_group: str = Field(min_length=1)
    variant_type: ReproductionVariantType
    rationale: str = Field(min_length=1)
    requested_change: str = Field(min_length=1)


class RunRecord(DomainModel):
    run_id: str = Field(min_length=1)
    state: RunState = RunState.CREATED
    source_url: str | None = None
    source_ref: str | None = None
    source_snapshot: str | None = Field(default=None, pattern=SHA256_PATTERN)
    config: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


MAX_HUNTER_TARGET_NODES = 4
MAX_HUNTER_TARGET_SIGNALS = 6


class HunterWorkItem(DomainModel):
    """Stable unit of Hunter scheduling, independent of its queue backend."""

    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    run_id: str = Field(min_length=1)
    source_snapshot: str = Field(pattern=SHA256_PATTERN)
    scan_scope_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    planning_policy: str = Field(min_length=1)
    slice_ids: tuple[str, ...] = ()
    target_node_ids: tuple[str, ...] = Field(
        default=(),
        max_length=MAX_HUNTER_TARGET_NODES,
    )
    target_signal_ids: tuple[str, ...] = Field(
        default=(),
        max_length=MAX_HUNTER_TARGET_SIGNALS,
    )
    changed_line_ranges: dict[str, tuple[tuple[int, int], ...]] = Field(
        default_factory=dict,
        max_length=32,
    )
    seed_file: str = Field(min_length=1)
    files: tuple[str, ...] = Field(min_length=1, max_length=32)
    hunter: str = Field(min_length=1)
    pass_index: int = Field(default=1, ge=1, le=8)
    risk: int = Field(default=1, ge=1, le=5)
    required: bool = False
    routing_reasons: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_work_item(self) -> "HunterWorkItem":
        _validate_relative_path(self.seed_file, label="Hunter seed file")
        for path in self.files:
            _validate_relative_path(path, label="Hunter context file")
        if self.seed_file not in self.files:
            raise ValueError("Hunter seed file must be included in files")
        if len(set(self.files)) != len(self.files):
            raise ValueError("Hunter context files must be unique")
        if len(set(self.slice_ids)) != len(self.slice_ids):
            raise ValueError("Hunter slice IDs must be unique")
        if len(set(self.target_node_ids)) != len(self.target_node_ids):
            raise ValueError("Hunter target node IDs must be unique")
        if len(set(self.target_signal_ids)) != len(self.target_signal_ids):
            raise ValueError("Hunter target signal IDs must be unique")
        for path, ranges in self.changed_line_ranges.items():
            _validate_relative_path(path, label="Hunter changed-range file")
            for start, end in ranges:
                if start < 1 or end < start:
                    raise ValueError("Hunter changed line ranges must be positive and ordered")
        return self


class HunterRoutingPlan(DomainModel):
    policy_version: str = Field(min_length=1)
    mode: str = Field(default="signal", pattern=r"^(signal|legacy)$")
    legacy_sessions: int = Field(ge=0)
    work_items: tuple[HunterWorkItem, ...] = ()
    detected_critical_sink_ids: tuple[str, ...] = ()
    covered_critical_sink_ids: tuple[str, ...] = ()
    uncovered_critical_sink_ids: tuple[str, ...] = ()
    forced_files: tuple[str, ...] = ()
    scan_scope_digest: str | None = Field(default=None, pattern=SHA256_PATTERN)
    scope_deferred_critical_sink_ids: tuple[str, ...] = ()
    repository_complete: bool = True

    @model_validator(mode="after")
    def validate_routing_coverage(self) -> "HunterRoutingPlan":
        detected = set(self.detected_critical_sink_ids)
        covered = set(self.covered_critical_sink_ids)
        uncovered = set(self.uncovered_critical_sink_ids)
        if covered | uncovered != detected or covered & uncovered:
            raise ValueError("critical-sink routing coverage is inconsistent")
        if detected & set(self.scope_deferred_critical_sink_ids):
            raise ValueError("in-scope and scope-deferred critical sinks overlap")
        if tuple(sorted(set(self.scope_deferred_critical_sink_ids))) != (
            self.scope_deferred_critical_sink_ids
        ):
            raise ValueError("scope-deferred critical sink IDs must be sorted and unique")
        work_ids = [item.work_id for item in self.work_items]
        if len(set(work_ids)) != len(work_ids):
            raise ValueError("routing plan contains duplicate work IDs")
        return self

    @property
    def scheduled_sessions(self) -> int:
        return len(self.work_items)

    @property
    def session_reduction_percent(self) -> float:
        if not self.legacy_sessions:
            return 0.0
        return round(
            (1 - self.scheduled_sessions / self.legacy_sessions) * 100,
            2,
        )


class BudgetPolicy(DomainModel):
    """Hard scheduling limits. Token limits work for API and subscription modes."""

    max_hunter_sessions: int = Field(default=100, ge=1)
    max_input_tokens: int = Field(default=2_000_000, ge=1)
    max_output_tokens: int = Field(default=200_000, ge=1)
    max_wall_clock_minutes: int = Field(default=60, ge=1)
    max_retries_per_work_item: int = Field(default=1, ge=0, le=8)


class BudgetUsage(DomainModel):
    """Provider-neutral observed consumption for one schedulable work item."""

    run_id: str = Field(min_length=1)
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    scope: str = Field(pattern=r"^(ranker|hunter|reviewer)$")
    model_id: str = Field(min_length=1)
    transport: str = Field(min_length=1)
    sessions: int = Field(default=0, ge=0)
    calls: int = Field(default=0, ge=0)
    iterations: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cache_read_tokens: int = Field(default=0, ge=0)
    cache_write_tokens: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    repeated_reads: int = Field(default=0, ge=0)
    poc_writes: int = Field(default=0, ge=0)
    exec_calls: int = Field(default=0, ge=0)
    wall_time_ms: int = Field(default=0, ge=0)
    estimated_cost_usd: float | None = Field(default=None, ge=0)
    created_at: datetime = Field(default_factory=utc_now)


class ProviderPreflightCode(StrEnum):
    READY = "ready"
    STATE_STORE_READ_ONLY = "state_store_read_only"
    APP_SERVER_INIT_DENIED = "app_server_init_denied"
    AUTHENTICATION_REQUIRED = "authentication_required"
    MODEL_UNAVAILABLE = "model_unavailable"
    UNSUPPORTED_CLI_FEATURE = "unsupported_cli_feature"
    PROVIDER_PROTOCOL_ERROR = "provider_protocol_error"
    PROVIDER_TRANSPORT_ERROR = "provider_transport_error"
    PROVIDER_CONFIGURATION_ERROR = "provider_configuration_error"


class ProviderPreflightCheck(DomainModel):
    name: str = Field(min_length=1, max_length=100)
    status: str = Field(pattern=r"^(passed|failed|skipped)$")
    detail: str = Field(default="", max_length=300)


class ProviderPreflightResult(DomainModel):
    """Redacted, provider-neutral readiness result produced before admission."""

    policy_version: str = "provider-preflight-v1"
    transport: str = Field(min_length=1, max_length=100)
    model_id: str = Field(min_length=1, max_length=300)
    ready: bool
    code: ProviderPreflightCode
    remediation: str = Field(default="", max_length=500)
    diagnostic_fingerprint: str | None = Field(
        default=None,
        pattern=SHA256_PATTERN,
    )
    model_probe_requested: bool = False
    billable_model_calls: int = Field(default=0, ge=0, le=1)
    checks: tuple[ProviderPreflightCheck, ...] = ()

    @model_validator(mode="after")
    def validate_readiness(self) -> "ProviderPreflightResult":
        if self.ready and self.code is not ProviderPreflightCode.READY:
            raise ValueError("ready provider preflight must use the ready code")
        if not self.ready:
            if self.code is ProviderPreflightCode.READY:
                raise ValueError("failed provider preflight requires a failure code")
            if not self.remediation:
                raise ValueError("failed provider preflight requires remediation")
            if self.diagnostic_fingerprint is None:
                raise ValueError("failed provider preflight requires a diagnostic fingerprint")
        if self.model_probe_requested and self.billable_model_calls != 1:
            raise ValueError("requested model probe must account for exactly one call")
        if not self.model_probe_requested and self.billable_model_calls:
            raise ValueError("local-only preflight cannot account for model calls")
        return self


class ScanScopeMode(StrEnum):
    FULL = "full"
    FILES = "files"
    COMPONENT = "component"


class ScanScopeManifest(DomainModel):
    """Canonical scheduling scope over an immutable full source snapshot."""

    policy_version: str = "scan-scope-v1"
    mode: ScanScopeMode = ScanScopeMode.FULL
    include_paths: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()
    selected_files: tuple[str, ...] = ()
    in_scope_critical_sink_ids: tuple[str, ...] = ()
    scope_deferred_critical_sink_ids: tuple[str, ...] = ()
    digest: str = Field(pattern=SHA256_PATTERN)
    repository_complete: bool

    @model_validator(mode="after")
    def validate_scope(self) -> "ScanScopeManifest":
        for label, paths in (
            ("scope include", self.include_paths),
            ("scope exclude", self.exclude_paths),
            ("scope selected", self.selected_files),
        ):
            if tuple(sorted(set(paths))) != paths:
                raise ValueError(f"{label} paths must be sorted and unique")
            for path in paths:
                _validate_relative_path(path, label=label)
        for label, identifiers in (
            ("in-scope critical", self.in_scope_critical_sink_ids),
            ("scope-deferred critical", self.scope_deferred_critical_sink_ids),
        ):
            if tuple(sorted(set(identifiers))) != identifiers:
                raise ValueError(f"{label} IDs must be sorted and unique")
        if set(self.in_scope_critical_sink_ids) & set(
            self.scope_deferred_critical_sink_ids
        ):
            raise ValueError("critical sink cannot be both in scope and deferred")
        if self.mode is ScanScopeMode.FULL:
            if self.include_paths or self.exclude_paths:
                raise ValueError("full scope cannot contain include or exclude paths")
            if not self.repository_complete:
                raise ValueError("full scope must be repository-complete")
            if self.scope_deferred_critical_sink_ids:
                raise ValueError("full scope cannot defer critical sinks by scope")
        else:
            if not self.include_paths:
                raise ValueError("bounded scope requires at least one include path")
            if self.repository_complete:
                raise ValueError("bounded scope cannot claim repository completeness")
        return self


class TaskLease(DomainModel):
    run_id: str = Field(min_length=1, max_length=200)
    task_type: str = Field(min_length=1, max_length=100)
    task_key: str = Field(min_length=1, max_length=1000)
    worker_id: str = Field(min_length=1, max_length=200)
    lease_token: str = Field(min_length=16, max_length=128)
    attempt: int = Field(ge=1)
    acquired_at: datetime
    heartbeat_at: datetime
    expires_at: datetime
    payload: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_lease_window(self) -> "TaskLease":
        if self.acquired_at.tzinfo is None:
            raise ValueError("task lease acquired_at must be timezone-aware")
        if self.heartbeat_at.tzinfo is None:
            raise ValueError("task lease heartbeat_at must be timezone-aware")
        if self.expires_at.tzinfo is None:
            raise ValueError("task lease expires_at must be timezone-aware")
        if self.heartbeat_at < self.acquired_at:
            raise ValueError("task lease heartbeat precedes acquisition")
        if self.expires_at <= self.heartbeat_at:
            raise ValueError("task lease expiry must follow heartbeat")
        return self


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


class SourceSymlinkEntry(DomainModel):
    path: str = Field(min_length=1)
    target: str = Field(min_length=1)
    resolved_path: str = Field(min_length=1)
    digest: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_source_paths(self) -> "SourceSymlinkEntry":
        _validate_relative_path(self.path, label="source symlink")
        _validate_relative_path(self.resolved_path, label="resolved source symlink")
        if "\0" in self.target:
            raise ValueError("source symlink target may not contain NUL")
        return self


class SourceManifest(DomainModel):
    schema_version: int = 1
    normalization_policy: str = "source-snapshot-v1"
    source_url: str | None = None
    resolved_ref: str | None = None
    files: tuple[SourceFileEntry, ...]
    excluded_paths: tuple[str, ...] = ()
    symlinks: tuple[SourceSymlinkEntry, ...] = ()


class SourceSnapshot(DomainModel):
    snapshot_artifact: str = Field(pattern=SHA256_PATTERN)
    manifest_artifact: str = Field(pattern=SHA256_PATTERN)
    file_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)


def _validate_relative_path(value: str, *, label: str) -> None:
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must be relative and may not traverse parents")


def _validate_command(command: tuple[str, ...], *, label: str) -> None:
    if not command or len(command) > 256:
        raise ValueError(f"{label} must contain 1..256 entries")
    if any(not arg or "\0" in arg for arg in command):
        raise ValueError(f"{label} entries may not be empty or contain NUL")
