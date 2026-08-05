"""Blind, code-only M17 benchmark and real-ImageIO effectiveness gate."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Awaitable, Callable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from ...domain.schemas import DomainModel, SHA256_PATTERN
from .benchmark import BlindRegressionGateResult
from .code_reviewer import StaticReportabilityStatus

M15_FROZEN_OBSERVATION_SHA256 = (
    "sha256:84e4a0cdbbf6b44c689a259c579ef57f475e8064bcad549b3b68adec783795a4"
)
_STATIC_STAGE_NAMES = (
    "decompilation",
    "normalization",
    "discovery",
    "analysis",
    "ranking",
    "admission",
    "capsule",
)
_ALL_STAGE_NAMES = _STATIC_STAGE_NAMES + (
    "hunter",
    "context",
    "reviewer",
    "reportability",
)


class M17BlindCohort(StrEnum):
    M16_COMPOSITE_RANGE = "m16_composite_range"
    M16_PARTIAL_INITIALIZATION = "m16_partial_initialization"
    CODE_FIRST = "code_first"
    HISTORICAL_IMAGEIO = "historical_imageio"


class M17BlindTargetRole(StrEnum):
    FIXTURE_POSITIVE = "fixture_positive"
    SAFE_CONTROL = "safe_control"
    HISTORICAL_VULNERABLE = "historical_vulnerable"
    HISTORICAL_PATCHED = "historical_patched"
    CURRENT_BUILD = "current_build"


class M17BlindHunterOutcome(StrEnum):
    CODE_HYPOTHESIS = "code_hypothesis"
    NEEDS_CODE_CONTEXT = "needs_code_context"
    NOT_VULNERABLE = "not_vulnerable"
    INCONCLUSIVE = "inconclusive"
    SCOPE_BLOCKED = "scope_blocked"
    NOT_RUN = "not_run"


class M17BlindGateFailure(StrEnum):
    M15_REGRESSION = "m15_regression"
    INPUT_CHANGED = "input_changed"
    STATIC_ARTIFACT_NONDETERMINISM = "static_artifact_nondeterminism"
    MODEL_OUTCOME_INSTABILITY = "model_outcome_instability"
    POSITIVE_NOT_ADMITTED = "positive_not_admitted"
    CODE_FIRST_HYPOTHESIS_MISSING = "code_first_hypothesis_missing"
    EXPECTED_REPORTABLE_MISSING = "expected_reportable_missing"
    SAFE_OR_PATCHED_REPORTABLE = "safe_or_patched_reportable"
    COST_CEILING_EXCEEDED = "cost_ceiling_exceeded"
    MISSING_REQUIRED_COHORT = "missing_required_cohort"
    INSUFFICIENT_CODE_FIRST_POSITIVES = "insufficient_code_first_positives"


class M17EffectivenessBlocker(StrEnum):
    HISTORICAL_IMAGEIO_COHORT_UNAVAILABLE = "historical_imageio_cohort_unavailable"


class M17BlindGateStatus(StrEnum):
    PASSED = "passed"
    IMPLEMENTATION_PASSED_EFFECTIVENESS_BLOCKED = "implementation_passed_effectiveness_blocked"
    FAILED = "failed"


class M17BlindBenchmarkPolicy(DomainModel):
    schema_version: Literal["m17-blind-code-policy-v1"] = "m17-blind-code-policy-v1"
    repeat_runs: Literal[2] = 2
    maximum_hunter_sessions_per_run: Literal[16] = 16
    maximum_continuation_roots_per_run: Literal[6] = 6
    maximum_hunter_continuation_calls_per_run: Literal[12] = 12
    maximum_reviewer_sessions_per_run: Literal[6] = 6
    maximum_reviewer_context_calls_per_run: Literal[6] = 6
    maximum_model_calls_per_run: Literal[34] = 34
    maximum_input_tokens_per_run: Literal[1_000_000] = 1_000_000
    maximum_output_tokens_per_run: Literal[100_000] = 100_000
    maximum_wall_clock_seconds_per_run: Literal[5400] = 5400


class M17BlindCase(DomainModel):
    case_id: str = Field(pattern=r"^case-[0-9]{3,4}$")
    build_id: str = Field(pattern=r"^build-[0-9]{3,4}$")
    artifact_name: str = Field(pattern=r"^case-[0-9]{3,4}(?:\.[A-Za-z0-9_-]+)*$")
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)


class M17BlindBenchmarkManifest(DomainModel):
    schema_version: Literal["m17-blind-code-manifest-v1"] = "m17-blind-code-manifest-v1"
    cases: tuple[M17BlindCase, ...] = Field(min_length=1, max_length=100)
    coverage_policy_sha256: str = Field(pattern=SHA256_PATTERN)
    hunter_prompt_sha256: str = Field(pattern=SHA256_PATTERN)
    reviewer_prompt_sha256: str = Field(pattern=SHA256_PATTERN)
    model_id: str = Field(min_length=1, max_length=300)
    budget_policy: M17BlindBenchmarkPolicy
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_manifest(self) -> "M17BlindBenchmarkManifest":
        if tuple(sorted(self.cases, key=lambda item: item.case_id)) != self.cases:
            raise ValueError("M17 blind cases must use opaque case order")
        if len({item.case_id for item in self.cases}) != len(self.cases):
            raise ValueError("M17 blind manifest contains duplicate case IDs")
        if len({item.build_id for item in self.cases}) != len(self.cases):
            raise ValueError("M17 blind manifest contains duplicate build IDs")
        if len({item.artifact_name for item in self.cases}) != len(self.cases):
            raise ValueError("M17 blind manifest contains duplicate artifact names")
        if any(not item.artifact_name.startswith(f"{item.case_id}.") for item in self.cases):
            raise ValueError("M17 artifact names must expose only their opaque case ID")
        expected = _digest(self.model_dump(mode="json", exclude={"manifest_sha256"}))
        if self.manifest_sha256 != expected:
            raise ValueError("M17 blind manifest digest mismatch")
        return self


class M17BlindExpectedOutcome(DomainModel):
    case_id: str = Field(pattern=r"^case-[0-9]{3,4}$")
    cohort: M17BlindCohort
    target_role: M17BlindTargetRole
    expected_admitted: bool
    expected_code_hypothesis: bool
    expected_reportable_static: bool
    deterministic_finding_visible: bool

    @model_validator(mode="after")
    def validate_outcome(self) -> "M17BlindExpectedOutcome":
        if (
            self.target_role
            in {
                M17BlindTargetRole.SAFE_CONTROL,
                M17BlindTargetRole.HISTORICAL_PATCHED,
                M17BlindTargetRole.CURRENT_BUILD,
            }
            and self.expected_reportable_static
        ):
            raise ValueError("safe, patched, and current controls cannot expect reportability")
        if self.cohort is M17BlindCohort.CODE_FIRST:
            if self.deterministic_finding_visible:
                raise ValueError("code-first cases must be invisible to deterministic rules")
            if (
                self.target_role is M17BlindTargetRole.FIXTURE_POSITIVE
                and not self.expected_code_hypothesis
            ):
                raise ValueError("code-first positives must expect a code hypothesis")
        if self.target_role is M17BlindTargetRole.HISTORICAL_VULNERABLE:
            if not self.expected_reportable_static:
                raise ValueError("historical vulnerable target must expect reportable_static")
        return self


class M17BlindOracle(DomainModel):
    schema_version: Literal["m17-blind-code-oracle-v1"] = "m17-blind-code-oracle-v1"
    outcomes: tuple[M17BlindExpectedOutcome, ...] = Field(min_length=1, max_length=100)
    oracle_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_oracle(self) -> "M17BlindOracle":
        if tuple(sorted(self.outcomes, key=lambda item: item.case_id)) != self.outcomes:
            raise ValueError("M17 oracle outcomes must use case order")
        if len({item.case_id for item in self.outcomes}) != len(self.outcomes):
            raise ValueError("M17 oracle contains duplicate case IDs")
        expected = _digest(self.model_dump(mode="json", exclude={"oracle_sha256"}))
        if self.oracle_sha256 != expected:
            raise ValueError("M17 oracle digest mismatch")
        return self


class M17BlindStageDigest(DomainModel):
    stage: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,39}$")
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)


class M17BlindCaseObservation(DomainModel):
    schema_version: Literal["m17-blind-code-observation-v1"] = "m17-blind-code-observation-v1"
    case_id: str = Field(pattern=r"^case-[0-9]{3,4}$")
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    stages: tuple[M17BlindStageDigest, ...] = Field(min_length=11, max_length=11)
    admitted: bool
    omission_reason: str = Field(default="", max_length=1000)
    deterministic_finding_count: int = Field(ge=0)
    hunter_outcome: M17BlindHunterOutcome
    hypothesis_fingerprints: tuple[str, ...] = Field(default=(), max_length=8)
    context_response_sha256s: tuple[str, ...] = Field(default=(), max_length=2)
    reportability_statuses: tuple[StaticReportabilityStatus, ...] = Field(default=(), max_length=8)
    hunter_sessions: int = Field(ge=0, le=16)
    continuation_roots: int = Field(ge=0, le=6)
    hunter_continuation_calls: int = Field(ge=0, le=12)
    reviewer_sessions: int = Field(ge=0, le=6)
    reviewer_context_calls: int = Field(ge=0, le=6)
    model_calls: int = Field(ge=0, le=34)
    input_tokens: int = Field(ge=0, le=1_000_000)
    output_tokens: int = Field(ge=0, le=100_000)
    wall_clock_seconds: float = Field(ge=0.0, le=5400.0)
    image_executions: Literal[0] = 0
    generated_inputs: Literal[0] = 0
    fuzzer_invocations: Literal[0] = 0
    vm_boots: Literal[0] = 0
    dynamic_experiments: Literal[0] = 0
    observation_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_observation(self) -> "M17BlindCaseObservation":
        if tuple(item.stage for item in self.stages) != _ALL_STAGE_NAMES:
            raise ValueError("M17 observation must bind every stage in normative order")
        if len({item.stage for item in self.stages}) != len(self.stages):
            raise ValueError("M17 observation contains duplicate stages")
        if tuple(sorted(set(self.hypothesis_fingerprints))) != self.hypothesis_fingerprints:
            raise ValueError("hypothesis fingerprints must be sorted and unique")
        if tuple(sorted(set(self.context_response_sha256s))) != self.context_response_sha256s:
            raise ValueError("context response digests must be sorted and unique")
        expected_statuses = tuple(
            sorted(set(self.reportability_statuses), key=lambda item: item.value)
        )
        if expected_statuses != self.reportability_statuses:
            raise ValueError("reportability statuses must be sorted and unique")
        if not self.admitted and not self.omission_reason:
            raise ValueError("omitted case requires a bounded omission reason")
        if self.admitted and self.omission_reason:
            raise ValueError("admitted case cannot retain an omission reason")
        if self.hunter_outcome is M17BlindHunterOutcome.CODE_HYPOTHESIS:
            if not self.hypothesis_fingerprints:
                raise ValueError("code_hypothesis observation requires a fingerprint")
        elif self.hypothesis_fingerprints:
            raise ValueError("non-hypothesis outcome cannot retain hypothesis fingerprints")
        if self.reportability_statuses and not self.hypothesis_fingerprints:
            raise ValueError("reportability decisions require a code hypothesis")
        expected = _digest(self.model_dump(mode="json", exclude={"observation_sha256"}))
        if self.observation_sha256 != expected:
            raise ValueError("M17 case observation digest mismatch")
        return self


class M17BlindRun(DomainModel):
    schema_version: Literal["m17-blind-code-run-v1"] = "m17-blind-code-run-v1"
    run_ordinal: int = Field(ge=1, le=2)
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    observations: tuple[M17BlindCaseObservation, ...] = Field(min_length=1, max_length=100)
    static_seal_sha256: str = Field(pattern=SHA256_PATTERN)
    semantic_seal_sha256: str = Field(pattern=SHA256_PATTERN)
    hunter_sessions: int = Field(ge=0)
    continuation_roots: int = Field(ge=0)
    hunter_continuation_calls: int = Field(ge=0)
    reviewer_sessions: int = Field(ge=0)
    reviewer_context_calls: int = Field(ge=0)
    model_calls: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    wall_clock_seconds: float = Field(ge=0.0)
    run_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_run(self) -> "M17BlindRun":
        if tuple(sorted(self.observations, key=lambda item: item.case_id)) != self.observations:
            raise ValueError("M17 run observations must use case order")
        fields = (
            "hunter_sessions",
            "continuation_roots",
            "hunter_continuation_calls",
            "reviewer_sessions",
            "reviewer_context_calls",
            "model_calls",
            "input_tokens",
            "output_tokens",
        )
        for field in fields:
            if getattr(self, field) != sum(getattr(item, field) for item in self.observations):
                raise ValueError(f"M17 run {field} accounting mismatch")
        if self.wall_clock_seconds != sum(item.wall_clock_seconds for item in self.observations):
            raise ValueError("M17 run wall-clock accounting mismatch")
        if self.static_seal_sha256 != _static_seal(self.observations):
            raise ValueError("M17 static seal digest mismatch")
        if self.semantic_seal_sha256 != _semantic_seal(self.observations):
            raise ValueError("M17 semantic seal digest mismatch")
        expected = _digest(self.model_dump(mode="json", exclude={"run_sha256"}))
        if self.run_sha256 != expected:
            raise ValueError("M17 run digest mismatch")
        return self


class M17BlindCaseGateResult(DomainModel):
    case_id: str = Field(pattern=r"^case-[0-9]{3,4}$")
    cohort: M17BlindCohort
    target_role: M17BlindTargetRole
    admitted_both_runs: bool
    code_hypothesis_both_runs: bool
    reportable_primary: bool
    reportable_repeat: bool
    static_deterministic: bool
    semantic_stable: bool
    passed: bool
    failures: tuple[M17BlindGateFailure, ...] = ()


class M17BlindBenchmarkResult(DomainModel):
    schema_version: Literal["m17-blind-code-gate-v1"] = "m17-blind-code-gate-v1"
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    oracle_sha256: str = Field(pattern=SHA256_PATTERN)
    m15_observation_sha256: str = Field(pattern=SHA256_PATTERN)
    primary: M17BlindRun
    repeat: M17BlindRun
    cases: tuple[M17BlindCaseGateResult, ...] = Field(min_length=1, max_length=100)
    failures: tuple[M17BlindGateFailure, ...]
    effectiveness_blockers: tuple[M17EffectivenessBlocker, ...]
    status: M17BlindGateStatus
    implementation_passed: bool
    effectiveness_complete: bool
    oracle_loaded_after_both_seals: Literal[True] = True
    image_executions: Literal[0] = 0
    generated_inputs: Literal[0] = 0
    fuzzer_invocations: Literal[0] = 0
    vm_boots: Literal[0] = 0
    dynamic_experiments: Literal[0] = 0
    result_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_result(self) -> "M17BlindBenchmarkResult":
        if tuple(sorted(set(self.failures), key=lambda item: item.value)) != self.failures:
            raise ValueError("M17 gate failures must be sorted and unique")
        if (
            tuple(sorted(set(self.effectiveness_blockers), key=lambda item: item.value))
            != self.effectiveness_blockers
        ):
            raise ValueError("M17 effectiveness blockers must be sorted and unique")
        if self.implementation_passed != (not self.failures):
            raise ValueError("M17 implementation status differs from gate failures")
        expected_complete = self.implementation_passed and not self.effectiveness_blockers
        if self.effectiveness_complete != expected_complete:
            raise ValueError("M17 effectiveness status differs from its blockers")
        expected_status = (
            M17BlindGateStatus.FAILED
            if self.failures
            else M17BlindGateStatus.PASSED
            if not self.effectiveness_blockers
            else M17BlindGateStatus.IMPLEMENTATION_PASSED_EFFECTIVENESS_BLOCKED
        )
        if self.status is not expected_status:
            raise ValueError("M17 gate status is inconsistent")
        expected = _digest(self.model_dump(mode="json", exclude={"result_sha256"}))
        if self.result_sha256 != expected:
            raise ValueError("M17 blind gate result digest mismatch")
        return self


M17BlindAnalyzer = Callable[[M17BlindCase, Path, int], Awaitable[M17BlindCaseObservation]]


def freeze_m17_blind_benchmark(
    artifacts: Mapping[str, tuple[Path, str]],
    *,
    coverage_policy_sha256: str,
    hunter_prompt_sha256: str,
    reviewer_prompt_sha256: str,
    model_id: str,
    policy: M17BlindBenchmarkPolicy | None = None,
) -> M17BlindBenchmarkManifest:
    cases_list: list[M17BlindCase] = []
    for ordinal, (case_id, (path, snapshot_sha256)) in enumerate(
        sorted(artifacts.items()), start=1
    ):
        artifact = _regular_file(path)
        if not artifact.name.startswith(f"{case_id}."):
            raise ValueError("M17 benchmark artifacts must be staged under opaque case-ID names")
        cases_list.append(
            M17BlindCase(
                case_id=case_id,
                build_id=f"build-{ordinal:03d}",
                artifact_name=artifact.name,
                artifact_sha256=_sha256_file(artifact),
                snapshot_sha256=snapshot_sha256,
            )
        )
    cases = tuple(cases_list)
    payload = {
        "schema_version": "m17-blind-code-manifest-v1",
        "cases": tuple(item.model_dump(mode="json") for item in cases),
        "coverage_policy_sha256": coverage_policy_sha256,
        "hunter_prompt_sha256": hunter_prompt_sha256,
        "reviewer_prompt_sha256": reviewer_prompt_sha256,
        "model_id": model_id,
        "budget_policy": (policy or M17BlindBenchmarkPolicy()).model_dump(mode="json"),
    }
    return M17BlindBenchmarkManifest(**payload, manifest_sha256=_digest(payload))


def make_m17_blind_oracle(
    outcomes: Sequence[M17BlindExpectedOutcome],
) -> M17BlindOracle:
    ordered = tuple(sorted(outcomes, key=lambda item: item.case_id))
    payload = {
        "schema_version": "m17-blind-code-oracle-v1",
        "outcomes": tuple(item.model_dump(mode="json") for item in ordered),
    }
    return M17BlindOracle(**payload, oracle_sha256=_digest(payload))


def make_m17_case_observation(**values: object) -> M17BlindCaseObservation:
    payload = {"schema_version": "m17-blind-code-observation-v1", **values}
    draft = M17BlindCaseObservation.model_construct(
        **payload,
        observation_sha256="sha256:" + "0" * 64,
    )
    normalized = draft.model_dump(mode="json", exclude={"observation_sha256"})
    return M17BlindCaseObservation(
        **normalized,
        observation_sha256=_digest(normalized),
    )


async def run_m17_blind_code_gate(
    manifest: M17BlindBenchmarkManifest,
    *,
    artifact_directory: Path,
    output_directory: Path,
    analyze_case: M17BlindAnalyzer,
    oracle_loader: Callable[[], M17BlindOracle],
    m15_gate: BlindRegressionGateResult,
) -> M17BlindBenchmarkResult:
    """Run and seal both blind passes before loading the private oracle."""

    root = _regular_directory(artifact_directory)
    output = _private_output(output_directory)
    primary = await _run_once(manifest, root, analyze_case, 1)
    _write_private_json(output / "sealed-run-01.json", primary.model_dump(mode="json"))
    repeat = await _run_once(manifest, root, analyze_case, 2)
    _write_private_json(output / "sealed-run-02.json", repeat.model_dump(mode="json"))
    oracle = oracle_loader()
    if tuple(item.case_id for item in oracle.outcomes) != tuple(
        item.case_id for item in manifest.cases
    ):
        raise ValueError("M17 oracle case inventory differs from frozen manifest")
    cases = _score_cases(manifest, primary, repeat, oracle)
    failures = {failure for item in cases for failure in item.failures}
    failures.update(_required_cohort_failures(oracle))
    if (
        not m15_gate.passed
        or m15_gate.benchmark.true_positives != 6
        or m15_gate.benchmark.false_positives != 0
        or m15_gate.benchmark.false_negatives != 0
        or m15_gate.primary_observation_sha256 != M15_FROZEN_OBSERVATION_SHA256
        or m15_gate.repeat_observation_sha256 != M15_FROZEN_OBSERVATION_SHA256
    ):
        failures.add(M17BlindGateFailure.M15_REGRESSION)
    if _over_cost(primary, manifest.budget_policy) or _over_cost(repeat, manifest.budget_policy):
        failures.add(M17BlindGateFailure.COST_CEILING_EXCEEDED)
    historical_roles = {
        item.target_role
        for item in oracle.outcomes
        if item.cohort is M17BlindCohort.HISTORICAL_IMAGEIO
    }
    required_history = {
        M17BlindTargetRole.HISTORICAL_VULNERABLE,
        M17BlindTargetRole.HISTORICAL_PATCHED,
        M17BlindTargetRole.CURRENT_BUILD,
    }
    blockers: set[M17EffectivenessBlocker] = set()
    if not required_history.issubset(historical_roles):
        blockers.add(M17EffectivenessBlocker.HISTORICAL_IMAGEIO_COHORT_UNAVAILABLE)
    ordered_failures = tuple(sorted(failures, key=lambda item: item.value))
    ordered_blockers = tuple(sorted(blockers, key=lambda item: item.value))
    status = (
        M17BlindGateStatus.FAILED
        if ordered_failures
        else M17BlindGateStatus.PASSED
        if not ordered_blockers
        else M17BlindGateStatus.IMPLEMENTATION_PASSED_EFFECTIVENESS_BLOCKED
    )
    payload = {
        "schema_version": "m17-blind-code-gate-v1",
        "manifest_sha256": manifest.manifest_sha256,
        "oracle_sha256": oracle.oracle_sha256,
        "m15_observation_sha256": m15_gate.primary_observation_sha256,
        "primary": primary.model_dump(mode="json"),
        "repeat": repeat.model_dump(mode="json"),
        "cases": tuple(item.model_dump(mode="json") for item in cases),
        "failures": tuple(item.value for item in ordered_failures),
        "effectiveness_blockers": tuple(item.value for item in ordered_blockers),
        "status": status.value,
        "implementation_passed": not ordered_failures,
        "effectiveness_complete": not ordered_failures and not ordered_blockers,
        "oracle_loaded_after_both_seals": True,
        "image_executions": 0,
        "generated_inputs": 0,
        "fuzzer_invocations": 0,
        "vm_boots": 0,
        "dynamic_experiments": 0,
    }
    result = M17BlindBenchmarkResult(**payload, result_sha256=_digest(payload))
    _write_private_json(output / "gate-result.json", result.model_dump(mode="json"))
    return result


async def _run_once(
    manifest: M17BlindBenchmarkManifest,
    root: Path,
    analyze_case: M17BlindAnalyzer,
    ordinal: int,
) -> M17BlindRun:
    observations: list[M17BlindCaseObservation] = []
    for case in manifest.cases:
        artifact = _regular_file(root / case.artifact_name)
        if _sha256_file(artifact) != case.artifact_sha256:
            raise ValueError(f"M17 frozen input changed before analysis: {case.case_id}")
        observation = await analyze_case(case, artifact, ordinal)
        if (
            observation.case_id != case.case_id
            or observation.artifact_sha256 != case.artifact_sha256
        ):
            raise ValueError("M17 analyzer changed blind case identity")
        observations.append(observation)
    ordered = tuple(observations)
    payload = {
        "schema_version": "m17-blind-code-run-v1",
        "run_ordinal": ordinal,
        "manifest_sha256": manifest.manifest_sha256,
        "observations": tuple(item.model_dump(mode="json") for item in ordered),
        "static_seal_sha256": _static_seal(ordered),
        "semantic_seal_sha256": _semantic_seal(ordered),
        "hunter_sessions": sum(item.hunter_sessions for item in ordered),
        "continuation_roots": sum(item.continuation_roots for item in ordered),
        "hunter_continuation_calls": sum(item.hunter_continuation_calls for item in ordered),
        "reviewer_sessions": sum(item.reviewer_sessions for item in ordered),
        "reviewer_context_calls": sum(item.reviewer_context_calls for item in ordered),
        "model_calls": sum(item.model_calls for item in ordered),
        "input_tokens": sum(item.input_tokens for item in ordered),
        "output_tokens": sum(item.output_tokens for item in ordered),
        "wall_clock_seconds": sum(item.wall_clock_seconds for item in ordered),
    }
    return M17BlindRun(**payload, run_sha256=_digest(payload))


def _score_cases(
    manifest: M17BlindBenchmarkManifest,
    primary: M17BlindRun,
    repeat: M17BlindRun,
    oracle: M17BlindOracle,
) -> tuple[M17BlindCaseGateResult, ...]:
    primary_by_id = {item.case_id: item for item in primary.observations}
    repeat_by_id = {item.case_id: item for item in repeat.observations}
    results: list[M17BlindCaseGateResult] = []
    for expected in oracle.outcomes:
        first = primary_by_id[expected.case_id]
        second = repeat_by_id[expected.case_id]
        failures: set[M17BlindGateFailure] = set()
        static_deterministic = _case_static_signature(first) == _case_static_signature(second)
        semantic_stable = _case_semantic_signature(first) == _case_semantic_signature(second)
        admitted_both = first.admitted and second.admitted
        hypothesis_both = bool(first.hypothesis_fingerprints) and bool(
            second.hypothesis_fingerprints
        )
        reportable_first = StaticReportabilityStatus.REPORTABLE_STATIC in (
            first.reportability_statuses
        )
        reportable_second = StaticReportabilityStatus.REPORTABLE_STATIC in (
            second.reportability_statuses
        )
        if not static_deterministic:
            failures.add(M17BlindGateFailure.STATIC_ARTIFACT_NONDETERMINISM)
        hypothesis_presence_changed = bool(first.hypothesis_fingerprints) != bool(
            second.hypothesis_fingerprints
        )
        reportability_changed = reportable_first != reportable_second
        if hypothesis_presence_changed or reportability_changed:
            failures.add(M17BlindGateFailure.MODEL_OUTCOME_INSTABILITY)
        if expected.expected_admitted and not admitted_both:
            failures.add(M17BlindGateFailure.POSITIVE_NOT_ADMITTED)
        if expected.expected_code_hypothesis and not hypothesis_both:
            failures.add(M17BlindGateFailure.CODE_FIRST_HYPOTHESIS_MISSING)
        if expected.cohort is M17BlindCohort.CODE_FIRST and (
            first.deterministic_finding_count or second.deterministic_finding_count
        ):
            failures.add(M17BlindGateFailure.CODE_FIRST_HYPOTHESIS_MISSING)
        if expected.expected_reportable_static and not (reportable_first and reportable_second):
            failures.add(M17BlindGateFailure.EXPECTED_REPORTABLE_MISSING)
        if expected.target_role in {
            M17BlindTargetRole.SAFE_CONTROL,
            M17BlindTargetRole.HISTORICAL_PATCHED,
            M17BlindTargetRole.CURRENT_BUILD,
        } and (reportable_first or reportable_second):
            failures.add(M17BlindGateFailure.SAFE_OR_PATCHED_REPORTABLE)
        ordered_failures = tuple(sorted(failures, key=lambda item: item.value))
        results.append(
            M17BlindCaseGateResult(
                case_id=expected.case_id,
                cohort=expected.cohort,
                target_role=expected.target_role,
                admitted_both_runs=admitted_both,
                code_hypothesis_both_runs=hypothesis_both,
                reportable_primary=reportable_first,
                reportable_repeat=reportable_second,
                static_deterministic=static_deterministic,
                semantic_stable=semantic_stable,
                passed=not ordered_failures,
                failures=ordered_failures,
            )
        )
    if tuple(item.case_id for item in manifest.cases) != tuple(item.case_id for item in results):
        raise ValueError("M17 scored case order differs from frozen manifest")
    return tuple(results)


def _required_cohort_failures(
    oracle: M17BlindOracle,
) -> set[M17BlindGateFailure]:
    failures: set[M17BlindGateFailure] = set()
    by_cohort: dict[M17BlindCohort, set[M17BlindTargetRole]] = {}
    for outcome in oracle.outcomes:
        by_cohort.setdefault(outcome.cohort, set()).add(outcome.target_role)
    required_pair = {
        M17BlindTargetRole.FIXTURE_POSITIVE,
        M17BlindTargetRole.SAFE_CONTROL,
    }
    for cohort in (
        M17BlindCohort.M16_COMPOSITE_RANGE,
        M17BlindCohort.M16_PARTIAL_INITIALIZATION,
    ):
        if not required_pair.issubset(by_cohort.get(cohort, set())):
            failures.add(M17BlindGateFailure.MISSING_REQUIRED_COHORT)
    code_first_positives = sum(
        outcome.cohort is M17BlindCohort.CODE_FIRST
        and outcome.target_role is M17BlindTargetRole.FIXTURE_POSITIVE
        for outcome in oracle.outcomes
    )
    if code_first_positives < 2:
        failures.add(M17BlindGateFailure.INSUFFICIENT_CODE_FIRST_POSITIVES)
    return failures


def _over_cost(run: M17BlindRun, policy: M17BlindBenchmarkPolicy) -> bool:
    return any(
        (
            run.hunter_sessions > policy.maximum_hunter_sessions_per_run,
            run.continuation_roots > policy.maximum_continuation_roots_per_run,
            run.hunter_continuation_calls > policy.maximum_hunter_continuation_calls_per_run,
            run.reviewer_sessions > policy.maximum_reviewer_sessions_per_run,
            run.reviewer_context_calls > policy.maximum_reviewer_context_calls_per_run,
            run.model_calls > policy.maximum_model_calls_per_run,
            run.input_tokens > policy.maximum_input_tokens_per_run,
            run.output_tokens > policy.maximum_output_tokens_per_run,
            run.wall_clock_seconds > policy.maximum_wall_clock_seconds_per_run,
        )
    )


def _case_static_signature(observation: M17BlindCaseObservation) -> object:
    return (
        tuple((item.stage, item.artifact_sha256) for item in observation.stages[:7]),
        observation.admitted,
        observation.omission_reason,
        observation.deterministic_finding_count,
        observation.context_response_sha256s,
    )


def _case_semantic_signature(observation: M17BlindCaseObservation) -> object:
    return (
        observation.hunter_outcome.value,
        observation.hypothesis_fingerprints,
        tuple(item.value for item in observation.reportability_statuses),
    )


def _static_seal(observations: Sequence[M17BlindCaseObservation]) -> str:
    return _digest(tuple((item.case_id, _case_static_signature(item)) for item in observations))


def _semantic_seal(observations: Sequence[M17BlindCaseObservation]) -> str:
    return _digest(tuple((item.case_id, _case_semantic_signature(item)) for item in observations))


def _regular_file(path: Path) -> Path:
    candidate = path.expanduser().resolve(strict=True)
    if path.is_symlink() or not candidate.is_file():
        raise ValueError(f"M17 benchmark artifact is not a regular file: {path}")
    return candidate


def _regular_directory(path: Path) -> Path:
    candidate = path.expanduser().resolve(strict=True)
    if path.is_symlink() or not candidate.is_dir():
        raise ValueError(f"M17 benchmark artifact root is not a directory: {path}")
    return candidate


def _private_output(path: Path) -> Path:
    candidate = path.expanduser().resolve(strict=True)
    if not candidate.is_dir() or any(
        (item / ".git").exists() for item in (candidate, *candidate.parents)
    ):
        raise ValueError("M17 benchmark output must be a private directory outside Git")
    return candidate


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _write_private_json(path: Path, payload: object) -> None:
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n"
    if path.is_symlink():
        raise RuntimeError("M17 benchmark artifact may not be a symbolic link")
    if path.exists():
        if not path.is_file() or path.read_bytes() != encoded:
            raise FileExistsError("immutable M17 benchmark artifact contains other data")
        return
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(payload: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload)).hexdigest()
