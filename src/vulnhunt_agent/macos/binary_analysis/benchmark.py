"""Blind benchmark and private Ghidra pilot for M14 binary analysis."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from ...domain.schemas import DomainModel, SHA256_PATTERN
from .adapters import GhidraJSONAdapter, load_decompiler_export
from .analyzers import (
    BinaryStaticFinding,
    BinaryVulnerabilityClass,
    analyze_binary_candidates,
)
from .discovery import discover_imageio_parsers
from .ranking import pack_ranked_binary_contexts, rank_binary_functions
from .snapshot import (
    BinarySnapshot,
    DyldArchitecture,
    capture_dyld_shared_cache_snapshot,
    write_binary_snapshot,
)

_GHIDRA_FOOTER = b"Ghidra DYLD extraction v1"
_DEFAULT_IMAGE_PATH = "/System/Library/Frameworks/ImageIO.framework/Versions/A/ImageIO"
_UUID_PATTERN = r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
_MAX_LOG_BYTES = 4 * 1024 * 1024
_SUPPORTED_BINARY_CLASSES = tuple(
    sorted(BinaryVulnerabilityClass, key=lambda item: item.value)
)


class BlindBenchmarkExpectedFinding(DomainModel):
    function_name: str = Field(min_length=1, max_length=500)
    vulnerability_class: BinaryVulnerabilityClass


class BlindBenchmarkOracle(DomainModel):
    schema_version: Literal["m14-blind-oracle-v1"] = "m14-blind-oracle-v1"
    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,79}$")
    expected_findings: tuple[BlindBenchmarkExpectedFinding, ...] = ()

    @model_validator(mode="after")
    def validate_oracle(self) -> "BlindBenchmarkOracle":
        keys = tuple(
            (item.function_name, item.vulnerability_class.value) for item in self.expected_findings
        )
        if tuple(sorted(set(keys))) != keys:
            raise ValueError("blind benchmark expectations must be sorted and unique")
        return self


class BlindBenchmarkCase(DomainModel):
    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,79}$")
    export_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$")
    export_sha256: str = Field(pattern=SHA256_PATTERN)
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)


class BlindBenchmarkManifest(DomainModel):
    schema_version: Literal["m14-blind-manifest-v1"] = "m14-blind-manifest-v1"
    cases: tuple[BlindBenchmarkCase, ...] = Field(min_length=1, max_length=1000)
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_manifest(self) -> "BlindBenchmarkManifest":
        if tuple(sorted(self.cases, key=lambda item: item.case_id)) != self.cases:
            raise ValueError("blind benchmark cases must be ordered by case id")
        if len({item.case_id for item in self.cases}) != len(self.cases):
            raise ValueError("blind benchmark case ids must be unique")
        if self.manifest_sha256 != _manifest_digest(self.cases):
            raise ValueError("blind benchmark manifest digest does not match its cases")
        return self


class BlindBenchmarkCaseResult(DomainModel):
    case_id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,79}$")
    observed_findings: tuple[BlindBenchmarkExpectedFinding, ...] = ()
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    runtime_seconds: float = Field(ge=0.0)


class BlindBenchmarkResult(DomainModel):
    schema_version: Literal["m14-blind-benchmark-v1"] = "m14-blind-benchmark-v1"
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    cases: tuple[BlindBenchmarkCaseResult, ...] = Field(min_length=1, max_length=1000)
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    recall: float = Field(ge=0.0, le=1.0)
    precision: float = Field(ge=0.0, le=1.0)
    runtime_seconds: float = Field(ge=0.0)
    model_calls: Literal[0] = 0
    input_tokens: Literal[0] = 0
    output_tokens: Literal[0] = 0
    estimated_cost_usd: float = Field(default=0.0, ge=0.0, le=0.0)
    oracle_loaded_after_analysis: Literal[True] = True


class BlindRegressionGatePolicy(DomainModel):
    schema_version: Literal["m15-blind-gate-policy-v1"] = "m15-blind-gate-policy-v1"
    minimum_case_count: int = Field(default=10, ge=1, le=1000)
    required_classes: tuple[BinaryVulnerabilityClass, ...] = Field(
        default=_SUPPORTED_BINARY_CLASSES, min_length=1, max_length=4
    )
    minimum_expected_findings_per_class: int = Field(default=1, ge=1, le=1000)
    minimum_recall_per_class: float = Field(default=1.0, ge=0.0, le=1.0)
    minimum_overall_precision: float = Field(default=1.0, ge=0.0, le=1.0)
    maximum_false_positives: int = Field(default=0, ge=0, le=10000)
    maximum_false_negatives: int = Field(default=0, ge=0, le=10000)
    determinism_runs: Literal[2] = 2

    @model_validator(mode="after")
    def validate_policy(self) -> "BlindRegressionGatePolicy":
        if tuple(sorted(set(self.required_classes), key=lambda item: item.value)) != (
            self.required_classes
        ):
            raise ValueError("blind gate required classes must be sorted and unique")
        return self


class BlindRegressionClassResult(DomainModel):
    vulnerability_class: BinaryVulnerabilityClass
    expected_findings: int = Field(ge=0)
    true_positives: int = Field(ge=0)
    false_positives: int = Field(ge=0)
    false_negatives: int = Field(ge=0)
    recall: float = Field(ge=0.0, le=1.0)


class BlindRegressionGateFailure(StrEnum):
    INSUFFICIENT_CASES = "insufficient_cases"
    MISSING_CLASS_COVERAGE = "missing_class_coverage"
    CLASS_RECALL_BELOW_MINIMUM = "class_recall_below_minimum"
    OVERALL_PRECISION_BELOW_MINIMUM = "overall_precision_below_minimum"
    FALSE_POSITIVES_EXCEEDED = "false_positives_exceeded"
    FALSE_NEGATIVES_EXCEEDED = "false_negatives_exceeded"
    NONDETERMINISTIC_RESULTS = "nondeterministic_results"


class BlindRegressionGateResult(DomainModel):
    schema_version: Literal["m15-blind-regression-gate-v1"] = (
        "m15-blind-regression-gate-v1"
    )
    policy: BlindRegressionGatePolicy
    benchmark: BlindBenchmarkResult
    class_results: tuple[BlindRegressionClassResult, ...]
    deterministic: bool
    primary_observation_sha256: str = Field(pattern=SHA256_PATTERN)
    repeat_observation_sha256: str = Field(pattern=SHA256_PATTERN)
    failures: tuple[BlindRegressionGateFailure, ...] = ()
    passed: bool
    runtime_seconds: float = Field(ge=0.0)
    model_calls: Literal[0] = 0
    input_tokens: Literal[0] = 0
    output_tokens: Literal[0] = 0
    estimated_cost_usd: float = Field(default=0.0, ge=0.0, le=0.0)
    oracle_loaded_after_all_analysis: Literal[True] = True

    @model_validator(mode="after")
    def validate_gate_result(self) -> "BlindRegressionGateResult":
        classes = tuple(item.vulnerability_class.value for item in self.class_results)
        if tuple(sorted(set(classes))) != classes:
            raise ValueError("blind gate class results must be sorted and unique")
        if tuple(sorted(set(self.failures), key=lambda item: item.value)) != self.failures:
            raise ValueError("blind gate failures must be sorted and unique")
        if self.deterministic != (
            self.primary_observation_sha256 == self.repeat_observation_sha256
        ):
            raise ValueError("blind gate determinism does not match observation digests")
        if self.passed != (not self.failures):
            raise ValueError("blind gate pass status does not match its failures")
        return self


@dataclass(frozen=True)
class _BlindAnalysisRun:
    observed_by_case: dict[str, tuple[BlindBenchmarkExpectedFinding, ...]]
    ranking_sha256_by_case: dict[str, str]
    runtime_by_case: dict[str, float]


class ImageIOPilotStatus(StrEnum):
    COMPLETED = "completed"
    BLOCKED_MISSING_GHIDRA = "blocked_missing_ghidra"
    BLOCKED_MISSING_CACHE = "blocked_missing_cache"
    EXTRACTION_FAILED = "extraction_failed"
    EXPORT_FAILED = "export_failed"
    INVALID_EXPORT = "invalid_export"


class ImageIOPilotStage(DomainModel):
    name: str = Field(min_length=1, max_length=80)
    runtime_seconds: float = Field(ge=0.0)
    exit_code: int | None = None
    completed: bool
    log_name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$")


class ImageIOPilotResult(DomainModel):
    schema_version: Literal["m14-imageio-pilot-v1"] = "m14-imageio-pilot-v1"
    created_at: datetime
    status: ImageIOPilotStatus
    snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    shared_cache_uuid: str | None = Field(default=None, pattern=_UUID_PATTERN)
    image_uuid: str | None = Field(default=None, pattern=_UUID_PATTERN)
    image_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    export_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    ir_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    function_count: int = Field(default=0, ge=0)
    parser_candidate_count: int = Field(default=0, ge=0)
    static_finding_count: int = Field(default=0, ge=0)
    ranked_function_count: int = Field(default=0, ge=0)
    context_pack_count: int = Field(default=0, ge=0)
    finding_classes: tuple[str, ...] = ()
    stages: tuple[ImageIOPilotStage, ...] = ()
    limitation: str = Field(min_length=1, max_length=2000)
    model_calls: Literal[0] = 0
    input_tokens: Literal[0] = 0
    output_tokens: Literal[0] = 0
    estimated_cost_usd: float = Field(default=0.0, ge=0.0, le=0.0)
    experiments_executed: Literal[0] = 0
    vulnerability_confirmed: Literal[False] = False

    @model_validator(mode="after")
    def validate_result(self) -> "ImageIOPilotResult":
        if self.created_at.tzinfo is None:
            raise ValueError("pilot result creation time must include a timezone")
        if tuple(sorted(set(self.finding_classes))) != self.finding_classes:
            raise ValueError("pilot finding classes must be sorted and unique")
        return self


def freeze_blind_benchmark(
    exports: Mapping[str, tuple[Path, str]],
) -> BlindBenchmarkManifest:
    """Freeze input digests without receiving or reading any vulnerability oracle."""

    cases: list[BlindBenchmarkCase] = []
    for case_id, (path, snapshot_sha256) in sorted(exports.items()):
        source = _regular_file(path, label="benchmark export")
        cases.append(
            BlindBenchmarkCase(
                case_id=case_id,
                export_name=source.name,
                export_sha256=_sha256_file(source),
                snapshot_sha256=snapshot_sha256,
            )
        )
    ordered = tuple(cases)
    return BlindBenchmarkManifest(cases=ordered, manifest_sha256=_manifest_digest(ordered))


def run_blind_binary_benchmark(
    manifest: BlindBenchmarkManifest,
    *,
    export_directory: Path,
    oracle_loader: Callable[[], Sequence[BlindBenchmarkOracle]],
) -> BlindBenchmarkResult:
    """Analyze every frozen case first, then load the separate scoring oracle."""

    started = time.monotonic()
    root = _regular_directory(export_directory, label="benchmark export directory")
    analysis = _analyze_blind_manifest(manifest, root)
    oracles = tuple(oracle_loader())
    return _score_blind_run(
        manifest,
        analysis,
        oracles,
        runtime_seconds=time.monotonic() - started,
    )


def run_blind_binary_regression_gate(
    manifest: BlindBenchmarkManifest,
    *,
    export_directory: Path,
    oracle_loader: Callable[[], Sequence[BlindBenchmarkOracle]],
    policy: BlindRegressionGatePolicy | None = None,
) -> BlindRegressionGateResult:
    """Run all cases twice before loading oracles, then enforce the M15 gate."""

    started = time.monotonic()
    active_policy = policy or BlindRegressionGatePolicy()
    root = _regular_directory(export_directory, label="benchmark export directory")
    primary = _analyze_blind_manifest(manifest, root)
    repeat = _analyze_blind_manifest(manifest, root)
    primary_digest = _observation_digest(primary)
    repeat_digest = _observation_digest(repeat)
    deterministic = primary_digest == repeat_digest

    # The loader is intentionally invoked only after every deterministic run.
    oracles = tuple(oracle_loader())
    benchmark = _score_blind_run(
        manifest,
        primary,
        oracles,
        runtime_seconds=sum(primary.runtime_by_case.values()),
    )
    class_results = _class_results(manifest, primary, oracles)
    by_class = {item.vulnerability_class: item for item in class_results}
    failures: set[BlindRegressionGateFailure] = set()
    if len(manifest.cases) < active_policy.minimum_case_count:
        failures.add(BlindRegressionGateFailure.INSUFFICIENT_CASES)
    for vulnerability_class in active_policy.required_classes:
        result = by_class[vulnerability_class]
        if result.expected_findings < active_policy.minimum_expected_findings_per_class:
            failures.add(BlindRegressionGateFailure.MISSING_CLASS_COVERAGE)
        elif result.recall < active_policy.minimum_recall_per_class:
            failures.add(BlindRegressionGateFailure.CLASS_RECALL_BELOW_MINIMUM)
    if benchmark.precision < active_policy.minimum_overall_precision:
        failures.add(BlindRegressionGateFailure.OVERALL_PRECISION_BELOW_MINIMUM)
    if benchmark.false_positives > active_policy.maximum_false_positives:
        failures.add(BlindRegressionGateFailure.FALSE_POSITIVES_EXCEEDED)
    if benchmark.false_negatives > active_policy.maximum_false_negatives:
        failures.add(BlindRegressionGateFailure.FALSE_NEGATIVES_EXCEEDED)
    if not deterministic:
        failures.add(BlindRegressionGateFailure.NONDETERMINISTIC_RESULTS)
    ordered_failures = tuple(sorted(failures, key=lambda item: item.value))
    return BlindRegressionGateResult(
        policy=active_policy,
        benchmark=benchmark,
        class_results=class_results,
        deterministic=deterministic,
        primary_observation_sha256=primary_digest,
        repeat_observation_sha256=repeat_digest,
        failures=ordered_failures,
        passed=not ordered_failures,
        runtime_seconds=time.monotonic() - started,
    )


def _analyze_blind_manifest(
    manifest: BlindBenchmarkManifest,
    root: Path,
) -> _BlindAnalysisRun:
    observed_by_case: dict[str, tuple[BlindBenchmarkExpectedFinding, ...]] = {}
    ranking_sha256_by_case: dict[str, str] = {}
    runtime_by_case: dict[str, float] = {}
    for case in manifest.cases:
        case_started = time.monotonic()
        source = _regular_file(root / case.export_name, label="benchmark export")
        if _sha256_file(source) != case.export_sha256:
            raise ValueError(f"benchmark export changed after freeze: {case.case_id}")
        ir = load_decompiler_export(
            source,
            adapter=GhidraJSONAdapter(),
            expected_snapshot_sha256=case.snapshot_sha256,
        )
        discovery = discover_imageio_parsers(ir)
        report = analyze_binary_candidates(ir, discovery)
        ranking = rank_binary_functions(ir, discovery, report)
        observed_by_case[case.case_id] = _finding_keys(report.findings)
        ranking_sha256_by_case[case.case_id] = ranking.ranking_sha256
        runtime_by_case[case.case_id] = time.monotonic() - case_started
    return _BlindAnalysisRun(observed_by_case, ranking_sha256_by_case, runtime_by_case)


def _score_blind_run(
    manifest: BlindBenchmarkManifest,
    analysis: _BlindAnalysisRun,
    oracles: tuple[BlindBenchmarkOracle, ...],
    *,
    runtime_seconds: float,
) -> BlindBenchmarkResult:
    oracle_by_case = _oracle_map(manifest, oracles)
    results: list[BlindBenchmarkCaseResult] = []
    total_tp = total_fp = total_fn = 0
    for case in manifest.cases:
        observed = analysis.observed_by_case[case.case_id]
        expected = oracle_by_case[case.case_id].expected_findings
        observed_keys = {(item.function_name, item.vulnerability_class) for item in observed}
        expected_keys = {(item.function_name, item.vulnerability_class) for item in expected}
        true_positives = len(observed_keys & expected_keys)
        false_positives = len(observed_keys - expected_keys)
        false_negatives = len(expected_keys - observed_keys)
        total_tp += true_positives
        total_fp += false_positives
        total_fn += false_negatives
        results.append(
            BlindBenchmarkCaseResult(
                case_id=case.case_id,
                observed_findings=observed,
                true_positives=true_positives,
                false_positives=false_positives,
                false_negatives=false_negatives,
                runtime_seconds=analysis.runtime_by_case[case.case_id],
            )
        )
    return BlindBenchmarkResult(
        manifest_sha256=manifest.manifest_sha256,
        cases=tuple(results),
        true_positives=total_tp,
        false_positives=total_fp,
        false_negatives=total_fn,
        recall=total_tp / max(1, total_tp + total_fn),
        precision=total_tp / max(1, total_tp + total_fp),
        runtime_seconds=runtime_seconds,
    )


def _class_results(
    manifest: BlindBenchmarkManifest,
    analysis: _BlindAnalysisRun,
    oracles: tuple[BlindBenchmarkOracle, ...],
) -> tuple[BlindRegressionClassResult, ...]:
    oracle_by_case = _oracle_map(manifest, oracles)
    results: list[BlindRegressionClassResult] = []
    for vulnerability_class in _SUPPORTED_BINARY_CLASSES:
        expected_keys: set[tuple[str, str]] = set()
        observed_keys: set[tuple[str, str]] = set()
        for case in manifest.cases:
            expected_keys.update(
                (case.case_id, item.function_name)
                for item in oracle_by_case[case.case_id].expected_findings
                if item.vulnerability_class is vulnerability_class
            )
            observed_keys.update(
                (case.case_id, item.function_name)
                for item in analysis.observed_by_case[case.case_id]
                if item.vulnerability_class is vulnerability_class
            )
        true_positives = len(expected_keys & observed_keys)
        false_positives = len(observed_keys - expected_keys)
        false_negatives = len(expected_keys - observed_keys)
        results.append(
            BlindRegressionClassResult(
                vulnerability_class=vulnerability_class,
                expected_findings=len(expected_keys),
                true_positives=true_positives,
                false_positives=false_positives,
                false_negatives=false_negatives,
                recall=true_positives / max(1, len(expected_keys)),
            )
        )
    return tuple(results)


def _oracle_map(
    manifest: BlindBenchmarkManifest,
    oracles: tuple[BlindBenchmarkOracle, ...],
) -> dict[str, BlindBenchmarkOracle]:
    oracle_by_case = {item.case_id: item for item in oracles}
    if len(oracle_by_case) != len(oracles) or set(oracle_by_case) != {
        item.case_id for item in manifest.cases
    }:
        raise ValueError("blind benchmark oracle cases do not exactly match the manifest")
    return oracle_by_case


def _observation_digest(
    analysis: _BlindAnalysisRun,
) -> str:
    payload = {
        "cases": {
            case_id: {
                "findings": [item.model_dump(mode="json") for item in findings],
                "ranking_sha256": analysis.ranking_sha256_by_case[case_id],
            }
            for case_id, findings in sorted(analysis.observed_by_case.items())
        },
        "schema_version": "m15-blind-observation-v1",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def run_imageio_ghidra_pilot(
    *,
    cache_path: Path,
    output_directory: Path,
    product_version: str,
    build_version: str,
    ghidra_headless: Path,
    script_directory: Path,
    java_home: Path,
    image_path: str = _DEFAULT_IMAGE_PATH,
    max_functions: int = 600,
    max_ops_per_function: int = 4000,
    decompile_seconds: int = 3,
    coverage_depth: int = 2,
    max_evidence_functions: int = 2000,
    analysis_timeout_seconds: int = 600,
    process_timeout_seconds: int = 900,
    ghidra_heap: str = "8G",
) -> ImageIOPilotResult:
    """Run the static-only ImageIO pilot; no image input or Hunter call is made."""

    output = _prepare_private_output_directory(output_directory)
    stages: list[ImageIOPilotStage] = []
    cache = cache_path.expanduser()
    if not cache.exists():
        return _persist_pilot_result(
            output,
            _blocked_pilot(
                ImageIOPilotStatus.BLOCKED_MISSING_CACHE, stages, "dyld cache is missing"
            ),
        )
    ghidra = ghidra_headless.expanduser()
    if not ghidra.is_file() or not os.access(ghidra, os.X_OK):
        return _persist_pilot_result(
            output,
            _blocked_pilot(
                ImageIOPilotStatus.BLOCKED_MISSING_GHIDRA,
                stages,
                "Ghidra analyzeHeadless is missing or not executable",
            ),
        )
    scripts = _regular_directory(script_directory, label="Ghidra script directory")
    _regular_file(scripts / "ExtractDyldImage.java", label="Ghidra extraction script")
    _regular_file(scripts / "ExportImageIOIR.java", label="Ghidra export script")
    if not re.fullmatch(r"[1-9][0-9]*[GgMmKk]", ghidra_heap):
        raise ValueError("Ghidra heap must use a bounded JVM memory value such as 8G")

    snapshot_started = time.monotonic()
    snapshot = capture_dyld_shared_cache_snapshot(
        cache,
        product_version=product_version,
        build_version=build_version,
        architecture=DyldArchitecture.ARM64,
    )
    write_binary_snapshot(snapshot, output)
    stages.append(
        ImageIOPilotStage(
            name="snapshot", runtime_seconds=time.monotonic() - snapshot_started, completed=True
        )
    )

    extracted = output / "ImageIO.ghidra-extracted"
    plain = output / "ImageIO.macho"
    export = output / "imageio-ghidra-export.json"
    # Ghidra rejects project path components that begin with a dot.
    project_root = output / "ghidra-projects"
    project_root.mkdir(mode=0o700)
    environment = {
        **os.environ,
        "JAVA_HOME": str(java_home.expanduser()),
        "GHIDRA_HEADLESS_MAXMEM": ghidra_heap,
    }
    extraction_command = [
        str(ghidra),
        str(project_root),
        "m14-extract",
        "-scriptPath",
        str(scripts),
        "-preScript",
        "ExtractDyldImage.java",
        str(cache),
        image_path,
        str(extracted),
        "-deleteProject",
    ]
    extraction = _run_ghidra_stage(
        "extraction",
        extraction_command,
        output / "ghidra-extraction.log",
        environment=environment,
        timeout_seconds=process_timeout_seconds,
    )
    stages.append(extraction)
    if not extraction.completed or not extracted.is_file():
        return _persist_pilot_result(
            output,
            _failed_pilot(
                ImageIOPilotStatus.EXTRACTION_FAILED,
                snapshot,
                stages,
                "Ghidra image extraction failed",
            ),
        )

    _strip_ghidra_extraction_footer(extracted, plain)
    image_uuid = macho_uuid(plain)
    image_sha256 = _sha256_file(plain)
    export_command = [
        str(ghidra),
        str(project_root),
        "m14-export",
        "-import",
        str(plain),
        "-scriptPath",
        str(scripts),
        "-analysisTimeoutPerFile",
        str(analysis_timeout_seconds),
        "-postScript",
        "ExportImageIOIR.java",
        str(export),
        snapshot.snapshot_sha256,
        image_uuid,
        str(max_functions),
        str(max_ops_per_function),
        str(decompile_seconds),
        str(coverage_depth),
        str(max_evidence_functions),
        "-deleteProject",
    ]
    export_stage = _run_ghidra_stage(
        "decompile_export",
        export_command,
        output / "ghidra-export.log",
        environment=environment,
        timeout_seconds=process_timeout_seconds,
    )
    stages.append(export_stage)
    if not export_stage.completed or not export.is_file():
        return _persist_pilot_result(
            output,
            _failed_pilot(
                ImageIOPilotStatus.EXPORT_FAILED, snapshot, stages, "Ghidra IR export failed"
            ),
        )

    static_started = time.monotonic()
    try:
        ir = load_decompiler_export(
            export,
            adapter=GhidraJSONAdapter(),
            expected_snapshot_sha256=snapshot.snapshot_sha256,
        )
        discovery = discover_imageio_parsers(ir)
        report = analyze_binary_candidates(ir, discovery)
        ranking = rank_binary_functions(ir, discovery, report)
        context_plan = pack_ranked_binary_contexts(ir, discovery, report, ranking)
    except (OSError, ValueError) as error:
        stages.append(
            ImageIOPilotStage(
                name="static_pipeline",
                runtime_seconds=time.monotonic() - static_started,
                completed=False,
            )
        )
        return _persist_pilot_result(
            output,
            _failed_pilot(
                ImageIOPilotStatus.INVALID_EXPORT,
                snapshot,
                stages,
                f"normalized static pipeline rejected the export: {error}",
            ),
        )
    stages.append(
        ImageIOPilotStage(
            name="static_pipeline",
            runtime_seconds=time.monotonic() - static_started,
            completed=True,
        )
    )
    _write_private_json(output / "normalized-ir.json", ir.model_dump(mode="json"))
    _write_private_json(output / "parser-discovery.json", discovery.model_dump(mode="json"))
    _write_private_json(output / "static-analysis.json", report.model_dump(mode="json"))
    _write_private_json(output / "binary-ranking.json", ranking.model_dump(mode="json"))
    _write_private_json(output / "context-plan.json", context_plan.model_dump(mode="json"))
    result = ImageIOPilotResult(
        created_at=datetime.now(UTC),
        status=ImageIOPilotStatus.COMPLETED,
        snapshot_sha256=snapshot.snapshot_sha256,
        shared_cache_uuid=snapshot.shared_cache_uuid,
        image_uuid=image_uuid,
        image_sha256=image_sha256,
        export_sha256=_sha256_file(export),
        ir_sha256=ir.ir_sha256,
        function_count=len(ir.functions),
        parser_candidate_count=len(discovery.candidates),
        static_finding_count=len(report.findings),
        ranked_function_count=len(ranking.entries),
        context_pack_count=len(context_plan.packs),
        finding_classes=tuple(
            sorted({finding.vulnerability_class.value for finding in report.findings})
        ),
        stages=tuple(stages),
        limitation=(
            "Static candidates are decompiler-derived hypotheses, not confirmed vulnerabilities. "
            "The pilot executes no image, Hunter session, or dynamic experiment."
        ),
    )
    return _persist_pilot_result(output, result)


def macho_uuid(path: Path) -> str:
    """Read LC_UUID from a thin little-endian 64-bit Mach-O without executing it."""

    source = _regular_file(path, label="Mach-O image")
    with source.open("rb") as handle:
        header = handle.read(32)
        if len(header) != 32 or header[:4] != b"\xcf\xfa\xed\xfe":
            raise ValueError("expected a thin little-endian 64-bit Mach-O image")
        command_count = struct.unpack_from("<I", header, 16)[0]
        if command_count > 4096:
            raise ValueError("Mach-O load-command count exceeds the safety limit")
        for _ in range(command_count):
            command_header = handle.read(8)
            if len(command_header) != 8:
                raise ValueError("truncated Mach-O load command")
            command, command_size = struct.unpack("<II", command_header)
            if command_size < 8 or command_size > 16 * 1024 * 1024:
                raise ValueError("invalid Mach-O load-command size")
            body = handle.read(command_size - 8)
            if len(body) != command_size - 8:
                raise ValueError("truncated Mach-O load command body")
            if command == 0x1B:
                if command_size < 24:
                    raise ValueError("truncated Mach-O LC_UUID")
                return str(uuid.UUID(bytes=body[:16])).upper()
    raise ValueError("Mach-O image does not contain LC_UUID")


def _strip_ghidra_extraction_footer(source: Path, destination: Path) -> None:
    original = _regular_file(source, label="Ghidra extracted image")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    size = original.stat().st_size
    if size <= len(_GHIDRA_FOOTER):
        raise ValueError("Ghidra extracted image is truncated")
    with original.open("rb") as reader:
        reader.seek(size - len(_GHIDRA_FOOTER))
        if reader.read() != _GHIDRA_FOOTER:
            raise ValueError("Ghidra extraction footer is missing")
        reader.seek(0)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            remaining = size - len(_GHIDRA_FOOTER)
            with os.fdopen(descriptor, "wb") as writer:
                while remaining:
                    chunk = reader.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Ghidra extracted image changed while copying")
                    writer.write(chunk)
                    remaining -= len(chunk)
                writer.flush()
                os.fsync(writer.fileno())
        except BaseException:
            destination.unlink(missing_ok=True)
            raise


def _run_ghidra_stage(
    name: str,
    command: Sequence[str],
    log_path: Path,
    *,
    environment: Mapping[str, str],
    timeout_seconds: int,
) -> ImageIOPilotStage:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            env=dict(environment),
            timeout=timeout_seconds,
        )
        output = completed.stdout[-_MAX_LOG_BYTES:]
        _write_private_bytes(log_path, output)
        return ImageIOPilotStage(
            name=name,
            runtime_seconds=time.monotonic() - started,
            exit_code=completed.returncode,
            completed=completed.returncode == 0,
            log_name=log_path.name,
        )
    except subprocess.TimeoutExpired as error:
        captured = (error.stdout or b"")[-_MAX_LOG_BYTES:]
        _write_private_bytes(log_path, captured + b"\nTIMEOUT\n")
        return ImageIOPilotStage(
            name=name,
            runtime_seconds=time.monotonic() - started,
            completed=False,
            log_name=log_path.name,
        )


def _finding_keys(
    findings: Sequence[BinaryStaticFinding],
) -> tuple[BlindBenchmarkExpectedFinding, ...]:
    unique = {
        (item.function_name, item.vulnerability_class): BlindBenchmarkExpectedFinding(
            function_name=item.function_name,
            vulnerability_class=item.vulnerability_class,
        )
        for item in findings
    }
    return tuple(unique[key] for key in sorted(unique, key=lambda item: (item[0], item[1].value)))


def _manifest_digest(cases: tuple[BlindBenchmarkCase, ...]) -> str:
    payload = {
        "cases": [item.model_dump(mode="json") for item in cases],
        "schema_version": "m14-blind-manifest-v1",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _regular_file(path: Path, *, label: str) -> Path:
    source = path.expanduser()
    metadata = source.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file")
    return source


def _regular_directory(path: Path, *, label: str) -> Path:
    source = path.expanduser()
    metadata = source.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink directory")
    return source


def _prepare_private_output_directory(path: Path) -> Path:
    output = path.expanduser()
    if output.exists() and output.is_symlink():
        raise ValueError("pilot output directory may not be a symlink")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    return output


def _write_private_bytes(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _write_private_json(path: Path, payload: object) -> None:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _persist_pilot_result(output: Path, result: ImageIOPilotResult) -> ImageIOPilotResult:
    _write_private_json(output / "pilot-result.json", result.model_dump(mode="json"))
    return result


def _blocked_pilot(
    status: ImageIOPilotStatus,
    stages: Sequence[ImageIOPilotStage],
    limitation: str,
) -> ImageIOPilotResult:
    return ImageIOPilotResult(
        created_at=datetime.now(UTC), status=status, stages=tuple(stages), limitation=limitation
    )


def _failed_pilot(
    status: ImageIOPilotStatus,
    snapshot: BinarySnapshot,
    stages: Sequence[ImageIOPilotStage],
    limitation: str,
) -> ImageIOPilotResult:
    return ImageIOPilotResult(
        created_at=datetime.now(UTC),
        status=status,
        snapshot_sha256=snapshot.snapshot_sha256,
        shared_cache_uuid=snapshot.shared_cache_uuid,
        stages=tuple(stages),
        limitation=limitation,
    )
