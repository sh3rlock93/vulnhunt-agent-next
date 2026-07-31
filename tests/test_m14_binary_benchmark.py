from __future__ import annotations

import json
import struct
import uuid
from pathlib import Path

import pytest
import vulnhunt_agent.macos.binary_analysis.benchmark as benchmark_module

from vulnhunt_agent.macos.binary_analysis import (
    BinaryAnalyzerLimits,
    BinaryVulnerabilityClass,
    BlindBenchmarkExpectedFinding,
    BlindBenchmarkOracle,
    BlindRegressionGateFailure,
    BlindRegressionGatePolicy,
    ImageIOPilotStatus,
    ImageIOParserDiscovery,
    NormalizedBinaryIR,
    freeze_blind_benchmark,
    macho_uuid,
    run_blind_binary_benchmark,
    run_blind_binary_regression_gate,
    run_imageio_ghidra_pilot,
)

_SNAPSHOT = "sha256:" + "9" * 64
_UUID = "92345678-1234-5678-9ABC-DEF012345678"


def _export(*, vulnerable: bool) -> dict[str, object]:
    base = 0x100001000
    instructions: list[dict[str, object]] = [
        {
            "address": hex(base),
            "op": "param",
            "result": "length",
            "inputs": [],
            "tags": ["input_length"],
            "text": "length = parameter",
        }
    ]
    if vulnerable:
        instructions.extend(
            [
                {
                    "address": hex(base + 4),
                    "op": "int_mult",
                    "result": "bytes",
                    "inputs": ["length"],
                    "constants": [4],
                    "text": "bytes = length * 4",
                },
                {
                    "address": hex(base + 8),
                    "op": "alloc",
                    "result": "buffer",
                    "inputs": ["bytes"],
                    "target": "malloc",
                    "text": "buffer = malloc(bytes)",
                },
            ]
        )
    else:
        instructions.append(
            {
                "address": hex(base + 4),
                "op": "alloc",
                "result": "buffer",
                "inputs": ["length"],
                "target": "malloc",
                "text": "buffer = malloc(length)",
            }
        )
    return {
        "schema_version": "ghidra-imageio-export-v1",
        "decompiler_version": "12.1.2",
        "snapshot_sha256": _SNAPSHOT,
        "image": {
            "name": "ImageIO",
            "uuid": _UUID,
            "architecture": "arm64",
            "base_address": "0x100000000",
        },
        "imports": ["malloc"],
        "strings": [],
        "functions": [
            {
                "entry": hex(base),
                "size": 64,
                "name": "decode_tiff",
                "parameters": ["length"],
                "pseudocode": "void decode_tiff(size_t length) { }",
                "blocks": [
                    {
                        "name": "entry",
                        "start": hex(base),
                        "size": 64,
                        "successors": [],
                        "instructions": instructions,
                    }
                ],
            }
        ],
    }


def _write_export(path: Path, *, vulnerable: bool) -> None:
    path.write_text(json.dumps(_export(vulnerable=vulnerable)), encoding="utf-8")


def test_blind_benchmark_freezes_inputs_before_scoring_oracle(tmp_path: Path) -> None:
    vulnerable = tmp_path / "vulnerable.json"
    safe = tmp_path / "safe.json"
    _write_export(vulnerable, vulnerable=True)
    _write_export(safe, vulnerable=False)
    manifest = freeze_blind_benchmark(
        {"known-overflow": (vulnerable, _SNAPSHOT), "known-safe": (safe, _SNAPSHOT)}
    )

    result = run_blind_binary_benchmark(
        manifest,
        export_directory=tmp_path,
        oracle_loader=lambda: (
            BlindBenchmarkOracle(case_id="known-safe"),
            BlindBenchmarkOracle(
                case_id="known-overflow",
                expected_findings=(
                    BlindBenchmarkExpectedFinding(
                        function_name="decode_tiff",
                        vulnerability_class=BinaryVulnerabilityClass.INTEGER_OVERFLOW,
                    ),
                ),
            ),
        ),
    )

    assert result.true_positives == 1
    assert result.false_positives == 0
    assert result.false_negatives == 0
    assert result.recall == 1.0
    assert result.precision == 1.0
    assert result.oracle_loaded_after_analysis is True
    assert result.model_calls == result.input_tokens == result.output_tokens == 0
    assert result.estimated_cost_usd == 0.0


def test_blind_benchmark_rejects_export_changed_after_freeze(tmp_path: Path) -> None:
    export = tmp_path / "case.json"
    _write_export(export, vulnerable=True)
    manifest = freeze_blind_benchmark({"case": (export, _SNAPSHOT)})
    _write_export(export, vulnerable=False)

    with pytest.raises(ValueError, match="changed after freeze"):
        run_blind_binary_benchmark(
            manifest,
            export_directory=tmp_path,
            oracle_loader=lambda: (BlindBenchmarkOracle(case_id="case"),),
        )


def test_blind_benchmark_requires_exact_separate_oracle_set(tmp_path: Path) -> None:
    export = tmp_path / "case.json"
    _write_export(export, vulnerable=False)
    manifest = freeze_blind_benchmark({"case": (export, _SNAPSHOT)})

    with pytest.raises(ValueError, match="do not exactly match"):
        run_blind_binary_benchmark(manifest, export_directory=tmp_path, oracle_loader=lambda: ())


def test_regression_gate_loads_oracle_after_both_determinism_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vulnerable = tmp_path / "vulnerable.json"
    safe = tmp_path / "safe.json"
    _write_export(vulnerable, vulnerable=True)
    _write_export(safe, vulnerable=False)
    manifest = freeze_blind_benchmark(
        {"case-001": (vulnerable, _SNAPSHOT), "case-002": (safe, _SNAPSHOT)}
    )
    analysis_calls = 0
    real_analyzer = benchmark_module.analyze_binary_candidates

    def counting_analyzer(
        ir: NormalizedBinaryIR,
        discovery: ImageIOParserDiscovery,
        *,
        limits: BinaryAnalyzerLimits | None = None,
    ):
        nonlocal analysis_calls
        analysis_calls += 1
        return real_analyzer(ir, discovery, limits=limits)

    monkeypatch.setattr(benchmark_module, "analyze_binary_candidates", counting_analyzer)

    def load_oracles() -> tuple[BlindBenchmarkOracle, ...]:
        assert analysis_calls == 4
        return (
            BlindBenchmarkOracle(
                case_id="case-001",
                expected_findings=(
                    BlindBenchmarkExpectedFinding(
                        function_name="decode_tiff",
                        vulnerability_class=BinaryVulnerabilityClass.INTEGER_OVERFLOW,
                    ),
                ),
            ),
            BlindBenchmarkOracle(case_id="case-002"),
        )

    result = run_blind_binary_regression_gate(
        manifest,
        export_directory=tmp_path,
        oracle_loader=load_oracles,
        policy=BlindRegressionGatePolicy(
            minimum_case_count=2,
            required_classes=(BinaryVulnerabilityClass.INTEGER_OVERFLOW,),
        ),
    )

    assert result.passed is True
    assert result.deterministic is True
    assert result.oracle_loaded_after_all_analysis is True
    assert result.failures == ()


def test_regression_gate_fails_closed_on_insufficient_class_coverage(tmp_path: Path) -> None:
    export = tmp_path / "case.json"
    _write_export(export, vulnerable=True)
    manifest = freeze_blind_benchmark({"case": (export, _SNAPSHOT)})

    result = run_blind_binary_regression_gate(
        manifest,
        export_directory=tmp_path,
        oracle_loader=lambda: (
            BlindBenchmarkOracle(
                case_id="case",
                expected_findings=(
                    BlindBenchmarkExpectedFinding(
                        function_name="decode_tiff",
                        vulnerability_class=BinaryVulnerabilityClass.INTEGER_OVERFLOW,
                    ),
                ),
            ),
        ),
    )

    assert result.passed is False
    assert BlindRegressionGateFailure.INSUFFICIENT_CASES in result.failures
    assert BlindRegressionGateFailure.MISSING_CLASS_COVERAGE in result.failures


def test_regression_gate_reports_false_positive_and_false_negative(tmp_path: Path) -> None:
    vulnerable = tmp_path / "vulnerable.json"
    safe = tmp_path / "safe.json"
    _write_export(vulnerable, vulnerable=True)
    _write_export(safe, vulnerable=False)
    manifest = freeze_blind_benchmark(
        {"case-001": (vulnerable, _SNAPSHOT), "case-002": (safe, _SNAPSHOT)}
    )

    result = run_blind_binary_regression_gate(
        manifest,
        export_directory=tmp_path,
        oracle_loader=lambda: (
            BlindBenchmarkOracle(case_id="case-001"),
            BlindBenchmarkOracle(
                case_id="case-002",
                expected_findings=(
                    BlindBenchmarkExpectedFinding(
                        function_name="decode_tiff",
                        vulnerability_class=BinaryVulnerabilityClass.INTEGER_OVERFLOW,
                    ),
                ),
            ),
        ),
        policy=BlindRegressionGatePolicy(
            minimum_case_count=2,
            required_classes=(BinaryVulnerabilityClass.INTEGER_OVERFLOW,),
        ),
    )

    assert result.passed is False
    assert result.benchmark.false_positives == 1
    assert result.benchmark.false_negatives == 1
    assert BlindRegressionGateFailure.FALSE_POSITIVES_EXCEEDED in result.failures
    assert BlindRegressionGateFailure.FALSE_NEGATIVES_EXCEEDED in result.failures
    assert BlindRegressionGateFailure.CLASS_RECALL_BELOW_MINIMUM in result.failures


def test_regression_gate_rejects_nondeterministic_observations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vulnerable = tmp_path / "vulnerable.json"
    safe = tmp_path / "safe.json"
    _write_export(vulnerable, vulnerable=True)
    _write_export(safe, vulnerable=False)
    manifest = freeze_blind_benchmark(
        {"case-001": (vulnerable, _SNAPSHOT), "case-002": (safe, _SNAPSHOT)}
    )
    analysis_calls = 0
    real_analyzer = benchmark_module.analyze_binary_candidates

    def alternating_analyzer(
        ir: NormalizedBinaryIR,
        discovery: ImageIOParserDiscovery,
        *,
        limits: BinaryAnalyzerLimits | None = None,
    ):
        nonlocal analysis_calls
        analysis_calls += 1
        report = real_analyzer(ir, discovery, limits=limits)
        if analysis_calls == 3:
            return report.model_copy(update={"findings": ()})
        return report

    monkeypatch.setattr(benchmark_module, "analyze_binary_candidates", alternating_analyzer)
    result = run_blind_binary_regression_gate(
        manifest,
        export_directory=tmp_path,
        oracle_loader=lambda: (
            BlindBenchmarkOracle(
                case_id="case-001",
                expected_findings=(
                    BlindBenchmarkExpectedFinding(
                        function_name="decode_tiff",
                        vulnerability_class=BinaryVulnerabilityClass.INTEGER_OVERFLOW,
                    ),
                ),
            ),
            BlindBenchmarkOracle(case_id="case-002"),
        ),
        policy=BlindRegressionGatePolicy(
            minimum_case_count=2,
            required_classes=(BinaryVulnerabilityClass.INTEGER_OVERFLOW,),
        ),
    )

    assert analysis_calls == 4
    assert result.passed is False
    assert result.deterministic is False
    assert BlindRegressionGateFailure.NONDETERMINISTIC_RESULTS in result.failures


def test_macho_uuid_reads_lc_uuid_without_loading_image(tmp_path: Path) -> None:
    expected = uuid.UUID(_UUID)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 6, 1, 24, 0, 0)
    command = struct.pack("<II", 0x1B, 24) + expected.bytes
    image = tmp_path / "ImageIO"
    image.write_bytes(header + command)

    assert macho_uuid(image) == str(expected).upper()


def test_real_pilot_reports_missing_ghidra_without_static_claim(tmp_path: Path) -> None:
    cache = tmp_path / "dyld_shared_cache_arm64e"
    cache.write_bytes(b"not-used")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    output = tmp_path / "private-output"

    result = run_imageio_ghidra_pilot(
        cache_path=cache,
        output_directory=output,
        product_version="26.5.2",
        build_version="25F84",
        ghidra_headless=tmp_path / "missing-ghidra",
        script_directory=scripts,
        java_home=tmp_path,
    )

    assert result.status is ImageIOPilotStatus.BLOCKED_MISSING_GHIDRA
    assert result.vulnerability_confirmed is False
    assert result.experiments_executed == 0
    assert (output / "pilot-result.json").stat().st_mode & 0o777 == 0o600


def test_real_pilot_reports_missing_cache_before_tool_lookup(tmp_path: Path) -> None:
    result = run_imageio_ghidra_pilot(
        cache_path=tmp_path / "missing-cache",
        output_directory=tmp_path / "private-output",
        product_version="26.5.2",
        build_version="25F84",
        ghidra_headless=tmp_path / "missing-ghidra",
        script_directory=tmp_path,
        java_home=tmp_path,
    )

    assert result.status is ImageIOPilotStatus.BLOCKED_MISSING_CACHE
