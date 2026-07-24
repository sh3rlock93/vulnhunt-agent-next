from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from benchmarks.detection_registry import DetectionBaseline, load_detection_registry
from benchmarks.m12.baseline import (
    _load_receipts,
    assert_frozen_protected_contracts,
    assert_no_production_leakage,
    load_m12_baseline,
    validate_m12_baseline,
)
from benchmarks.run_detection_release_matrix import validate_release_contract
from benchmarks.run_libtiff_blind_benchmark import BenchmarkContractError

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "benchmarks" / "m12" / "m11-7-baseline.toml"
REGISTRY = ROOT / "benchmarks" / "historical-detections.toml"
MATRIX = ROOT / "benchmarks" / "detection-release-matrix.toml"
RECEIPTS = ROOT / "benchmarks" / "authenticated-detection-receipts.toml"


def _contracts() -> tuple[
    tuple[DetectionBaseline, ...],
    tuple,
    dict[str, dict],
]:
    detections = load_detection_registry(REGISTRY)
    gates = validate_release_contract(REGISTRY, MATRIX, RECEIPTS)
    receipts = _load_receipts(RECEIPTS)
    return detections, gates, receipts


def test_m11_7_baseline_validates_frozen_git_and_six_protected_results() -> None:
    result = validate_m12_baseline(
        BASELINE,
        REGISTRY,
        MATRIX,
        RECEIPTS,
        repository_root=ROOT,
    )

    assert result["passed"] is True
    assert result["implementation_commit"] == "1e99bd24e779f47e511165c069fd1cc659b01967"
    assert result["action_run_id"] == 29987233593
    assert result["release_matrix_job_id"] == 89141917213
    assert len(result["protected_detection_ids"]) == 6


def test_frozen_protected_detection_cannot_be_demoted() -> None:
    baseline = load_m12_baseline(BASELINE)
    detections, gates, receipts = _contracts()
    demoted = tuple(
        replace(item, status="known_gap") if item.baseline_id == "cjson-issue-800" else item
        for item in detections
    )

    with pytest.raises(BenchmarkContractError, match="was demoted"):
        assert_frozen_protected_contracts(baseline, demoted, gates, receipts)


def test_frozen_detection_contract_cannot_be_weakened() -> None:
    baseline = load_m12_baseline(BASELINE)
    detections, gates, receipts = _contracts()
    weakened = tuple(
        replace(item, maximum_admission_rank=item.maximum_admission_rank + 1)
        if item.baseline_id == "libwebp-cve-2023-4863"
        else item
        for item in detections
    )

    with pytest.raises(BenchmarkContractError, match="contract changed"):
        assert_frozen_protected_contracts(baseline, weakened, gates, receipts)


def test_new_detection_does_not_change_the_frozen_six() -> None:
    baseline = load_m12_baseline(BASELINE)
    detections, gates, receipts = _contracts()
    additional = DetectionBaseline(
        baseline_id="future-protected-detection",
        status="must_detect",
        source_repository="https://example.invalid/future.git",
        source_commit="6" * 40,
        source_tree="7" * 40,
        expected_hunter="c-bounds-integers",
        required_paths=("future.c",),
        weakness_terms=("out-of-bounds write",),
        maximum_admission_rank=12,
    )

    assert_frozen_protected_contracts(
        baseline,
        detections + (additional,),
        gates,
        receipts,
    )


def test_authenticated_receipt_mutation_invalidates_frozen_result() -> None:
    baseline = load_m12_baseline(BASELINE)
    detections, gates, receipts = _contracts()
    changed = {key: dict(value) for key, value in receipts.items()}
    changed["cjson-m11-7-authenticated"]["output_tokens"] += 1

    with pytest.raises(BenchmarkContractError, match="receipt changed"):
        assert_frozen_protected_contracts(baseline, detections, gates, changed)


def test_repository_specific_oracle_token_cannot_enter_production(tmp_path: Path) -> None:
    baseline = load_m12_baseline(BASELINE)
    production = tmp_path / "src" / "vulnhunt_agent"
    production.mkdir(parents=True)
    leaked_token = baseline.protected[0].oracle_tokens[0]
    (production / "prompt.py").write_text(f'TARGET = "{leaked_token}"\n', encoding="utf-8")

    with pytest.raises(BenchmarkContractError, match="leaked into production"):
        assert_no_production_leakage(baseline, production)
