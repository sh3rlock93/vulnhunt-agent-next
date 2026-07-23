from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.run_detection_release_matrix import (
    evaluate_release_matrix,
    validate_release_contract,
)
from benchmarks.run_libtiff_blind_benchmark import BenchmarkContractError

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "benchmarks" / "historical-detections.toml"
MATRIX = ROOT / "benchmarks" / "detection-release-matrix.toml"
RECEIPTS = ROOT / "benchmarks" / "authenticated-detection-receipts.toml"


def test_release_matrix_covers_every_protected_detection_exactly() -> None:
    gates = validate_release_contract(REGISTRY, MATRIX, RECEIPTS)

    assert tuple(gate.baseline_id for gate in gates) == (
        "zlib-cve-2023-45853",
        "libjpeg-turbo-issue-387",
        "libwebp-cve-2023-4863",
        "libcue-time-global-buffer-overflow",
        "libcue-cve-2023-43641",
        "cjson-issue-800",
    )
    assert gates[-1].require_differential_reproduction is True
    assert gates[-1].authenticated_receipt == "cjson-m11-7-authenticated"


def test_release_matrix_passes_only_when_every_unique_job_succeeds() -> None:
    gates = validate_release_contract(REGISTRY, MATRIX, RECEIPTS)
    statuses = {gate.ci_job: "success" for gate in gates}

    passed = evaluate_release_matrix(gates, statuses)
    failed = evaluate_release_matrix(
        gates,
        {**statuses, "m11-5-libcue-specialist": "failure"},
    )

    assert passed["passed"] is True
    assert failed["passed"] is False
    assert {
        item["baseline_id"]
        for item in failed["results"]
        if not item["passed"]
    } == {
        "libcue-time-global-buffer-overflow",
        "libcue-cve-2023-43641",
    }


def test_release_matrix_rejects_missing_or_unknown_job_status() -> None:
    gates = validate_release_contract(REGISTRY, MATRIX, RECEIPTS)

    assert evaluate_release_matrix(gates, {})["passed"] is False
    with pytest.raises(BenchmarkContractError, match="unknown release job"):
        evaluate_release_matrix(gates, {"unmapped-job": "success"})


def test_differential_gate_cannot_exist_without_receipt(tmp_path: Path) -> None:
    unproved = tmp_path / "matrix.toml"
    unproved.write_text(
        MATRIX.read_text(encoding="utf-8").replace(
            'baseline_id = "libcue-cve-2023-43641"\n'
            'ci_job = "m11-5-libcue-specialist"\n'
            'authenticated_receipt = "libcue-m11-5-authenticated"\n',
            'baseline_id = "libcue-cve-2023-43641"\n'
            'ci_job = "m11-5-libcue-specialist"\n',
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        BenchmarkContractError,
        match="differential reproduction requires an authenticated receipt",
    ):
        validate_release_contract(REGISTRY, unproved, RECEIPTS)
