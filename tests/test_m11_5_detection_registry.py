from __future__ import annotations

import tomllib
from dataclasses import replace
from pathlib import Path

import pytest

from benchmarks.detection_registry import (
    assert_no_status_demotion,
    load_detection_registry,
    protected_detection_ids,
)
from benchmarks.run_libcue_specialist_benchmark import (
    REQUIRED_BUDGET,
    REQUIRED_LIMITS,
    _candidate_matches_oracle,
    _contains_exact,
    _specialist_record,
)
from benchmarks.run_libtiff_blind_benchmark import (
    BenchmarkContractError,
    load_scan_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "benchmarks" / "historical-detections.toml"
SCAN = ROOT / "benchmarks" / "libcue-blind-scan.toml"
ORACLE = ROOT / "benchmarks" / "oracles" / "libcue-cve-2023-43641.toml"


def test_registry_protects_every_current_green_detection() -> None:
    entries = load_detection_registry(REGISTRY)

    assert protected_detection_ids(entries) == (
        "zlib-cve-2023-45853",
        "libjpeg-turbo-issue-387",
        "libwebp-cve-2023-4863",
        "libcue-time-global-buffer-overflow",
    )
    assert {entry.baseline_id for entry in entries} >= {
        "libcue-cve-2023-43641",
        "libtiff-cve-2023-41175",
        "libyaml-utf16-retry-oob",
        "libpng-visualpng-candidates",
    }


def test_protected_detection_cannot_be_removed_or_demoted() -> None:
    entries = load_detection_registry(REGISTRY)
    protected = next(entry for entry in entries if entry.status == "must_detect")

    with pytest.raises(BenchmarkContractError, match="demoted"):
        assert_no_status_demotion(
            entries,
            tuple(
                replace(entry, status="known_gap")
                if entry == protected else entry
                for entry in entries
            ),
        )
    with pytest.raises(BenchmarkContractError, match="removed"):
        assert_no_status_demotion(
            entries,
            tuple(entry for entry in entries if entry != protected),
        )


def test_libcue_scan_manifest_is_oracle_free_and_budget_locked() -> None:
    raw = SCAN.read_text(encoding="utf-8")
    scan = load_scan_manifest(SCAN)

    assert "CVE-" not in raw
    assert "4294567296" not in raw
    assert "fixed_source" not in raw
    assert _contains_exact(scan["budget"], REQUIRED_BUDGET)
    assert _contains_exact(scan["limits"], REQUIRED_LIMITS)
    assert scan["policies"]["admission"] == "c-budget-v9"
    assert scan["policies"]["input_fairness"] == "work-input-fairness-v3"


def test_libcue_candidate_requires_parser_paths_and_exact_sink() -> None:
    oracle = tomllib.loads(ORACLE.read_text(encoding="utf-8"))
    matching = {
        "title": "Parser integer wrap reaches negative out-of-bounds index",
        "weakness": "out-of-bounds write",
        "entrypoint": {"path": "cue_scanner.l", "line": 10},
        "sink": {"path": "cd.c", "line": 347},
        "dataflow": [{"path": "cue_parser.y", "line": 261}],
        "impact": ["Negative array index corrupts Track state"],
    }

    assert _candidate_matches_oracle(matching, oracle)
    assert not _candidate_matches_oracle(
        {**matching, "dataflow": []}, oracle
    )
    assert not _candidate_matches_oracle(
        {**matching, "sink": {"path": "time.c", "line": 33}}, oracle
    )


def test_specialist_record_does_not_accept_bounds_as_parser_coverage() -> None:
    target = "sig-target"
    plan = {
        "work_items": [
            {
                "work_id": "work-bounds",
                "hunter": "c-bounds-integers",
                "target_signal_ids": [target],
            },
            {
                "work_id": "work-parser",
                "hunter": "c-parser-state",
                "target_signal_ids": [target],
            },
        ],
        "allocation": {
            "decisions": [{"work_id": "work-bounds", "rank": 1}],
            "ranking": [
                {
                    "work_id": "work-parser",
                    "pre_admission_rank": 7,
                    "disposition": "duplicate_deferred",
                    "reason": "duplicate_capacity_chain",
                }
            ],
        },
        "contexts": [],
    }
    location = tomllib.loads(ORACLE.read_text(encoding="utf-8"))["location"]

    record = _specialist_record(plan, {target}, location)

    assert record is not None
    assert record["work_id"] == "work-parser"
    assert record["admission_rank"] is None
    assert record["quota"] is None
    assert record["reason"] == "duplicate_capacity_chain"
