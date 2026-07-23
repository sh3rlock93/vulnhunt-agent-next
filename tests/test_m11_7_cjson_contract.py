from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

from benchmarks.detection_registry import load_detection_registry
from benchmarks.run_cjson_cursor_benchmark import (
    REQUIRED_BUDGET,
    REQUIRED_LIMITS,
    REQUIRED_POLICIES,
    _candidate_matches_oracle,
    _specialist_cursor_finding,
)
from benchmarks.run_libcue_specialist_benchmark import _contains_exact
from benchmarks.run_libtiff_blind_benchmark import load_scan_manifest

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "benchmarks" / "cjson-blind-scan.toml"
ORACLE = ROOT / "benchmarks" / "oracles" / "cjson-issue-800.toml"
REGISTRY = ROOT / "benchmarks" / "historical-detections.toml"
FIXTURES = ROOT / "tests" / "fixtures" / "cursor_parser"


def test_scan_manifest_is_oracle_free_pinned_and_budget_locked() -> None:
    raw = SCAN.read_text(encoding="utf-8")
    scan = load_scan_manifest(SCAN)

    assert "issue-800" not in raw.casefold()
    assert "98f9eb0412067a852ec107c68e49180fe4e472dc" in raw
    assert "fixed_source" not in raw
    assert "parse_string" not in raw
    assert "parse_object" not in raw
    assert _contains_exact(scan["budget"], REQUIRED_BUDGET)
    assert _contains_exact(scan["limits"], REQUIRED_LIMITS)
    assert all(
        scan["policies"].get(key) == value
        for key, value in REQUIRED_POLICIES.items()
    )


def test_withheld_oracle_pins_independent_fixed_revision_and_two_attempts() -> None:
    oracle = tomllib.loads(ORACLE.read_text(encoding="utf-8"))

    assert oracle["fixed_source"] == {
        "commit": "3ef4e4e730e5efd381be612df41e1ff3f5bb3c32",
        "tree": "3d1d654872dff42cfebca69133ef6acdf4354f2b",
    }
    assert oracle["reproduction"]["attempts"] == 2
    assert oracle["location"]["required_hunter"] == "c-parser-state"
    assert oracle["location"]["required_signal_category"] == "cursor_index_read"


def test_candidate_match_requires_transition_and_read_sink() -> None:
    oracle = tomllib.loads(ORACLE.read_text(encoding="utf-8"))
    matching = {
        "title": "Cursor advance reaches an out-of-bounds read",
        "weakness": "heap_buffer_overflow_read",
        "entrypoint": {"path": "cJSON.c", "line": 1664},
        "sink": {"path": "cJSON.c", "line": 787},
        "dataflow": [],
        "impact": ["A bounded input causes a read of size one past the buffer."],
    }

    assert _candidate_matches_oracle(matching, oracle)
    assert not _candidate_matches_oracle(
        {**matching, "entrypoint": {"path": "cJSON.c", "line": 1200}}, oracle
    )
    assert not _candidate_matches_oracle(
        {**matching, "sink": {"path": "cJSON.c", "line": 978}}, oracle
    )
    assert not _candidate_matches_oracle(
        {**matching, "title": "Cursor formatting issue", "weakness": "logic"},
        oracle,
    )


def test_candidate_match_accepts_public_entry_only_with_target_reproduction() -> None:
    oracle = tomllib.loads(ORACLE.read_text(encoding="utf-8"))
    candidate = {
        "candidate_id": "cand-target",
        "title": "Trailing object comma causes an out-of-bounds read",
        "weakness": "out_of_bounds_read",
        "entrypoint": {"path": "cJSON.c", "line": 1101},
        "sink": {"path": "cJSON.c", "line": 787},
        "dataflow": [],
    }
    evidence = [{
        "candidate_id": "cand-target",
        "kind": "reproduction",
        "target_source_reached": True,
        "sanitizer_frames": [
            {"path": "/code/cJSON.c", "line": 787, "in_target": True},
            {"path": "/code/cJSON.c", "line": 1666, "in_target": True},
        ],
    }]

    assert not _candidate_matches_oracle(candidate, oracle)
    assert _candidate_matches_oracle(candidate, oracle, evidence=evidence)
    assert not _candidate_matches_oracle(
        candidate,
        oracle,
        evidence=[{**evidence[0], "candidate_id": "cand-unrelated"}],
    )
    assert not _candidate_matches_oracle(
        candidate,
        oracle,
        evidence=[{
            **evidence[0],
            "sanitizer_frames": [
                {"path": "/code/cJSON.c", "line": 416, "in_target": True}
            ],
        }],
    )
    assert not _candidate_matches_oracle(
        {
            **candidate,
            "state": "unclear",
            "resolution": {"disposition": "verification_deferred"},
        },
        oracle,
        evidence=evidence,
    )


def test_specialist_gate_requires_executed_unsafe_cursor_proof(
    tmp_path: Path,
) -> None:
    oracle = tomllib.loads(ORACLE.read_text(encoding="utf-8"))
    findings_path = (
        tmp_path
        / "run"
        / "hunters"
        / "work-parser"
        / "hunts"
        / "c-parser-state"
        / "findings.json"
    )
    findings_path.parent.mkdir(parents=True)
    payload: dict[str, Any] = {
        "findings": [{
            "title": "Cursor advance reaches an out-of-bounds read",
            "sink_file": "cJSON.c",
            "sink_line": 787,
        }],
        "target_dispositions": [{
            "target_id": "sig-target",
            "status": "finding",
            "finding_indices": [0],
            "cursor_proof": {
                "policy_version": "c-cursor-proof-v1",
                "conclusion": "unsafe_reachable",
                "boundary_attempt": {"status": "executed"},
            },
        }],
    }
    findings_path.write_text(json.dumps(payload), encoding="utf-8")
    specialist = {"work_id": "work-parser"}

    matched = _specialist_cursor_finding(
        tmp_path,
        specialist,
        {"sig-target"},
        oracle["location"],
    )
    assert matched is not None
    assert matched["sink"] == "cJSON.c:787"

    payload["target_dispositions"][0]["cursor_proof"]["boundary_attempt"] = {
        "status": "not_attempted"
    }
    findings_path.write_text(json.dumps(payload), encoding="utf-8")
    assert _specialist_cursor_finding(
        tmp_path,
        specialist,
        {"sig-target"},
        oracle["location"],
    ) is None


def test_registry_promotes_cjson_only_after_authenticated_recovery() -> None:
    entry = next(
        item
        for item in load_detection_registry(REGISTRY)
        if item.baseline_id == "cjson-issue-800"
    )

    assert entry.status == "must_detect"
    assert entry.expected_hunter == "c-parser-state"
    assert entry.source_commit == "98f9eb0412067a852ec107c68e49180fe4e472dc"
    assert entry.required_paths == ("cJSON.c",)


def test_neutral_cursor_fixtures_do_not_embed_target_signatures() -> None:
    vulnerable = (FIXTURES / "vulnerable" / "parser.c").read_text()
    guarded = (FIXTURES / "guarded" / "parser.c").read_text()

    assert "cJSON" not in vulnerable + guarded
    assert "parse_string" not in vulnerable + guarded
    assert "parse_object" not in vulnerable + guarded
    assert "HAS(view, 1)" not in vulnerable
    assert "MISSING(view, 1)" in guarded
