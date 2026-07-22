from __future__ import annotations

import tomllib
from pathlib import Path

from benchmarks.run_libwebp_capacity_benchmark import (
    REQUIRED_BUDGET,
    REQUIRED_LIMITS,
    _candidate_matches_oracle,
    _capacity_policies_recorded,
    _contains_exact,
)
from benchmarks.run_libtiff_blind_benchmark import load_scan_manifest

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "benchmarks" / "libwebp-blind-scan.toml"
ORACLE = ROOT / "benchmarks" / "oracles" / "libwebp-cve-2023-4863.toml"


def test_scan_input_is_oracle_free_and_keeps_the_fixed_budget() -> None:
    raw = SCAN.read_text(encoding="utf-8")
    scan = load_scan_manifest(SCAN)

    assert "CVE-" not in raw
    assert "poc" not in raw.casefold()
    assert "fixed_source" not in raw
    assert _capacity_policies_recorded(scan["policies"])
    assert _contains_exact(scan["budget"], REQUIRED_BUDGET)
    assert _contains_exact(scan["limits"], REQUIRED_LIMITS)


def test_candidate_match_requires_root_and_cross_file_write_path() -> None:
    oracle = tomllib.loads(ORACLE.read_text(encoding="utf-8"))
    matching = {
        "title": "Unchecked Huffman table capacity permits out-of-bounds write",
        "weakness": "heap buffer overflow",
        "entrypoint": {"path": "src/dec/vp8l_dec.c", "line": 432},
        "sink": {"path": "src/utils/huffman_utils.c", "line": 59},
        "dataflow": [],
        "impact": ["Memory corruption while decoding an input image"],
    }

    assert _candidate_matches_oracle(matching, oracle)
    assert not _candidate_matches_oracle(
        {**matching, "sink": {"path": "src/dec/vp8l_dec.c", "line": 478}},
        oracle,
    )
