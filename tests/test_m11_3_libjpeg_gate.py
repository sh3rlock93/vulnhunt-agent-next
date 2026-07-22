from __future__ import annotations

import tomllib
from pathlib import Path

from benchmarks.run_libjpeg_capacity_benchmark import (
    REQUIRED_BUDGET,
    REQUIRED_LIMITS,
    _candidate_matches_oracle,
    _capacity_policies_recorded,
)
from benchmarks.run_libwebp_capacity_benchmark import _contains_exact
from benchmarks.run_libtiff_blind_benchmark import load_scan_manifest

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "benchmarks" / "libjpeg-turbo-blind-scan.toml"
ORACLE = ROOT / "benchmarks" / "oracles" / "libjpeg-turbo-issue-387.toml"


def test_libjpeg_scan_is_oracle_free_pinned_and_bounded() -> None:
    raw = SCAN.read_text(encoding="utf-8")
    scan = load_scan_manifest(SCAN)

    assert "issue-387" not in raw.casefold()
    assert "fixed_source" not in raw
    assert scan["source"]["commit"] == "c30b1e72dac76343ef9029833d1561de07d29bad"
    assert scan["source"]["tree"] == "48074ffcebfb949fd22ded3281301259d4c9f265"
    assert _capacity_policies_recorded(scan["policies"])
    assert _contains_exact(scan["budget"], REQUIRED_BUDGET)
    assert _contains_exact(scan["limits"], REQUIRED_LIMITS)


def test_libjpeg_candidate_requires_caller_and_callee_paths() -> None:
    oracle = tomllib.loads(ORACLE.read_text(encoding="utf-8"))
    matching = {
        "title": "Unchecked plane width permits an out-of-bounds write",
        "weakness": "heap buffer overflow",
        "entrypoint": {"path": "tjbench.c", "line": 183},
        "sink": {"path": "turbojpeg.c", "line": 1726},
        "dataflow": [],
        "impact": ["Memory corruption while decoding a crafted JPEG"],
    }

    assert _candidate_matches_oracle(matching, oracle)
    assert not _candidate_matches_oracle(
        {**matching, "entrypoint": {"path": "turbojpeg.c", "line": 1572}},
        oracle,
    )
