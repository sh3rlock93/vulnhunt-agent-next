from __future__ import annotations

import json
import tomllib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from benchmarks.run_libjpeg_capacity_benchmark import (
    REQUIRED_BUDGET,
    REQUIRED_LIMITS,
    _candidate_matches_oracle,
    _capacity_policies_recorded,
    _input_fairness_enforced,
    _load_model_candidates,
    _matching_provider_start_rank,
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


def test_authenticated_gate_uses_actual_provider_start_order() -> None:
    chain = SimpleNamespace(chain_id="capacity_risk_" + "a" * 20)
    plan = {
        "budget_allocation": {
            "ranking": [
                {"work_id": "other", "chain_ids": []},
                {"work_id": "target", "chain_ids": [chain.chain_id]},
            ],
            "admission_ledger": {
                "events": [
                    {
                        "event": "provider_started",
                        "provider_started": True,
                        "work_id": "other",
                    },
                    {"event": "done", "work_id": "other"},
                    {
                        "event": "provider_started",
                        "provider_started": True,
                        "work_id": "target",
                    },
                ]
            },
        }
    }

    assert _matching_provider_start_rank(plan, [chain]) == 2


def test_authenticated_gate_loads_unverified_raw_hunter_finding(
    tmp_path: Path,
) -> None:
    finding_dir = (
        tmp_path / "run" / "hunters" / "work" / "hunts" / "c-bounds-integers"
    )
    finding_dir.mkdir(parents=True)
    (finding_dir / "findings.json").write_text(json.dumps({
        "findings": [{
            "title": "YUV buffer overflow",
            "type": "heap_buffer_overflow",
            "status": "unverified",
            "entry_file": "tjbench.c",
            "entry_line": 537,
            "sink_file": "turbojpeg.c",
            "sink_line": 1726,
            "files_touched": ["tjbench.c", "turbojpeg.c"],
            "description": "out-of-bounds write",
        }],
    }))

    candidates = _load_model_candidates(tmp_path, {"candidates": []})

    assert len(candidates) == 1
    assert candidates[0]["status"] == "unverified"
    assert candidates[0]["candidate_origin"] == "raw_hunter_finding"
    assert candidates[0]["entrypoint"]["path"] == "tjbench.c"
    assert candidates[0]["sink"] == {"path": "turbojpeg.c", "line": 1726}


def test_authenticated_gate_requires_enforced_per_work_input_limit() -> None:
    plan: dict[str, Any] = {
        "budget_allocation": {
            "input_fairness": {
                "policy_version": "work-input-fairness-v2",
                "per_work_input_limit": 100,
                "work_input_limits": {"first": 90, "second": 100},
            }
        },
        "budget_state": {
            "input_fairness_policy": "work-input-fairness-v2",
            "work_input_tokens": {"first": 80, "second": 100},
        },
    }

    assert _input_fairness_enforced(plan)
    plan["budget_state"]["work_input_tokens"]["second"] = 101
    assert not _input_fairness_enforced(plan)
