from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from benchmarks.m12.benchmark_case import BenchmarkCase
from benchmarks.m12.calibration import DEFAULT_CATALOG, load_calibration_catalog
from benchmarks.m12.calibration_cohort import create_cohort_plan, execute_cohort
from benchmarks.m12.calibration_evaluation import (
    _finding_matches_oracle,
    _target_matches_oracle,
    evaluate_calibration_cohort,
)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _ids() -> Any:
    for value in range(1, 100):
        yield f"{value:016x}"


def _discover(oracles: dict[str, dict[str, Any]]):
    def discover(
        case: BenchmarkCase,
        _repo: Path,
        output: Path,
        image: str,
        model_id: str | None,
    ) -> dict[str, Any]:
        target_id = f"sig_{case.case_id.removeprefix('case_')[:16]}"
        work_id = f"work_{case.case_id.removeprefix('case_')}_{case.repetition_index}"
        location = oracles[case.case_id]["location"]
        _write_json(output / "plan.json", {
            "work_items": [{
                "work_id": work_id,
                "hunter": case.required_hunter,
                "target_signal_ids": [target_id],
            }],
            "budget_allocation": {
                "decisions": [{"work_id": work_id, "rank": 1}],
                "admission_ledger": {"events": [{
                    "event": "provider_started",
                    "provider_started": True,
                    "work_id": work_id,
                }]},
            },
        })
        _write_json(output / "analysis.json", {
            "graph": {
                "signals": [{
                    "signal_id": target_id,
                    "path": location["sink_file"],
                    "line": location["sink_line_min"],
                }],
                "nodes": [],
            }
        })
        _write_json(output / "findings.json", [])
        result = {
            "schema_version": 2,
            "phase": "discover",
            "complete": True,
            "mode": "authenticated",
            "run_identity": {
                "run_id": f"internal-{case.case_id}-{case.repetition_index}",
                "source": {
                    "origin": case.source.repository,
                    "commit": case.source.commit,
                    "tree": case.source.tree,
                },
            },
            "model": {
                "adapter": "codex_subscription",
                "model_id": model_id or "gpt-test",
            },
            "policies": {"admission": "c-budget-v10"},
            "usage": {
                "sessions": 1,
                "input_tokens": 100,
                "output_tokens": 10,
                "cache_read_tokens": 20,
                "cache_write_tokens": 0,
                "wall_time_ms": 1000,
            },
            "summary": {"deferred_sessions": 0},
            "prepared_image": image,
            "oracle_access_audit": {
                "oracle_received": False,
                "fixed_tree_received": False,
                "denied_attempts": [],
            },
        }
        _write_json(output / "discovery.json", result)
        return result

    return discover


def test_exact_entry_and_sink_ranges_are_required_for_target_matching() -> None:
    oracle = {
        "location": {
            "entry_file": "src/parser.c",
            "entry_line_min": 10,
            "entry_line_max": 20,
            "sink_file": "src/parser.c",
            "sink_line_min": 40,
            "sink_line_max": 50,
        }
    }
    exact = {
        "entrypoint": {"path": "src/parser.c", "line": 12},
        "sink": {"path": "src/parser.c", "line": 45},
    }
    wrong_sink = {
        "entrypoint": {"path": "src/parser.c", "line": 12},
        "sink": {"path": "src/helper.c", "line": 45},
    }
    analysis = {
        "graph": {
            "signals": [{"signal_id": "sig_target", "path": "src/parser.c", "line": 45}],
            "nodes": [],
        }
    }

    assert _finding_matches_oracle(exact, oracle) is True
    assert _finding_matches_oracle(wrong_sink, oracle) is False
    assert _target_matches_oracle("sig_target", analysis, oracle) is True
    assert _target_matches_oracle("sig_missing", analysis, oracle) is False


def test_closed_cohort_evaluation_is_deterministic_and_keeps_valid_misses(
    tmp_path: Path,
) -> None:
    values = _ids()
    cohort_root = tmp_path / "cohort"
    plan = create_cohort_plan(
        DEFAULT_CATALOG,
        cohort_root,
        id_factory=lambda: next(values),
    )
    catalog = load_calibration_catalog(DEFAULT_CATALOG)
    oracles = {item.case.case_id: item.oracle for item in catalog.definitions}
    case_ids = {str(item["case_id"]) for item in plan["run"]}
    repositories = {case_id: tmp_path / "repos" / case_id for case_id in case_ids}
    prepared = {case_id: tmp_path / "prepared" / case_id for case_id in case_ids}
    for path in repositories.values():
        path.mkdir(parents=True)

    execute_cohort(
        cohort_root / "cohort-plan.json",
        repositories=repositories,
        prepared_runs=prepared,
        discover_runner=_discover(oracles),
        prepared_image_loader=lambda path: f"prepared:{path.name}",
    )
    report = evaluate_calibration_cohort(cohort_root / "cohort-plan.json")
    before = (cohort_root / "evaluation" / "release-report.json").read_bytes()
    repeated = evaluate_calibration_cohort(cohort_root / "cohort-plan.json")

    metrics = json.loads((cohort_root / "evaluation" / "metrics.json").read_text())
    assert metrics["run_accounting"]["valid_run_rate"]["rate"] == 1.0
    assert metrics["detection"]["hunter_detection_at_k"]["12"]["rate"] == 0.0
    assert report == repeated
    assert (cohort_root / "evaluation" / "release-report.json").read_bytes() == before
    assert report["assessment"]["decision"] == "stop_and_design_m12_2_x"
