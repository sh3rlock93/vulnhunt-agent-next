from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from benchmarks.m12.benchmark_case import BenchmarkCase
from benchmarks.m12.calibration import DEFAULT_CATALOG, load_calibration_catalog
from benchmarks.m12.calibration_cohort import (
    COHORT_FREEZE_POLICY,
    create_cohort_plan,
    execute_cohort,
    open_evaluation,
    verify_cohort_plan,
)
from benchmarks.run_libtiff_blind_benchmark import BenchmarkContractError


def _ids() -> Any:
    for value in range(1, 100):
        yield f"{value:016x}"


def _plan(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    values = _ids()
    output = tmp_path / "cohort"
    result = create_cohort_plan(
        DEFAULT_CATALOG,
        output,
        id_factory=lambda: next(values),
    )
    return output / "cohort-plan.json", result


def _maps(plan: dict[str, Any], tmp_path: Path) -> tuple[dict[str, Path], dict[str, Path]]:
    case_ids = {str(item["case_id"]) for item in plan["run"]}
    repositories = {case_id: tmp_path / "repos" / case_id for case_id in case_ids}
    prepared = {case_id: tmp_path / "prepared" / case_id for case_id in case_ids}
    for path in repositories.values():
        path.mkdir(parents=True)
    return repositories, prepared


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _fake_discover(calls: list[tuple[str, int]]):
    def discover(
        case: BenchmarkCase,
        _repo: Path,
        output: Path,
        image: str,
        model_id: str | None,
    ) -> dict[str, Any]:
        calls.append((case.case_id, case.repetition_index))
        work_id = f"work_{case.case_id.removeprefix('case_')}_{case.repetition_index}"
        _write_json(output / "plan.json", {
            "work_items": [{
                "work_id": work_id,
                "hunter": case.required_hunter,
                "target_signal_ids": [f"signal_{case.repetition_index}"],
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
        _write_json(output / "findings.json", [])
        discovery_result = {
            "schema_version": 2,
            "phase": "discover",
            "complete": True,
            "mode": "authenticated",
            "run_identity": {
                "run_id": f"internal-{case.case_id}-{case.repetition_index}",
                "source": asdict(case.source),
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
        _write_json(output / "discovery.json", discovery_result)
        return discovery_result

    return discover


def test_plan_freezes_exact_four_by_three_unique_matrix(tmp_path: Path) -> None:
    plan_path, plan = _plan(tmp_path)

    verified = verify_cohort_plan(plan_path)
    run_ids = [item["run_id"] for item in verified["run"]]
    repetitions = {
        (item["case_id"], item["repetition_index"]) for item in verified["run"]
    }

    assert plan["cohort_id"] == "cohort_0000000000000001"
    assert len(run_ids) == len(set(run_ids)) == 12
    assert len(repetitions) == 12
    assert {item["repetition_index"] for item in verified["run"]} == {1, 2, 3}


def test_plan_lock_rejects_run_identity_mutation(tmp_path: Path) -> None:
    plan_path, _plan_value = _plan(tmp_path)
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["run"][0]["run_id"] = "run_ffffffffffffffff"
    _write_json(plan_path, payload)

    with pytest.raises(BenchmarkContractError, match="plan hash mismatch"):
        verify_cohort_plan(plan_path)


def test_runner_freezes_every_valid_miss_once_and_writes_immutable_receipts(
    tmp_path: Path,
) -> None:
    plan_path, plan = _plan(tmp_path)
    repositories, prepared = _maps(plan, tmp_path)
    calls: list[tuple[str, int]] = []

    cohort_freeze = execute_cohort(
        plan_path,
        repositories=repositories,
        prepared_runs=prepared,
        model_id="gpt-test",
        discover_runner=_fake_discover(calls),
        prepared_image_loader=lambda path: f"prepared:{path.name}",
    )

    assert cohort_freeze["policy_version"] == COHORT_FREEZE_POLICY
    assert len(calls) == len(cohort_freeze["run"]) == 12
    assert len({item["run_id"] for item in cohort_freeze["run"]}) == 12
    for item in plan["run"]:
        receipt = json.loads((plan_path.parent / item["receipt"]).read_text())
        assert receipt["hunter_findings"] == []
        assert receipt["outcome"] == "completed"
        assert receipt["oracle_isolated"] is True

    execute_cohort(
        plan_path,
        repositories=repositories,
        prepared_runs=prepared,
        discover_runner=lambda *_args: pytest.fail("valid miss was retried"),
        prepared_image_loader=lambda path: f"prepared:{path.name}",
    )
    assert len(calls) == 12


def test_incomplete_run_is_not_retried_under_the_same_id(tmp_path: Path) -> None:
    plan_path, plan = _plan(tmp_path)
    repositories, prepared = _maps(plan, tmp_path)
    first = plan["run"][0]
    _write_json(
        plan_path.parent / first["discovery_root"] / "discovery.json",
        {"phase": "discover", "complete": False},
    )
    calls: list[tuple[str, int]] = []

    with pytest.raises(BenchmarkContractError, match="cannot be retried"):
        execute_cohort(
            plan_path,
            repositories=repositories,
            prepared_runs=prepared,
            discover_runner=_fake_discover(calls),
            prepared_image_loader=lambda path: f"prepared:{path.name}",
        )

    assert calls == []


def test_oracle_loader_stays_closed_until_all_twelve_freezes_verify(
    tmp_path: Path,
) -> None:
    plan_path, plan = _plan(tmp_path)
    repositories, prepared = _maps(plan, tmp_path)
    opened: list[Path] = []

    def loader(path: Path):
        opened.append(path)
        return load_calibration_catalog(path)

    with pytest.raises(BenchmarkContractError):
        open_evaluation(plan_path, DEFAULT_CATALOG, loader=loader)
    assert opened == []

    execute_cohort(
        plan_path,
        repositories=repositories,
        prepared_runs=prepared,
        discover_runner=_fake_discover([]),
        prepared_image_loader=lambda path: f"prepared:{path.name}",
    )
    catalog = open_evaluation(plan_path, DEFAULT_CATALOG, loader=loader)

    assert catalog.sha256 == plan["catalog_sha256"]
    assert opened == [DEFAULT_CATALOG.resolve()]


def test_partial_repository_mapping_fails_before_any_authenticated_run(
    tmp_path: Path,
) -> None:
    plan_path, plan = _plan(tmp_path)
    repositories, prepared = _maps(plan, tmp_path)
    repositories.pop(next(iter(repositories)))
    calls: list[tuple[str, int]] = []

    with pytest.raises(BenchmarkContractError, match="cover the cohort exactly"):
        execute_cohort(
            plan_path,
            repositories=repositories,
            prepared_runs=prepared,
            discover_runner=_fake_discover(calls),
            prepared_image_loader=lambda path: f"prepared:{path.name}",
        )

    assert calls == []
