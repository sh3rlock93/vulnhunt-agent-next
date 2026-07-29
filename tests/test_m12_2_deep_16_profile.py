from __future__ import annotations

import argparse

import pytest

from tests.factories import HASH_A
from vulnhunt_agent.domain.schemas import BudgetPolicy
from vulnhunt_agent.interfaces.cli import (
    _load_hunter_budget_config,
    build_parser,
)
from vulnhunt_agent.pipeline.hunt import (
    _deep_extension_metrics,
    _finding_identity,
    _high_risk_extension_findings,
    _run_tasks_in_ranked_waves,
    _should_stop_deep_extension,
)
from vulnhunt_agent.scheduling import (
    BudgetController,
    BudgetExceededError,
    DEEP_16,
    STANDARD_12,
    allocate_work_items,
    build_shadow_plan,
    resolve_hunter_budget_config,
)


def test_named_profiles_keep_standard_12_and_bound_deep_16() -> None:
    standard = resolve_hunter_budget_config({
        "hunter_budget_profile": "standard-12",
    })
    deep = resolve_hunter_budget_config({
        "hunter_budget_profile": "deep-16",
        "budget_max_hunter_sessions": 999,
    })

    assert standard == STANDARD_12.config()
    assert deep == DEEP_16.config()
    assert standard["budget_max_hunter_sessions"] == 12
    assert standard["budget_soft_input_token_stop"] == 1_500_000
    assert deep["budget_max_hunter_sessions"] == 16
    assert deep["budget_max_input_tokens"] == 2_300_000
    assert deep["budget_max_output_tokens"] == 200_000
    assert deep["budget_extension_early_stop"] is True


def test_custom_profile_preserves_legacy_defaults_and_override() -> None:
    legacy = resolve_hunter_budget_config({})
    custom = resolve_hunter_budget_config({
        "hunter_budget_profile": "custom",
        "budget_max_hunter_sessions": 24,
        "budget_max_input_tokens": 900_000,
    })

    assert legacy["budget_max_hunter_sessions"] == 100
    assert legacy["budget_soft_input_token_stop"] == 1_500_000
    assert custom["budget_max_hunter_sessions"] == 24
    assert custom["budget_soft_input_token_stop"] == 900_000
    assert custom["budget_extension_early_stop"] is False


def test_cli_selects_deep_profile_and_rejects_mixed_custom_override() -> None:
    args = build_parser().parse_args([
        "scan",
        ".",
        "--hunter-budget-profile",
        "deep-16",
    ])
    config = _load_hunter_budget_config(args)

    assert config["hunter_budget_profile"] == "deep-16"
    assert config["budget_max_hunter_sessions"] == 16
    assert config["budget_soft_input_token_stop"] == 2_300_000

    mixed = argparse.Namespace(
        hunter_budget_profile="deep-16",
        max_hunter_sessions=20,
    )
    with pytest.raises(ValueError, match="custom"):
        _load_hunter_budget_config(mixed)


def test_deep_soft_stop_allows_extension_beyond_standard_limit() -> None:
    policy = BudgetPolicy(
        max_hunter_sessions=16,
        max_input_tokens=2_300_000,
        max_output_tokens=200_000,
        max_wall_clock_minutes=90,
    )
    standard_stop = BudgetController(policy)
    with pytest.raises(BudgetExceededError, match="soft_input_token_stop"):
        standard_stop.reserve_call(
            input_upper_bound=1_600_000,
            requested_output_tokens=1,
        )

    deep_stop = BudgetController(
        policy,
        soft_input_token_stop=2_300_000,
    )
    reservation = deep_stop.reserve_call(
        input_upper_bound=1_600_000,
        requested_output_tokens=1,
    )
    assert reservation.input_tokens == 1_600_000
    assert deep_stop.snapshot()["soft_input_token_stop"] == 2_300_000


def test_deep_16_reserves_two_retries_and_admits_fourteen_new_work_items() -> None:
    work = build_shadow_plan(
        run_id="run-deep-16",
        source_snapshot=HASH_A,
        selected_files=[f"file-{index}.c" for index in range(20)],
        hunters=["c-bounds-integers"],
        analysis={},
    )
    allocation = allocate_work_items(
        work,
        BudgetPolicy(
            max_hunter_sessions=16,
            max_retries_per_work_item=1,
        ),
    )

    assert allocation.retry_slots == 2
    assert len(allocation.admitted_work_ids) == 14
    assert len(allocation.deferred) == 6


def test_deep_extension_stops_before_unused_retry_slots_without_high_risk() -> None:
    profile = DEEP_16.artifact()
    session_indices = {
        f"work-{index}": index
        for index in range(1, 15)
    }

    assert _should_stop_deep_extension(
        profile,
        session_indices=session_indices,
        high_risk_findings=[],
        has_deferred_work=True,
        retry_needed=False,
    ) is True
    assert _should_stop_deep_extension(
        profile,
        session_indices=session_indices,
        high_risk_findings=[{"title": "new OOB"}],
        has_deferred_work=True,
        retry_needed=False,
    ) is False
    assert _should_stop_deep_extension(
        profile,
        session_indices=session_indices,
        high_risk_findings=[],
        has_deferred_work=True,
        retry_needed=True,
    ) is False


def test_deep_extension_records_only_provider_started_post_12_yield() -> None:
    session_indices = {
        "work-a": 11,
        "work-b": 12,
        "work-c": 13,
        "work-d": 14,
    }
    metrics = _deep_extension_metrics(
        DEEP_16.artifact(),
        session_indices=session_indices,
        finding_count=2,
        high_risk_findings=[{"title": "new OOB", "session_index": 13}],
        early_stopped=False,
        started_work_ids={"work-a", "work-b", "work-c"},
    )

    assert metrics["standard_session_boundary"] == 12
    assert metrics["executed_session_indices"] == [13]
    assert metrics["executed_sessions"] == 1
    assert metrics["incremental_findings"] == 2
    assert metrics["incremental_high_risk_findings"] == 1
    assert metrics["full_extension_consumed"] is False

    standard_metrics = _deep_extension_metrics(
        STANDARD_12.artifact(),
        session_indices={"work-c": 13},
        finding_count=0,
        high_risk_findings=[],
        early_stopped=False,
        started_work_ids={"work-c"},
    )
    assert standard_metrics["enabled"] is False
    assert standard_metrics["executed_session_indices"] == []


def test_extension_high_risk_requires_high_severity_or_missing_severity_on_risk() -> None:
    item = build_shadow_plan(
        run_id="run-extension-risk",
        source_snapshot=HASH_A,
        selected_files=["parser.c"],
        hunters=["c-bounds-integers"],
        analysis={},
    )[0].model_copy(update={"risk": 5})
    findings = [
        {"title": "critical OOB", "severity": "critical", "entry_line": 7},
        {"title": "low issue", "severity": "low", "entry_line": 8},
        {"title": "unrated high-risk lead", "entry_line": 9},
    ]

    high_risk = _high_risk_extension_findings(
        findings,
        item=item,
        session_index=13,
    )

    assert [finding["title"] for finding in high_risk] == [
        "critical OOB",
        "unrated high-risk lead",
    ]
    assert all(finding["session_index"] == 13 for finding in high_risk)


def test_extension_duplicate_identity_ignores_title_for_same_sink() -> None:
    standard = {
        "title": "Buffer overflow in query builder",
        "type": "buffer_overflow",
        "entry_file": "src/query.c",
        "entry_line": 10,
        "sink_file": "src/query.c",
        "sink_line": 42,
    }
    extension = {
        **standard,
        "title": "Query construction writes beyond allocation",
        "severity": "critical",
    }

    assert _finding_identity(standard) == _finding_identity(extension)


async def test_ranked_waves_do_not_cross_the_standard_session_boundary() -> None:
    tasks = [
        type("Task", (), {"work_id": f"work-{index}"})()
        for index in range(1, 15)
    ]
    session_indices = {
        task.work_id: index
        for index, task in enumerate(tasks, start=1)
    }
    activated: list[tuple[str, ...]] = []

    class Controller:
        def activate_priority_window(self, work_ids: tuple[str, ...]) -> None:
            activated.append(work_ids)

    async def run_work(task) -> None:
        return None

    await _run_tasks_in_ranked_waves(
        tasks,
        max_parallel=5,
        budget_controller=Controller(),  # type: ignore[arg-type]
        run_work=run_work,
        session_indices=session_indices,
        standard_session_boundary=12,
    )

    assert [len(wave) for wave in activated] == [5, 5, 2, 2]
    assert activated[-2] == ("work-11", "work-12")
    assert activated[-1] == ("work-13", "work-14")
