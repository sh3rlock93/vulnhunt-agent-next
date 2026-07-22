from __future__ import annotations

from pathlib import Path

from tests.factories import HASH_A
from vulnhunt_agent.agents.durable_queue import DurableHuntQueueStore
from vulnhunt_agent.analysis import GuardState, RiskChain, RiskTransform
from vulnhunt_agent.domain.schemas import (
    BudgetPolicy,
    BudgetUsage,
    HunterWorkItem,
    RunRecord,
)
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.scheduling import (
    BudgetAllocation,
    RecyclableAdmissionLedger,
    allocate_work_items,
    build_shadow_plan,
    work_id_for,
)


def _work(
    index: int,
    path: str,
    *,
    signal_id: str | None = None,
    required: bool = True,
    risk: int = 5,
) -> HunterWorkItem:
    signal = signal_id or f"sig-{index:03d}"
    slice_id = f"slice-{index:03d}"
    work_id = work_id_for(
        source_snapshot=HASH_A,
        planning_policy="c-slice-work-v4",
        slice_ids=(slice_id,),
        files=(path,),
        hunter="c-bounds-integers",
        target_signal_ids=(signal,),
    )
    return HunterWorkItem(
        work_id=work_id,
        run_id="run-fair",
        source_snapshot=HASH_A,
        planning_policy="c-slice-work-v4",
        slice_ids=(slice_id,),
        target_signal_ids=(signal,),
        seed_file=path,
        files=(path,),
        hunter="c-bounds-integers",
        risk=risk,
        required=required,
        routing_reasons=("fixture",),
    )


def _chain(item: HunterWorkItem, index: int) -> RiskChain:
    return RiskChain(
        chain_id="risk_" + f"{index:020x}",
        node_id=f"{item.seed_file}::parse@1",
        path=item.seed_file,
        function="parse",
        source_signal_ids=(f"source-{index}",),
        source_variables=("size",),
        source_lines=(2,),
        transform_steps=(RiskTransform(
            line=3,
            target="size",
            expression="size * unit",
            operations=("*",),
            operand_types=("size_t",),
            narrowing_or_wrap=True,
        ),),
        guard_state=GuardState.ABSENT,
        allocation_signal_ids=item.target_signal_ids,
        sink_lines=(4,),
        score=95,
        confidence="high",
        rationale="fixture critical chain",
    )


def test_twelve_session_dense_plan_admits_distinct_critical_seeds() -> None:
    dense = [_work(index, "expat/lib/xmlparse.c") for index in range(20)]
    diverse = [
        _work(100, "expat/lib/xmltok_impl.c"),
        _work(101, "expat/lib/xmltok.c"),
        _work(102, "expat/lib/xmlrole.c"),
    ]
    items = tuple((*dense, *diverse))
    chains = tuple(_chain(item, index + 1) for index, item in enumerate(dense))
    policy = BudgetPolicy(max_hunter_sessions=12, max_retries_per_work_item=1)

    first = allocate_work_items(
        items,
        policy,
        risk_chains=chains,
        native_full_scan=True,
    )
    second = allocate_work_items(
        tuple(reversed(items)),
        policy,
        risk_chains=tuple(reversed(chains)),
        native_full_scan=True,
    )

    admitted = {
        item.work_id: item for item in items
        if item.work_id in first.admitted_work_ids
    }
    seeds = {item.seed_file for item in admitted.values() if item.required}
    assert first == second
    assert first.policy_version == "c-budget-v6"
    assert len(first.admitted_work_ids) == 11
    assert first.retry_slots == 1
    assert first.chain_critical_slots == 6
    assert first.chain_revisit_slots == 4
    assert first.seed_diverse_slots == 3
    assert first.borrowed_slots > 0
    assert len(seeds) >= 3
    assert sum(item.seed_file.endswith("xmlparse.c") for item in admitted.values()) < 11
    assert all(item.seed_family and item.coverage_group for item in first.decisions)


def test_seed_capped_critical_work_is_revisited_after_diversity() -> None:
    dense = tuple(_work(index, "src/dense.c") for index in range(3))
    diverse = (
        _work(10, "src/other-a.c"),
        _work(11, "src/other-b.c"),
    )
    allocation = allocate_work_items(
        (*dense, *diverse),
        BudgetPolicy(max_hunter_sessions=5, max_retries_per_work_item=0),
        risk_chains=tuple(
            _chain(item, index + 1) for index, item in enumerate(dense)
        ),
        native_full_scan=True,
    )

    assert allocation.admitted_work_ids == tuple(
        decision.work_id for decision in allocation.decisions
    )
    assert [decision.quota for decision in allocation.decisions] == [
        "chain_critical",
        "chain_critical",
        "seed_diverse",
        "seed_diverse",
        "chain_critical_revisit",
    ]
    assert allocation.chain_critical_slots == 3
    assert allocation.chain_revisit_slots == 1
    assert allocation.decisions[-1].cap_exception is True
    assert allocation.deferred == {}


def test_unused_retry_and_class_quotas_are_borrowed_deterministically() -> None:
    items = tuple(_work(index, f"src/file-{index}.c", required=False, risk=2)
                  for index in range(15))
    policy = BudgetPolicy(max_hunter_sessions=12, max_retries_per_work_item=0)

    allocation = allocate_work_items(
        tuple(reversed(items)),
        policy,
        native_full_scan=True,
    )

    assert allocation.retry_slots == 0
    assert len(allocation.admitted_work_ids) == 12
    assert allocation.borrowed_slots == 12
    assert [item.rank for item in allocation.decisions] == list(range(1, 13))


def test_duplicate_coverage_groups_do_not_consume_borrowed_slots() -> None:
    duplicates = tuple(
        _work(index, f"src/duplicate-{index}.c", signal_id="sig-same", required=False, risk=2)
        for index in range(3)
    )
    unique = tuple(
        _work(index + 10, f"src/unique-{index}.c", required=False, risk=2)
        for index in range(3)
    )

    allocation = allocate_work_items(
        (*duplicates, *unique),
        BudgetPolicy(max_hunter_sessions=6, max_retries_per_work_item=0),
        native_full_scan=True,
    )

    admitted_groups = [item.coverage_group for item in allocation.decisions]
    assert len(admitted_groups) == len(set(admitted_groups)) == 4
    assert allocation.duplicate_coverage_deferred == 2
    assert list(allocation.deferred.values()).count("duplicate_coverage_group") == 2


def test_unstarted_release_recycles_but_started_usage_is_retained() -> None:
    first = "work_" + "a" * 64
    second = "work_" + "b" * 64
    allocation = BudgetAllocation(
        admitted_work_ids=(first,),
        deferred={second: "max_hunter_sessions"},
        critical_slots=1,
        high_risk_slots=0,
        retry_slots=0,
        general_slots=0,
    )
    ledger = RecyclableAdmissionLedger(allocation)

    assert ledger.finish(
        first,
        status="cancelled",
        reason="sandbox setup failed",
        recyclable=True,
    ) == second
    event = ledger.snapshot()["events"][-1]
    assert event["provider_started"] is False
    assert event["usage"] is None
    assert event["promoted_work_id"] == second

    usage = BudgetUsage(
        run_id="run-fair",
        work_id=second,
        scope="hunter",
        model_id="fixture",
        transport="fixture",
        sessions=1,
        calls=1,
        input_tokens=123,
        output_tokens=7,
        wall_time_ms=45,
    )
    ledger.mark_provider_started(second)
    assert ledger.finish(
        second,
        status="cancelled",
        reason="provider cancelled",
        recyclable=True,
        usage=usage,
    ) is None
    event = ledger.snapshot()["events"][-1]
    assert event["provider_started"] is True
    assert event["usage"]["input_tokens"] == 123
    assert event["usage"]["wall_time_ms"] == 45


def test_unused_retry_reservation_is_borrowed_after_clean_completion() -> None:
    first = "work_" + "c" * 64
    second = "work_" + "d" * 64
    allocation = BudgetAllocation(
        admitted_work_ids=(first,),
        deferred={second: "max_hunter_sessions"},
        critical_slots=1,
        high_risk_slots=0,
        retry_slots=1,
        general_slots=0,
    )
    ledger = RecyclableAdmissionLedger(allocation)

    ledger.mark_provider_started(first)
    ledger.finish(first, status="done")

    assert ledger.borrow_unused_retry() == second
    assert ledger.borrow_unused_retry() is None
    snapshot = ledger.snapshot()
    assert snapshot["retry_slots_remaining"] == 0
    assert snapshot["events"][-1]["event"] == "retry_borrowed"


def test_durable_budget_deferral_can_be_requeued_without_an_attempt(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    with SqliteRepository(database) as repository:
        repository.save_run(RunRecord(run_id="run-fair"))
    item = build_shadow_plan(
        run_id="run-fair",
        source_snapshot=HASH_A,
        selected_files=["state.c"],
        hunters=["c-bounds-integers"],
        analysis={},
    )[0]
    qstore = DurableHuntQueueStore(
        tmp_path / "hunters",
        database,
        "run-fair",
    )
    task = qstore.init_from_work_items((item,)).tasks[0]
    with SqliteRepository(database, read_only=True) as repository:
        initial_attempt = repository.list_tasks("run-fair")[0]["attempt"]

    qstore.defer(task, reason="max_hunter_sessions")
    assert qstore.load().tasks[0].status == "budget_deferred"
    qstore.requeue_budget_deferred(task)

    restored = qstore.load().tasks[0]
    assert restored.status == "pending"
    with SqliteRepository(database, read_only=True) as repository:
        row = repository.list_tasks("run-fair")[0]
    assert row["attempt"] == initial_attempt
    assert row["last_error"] is None
