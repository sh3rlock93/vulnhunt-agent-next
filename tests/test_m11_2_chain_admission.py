from __future__ import annotations

from tests.factories import HASH_A
from vulnhunt_agent.analysis import (
    CapacityPriorityClass,
    CapacityRiskChain,
    GuardState,
)
from vulnhunt_agent.domain.schemas import BudgetPolicy, HunterWorkItem
from vulnhunt_agent.scheduling import allocate_work_items, work_id_for


def _work(
    index: int,
    path: str,
    signal: str | tuple[str, ...],
    hunter: str,
) -> HunterWorkItem:
    signals = (signal,) if isinstance(signal, str) else signal
    work_id = work_id_for(
        source_snapshot=HASH_A,
        planning_policy="c-slice-work-v4",
        slice_ids=(f"slice-{index}",),
        files=(path,),
        hunter=hunter,
        target_signal_ids=signals,
    )
    return HunterWorkItem(
        work_id=work_id,
        run_id="run-chain-admission",
        source_snapshot=HASH_A,
        planning_policy="c-slice-work-v4",
        slice_ids=(f"slice-{index}",),
        target_signal_ids=signals,
        seed_file=path,
        files=(path,),
        hunter=hunter,
        risk=5,
        required=True,
        routing_reasons=("chain admission fixture",),
    )


def _chain(
    *,
    priority: CapacityPriorityClass = CapacityPriorityClass.COMPLETE_UNCHECKED,
    score: int = 70,
) -> CapacityRiskChain:
    return CapacityRiskChain(
        chain_id="capacity_risk_" + "a" * 20,
        root_cause_group="capacity_group_" + "b" * 20,
        allocation_fact_id="capacity_" + "c" * 20,
        root_node_id="decode.c::decode@1",
        root_path="decode.c",
        root_function="decode",
        base="base",
        element_count="capacity",
        element_size="sizeof(*base)",
        node_ids=("decode.c::decode@1", "table.c::store@1"),
        paths=("decode.c", "table.c"),
        fact_ids=("capacity_" + "c" * 20,),
        allocation_signal_ids=("allocation",),
        write_signal_ids=("write",),
        guard_state=(
            GuardState.ABSENT
            if priority is CapacityPriorityClass.COMPLETE_UNCHECKED
            else GuardState.UNKNOWN
        ),
        priority_class=priority,
        score=score,
        confidence="high",
        rationale="chain-level admission fixture",
    )


def test_one_capacity_root_is_one_bounds_first_admission_unit() -> None:
    chain = _chain()
    items = (
        _work(1, "decode.c", "allocation", "c-memory-lifetime"),
        _work(2, "decode.c", "allocation", "c-bounds-integers"),
        _work(3, "table.c", "write", "c-bounds-integers"),
    )

    first = allocate_work_items(
        items,
        BudgetPolicy(max_hunter_sessions=4, max_retries_per_work_item=0),
        capacity_chains=(chain,),
        native_full_scan=True,
    )
    second = allocate_work_items(
        tuple(reversed(items)),
        BudgetPolicy(max_hunter_sessions=4, max_retries_per_work_item=0),
        capacity_chains=(chain,),
        native_full_scan=True,
    )

    admitted = next(item for item in items if item.work_id in first.admitted_work_ids)
    assert first == second
    assert first.policy_version == "c-budget-v5"
    assert admitted.hunter == "c-bounds-integers"
    assert admitted.seed_file == "decode.c"
    assert first.chain_critical_slots == 1
    assert len(first.admitted_work_ids) == 1
    assert set(first.deferred.values()) == {"duplicate_capacity_chain"}
    assert all(
        record.disposition == "duplicate_deferred"
        for record in first.ranking
        if record.work_id not in first.admitted_work_ids
    )
    assert first.duplicate_coverage_deferred == 2
    assert len({record.logical_chain_group for record in first.ranking}) == 1
    assert first.ranking[0].logical_chain_group == chain.root_cause_group


def test_complete_priority_is_eligible_without_fixed_score_threshold() -> None:
    chain = _chain(
        priority=CapacityPriorityClass.COMPLETE_UNKNOWN_GUARD,
        score=70,
    )
    work = _work(1, "decode.c", "allocation", "c-bounds-integers")

    allocation = allocate_work_items(
        (work,),
        BudgetPolicy(max_hunter_sessions=1, max_retries_per_work_item=0),
        capacity_chains=(chain,),
        native_full_scan=True,
    )

    assert allocation.chain_critical_slots == 1
    assert allocation.decisions[0].quota == "chain_critical"
    assert allocation.decisions[0].score_components["capacity_chain"] == 70


def test_partial_capacity_path_is_not_critical_from_raw_score_alone() -> None:
    chain = _chain(priority=CapacityPriorityClass.PARTIAL, score=95)
    work = _work(1, "decode.c", "allocation", "c-bounds-integers")

    allocation = allocate_work_items(
        (work,),
        BudgetPolicy(max_hunter_sessions=1, max_retries_per_work_item=0),
        capacity_chains=(chain,),
        native_full_scan=True,
    )

    assert allocation.chain_critical_slots == 0
    assert allocation.decisions[0].quota == "seed_diverse"


def test_multi_chain_batch_is_admitted_when_any_group_is_uncovered() -> None:
    first_chain = _chain()
    second_chain = first_chain.model_copy(update={
        "chain_id": "capacity_risk_" + "d" * 20,
        "root_cause_group": "capacity_group_" + "e" * 20,
        "allocation_fact_id": "capacity_" + "f" * 20,
        "root_node_id": "other.c::decode@1",
        "root_path": "other.c",
        "base": "other_base",
        "fact_ids": ("capacity_" + "f" * 20,),
        "allocation_signal_ids": ("other-allocation",),
        "write_signal_ids": (),
    })
    first_work = _work(1, "a.c", "allocation", "c-bounds-integers")
    multi_work = _work(
        2,
        "b.c",
        ("allocation", "other-allocation"),
        "c-bounds-integers",
    )

    allocation = allocate_work_items(
        (first_work, multi_work),
        BudgetPolicy(max_hunter_sessions=2, max_retries_per_work_item=0),
        capacity_chains=(first_chain, second_chain),
        native_full_scan=True,
    )

    assert allocation.admitted_work_ids == (first_work.work_id, multi_work.work_id)
    multi_record = next(
        record for record in allocation.ranking if record.work_id == multi_work.work_id
    )
    assert set(multi_record.logical_chain_groups) == {
        first_chain.root_cause_group,
        second_chain.root_cause_group,
    }


def test_end_to_end_capacity_evidence_breaks_equal_class_and_score_ties() -> None:
    local_chain = _chain().model_copy(update={
        "paths": ("decode.c",),
        "node_ids": ("decode.c::decode@1",),
    })
    linked_chain = _chain().model_copy(update={
        "chain_id": "capacity_risk_" + "d" * 20,
        "root_cause_group": "capacity_group_" + "e" * 20,
        "allocation_fact_id": "capacity_" + "f" * 20,
        "allocation_signal_ids": ("linked-allocation",),
        "return_consumption_call_ids": ("capacity_call_" + "1" * 20,),
        "pointer_advance_fact_ids": ("capacity_" + "2" * 20,),
        "write_fact_ids": ("capacity_" + "3" * 20,),
    })
    local_work = _work(1, "decode.c", "allocation", "c-bounds-integers")
    linked_work = _work(
        2,
        "decode.c",
        "linked-allocation",
        "c-bounds-integers",
    )

    allocation = allocate_work_items(
        (local_work, linked_work),
        BudgetPolicy(max_hunter_sessions=2, max_retries_per_work_item=0),
        capacity_chains=(local_chain, linked_chain),
        native_full_scan=True,
    )

    assert allocation.ranking[0].work_id == linked_work.work_id
    assert allocation.ranking[0].score_components["capacity_evidence"] == 100
    assert allocation.ranking[1].score_components["capacity_evidence"] == 0
