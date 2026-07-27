from __future__ import annotations

from tests.factories import HASH_A
from vulnhunt_agent.analysis import (
    CapacityPriorityClass,
    CapacityRiskChain,
    GuardState,
)
from vulnhunt_agent.domain.schemas import BudgetPolicy, HunterWorkItem
from vulnhunt_agent.scheduling import (
    allocate_work_items,
    apply_admission_focus,
    build_work_input_budget,
    work_id_for,
)


def _work(
    index: int,
    path: str,
    signal: str | tuple[str, ...],
    hunter: str,
    *,
    routing_reasons: tuple[str, ...] = ("chain admission fixture",),
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
        routing_reasons=routing_reasons,
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


def test_one_capacity_root_preserves_distinct_hunter_specialists() -> None:
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

    admitted = [item for item in items if item.work_id in first.admitted_work_ids]
    assert first == second
    assert first.policy_version == "c-budget-v10"
    assert {item.hunter for item in admitted} == {
        "c-bounds-integers",
        "c-memory-lifetime",
    }
    representative = next(
        item for item in admitted if item.hunter == "c-bounds-integers"
    )
    assert representative.seed_file == "decode.c"
    assert first.chain_critical_slots == 1
    assert first.required_specialist_slots == 1
    assert len(first.admitted_work_ids) == 2
    assert set(first.deferred.values()) == {"duplicate_capacity_chain"}
    assert all(
        record.disposition == "budget_deferred"
        for record in first.ranking
        if record.work_id not in first.admitted_work_ids
    )
    assert first.duplicate_coverage_deferred == 1
    assert len({record.logical_chain_group for record in first.ranking}) == 1
    assert first.ranking[0].logical_chain_group == chain.root_cause_group
    assert len(first.capacity_units) == 1
    unit = first.capacity_units[0]
    assert unit.policy_version == "capacity-admission-unit-v1"
    assert unit.root_cause_group == chain.root_cause_group
    assert unit.representative_chain_id == chain.chain_id
    assert unit.representative_work_id == representative.work_id
    assert unit.chain_ids == (chain.chain_id,)
    assert unit.work_ids == tuple(sorted(item.work_id for item in items))
    assert unit.required_paths == chain.paths
    assert all(record.capacity_unit_ids == (unit.unit_id,) for record in first.ranking)
    assert all(
        record.chain_ids == ()
        for record in first.ranking
        if record.work_id != unit.representative_work_id
    )


def test_distinct_capacity_specialist_is_budget_deferred_not_deduplicated() -> None:
    chain = _chain()
    bounds = _work(1, "decode.c", "allocation", "c-bounds-integers")
    lifetime = _work(2, "decode.c", "allocation", "c-memory-lifetime")

    allocation = allocate_work_items(
        (lifetime, bounds),
        BudgetPolicy(max_hunter_sessions=1, max_retries_per_work_item=0),
        capacity_chains=(chain,),
        native_full_scan=True,
    )

    assert allocation.admitted_work_ids == (bounds.work_id,)
    assert allocation.deferred == {lifetime.work_id: "max_hunter_sessions"}
    lifetime_record = next(
        record for record in allocation.ranking
        if record.work_id == lifetime.work_id
    )
    assert lifetime_record.disposition == "budget_deferred"


def test_required_specialist_displaces_lower_priority_work_when_saturated() -> None:
    chain = _chain()
    bounds = _work(1, "decode.c", "allocation", "c-bounds-integers")
    parser = _work(2, "decode.c", "allocation", "c-parser-state")
    unrelated = _work(3, "other.c", "other-signal", "c-bounds-integers")

    allocation = allocate_work_items(
        (unrelated, parser, bounds),
        BudgetPolicy(max_hunter_sessions=2, max_retries_per_work_item=0),
        capacity_chains=(chain,),
        native_full_scan=True,
    )

    assert allocation.admitted_work_ids == (bounds.work_id, parser.work_id)
    assert allocation.required_specialist_slots == 1
    assert allocation.decisions[1].quota == "required_specialist"
    assert allocation.deferred == {unrelated.work_id: "max_hunter_sessions"}
    assert len(allocation.admitted_work_ids) == 2

    input_budget = build_work_input_budget(
        (bounds, parser, unrelated),
        allocation,
        BudgetPolicy(
            max_hunter_sessions=2,
            max_retries_per_work_item=0,
            max_input_tokens=200_000,
        ),
    )
    assert input_budget.critical_work_ids == (bounds.work_id, parser.work_id)


def test_explicit_cursor_specialist_uses_existing_specialist_reservation() -> None:
    chain = _chain()
    bounds = _work(1, "decode.c", "allocation", "c-bounds-integers")
    capacity_specialist = _work(
        2,
        "decode.c",
        "allocation",
        "c-memory-lifetime",
    )
    cursor_specialist = _work(
        3,
        "parser.c",
        "cursor-read",
        "c-parser-state",
        routing_reasons=(
            "required:cursor-transition",
            "signal:cursor_index_read",
        ),
    )

    allocation = allocate_work_items(
        (capacity_specialist, cursor_specialist, bounds),
        BudgetPolicy(max_hunter_sessions=2, max_retries_per_work_item=0),
        capacity_chains=(chain,),
        native_full_scan=True,
    )

    assert allocation.policy_version == "c-budget-v10"
    assert allocation.admitted_work_ids == (
        bounds.work_id,
        cursor_specialist.work_id,
    )
    assert allocation.required_specialist_slots == 1
    assert allocation.decisions[1].quota == "required_specialist"
    assert allocation.decisions[1].reason == (
        "required cursor-transition Hunter retained"
    )
    assert allocation.deferred == {
        capacity_specialist.work_id: "max_hunter_sessions"
    }


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


def test_capacity_representative_focuses_one_root_cause_obligation() -> None:
    chain = _chain()
    work = _work(
        1,
        "decode.c",
        ("unrelated", "allocation"),
        "c-bounds-integers",
    )
    allocation = allocate_work_items(
        (work,),
        BudgetPolicy(max_hunter_sessions=1, max_retries_per_work_item=0),
        capacity_chains=(chain,),
        native_full_scan=True,
    )

    focused = apply_admission_focus(
        (work,),
        allocation,
        capacity_chains=(chain,),
    )[0]

    assert focused.work_id == work.work_id
    assert focused.focus_chain_ids == (chain.chain_id,)
    assert focused.target_signal_ids == ("allocation",)


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
    assert len(allocation.capacity_units) == 2
    units = {unit.root_cause_group: unit for unit in allocation.capacity_units}
    assert units[first_chain.root_cause_group].representative_work_id == (
        first_work.work_id
    )
    assert units[second_chain.root_cause_group].representative_work_id == (
        multi_work.work_id
    )
    assert set(multi_record.capacity_unit_ids) == {
        units[first_chain.root_cause_group].unit_id,
        units[second_chain.root_cause_group].unit_id,
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
