from __future__ import annotations

from tests.factories import HASH_A
from vulnhunt_agent.analysis import GuardState, RiskChain, RiskTransform
from vulnhunt_agent.domain.schemas import BudgetPolicy, HunterWorkItem
from vulnhunt_agent.scheduling import allocate_work_items, work_id_for


def _work(index: int, path: str, *, target: str, required: bool = True) -> HunterWorkItem:
    work_id = work_id_for(
        source_snapshot=HASH_A,
        planning_policy="c-slice-work-v4",
        slice_ids=(f"slice-{index}",),
        files=(path,),
        hunter="c-bounds-integers",
        target_signal_ids=(target,),
    )
    return HunterWorkItem(
        work_id=work_id,
        run_id="run-m11-2-ranking",
        source_snapshot=HASH_A,
        planning_policy="c-slice-work-v4",
        slice_ids=(f"slice-{index}",),
        target_signal_ids=(target,),
        seed_file=path,
        files=(path,),
        hunter="c-bounds-integers",
        risk=5,
        required=required,
        routing_reasons=("fixture",),
    )


def _chain(target: str, *, sink: bool, guard: GuardState) -> RiskChain:
    return RiskChain(
        chain_id="risk_" + target.rsplit("-", 1)[-1].zfill(20),
        node_id=f"src/{target}.c::decode@1",
        path=f"src/{target}.c",
        function="decode",
        source_signal_ids=(f"source-{target}",),
        source_variables=("count",),
        source_lines=(2,),
        transform_steps=(RiskTransform(
            line=3,
            target="size",
            expression="count * width",
            operations=("*",),
            operand_types=("size_t",),
        ),),
        guard_state=guard,
        guard_lines=((4,) if guard is not GuardState.ABSENT else ()),
        allocation_signal_ids=(target,),
        sink_signal_ids=((f"sink-{target}",) if sink else ()),
        sink_lines=(5,),
        score=90 if sink else 60,
        confidence="high" if sink else "medium",
        rationale="ranking observability fixture",
    )


def test_complete_pre_admission_ranking_is_deterministic_and_auditable() -> None:
    items = (
        _work(1, "src/critical.c", target="target-1"),
        _work(2, "src/partial.c", target="target-2"),
        _work(3, "src/no-chain.c", target="target-3", required=False),
    )
    chains = (
        _chain("target-1", sink=True, guard=GuardState.ABSENT),
        _chain("target-2", sink=False, guard=GuardState.UNKNOWN),
    )
    policy = BudgetPolicy(max_hunter_sessions=2, max_retries_per_work_item=0)

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

    assert first == second
    assert len(first.ranking) == len(items)
    assert [record.pre_admission_rank for record in first.ranking] == [1, 2, 3]
    assert len({record.record_id for record in first.ranking}) == len(items)
    assert all(record.record_id.startswith("ranking_") for record in first.ranking)
    assert first.ranking[0].chain_ids == (chains[0].chain_id,)
    assert first.ranking[0].guard_states == ("absent",)
    assert first.ranking[0].missing_chain_elements == ()
    assert first.ranking[1].missing_chain_elements == ("write_sink",)
    assert first.ranking[2].missing_chain_elements == ("risk_chain",)
    assert {record.disposition for record in first.ranking} == {
        "admitted", "budget_deferred"
    }
    assert first.ranking[-1].reason == "max_hunter_sessions"


def test_observability_does_not_change_native_admission_order() -> None:
    items = tuple(
        _work(index, f"src/file-{index}.c", target=f"target-{index}")
        for index in range(1, 5)
    )
    chains = tuple(
        _chain(f"target-{index}", sink=True, guard=GuardState.ABSENT)
        for index in range(1, 5)
    )
    allocation = allocate_work_items(
        items,
        BudgetPolicy(max_hunter_sessions=3, max_retries_per_work_item=0),
        risk_chains=chains,
        native_full_scan=True,
    )

    assert allocation.admitted_work_ids == tuple(
        decision.work_id for decision in allocation.decisions
    )
    assert [record.work_id for record in allocation.ranking] == [
        item.work_id
        for item in sorted(
            items,
            key=lambda item: (item.seed_file, item.work_id),
        )
    ]
    assert allocation.chain_critical_slots == 2
    assert allocation.seed_diverse_slots == 1
    assert allocation.borrowed_slots == 0
