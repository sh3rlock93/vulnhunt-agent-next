from __future__ import annotations

from tests.factories import HASH_A
from vulnhunt_agent.analysis import GuardState, RiskChain, RiskTransform, context_for_work_item
from vulnhunt_agent.analysis.context_cache import context_cache_key
from vulnhunt_agent.domain.schemas import BudgetPolicy, HunterWorkItem
from vulnhunt_agent.scheduling import (
    allocate_work_items,
    apply_admission_focus,
    work_id_for,
)


def _work() -> HunterWorkItem:
    work_id = work_id_for(
        source_snapshot=HASH_A,
        planning_policy="c-slice-work-v4",
        slice_ids=("slice-focus",),
        files=("decode.c",),
        hunter="c-bounds-integers",
        target_signal_ids=("alloc-focus",),
    )
    return HunterWorkItem(
        work_id=work_id,
        run_id="run-focus-chain",
        source_snapshot=HASH_A,
        planning_policy="c-slice-work-v4",
        slice_ids=("slice-focus",),
        target_signal_ids=("alloc-focus",),
        seed_file="decode.c",
        files=("decode.c",),
        hunter="c-bounds-integers",
        risk=5,
        required=True,
        routing_reasons=("focus chain fixture",),
    )


def _chain(chain_id: str, score: int) -> RiskChain:
    return RiskChain(
        chain_id=chain_id,
        node_id="decode.c::decode@1",
        path="decode.c",
        function="decode",
        source_variables=("count",),
        source_lines=(3,),
        transform_steps=(RiskTransform(
            line=4,
            target="size",
            expression="count * width",
            operations=("*",),
            operand_types=("size_t",),
        ),),
        guard_state=GuardState.ABSENT,
        allocation_signal_ids=("alloc-focus",),
        sink_signal_ids=(f"sink-{chain_id}",),
        sink_lines=(8,),
        score=score,
        confidence="high",
        rationale="focus propagation fixture",
    )


def test_admission_ranking_chains_reach_hunter_context_and_cache_identity() -> None:
    work = _work()
    chains = (
        _chain("risk_bbbbbbbbbbbbbbbbbbbb", 90),
        _chain("risk_aaaaaaaaaaaaaaaaaaaa", 80),
    )
    allocation = allocate_work_items(
        (work,),
        BudgetPolicy(max_hunter_sessions=1, max_retries_per_work_item=0),
        risk_chains=chains,
        native_full_scan=True,
    )

    focused = apply_admission_focus((work,), allocation)[0]
    analysis = {
        "language": "c",
        "graph": {
            "schema_version": 1,
            "nodes": [],
            "signals": [],
            "risk_chains": [chain.model_dump(mode="json") for chain in chains],
        },
        "coverage_plan": {"policy_version": "fixture", "slices": []},
    }

    assert focused.work_id == work.work_id
    assert focused.focus_chain_ids == allocation.ranking[0].chain_ids
    packet = context_for_work_item(analysis, focused)
    assert packet["focus_chain_ids"] == list(allocation.ranking[0].chain_ids)
    assert [chain["chain_id"] for chain in packet["risk_chains"]] == list(
        allocation.ranking[0].chain_ids
    )
    assert context_cache_key(
        source_snapshot=HASH_A,
        analysis=analysis,
        work_item=work,
    ) != context_cache_key(
        source_snapshot=HASH_A,
        analysis=analysis,
        work_item=focused,
    )


def test_legacy_admission_preserves_existing_focus() -> None:
    work = HunterWorkItem.model_validate({
        **_work().model_dump(mode="python"),
        "focus_chain_ids": ("risk_existing00000000000000",),
    })
    allocation = allocate_work_items(
        (work,),
        BudgetPolicy(max_hunter_sessions=1, max_retries_per_work_item=0),
    )

    assert apply_admission_focus((work,), allocation) == (work,)
