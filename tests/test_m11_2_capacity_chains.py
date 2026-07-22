from __future__ import annotations

from tests.factories import HASH_A
from vulnhunt_agent.analysis import (
    CapacityPriorityClass,
    GuardState,
    RiskChain,
    RiskTransform,
    build_c_analysis_graph,
    context_for_work_item,
)
from vulnhunt_agent.domain.schemas import BudgetPolicy, HunterWorkItem
from vulnhunt_agent.scheduling import allocate_work_items, work_id_for


def _fixture_graph(tmp_path, *, guarded: bool = True):
    repo = tmp_path / "capacity-chain"
    repo.mkdir()
    guard = "  if (used + 1 > capacity) return 0;\n" if guarded else ""
    (repo / "decode.c").write_text(
        "#include <stdlib.h>\n"
        "typedef struct { int value; } Entry;\n"
        "int fill(Entry *, int);\n"
        "int decode(int capacity, int used) {\n"
        "  Entry *base = malloc(capacity * sizeof(*base));\n"
        "  Entry *cursor = base;\n"
        + guard
        +
        "  int consumed = fill(cursor, capacity - used);\n"
        "  cursor += consumed;\n"
        "  return consumed;\n"
        "}\n"
    )
    (repo / "table.c").write_text(
        "typedef struct { int value; } Entry;\n"
        "static int store(Entry *table, int required) {\n"
        "  table[required - 1].value = 7;\n"
        "  return required;\n"
        "}\n"
        "int fill(Entry *output, int available) {\n"
        "  return store(output, available);\n"
        "}\n"
    )
    return repo, build_c_analysis_graph(repo, ["table.c", "decode.c"])


def _work(index: int, path: str, signal_id: str) -> HunterWorkItem:
    work_id = work_id_for(
        source_snapshot=HASH_A,
        planning_policy="c-slice-work-v4",
        slice_ids=(f"slice-{index}",),
        files=(path,),
        hunter="c-bounds-integers",
        target_signal_ids=(signal_id,),
    )
    return HunterWorkItem(
        work_id=work_id,
        run_id="run-capacity-chain",
        source_snapshot=HASH_A,
        planning_policy="c-slice-work-v4",
        slice_ids=(f"slice-{index}",),
        target_signal_ids=(signal_id,),
        seed_file=path,
        files=(path,),
        hunter="c-bounds-integers",
        risk=5,
        required=True,
        routing_reasons=("capacity chain fixture",),
    )


def test_cross_file_capacity_chain_is_complete_and_deterministic(tmp_path) -> None:
    repo, first = _fixture_graph(tmp_path)
    second = build_c_analysis_graph(repo, ["decode.c", "table.c"])
    chain = next(
        item for item in first.capacity_risk_chains if item.root_path == "decode.c"
    )

    assert first == second
    assert chain.policy_version == "c-capacity-risk-chain-v2"
    assert chain.priority_class is CapacityPriorityClass.PARTIAL
    assert chain.guard_state is GuardState.DOMINATES
    assert chain.score == 40
    assert chain.entrypoint_reachable is True
    assert chain.paths == ("decode.c", "table.c")
    assert len(chain.call_ids) == 2
    assert chain.return_consumption_call_ids
    assert chain.pointer_advance_fact_ids
    assert chain.write_fact_ids
    assert chain.allocation_signal_ids
    assert chain.write_signal_ids
    assert "source" in chain.missing_elements
    assert "write" not in chain.missing_elements
    assert set(chain.evidence_lines) == {"decode.c", "table.c"}


def test_capacity_priority_class_precedes_legacy_raw_score(tmp_path) -> None:
    _, graph = _fixture_graph(tmp_path, guarded=False)
    capacity_chain = next(
        item for item in graph.capacity_risk_chains if item.root_path == "decode.c"
    )
    capacity_work = _work(1, "decode.c", capacity_chain.allocation_signal_ids[0])
    legacy_work = _work(2, "legacy.c", "legacy-allocation")
    legacy_chain = RiskChain(
        chain_id="risk_" + "f" * 20,
        node_id="legacy.c::decode@1",
        path="legacy.c",
        function="decode",
        source_signal_ids=("legacy-source",),
        source_variables=("size",),
        source_lines=(1,),
        transform_steps=(RiskTransform(
            line=2,
            target="size",
            expression="size * width",
            operations=("*",),
            operand_types=("size_t",),
            narrowing_or_wrap=True,
        ),),
        guard_state=GuardState.ABSENT,
        allocation_signal_ids=("legacy-allocation",),
        sink_signal_ids=("legacy-write",),
        sink_lines=(3,),
        score=95,
        confidence="high",
        rationale="legacy score fixture",
    )

    allocation = allocate_work_items(
        (legacy_work, capacity_work),
        BudgetPolicy(max_hunter_sessions=1, max_retries_per_work_item=0),
        risk_chains=(legacy_chain,),
        capacity_chains=(capacity_chain,),
        native_full_scan=True,
    )

    assert allocation.policy_version == "c-budget-v4"
    assert allocation.admitted_work_ids == (capacity_work.work_id,)
    assert allocation.ranking[0].priority_class == (
        "complete_unchecked_capacity_path"
    )
    assert allocation.ranking[0].score_components["capacity_chain"] == 100
    assert allocation.ranking[1].score_components["risk_chain"] == 95


def test_capacity_chain_is_present_in_exact_work_context(tmp_path) -> None:
    _, graph = _fixture_graph(tmp_path)
    chain = next(item for item in graph.capacity_risk_chains if item.root_path == "decode.c")
    work = _work(1, "decode.c", chain.allocation_signal_ids[0])
    analysis = {
        "language": "c",
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": {"policy_version": "fixture", "slices": []},
    }

    packet = context_for_work_item(analysis, work)

    assert packet["capacity_risk_chain_policy_version"] == "c-capacity-risk-chain-v2"
    assert packet["capacity_risk_chains"][0]["chain_id"] == chain.chain_id
    assert packet["capacity_risk_chains"][0]["paths"] == ["decode.c", "table.c"]
