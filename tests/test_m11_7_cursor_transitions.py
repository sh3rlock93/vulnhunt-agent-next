from __future__ import annotations

from pathlib import Path

from vulnhunt_agent.analysis import (
    build_c_analysis_graph,
    build_coverage_plan,
    context_for_work_item,
)
from vulnhunt_agent.domain.schemas import HunterWorkItem

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "cursor_parser"


def _graph(name: str):
    return build_c_analysis_graph(FIXTURES / name, ["parser.c"])


def test_vulnerable_cursor_transition_becomes_one_critical_read_target() -> None:
    graph = _graph("vulnerable")
    signals = [
        item for item in graph.signals if item.category == "cursor_index_read"
    ]

    assert len(signals) == 1
    assert signals[0].risk == 5
    assert signals[0].line == 14
    assert signals[0].signal_id in graph.critical_sink_ids
    assert "required_guard_index=1" in signals[0].detail
    assert "observed_guard_index=0" in signals[0].detail

    assert len(graph.cursor_transition_chains) == 1
    chain = graph.cursor_transition_chains[0]
    assert chain.guard_state.value == "partial"
    assert chain.required_access_index == 1
    assert chain.observed_guard_index == 0
    assert chain.call_line == 21
    assert chain.subject == "view->position"
    assert chain.bound == "view->length"
    assert chain.evidence_lines["parser.c"] == (14, 20, 21, 24)


def test_guarded_transition_is_retained_but_not_critical() -> None:
    graph = _graph("guarded")
    signals = [
        item
        for item in graph.signals
        if item.category.startswith("cursor_index_read")
    ]

    assert len(signals) == 1
    assert signals[0].category == "cursor_index_read_guarded"
    assert signals[0].risk == 2
    assert signals[0].signal_id not in graph.critical_sink_ids
    assert len(graph.cursor_transition_chains) == 1
    chain = graph.cursor_transition_chains[0]
    assert chain.guard_state.value == "dominates"
    assert chain.required_access_index == 1
    assert chain.observed_guard_index == 1


def test_rejecting_accessible_state_is_not_misclassified_as_a_safety_guard() -> None:
    graph = _graph("reversed_guard")
    signal = next(
        item for item in graph.signals if item.category == "cursor_index_read"
    )
    chain = graph.cursor_transition_chains[0]

    assert signal.risk == 5
    assert chain.guard_state.value == "absent"
    assert chain.observed_guard_index is None


def test_cursor_ids_are_deterministic_and_slice_reaches_caller() -> None:
    first = _graph("vulnerable")
    second = _graph("vulnerable")

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    signal = next(
        item for item in first.signals if item.category == "cursor_index_read"
    )
    coverage = build_coverage_plan(first)
    target = next(
        item for item in coverage.slices if item.sink_signal_id == signal.signal_id
    )
    symbols = {
        node.node_id: node.symbol for node in first.nodes
    }
    assert [symbols[node_id] for node_id in target.node_ids] == [
        "read_record",
        "read_label",
    ]

    work = HunterWorkItem(
        work_id="work_" + "1" * 64,
        run_id="cursor-fixture",
        source_snapshot="sha256:" + "2" * 64,
        planning_policy="fixture",
        slice_ids=(target.slice_id,),
        target_signal_ids=(signal.signal_id,),
        seed_file="parser.c",
        files=("parser.c",),
        hunter="c-bounds-integers",
        risk=5,
        required=True,
        routing_reasons=("fixture",),
    )
    packet = context_for_work_item({
        "language": "c",
        "graph": first.model_dump(mode="json"),
        "coverage_plan": coverage.model_dump(mode="json"),
    }, work)
    assert packet["cursor_transition_policy_version"] == (
        "c-cursor-transition-v1"
    )
    assert packet["cursor_transition_chains"][0]["chain_id"] == (
        first.cursor_transition_chains[0].chain_id
    )
    assert packet["cursor_transition_chains"][0]["evidence_lines"] == {
        "parser.c": [14, 20, 21, 24]
    }


def test_ordinary_array_read_does_not_create_cursor_target(tmp_path: Path) -> None:
    (tmp_path / "plain.c").write_text(
        "int read_value(const int *items, int index) { return items[index]; }\n",
        encoding="utf-8",
    )

    graph = build_c_analysis_graph(tmp_path, ["plain.c"])

    assert not graph.cursor_facts
    assert not graph.cursor_transition_chains
    assert not any(
        signal.category.startswith("cursor_index_read")
        for signal in graph.signals
    )
