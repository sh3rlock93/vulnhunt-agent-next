from __future__ import annotations

from pathlib import Path

from tests.factories import HASH_A
from vulnhunt_agent.analysis import (
    AnalysisSlice,
    CAnalysisGraph,
    CoveragePlan,
    GraphNode,
    NodeKind,
    SecuritySignal,
    SignalRole,
    build_c_analysis_graph,
    build_coverage_plan,
)
from vulnhunt_agent.scheduling import build_routing_plan

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "cursor_parser"
HUNTERS = [
    "c-bounds-integers",
    "c-memory-lifetime",
    "c-parser-state",
]


def _route_fixture(name: str):
    graph = build_c_analysis_graph(FIXTURES / name, ["parser.c"])
    coverage = build_coverage_plan(graph)
    routing = build_routing_plan(
        run_id=f"cursor-{name}",
        source_snapshot=HASH_A,
        selected_files=list(coverage.selected_files),
        enabled_hunters=HUNTERS,
        analysis={
            "language": "c",
            "graph": graph.model_dump(mode="json"),
            "coverage_plan": coverage.model_dump(mode="json"),
        },
    )
    return graph, routing


def test_handwritten_cursor_parser_routes_to_parser_state() -> None:
    graph, routing = _route_fixture("vulnerable")
    target = next(
        signal for signal in graph.signals if signal.category == "cursor_index_read"
    )
    matching = [
        item
        for item in routing.work_items
        if target.signal_id in item.target_signal_ids
    ]

    assert routing.policy_version == "c-signal-router-v4"
    assert [item.hunter for item in matching] == ["c-parser-state"]
    assert matching[0].required is True
    assert "required:cursor-transition" in matching[0].routing_reasons


def test_guarded_cursor_read_does_not_require_parser_specialist() -> None:
    _, routing = _route_fixture("guarded")

    assert not any(item.hunter == "c-parser-state" for item in routing.work_items)


def test_parser_specialist_is_added_only_to_batch_containing_cursor_target() -> None:
    node = GraphNode(
        node_id="mixed.c::decode@1",
        path="mixed.c",
        symbol="decode",
        line=1,
        end_line=100,
        kind=NodeKind.FUNCTION,
        visibility="external",
    )
    bounds = tuple(
        SecuritySignal(
            signal_id=f"sig-00{index}",
            node_id=node.node_id,
            path=node.path,
            line=index + 2,
            role=SignalRole.SINK,
            category="array_index_write",
            operation="subscript assignment",
            risk=5,
        )
        for index in range(6)
    )
    cursor = SecuritySignal(
        signal_id="sig-999",
        node_id=node.node_id,
        path=node.path,
        line=20,
        role=SignalRole.SINK,
        category="cursor_index_read",
        operation="cursor-backed subscript read",
        risk=5,
    )
    signals = (*bounds, cursor)
    slices = tuple(
        AnalysisSlice(
            slice_id=f"slice-{index}",
            entrypoint_id=node.node_id,
            sink_signal_id=signal.signal_id,
            node_ids=(node.node_id,),
            files=(node.path,),
            categories=(signal.category,),
            risk=5,
            rationale="mixed target fixture",
        )
        for index, signal in enumerate(signals)
    )
    graph = CAnalysisGraph(
        nodes=(node,),
        signals=signals,
        entrypoint_ids=(node.node_id,),
        critical_sink_ids=tuple(signal.signal_id for signal in signals),
    )
    coverage = CoveragePlan(
        slices=slices,
        selected_files=(node.path,),
        covered_entrypoint_ids=(node.node_id,),
        covered_sink_ids=graph.critical_sink_ids,
    )

    routing = build_routing_plan(
        run_id="mixed",
        source_snapshot=HASH_A,
        selected_files=[node.path],
        enabled_hunters=HUNTERS,
        analysis={
            "language": "c",
            "graph": graph.model_dump(mode="json"),
            "coverage_plan": coverage.model_dump(mode="json"),
        },
    )
    parser_work = [
        item for item in routing.work_items if item.hunter == "c-parser-state"
    ]

    assert len(parser_work) == 1
    assert parser_work[0].target_signal_ids == (cursor.signal_id,)
    assert len([
        item for item in routing.work_items if item.hunter == "c-bounds-integers"
    ]) == 2
