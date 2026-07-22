from __future__ import annotations

from vulnhunt_agent.analysis import (
    MAX_CAPACITY_CALL_DEPTH,
    CapacityReturnKind,
    build_c_analysis_graph,
)


def _summary(graph, function: str):
    return next(item for item in graph.capacity_summaries if item.function == function)


def test_capacity_summary_propagates_writes_and_consumed_extent(tmp_path) -> None:
    repo = tmp_path / "summaries"
    repo.mkdir()
    (repo / "chain.c").write_text(
        "typedef struct { int value; } Entry;\n"
        "static int leaf(Entry *table, int count) {\n"
        "  table[count - 1].value = 1;\n"
        "  return count;\n"
        "}\n"
        "static int middle(Entry *output, int available) {\n"
        "  int used = leaf(output, available);\n"
        "  return used;\n"
        "}\n"
        "int outer(Entry *destination, int capacity) {\n"
        "  return middle(destination, capacity);\n"
        "}\n"
        "int *identity(int *p) { return p; }\n"
        "int *forward(int *out) { return identity(out); }\n"
    )

    graph = build_c_analysis_graph(repo, ["chain.c"])
    leaf = _summary(graph, "leaf")
    middle = _summary(graph, "middle")
    outer = _summary(graph, "outer")

    assert leaf.written_parameters == ("table",)
    assert leaf.return_kind is CapacityReturnKind.CONSUMED_OR_REQUIRED
    assert middle.written_parameters == ("output",)
    assert middle.return_kind is CapacityReturnKind.CONSUMED_OR_REQUIRED
    assert outer.written_parameters == ("destination",)
    assert outer.return_kind is CapacityReturnKind.CONSUMED_OR_REQUIRED
    assert outer.propagation_depth == 2
    calls = {call.callee: call for call in graph.capacity_calls}
    assert calls["leaf"].arguments == ("output", "available")
    assert calls["leaf"].result_subject == "used"
    assert calls["leaf"].target_node_id == leaf.node_id
    assert calls["middle"].arguments == ("destination", "capacity")
    forward = _summary(graph, "forward")
    assert forward.return_kind is CapacityReturnKind.PASS_THROUGH
    assert forward.pass_through_parameters == ("out",)


def test_capacity_summary_call_depth_is_hard_bounded(tmp_path) -> None:
    repo = tmp_path / "depth"
    repo.mkdir()
    wrappers = "\n".join(
        f"int wrap{index}(int *p, int n) {{ return "
        f"{('leaf' if index == 1 else f'wrap{index - 1}')}(p, n); }}"
        for index in range(1, 7)
    )
    (repo / "depth.c").write_text(
        "int leaf(int *p, int n) { p[n - 1] = 1; return n; }\n"
        f"{wrappers}\n"
    )

    graph = build_c_analysis_graph(repo, ["depth.c"])

    assert _summary(graph, f"wrap{MAX_CAPACITY_CALL_DEPTH}").written_parameters == ("p",)
    assert _summary(graph, f"wrap{MAX_CAPACITY_CALL_DEPTH}").propagation_depth == 5
    assert _summary(graph, "wrap6").written_parameters == ()
    assert _summary(graph, "wrap6").return_kind is CapacityReturnKind.UNKNOWN


def test_external_and_function_pointer_calls_stay_unknown(tmp_path) -> None:
    repo = tmp_path / "unknown"
    repo.mkdir()
    (repo / "unknown.c").write_text(
        "int external_fill(int *, int);\n"
        "int dispatch(int (*fill)(int *, int), int *p, int n) {\n"
        "  int first = external_fill(p, n);\n"
        "  int second = fill(p, n);\n"
        "  return first + second;\n"
        "}\n"
    )

    graph = build_c_analysis_graph(repo, ["unknown.c"])
    calls = {call.callee: call for call in graph.capacity_calls}
    summary = _summary(graph, "dispatch")

    assert calls["external_fill"].direct is True
    assert calls["external_fill"].target_node_id == ""
    assert calls["fill"].direct is False
    assert calls["fill"].target_node_id == ""
    assert summary.written_parameters == ()
    assert summary.return_kind is CapacityReturnKind.UNKNOWN
