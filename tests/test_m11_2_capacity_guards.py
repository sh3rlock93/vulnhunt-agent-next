from __future__ import annotations

from vulnhunt_agent.analysis import (
    CapacityPriorityClass,
    GuardState,
    build_c_analysis_graph,
)


def _chain(graph):
    return next(item for item in graph.capacity_risk_chains if item.root_function == "decode")


def test_unknown_capacity_comparison_is_not_treated_as_safe(tmp_path) -> None:
    repo = tmp_path / "unknown-guard"
    repo.mkdir()
    (repo / "unknown.c").write_text(
        "#include <stdlib.h>\n"
        "void observe(int);\n"
        "int store(int *p, int required) { p[required - 1] = 1; return required; }\n"
        "int decode(int capacity, int required) {\n"
        "  int *base = malloc(capacity * sizeof(*base));\n"
        "  int *cursor = base;\n"
        "  if (required <= capacity) observe(required);\n"
        "  int consumed = store(cursor, required);\n"
        "  cursor += consumed;\n"
        "  return consumed;\n"
        "}\n"
    )

    chain = _chain(build_c_analysis_graph(repo, ["unknown.c"]))

    assert chain.guard_state is GuardState.UNKNOWN
    assert chain.priority_class is CapacityPriorityClass.COMPLETE_UNKNOWN_GUARD
    assert chain.score == 90
    assert chain.guard_fact_ids


def test_checked_growth_terminates_the_critical_capacity_path(tmp_path) -> None:
    repo = tmp_path / "safe-growth"
    repo.mkdir()
    (repo / "growth.c").write_text(
        "#include <stdlib.h>\n"
        "int store(int *p, int required) { p[required - 1] = 1; return required; }\n"
        "int decode(int capacity, int used, int required) {\n"
        "  int *base = malloc(capacity * sizeof(*base));\n"
        "  int *cursor = base + used;\n"
        "  if (required > capacity - used) {\n"
        "    int *grown = realloc(base, (capacity + required) * sizeof(*base));\n"
        "    if (grown == NULL) return 0;\n"
        "    base = grown;\n"
        "    cursor = base + used;\n"
        "  }\n"
        "  int consumed = store(cursor, required);\n"
        "  cursor += consumed;\n"
        "  return consumed;\n"
        "}\n"
    )

    graph = build_c_analysis_graph(repo, ["growth.c"])
    chain = _chain(graph)

    assert chain.guard_state is GuardState.DOMINATES
    assert chain.priority_class is CapacityPriorityClass.PARTIAL
    assert chain.score == 40
    assert chain.safe_growth_fact_ids
    growth = {
        fact.fact_id: fact for fact in graph.capacity_facts
        if fact.kind.value == "growth"
    }
    assert set(chain.safe_growth_fact_ids) <= set(growth)


def test_irrelevant_limits_do_not_mask_unchecked_capacity_path(tmp_path) -> None:
    repo = tmp_path / "irrelevant"
    repo.mkdir()
    (repo / "irrelevant.c").write_text(
        "#include <stdlib.h>\n"
        "int store(int *p, int required) { p[required - 1] = 1; return required; }\n"
        "int decode(int capacity, int required, int metadata_limit) {\n"
        "  int *base = malloc(capacity * sizeof(*base));\n"
        "  if (metadata_limit > 100) return 0;\n"
        "  int consumed = store(base, required);\n"
        "  base += consumed;\n"
        "  return consumed;\n"
        "}\n"
    )

    chain = _chain(build_c_analysis_graph(repo, ["irrelevant.c"]))

    assert chain.guard_state is GuardState.ABSENT
    assert chain.priority_class is CapacityPriorityClass.COMPLETE_UNCHECKED
    assert chain.guard_fact_ids == ()


def test_rejecting_overflow_builtin_is_a_dominating_capacity_guard(tmp_path) -> None:
    repo = tmp_path / "overflow-guard"
    repo.mkdir()
    (repo / "overflow.c").write_text(
        "#include <stdlib.h>\n"
        "int store(int *p, int required) { p[required - 1] = 1; return required; }\n"
        "int decode(int capacity, int used, int required) {\n"
        "  int *base = malloc(capacity * sizeof(*base));\n"
        "  int needed;\n"
        "  if (__builtin_add_overflow(used, required, &needed) || needed > capacity) "
        "return 0;\n"
        "  int consumed = store(base + used, required);\n"
        "  base += consumed;\n"
        "  return consumed;\n"
        "}\n"
    )

    chain = _chain(build_c_analysis_graph(repo, ["overflow.c"]))

    assert chain.guard_state is GuardState.DOMINATES
    assert chain.priority_class is CapacityPriorityClass.PARTIAL
    assert chain.score == 40
