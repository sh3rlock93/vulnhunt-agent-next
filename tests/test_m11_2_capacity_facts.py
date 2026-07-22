from __future__ import annotations

from vulnhunt_agent.analysis import (
    MAX_ALIAS_HOPS,
    MAX_CAPACITY_TRANSFORMS,
    CapacityFactKind,
    build_c_analysis_graph,
)


def test_capacity_facts_link_allocation_alias_advance_write_and_guard(tmp_path) -> None:
    repo = tmp_path / "capacity"
    repo.mkdir()
    (repo / "decode.c").write_text(
        "#include <stddef.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "typedef struct { int value; } Entry;\n"
        "void decode(size_t count, size_t used, size_t required, Entry value) {\n"
        "  Entry *base = malloc(count * sizeof(*base));\n"
        "  Entry *unused = NULL;\n"
        "  Entry *cursor = base + used;\n"
        "  if (used + required <= count) {\n"
        "    cursor[required - 1] = value;\n"
        "    memcpy(cursor, base, required * sizeof(*cursor));\n"
        "  }\n"
        "  cursor += required;\n"
        "}\n"
    )

    first = build_c_analysis_graph(repo, ["decode.c"])
    second = build_c_analysis_graph(repo, ["decode.c"])
    facts = first.capacity_facts

    assert first == second
    assert all(fact.base != "NULL" for fact in facts)
    assert {fact.kind for fact in facts} >= {
        CapacityFactKind.ALLOCATION,
        CapacityFactKind.ALIAS,
        CapacityFactKind.ADVANCE,
        CapacityFactKind.WRITE,
    }
    allocation = next(fact for fact in facts if fact.kind is CapacityFactKind.ALLOCATION)
    assert allocation.subject == allocation.base == "base"
    assert allocation.element_count == "count"
    assert allocation.element_size == "sizeof(*base)"
    assert allocation.remaining_capacity == "count"
    alias = next(
        fact for fact in facts
        if fact.kind is CapacityFactKind.ALIAS and fact.subject == "cursor"
    )
    assert alias.base == "base"
    assert alias.offset == "used"
    assert alias.remaining_capacity == "(count) - (used)"
    advance = next(fact for fact in facts if fact.kind is CapacityFactKind.ADVANCE)
    assert advance.offset == "(used) + (required)"
    writes = [fact for fact in facts if fact.kind is CapacityFactKind.WRITE]
    assert {fact.write_extent for fact in writes} == {
        "(required - 1) + (1)",
        "required * sizeof(*cursor)",
    }
    guard = next(fact for fact in facts if fact.kind is CapacityFactKind.GUARD)
    assert guard.relation == "used + required <= count"


def test_safe_allocator_wrapper_keeps_count_and_element_size(tmp_path) -> None:
    repo = tmp_path / "wrapper"
    repo.mkdir()
    (repo / "table.c").write_text(
        "typedef struct { int bits; } Code;\n"
        "void *ProjectSafeMalloc(unsigned long, unsigned long);\n"
        "Code *make(unsigned long groups, unsigned long width) {\n"
        "  Code *tables = (Code*)ProjectSafeMalloc(groups * width, sizeof(*tables));\n"
        "  return tables;\n"
        "}\n"
    )

    allocation = next(
        fact for fact in build_c_analysis_graph(repo, ["table.c"]).capacity_facts
        if fact.kind is CapacityFactKind.ALLOCATION
    )
    assert allocation.subject == "tables"
    assert allocation.element_count == "groups * width"
    assert allocation.element_size == "sizeof(*tables)"


def test_capacity_traversal_is_bounded_and_deterministic(tmp_path) -> None:
    repo = tmp_path / "bounded"
    repo.mkdir()
    aliases = "\n".join(
        f"  int *p{index} = p{index - 1};" for index in range(1, 11)
    )
    writes = "\n".join(f"  p8[{index}] = {index};" for index in range(15))
    (repo / "bounded.c").write_text(
        "#include <stdlib.h>\n"
        "void fill(unsigned count) {\n"
        "  int *p0 = malloc(count * sizeof(*p0));\n"
        f"{aliases}\n"
        f"{writes}\n"
        "}\n"
    )

    graph = build_c_analysis_graph(repo, ["bounded.c"])
    alias_facts = [fact for fact in graph.capacity_facts if fact.kind is CapacityFactKind.ALIAS]
    write_facts = [fact for fact in graph.capacity_facts if fact.kind is CapacityFactKind.WRITE]

    assert max(fact.alias_depth for fact in alias_facts) == MAX_ALIAS_HOPS
    assert {fact.subject for fact in alias_facts} == {f"p{index}" for index in range(1, 9)}
    assert len(write_facts) == MAX_CAPACITY_TRANSFORMS
    assert max(fact.transform_depth for fact in write_facts) == MAX_CAPACITY_TRANSFORMS
