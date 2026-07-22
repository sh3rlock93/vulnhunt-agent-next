from __future__ import annotations

from vulnhunt_agent.analysis import CapacityPriorityClass, build_c_analysis_graph


def test_pointer_array_aliases_propagate_caller_capacity_to_leaf_write(
    tmp_path,
) -> None:
    repo = tmp_path / "pointer-array-alias"
    repo.mkdir()
    (repo / "decode.c").write_text(
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "typedef unsigned char Byte;\n"
        "static void leaf(Byte **rows, Byte *source, int span) {\n"
        "  Byte *cursor = rows[0];\n"
        "  rows[0] = cursor;\n"
        "  memcpy(rows[0], source, span);\n"
        "}\n"
        "static void wrapper(Byte *destination, Byte *source, int span) {\n"
        "  Byte *planes[1];\n"
        "  planes[0] = destination;\n"
        "  leaf(planes, source, span);\n"
        "}\n"
        "int decode(int capacity, Byte *source, int span) {\n"
        "  Byte *base = malloc(capacity);\n"
        "  wrapper(base, source, span);\n"
        "  return base != 0;\n"
        "}\n",
        encoding="utf-8",
    )

    graph = build_c_analysis_graph(repo, ["decode.c"])
    summaries = {item.function: item for item in graph.capacity_summaries}
    chain = next(
        item for item in graph.capacity_risk_chains
        if item.root_function == "decode" and item.base == "base"
    )

    assert summaries["leaf"].pointer_aliases == {"cursor": "rows"}
    assert summaries["leaf"].written_parameters == ("rows",)
    assert summaries["wrapper"].pointer_aliases == {"planes": "destination"}
    assert summaries["wrapper"].written_parameters == ("destination",)
    assert len(chain.call_ids) == 2
    assert chain.write_fact_ids
    assert chain.priority_class is CapacityPriorityClass.COMPLETE_UNCHECKED
    assert chain.score == 100


def test_named_sizing_helper_lowers_only_the_derived_write_chain(tmp_path) -> None:
    repo = tmp_path / "write-derivation"
    repo.mkdir()
    (repo / "decode.c").write_text(
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "typedef unsigned char Byte;\n"
        "static int plane_width(int width) { return width; }\n"
        "static void helper_copy(Byte *dst, Byte *src, int width) {\n"
        "  int spans[1];\n"
        "  spans[0] = plane_width(width);\n"
        "  memcpy(dst, src, spans[0]);\n"
        "}\n"
        "static void raw_copy(Byte *dst, Byte *src, int width) {\n"
        "  int spans[1];\n"
        "  spans[0] = (width + 7) / 8;\n"
        "  memcpy(dst, src, spans[0]);\n"
        "}\n"
        "int decode_helper(int capacity, Byte *src, int width) {\n"
        "  Byte *base = malloc(capacity);\n"
        "  helper_copy(base, src, width);\n"
        "  return base != 0;\n"
        "}\n"
        "int decode_raw(int capacity, Byte *src, int width) {\n"
        "  Byte *base = malloc(capacity);\n"
        "  raw_copy(base, src, width);\n"
        "  return base != 0;\n"
        "}\n",
        encoding="utf-8",
    )

    graph = build_c_analysis_graph(repo, ["decode.c"])
    chains = {item.root_function: item for item in graph.capacity_risk_chains}

    assert chains["decode_helper"].priority_class is (
        CapacityPriorityClass.COMPLETE_UNKNOWN_GUARD
    )
    assert chains["decode_helper"].score == 80
    assert "bounded_write_derivation=True" in chains["decode_helper"].rationale
    assert chains["decode_raw"].priority_class is (
        CapacityPriorityClass.COMPLETE_UNCHECKED
    )
    assert chains["decode_raw"].score == 100
    assert "bounded_write_derivation=False" in chains["decode_raw"].rationale
