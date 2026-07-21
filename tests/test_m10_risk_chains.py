from __future__ import annotations

from vulnhunt_agent.analysis import build_c_analysis_graph


def _size_chain_source(*, guarded: bool) -> str:
    guard = (
        "    if (!bands || span > UINT_MAX / bands / unit) {\n"
        "        return 1;\n"
        "    }\n"
        if guarded else ""
    )
    return (
        "#include <stdint.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "#include <limits.h>\n"
        "void *project_malloc(unsigned long);\n"
        "int main(int argc, char **argv) {\n"
        "    uint32_t span = 0, bands = 1, unit = 4, total;\n"
        "    uint32_t index;\n"
        "    unsigned char *output;\n"
        "    unsigned char input[4] = {0};\n"
        "    span = atoi(argv[1]);\n"
        "    bands = atoi(argv[2]);\n"
        + guard
        + "    total = span * bands * unit;\n"
        "    output = (unsigned char *)project_malloc(total);\n"
        "    for (index = 0; index < span; index++) {\n"
        "        memcpy(output + (index * bands) * unit, input, unit);\n"
        "    }\n"
        "    return output == 0 || argc == 0;\n"
        "}\n"
    )


def _target_chain(graph):
    return max(graph.risk_chains, key=lambda item: item.score)


def test_ssa_lite_chain_links_input_arithmetic_allocation_and_copy(tmp_path) -> None:
    repo = tmp_path / "risk-chain"
    repo.mkdir()
    (repo / "convert.c").write_text(_size_chain_source(guarded=False))

    first = build_c_analysis_graph(repo, ["convert.c"])
    second = build_c_analysis_graph(repo, ["convert.c"])
    chain = _target_chain(first)

    assert first == second
    assert first.schema_version == 2
    assert chain.policy_version == "c-risk-chain-v1"
    assert chain.path == "convert.c"
    assert chain.function == "main"
    assert chain.guard_state.value == "absent"
    assert chain.score >= 90
    assert chain.confidence == "high"
    assert len(chain.source_signal_ids) == 2
    assert len(chain.source_lines) >= 2
    assert chain.allocation_signal_ids
    assert chain.sink_signal_ids
    assert {step.target for step in chain.transform_steps} >= {"total"}
    assert any(step.narrowing_or_wrap for step in chain.transform_steps)
    assert {"span", "bands", "total", "output"}.issubset(
        chain.source_variables
    )


def test_dominating_overflow_guard_lowers_chain_priority(tmp_path) -> None:
    repo = tmp_path / "guarded-chain"
    repo.mkdir()
    (repo / "convert.c").write_text(_size_chain_source(guarded=True))

    graph = build_c_analysis_graph(repo, ["convert.c"])
    chain = _target_chain(graph)

    assert chain.guard_state.value == "dominates"
    assert chain.guard_lines
    assert chain.score <= 45
    assert chain.score < 80
    assert chain.allocation_signal_ids
    assert chain.sink_signal_ids


def test_parameter_derived_size_is_tracked_without_a_source_call(tmp_path) -> None:
    repo = tmp_path / "parameter-chain"
    repo.mkdir()
    (repo / "allocate.c").write_text(
        "#include <stdint.h>\n"
        "void *project_malloc(unsigned long);\n"
        "void *allocate(uint32_t count, uint32_t width) {\n"
        "    uint32_t bytes = count * width;\n"
        "    return project_malloc(bytes);\n"
        "}\n"
    )

    graph = build_c_analysis_graph(repo, ["allocate.c"])
    chain = _target_chain(graph)

    assert chain.source_signal_ids == ()
    assert {"count", "width", "bytes"}.issubset(chain.source_variables)
    assert chain.transform_steps[0].target == "bytes"
    assert chain.allocation_signal_ids
