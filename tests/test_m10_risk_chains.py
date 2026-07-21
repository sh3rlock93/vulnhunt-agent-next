from __future__ import annotations

from tests.factories import HASH_A
from vulnhunt_agent.analysis import (
    GuardState,
    RiskChain,
    RiskTransform,
    build_c_analysis_graph,
)
from vulnhunt_agent.domain.schemas import BudgetPolicy, HunterWorkItem
from vulnhunt_agent.scheduling import allocate_work_items, work_id_for


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


def test_full_native_admission_prioritizes_chain_and_component_diversity() -> None:
    paths = ["tools/dense.c"] * 20 + [
        "libtiff/codec.c",
        "archive/decoder.c",
        "contrib/import.c",
        "port/compat.c",
        "test/fuzzer.c",
        "root.c",
        "libtiff/image.c",
        "archive/reader.c",
        "contrib/parser.c",
        "port/io.c",
    ]
    items = []
    for index, path in enumerate(paths):
        signal_id = f"sig-work-{index:03d}"
        work_id = work_id_for(
            source_snapshot=HASH_A,
            planning_policy="c-slice-work-v4",
            slice_ids=(),
            files=(path,),
            hunter="c-bounds-integers",
            target_signal_ids=(signal_id,),
        )
        items.append(HunterWorkItem(
            work_id=work_id,
            run_id="run-diverse",
            source_snapshot=HASH_A,
            planning_policy="c-slice-work-v4",
            target_signal_ids=(signal_id,),
            seed_file=path,
            files=(path,),
            hunter="c-bounds-integers",
            risk=5,
            required=True,
            routing_reasons=("test",),
        ))
    target = items[19]
    chain = RiskChain(
        chain_id="risk_" + "a" * 20,
        node_id="tools/dense.c::convert@1",
        path="tools/dense.c",
        function="convert",
        source_signal_ids=("sig-source",),
        source_variables=("width", "size"),
        source_lines=(2,),
        transform_steps=(RiskTransform(
            line=3,
            target="size",
            expression="width * unit",
            operations=("*",),
            operand_types=("uint32_t",),
            narrowing_or_wrap=True,
        ),),
        guard_state=GuardState.ABSENT,
        allocation_signal_ids=(target.target_signal_ids[0],),
        sink_lines=(4,),
        score=95,
        confidence="high",
        rationale="test chain",
    )
    policy = BudgetPolicy(max_hunter_sessions=24, max_retries_per_work_item=1)

    first = allocate_work_items(
        tuple(items),
        policy,
        risk_chains=(chain,),
        entrypoint_ids=(chain.node_id,),
        native_full_scan=True,
    )
    second = allocate_work_items(
        tuple(reversed(items)),
        policy,
        risk_chains=(chain,),
        entrypoint_ids=(chain.node_id,),
        native_full_scan=True,
    )

    assert first == second
    assert first.policy_version == "c-diverse-admission-v1"
    assert len(first.admitted_work_ids) == 22
    assert first.retry_slots == 2
    assert first.chain_critical_slots == 1
    assert first.component_diverse_slots == 5
    assert first.high_risk_non_chain_slots == 3
    assert first.admitted_work_ids[0] == target.work_id
    assert first.decisions[0].quota == "chain_critical"
    assert first.decisions[0].score_components["risk_chain"] == 95
    assert [item.rank for item in first.decisions] == list(range(1, 23))
    assert len({item.component for item in first.decisions}) >= 6
    assert len(first.deferred) == 8
