from __future__ import annotations

import pytest
from pydantic import ValidationError

from vulnhunt_agent.analysis import (
    CAnalysisGraph,
    GuardState,
    InvariantClosureState,
    InvariantObligationDisposition,
    ObligationEvidenceRange,
    RiskChain,
    RiskTransform,
    build_c_analysis_graph,
    build_invariant_obligations,
)


def _risk_chain(
    *,
    path: str = "first.c",
    node_id: str = "node-first",
    variable: str = "count",
    operation: str = "*",
    guard: GuardState = GuardState.ABSENT,
) -> RiskChain:
    return RiskChain(
        chain_id="risk_" + ("a" if path == "first.c" else "b") * 20,
        node_id=node_id,
        path=path,
        function="renamable_function",
        source_signal_ids=("source-renamable",),
        source_variables=(variable,),
        source_lines=(10,),
        transform_steps=(RiskTransform(
            line=12,
            target="renamable_result",
            expression=f"{variable} {operation} width",
            operations=(operation,),
            operand_types=("uint32_t", "uint32_t"),
            narrowing_or_wrap=True,
        ),),
        guard_state=guard,
        guard_lines=((11,) if guard is GuardState.DOMINATES else ()),
        allocation_signal_ids=("allocation-renamable",),
        sink_signal_ids=("sink-renamable",),
        sink_lines=(20,),
        score=90,
        confidence="high",
        rationale="current graph evidence",
    )


def _obligations(chain: RiskChain):
    return build_invariant_obligations(CAnalysisGraph(risk_chains=(chain,)))


def test_repository_path_symbol_and_variable_renames_preserve_semantic_identity() -> None:
    first = _obligations(_risk_chain())
    renamed = _obligations(_risk_chain(
        path="renamed/module.c",
        node_id="different-node",
        variable="items",
    ))

    assert len(first) == len(renamed) == 1
    assert first[0].obligation_id == renamed[0].obligation_id
    assert first[0].kind.value == "integer_memory_relation"
    assert first[0].evidence_ranges != renamed[0].evidence_ranges


def test_guard_or_arithmetic_structure_changes_semantic_identity() -> None:
    baseline = _obligations(_risk_chain())[0]
    guarded = _obligations(_risk_chain(guard=GuardState.DOMINATES))[0]
    added = _obligations(_risk_chain(operation="+"))[0]

    assert len({
        baseline.obligation_id,
        guarded.obligation_id,
        added.obligation_id,
    }) == 3


def test_knowledge_without_current_graph_facts_cannot_create_an_obligation() -> None:
    graph = CAnalysisGraph()

    assert graph.invariant_obligations == ()
    assert build_invariant_obligations(graph) == ()


def test_chain_without_current_source_range_cannot_create_an_obligation() -> None:
    from vulnhunt_agent.analysis import (
        CapacityPriorityClass,
        CapacityRiskChain,
    )

    graph = CAnalysisGraph(capacity_risk_chains=(CapacityRiskChain(
        chain_id="capacity_risk_" + "1" * 20,
        root_cause_group="capacity_group_" + "2" * 20,
        allocation_fact_id="capacity_" + "3" * 20,
        root_node_id="node",
        root_path="missing.c",
        root_function="allocate",
        base="buffer",
        element_count="count",
        element_size="1",
        node_ids=("node",),
        paths=("missing.c",),
        fact_ids=("capacity_" + "3" * 20,),
        guard_state=GuardState.UNKNOWN,
        priority_class=CapacityPriorityClass.ISOLATED,
        score=10,
        confidence="low",
        rationale="no source range",
    ),))

    assert build_invariant_obligations(graph) == ()


@pytest.mark.parametrize(
    "state,candidate_ids",
    [
        (InvariantClosureState.PROVED_SAFE, ()),
        (InvariantClosureState.CANDIDATE, ("candidate-1",)),
        (InvariantClosureState.UNRESOLVED_WITH_EVIDENCE, ()),
    ],
)
def test_all_terminal_closure_states_require_current_source_evidence(
    state: InvariantClosureState,
    candidate_ids: tuple[str, ...],
) -> None:
    disposition = InvariantObligationDisposition(
        obligation_id="obligation_" + "c" * 20,
        state=state,
        evidence_ranges=(ObligationEvidenceRange(
            path="current.c",
            line=7,
            end_line=9,
            structural_role="relation",
        ),),
        rationale="closed from current source",
        candidate_ids=candidate_ids,
    )

    assert disposition.state is state


def test_candidate_closure_without_candidate_link_fails_closed() -> None:
    with pytest.raises(ValidationError, match="requires a candidate ID"):
        InvariantObligationDisposition(
            obligation_id="obligation_" + "d" * 20,
            state=InvariantClosureState.CANDIDATE,
            evidence_ranges=(ObligationEvidenceRange(
                path="current.c",
                line=7,
                end_line=7,
                structural_role="access",
            ),),
            rationale="missing candidate",
        )


def test_native_graph_persists_current_fact_obligations_deterministically(tmp_path) -> None:
    source = (
        "#include <stdint.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "int parse(const char *text) {\n"
        "  uint32_t count = (uint32_t)strtoul(text, 0, 10);\n"
        "  uint32_t bytes = count * 8;\n"
        "  char *out = malloc(bytes);\n"
        "  memcpy(out, text, count);\n"
        "  return out == 0;\n"
        "}\n"
    )
    (tmp_path / "sample.c").write_text(source, encoding="utf-8")

    first = build_c_analysis_graph(tmp_path, ["sample.c"])
    second = build_c_analysis_graph(tmp_path, ["sample.c"])

    assert first.invariant_obligations
    assert first.invariant_obligations == second.invariant_obligations
    assert all(item.source_fact_ids for item in first.invariant_obligations)
