from __future__ import annotations

from pathlib import Path

from vulnhunt_agent.analysis import (
    CAnalysisGraph,
    FormattedDestinationKind,
    FormattedExpansionClass,
    GuardState,
    InvariantObligationKind,
    build_c_analysis_graph,
)


def _graph(tmp_path: Path, source: str, path: str = "formatter.c") -> CAnalysisGraph:
    (tmp_path / path).write_text(source, encoding="utf-8")
    return build_c_analysis_graph(tmp_path, [path])


def test_unbounded_type_expansion_creates_cross_specialist_obligation(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path, """
int render(double input) {
    char output[64];
    return sprintf(output, "%f", input);
}
""")

    fact = graph.formatted_output_facts[0]
    obligation = next(
        item for item in graph.invariant_obligations
        if item.kind is InvariantObligationKind.FORMATTED_OUTPUT_EXPANSION
    )

    assert fact.destination_kind is FormattedDestinationKind.FIXED_ARRAY
    assert fact.capacity_bytes == 64
    assert fact.expansion_class is FormattedExpansionClass.TYPE_DEPENDENT
    assert fact.conversion_classes == ("floating_fixed",)
    assert fact.maximum_output_chars is not None
    assert fact.maximum_output_chars + 1 > fact.capacity_bytes
    assert fact.guard_state is GuardState.ABSENT
    assert set(obligation.required_hunters) == {
        "c-bounds-integers",
        "c-memory-lifetime",
    }
    assert {item.structural_role for item in obligation.evidence_ranges} == {
        "access",
        "relation",
    }


def test_bounded_output_with_matching_capacity_and_checked_return_is_safe(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path, """
int render(double input) {
    char output[64];
    int written = snprintf(output, sizeof(output), "%f", input);
    if (written < 0 || written >= sizeof(output)) return -1;
    return 0;
}
""")

    fact = graph.formatted_output_facts[0]

    assert fact.bounded_api
    assert fact.bound_matches_destination
    assert fact.return_checked
    assert fact.guard_state is GuardState.DOMINATES


def test_fixed_literal_that_fits_is_safe_without_repository_specific_rules(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path, """
int render(void) {
    char output[4];
    return sprintf(output, "ok");
}
""")

    fact = graph.formatted_output_facts[0]

    assert fact.expansion_class is FormattedExpansionClass.FIXED_LITERAL
    assert fact.maximum_output_chars == 2
    assert fact.guard_state is GuardState.DOMINATES


def test_precision_sign_locale_exponent_and_terminator_are_in_capacity_model(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path, """
int render(double input) {
    char output[128];
    return sprintf(output, "%'+.2000e", input);
}
""")

    fact = graph.formatted_output_facts[0]

    assert fact.locale_sensitive
    assert fact.maximum_output_chars is not None
    assert fact.maximum_output_chars > 2_000
    assert fact.terminator_bytes == 1
    assert fact.guard_state is GuardState.ABSENT


def test_input_dependent_and_dynamic_formats_fail_closed(tmp_path: Path) -> None:
    graph = _graph(tmp_path, """
int render(const char *format, const char *input) {
    char first[128];
    char second[128];
    sprintf(first, "%*s", 10, input);
    sprintf(second, format, input);
    return first[0] + second[0];
}
""")

    assert [item.expansion_class for item in graph.formatted_output_facts] == [
        FormattedExpansionClass.INPUT_DEPENDENT,
        FormattedExpansionClass.DYNAMIC_FORMAT,
    ]
    assert all(
        item.maximum_output_chars is None
        and item.guard_state is GuardState.ABSENT
        for item in graph.formatted_output_facts
    )
    obligations = {
        item.source_fact_ids[0]: set(item.required_hunters)
        for item in graph.invariant_obligations
        if item.kind is InvariantObligationKind.FORMATTED_OUTPUT_EXPANSION
    }
    literal, dynamic = graph.formatted_output_facts
    assert obligations[literal.fact_id] == {
        "c-bounds-integers",
        "c-memory-lifetime",
    }
    assert obligations[dynamic.fact_id] == {
        "c-bounds-integers",
        "c-injection-format",
    }


def test_semantic_identity_survives_path_function_and_variable_renames(
    tmp_path: Path,
) -> None:
    first = _graph(tmp_path, """
int render(double input) {
    char output[64];
    return sprintf(output, "%f", input);
}
""", "first.c")
    second = _graph(tmp_path, """
int serialize(double measurement) {
    char scratch[64];
    return sprintf(scratch, "%f", measurement);
}
""", "renamed.c")

    first_obligation = next(
        item for item in first.invariant_obligations
        if item.kind is InvariantObligationKind.FORMATTED_OUTPUT_EXPANSION
    )
    second_obligation = next(
        item for item in second.invariant_obligations
        if item.kind is InvariantObligationKind.FORMATTED_OUTPUT_EXPANSION
    )

    assert first_obligation.obligation_id == second_obligation.obligation_id
    assert first_obligation.evidence_ranges != second_obligation.evidence_ranges


def test_production_detector_contains_no_calibration_identity_or_literal() -> None:
    module = (
        Path(__file__).parents[1]
        / "src/vulnhunt_agent/analysis/formatted_output.py"
    ).read_text(encoding="utf-8")

    for forbidden in (
        "Mini-XML",
        "mini-xml",
        "mxml-file.c",
        "mxml_write_node",
        "libcue",
        "255",
    ):
        assert forbidden not in module
