from __future__ import annotations

from pathlib import Path

from vulnhunt_agent.analysis import (
    CAnalysisGraph,
    GuardState,
    InvariantObligationKind,
    OutputComponentKind,
    build_c_analysis_graph,
)


def _source(update: str = "") -> str:
    return f"""
typedef struct Item {{ const char *data; int length; struct Item *next; }} Item;
int encode(const char *, char *);
int compose(char *destination, Item *items, int capacity) {{
    int first = 1;
    int separator_length = 0;
    char *cursor = destination;
    capacity--;
    while (items != 0) {{
        int required = items->length * 3;
        if ((cursor - destination) + separator_length + required > capacity) {{
            return -1;
        }}
        if (first == 1) {{
            {update}
            first = 0;
        }} else {{
            cursor[0] = ',';
            cursor++;
        }}
        cursor[0] = ':';
        cursor++;
        cursor += encode(items->data, cursor);
        items = items->next;
    }}
    cursor[0] = '\\0';
    return 0;
}}
"""


def _graph(tmp_path: Path, source: str, path: str = "builder.c") -> CAnalysisGraph:
    (tmp_path / path).write_text(source, encoding="utf-8")
    return build_c_analysis_graph(tmp_path, [path])


def test_second_iteration_separator_deficit_is_a_state_obligation(tmp_path: Path) -> None:
    graph = _graph(tmp_path, _source())

    fact = graph.stateful_output_facts[0]
    obligation = next(
        item for item in graph.invariant_obligations
        if item.kind is InvariantObligationKind.STATEFUL_OUTPUT_CAPACITY
    )

    assert fact.first_iteration_overhead == 0
    assert fact.subsequent_iteration_overhead == 1
    assert fact.guarded_subsequent_overhead == 0
    assert fact.terminator_reserve == 1
    assert fact.guard_state is GuardState.ABSENT
    assert not fact.transition_updates_guard_term
    assert set(fact.component_kinds) == {
        OutputComponentKind.DATA,
        OutputComponentKind.PREFIX,
        OutputComponentKind.SEPARATOR,
        OutputComponentKind.ESCAPE,
        OutputComponentKind.TERMINATOR,
        OutputComponentKind.POINTER_ADVANCE,
    }
    assert obligation.required_hunters == ("c-bounds-integers",)


def test_transition_update_closes_first_empty_exact_fit_and_extra_capacity_controls(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path, _source("separator_length = 1;"))

    fact = graph.stateful_output_facts[0]

    assert fact.transition_updates_guard_term
    assert fact.guarded_subsequent_overhead == fact.subsequent_iteration_overhead
    assert fact.guard_state is GuardState.DOMINATES
    assert fact.first_iteration_overhead == 0
    assert fact.empty_list_terminator_safe
    assert fact.exact_fit_allowed


def test_distinct_transitions_sharing_destination_remain_distinct(tmp_path: Path) -> None:
    source = _source().replace(
        "items = items->next;",
        """
        if ((cursor - destination) + prefix_length > capacity) {
            return -1;
        }
        if (first_prefix == 1) {
            first_prefix = 0;
        } else {
            cursor[0] = '/';
            cursor++;
        }
        items = items->next;""",
    ).replace(
        "int separator_length = 0;",
        "int separator_length = 0;\n    int first_prefix = 1;\n    int prefix_length = 0;",
    )
    graph = _graph(tmp_path, source)

    facts = graph.stateful_output_facts
    obligations = [
        item for item in graph.invariant_obligations
        if item.kind is InvariantObligationKind.STATEFUL_OUTPUT_CAPACITY
    ]

    assert len(facts) == 2
    assert {item.transition_ordinal for item in facts} == {1, 2}
    assert len({item.obligation_id for item in obligations}) == 2


def test_state_obligation_identity_is_rename_stable_and_not_signed_length(
    tmp_path: Path,
) -> None:
    first = _graph(tmp_path, _source(), "first.c")
    renamed = _graph(
        tmp_path,
        _source()
        .replace("compose", "serialize")
        .replace("destination", "output")
        .replace("separator_length", "delimiter_width")
        .replace("cursor", "write_head")
        .replace("capacity", "available"),
        "renamed.c",
    )

    first_obligation = next(
        item for item in first.invariant_obligations
        if item.kind is InvariantObligationKind.STATEFUL_OUTPUT_CAPACITY
    )
    renamed_obligation = next(
        item for item in renamed.invariant_obligations
        if item.kind is InvariantObligationKind.STATEFUL_OUTPUT_CAPACITY
    )

    assert first_obligation.obligation_id == renamed_obligation.obligation_id
    assert first_obligation.kind is not InvariantObligationKind.INTEGER_MEMORY_RELATION


def test_detector_has_no_calibration_repository_or_symbol_identity() -> None:
    module = (
        Path(__file__).parents[1]
        / "src/vulnhunt_agent/analysis/stateful_output.py"
    ).read_text(encoding="utf-8")

    for forbidden in (
        "uriparser",
        "UriQuery",
        "ComposeQuery",
        "ampersandLen",
        "firstItem",
    ):
        assert forbidden not in module
