from __future__ import annotations

from pathlib import Path

from vulnhunt_agent.analysis import (
    CAnalysisGraph,
    GuardState,
    InvariantObligationKind,
    build_c_analysis_graph,
)


def _reader(function: str = "decode", parameter: str = "cursor") -> str:
    return f"""
int {function}(const unsigned char *{parameter}) {{
    int tag = *{parameter};
    ++{parameter};
    if (tag & 1) ++{parameter};
    return *{parameter}++;
}}
"""


def _caller(*, safe: bool, decoder: str = "decode", cursor: str = "cursor", length: str = "remaining") -> str:
    operation = (
        f"size_t consumed = validate(&{cursor}, &{length});\n"
        f"        value = consumed ? {decoder}({cursor} - consumed) : 0;"
        if safe
        else (
            f"value = {decoder}({cursor});\n"
            f"        validate(&{cursor}, &{length});"
        )
    )
    return f"""
#include <stddef.h>
size_t validate(unsigned char **, size_t *);
int {decoder}(const unsigned char *);
int parse(unsigned char *{cursor}, size_t {length}) {{
    int value = 0;
    while ({length} > 0) {{
        {operation}
        break;
    }}
    return value;
}}
"""


def _graph(tmp_path: Path, caller: str, reader: str) -> CAnalysisGraph:
    (tmp_path / "caller.c").write_text(caller, encoding="utf-8")
    (tmp_path / "reader.c").write_text(reader, encoding="utf-8")
    return build_c_analysis_graph(tmp_path, ["caller.c", "reader.c"])


def test_post_read_length_check_creates_cross_file_obligation_without_write_signal(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path, _caller(safe=False), _reader())

    chain = graph.length_before_read_chains[0]
    obligation = next(
        item for item in graph.invariant_obligations
        if item.kind is InvariantObligationKind.CURSOR_LENGTH_RELATION
        and "precondition_family=length_before_read" in item.structural_facts
    )

    assert len(chain.paths) == 2
    assert chain.checked_after_read
    assert not chain.checked_before_read
    assert chain.guard_state is GuardState.ABSENT
    assert chain.required_access_index == 2
    assert chain.boundary_cases == (
        "zero_remaining",
        "one_byte_header",
        "maximum_extension_3_bytes",
    )
    assert not graph.capacity_risk_chains
    assert set(obligation.required_hunters) == {
        "c-bounds-integers",
        "c-parser-state",
    }


def test_dominating_check_and_checked_size_rebase_close_fixed_control(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path, _caller(safe=True), _reader())

    chain = graph.length_before_read_chains[0]

    assert chain.checked_before_read
    assert not chain.checked_after_read
    assert chain.pointer_rebased_from_checked_size
    assert chain.check_result_controls_read
    assert chain.guard_state is GuardState.DOMINATES
    assert chain.score == 15


def test_path_function_cursor_and_length_renames_preserve_semantic_identity(
    tmp_path: Path,
) -> None:
    first = _graph(tmp_path, _caller(safe=False), _reader())
    first_obligation = next(
        item for item in first.invariant_obligations
        if "precondition_family=length_before_read" in item.structural_facts
    )

    renamed_dir = tmp_path / "renamed"
    renamed_dir.mkdir()
    (renamed_dir / "front.c").write_text(
        _caller(
            safe=False,
            decoder="inspect_header",
            cursor="input_head",
            length="available_bytes",
        ),
        encoding="utf-8",
    )
    (renamed_dir / "back.c").write_text(
        _reader("inspect_header", "input_head"),
        encoding="utf-8",
    )
    renamed = build_c_analysis_graph(renamed_dir, ["front.c", "back.c"])
    renamed_obligation = next(
        item for item in renamed.invariant_obligations
        if "precondition_family=length_before_read" in item.structural_facts
    )

    assert first_obligation.obligation_id == renamed_obligation.obligation_id
    assert first_obligation.evidence_ranges != renamed_obligation.evidence_ranges


def test_pointer_reader_and_length_chain_are_deterministic(tmp_path: Path) -> None:
    first = _graph(tmp_path, _caller(safe=False), _reader())
    second = build_c_analysis_graph(tmp_path, ["reader.c", "caller.c"])

    assert first.pointer_read_summaries == second.pointer_read_summaries
    assert first.length_before_read_chains == second.length_before_read_chains


def test_detector_contains_no_calibration_repository_or_symbol_identity() -> None:
    module = (
        Path(__file__).parents[1]
        / "src/vulnhunt_agent/analysis/pointer_reads.py"
    ).read_text(encoding="utf-8")

    for forbidden in (
        "libcoap",
        "coap_opt_length",
        "next_option_safe",
        "pdu.c",
        "option.c",
    ):
        assert forbidden not in module
