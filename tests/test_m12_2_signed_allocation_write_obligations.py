from __future__ import annotations

from pathlib import Path

from vulnhunt_agent.analysis import (
    CAnalysisGraph,
    GuardState,
    InvariantObligationKind,
    build_c_analysis_graph,
)


def _header(field: str = "rate", signed: bool = True) -> str:
    type_name = "int" if signed else "unsigned int"
    return f"""
typedef struct Config {{ {type_name} {field}; }} Config;
typedef struct Context {{
    {type_name} {field};
    unsigned int block_count, capacity;
    int *buffer;
}} Context;
"""


def _source(
    guard: str = "!config->rate",
    field: str = "rate",
    configure: str = "configure",
    checked: bool = False,
) -> str:
    allocation = (
        "malloc(checked_size(context->capacity, sizeof(int)))"
        if checked
        else "malloc(context->capacity * sizeof(int))"
    )
    return f"""
#include <stddef.h>
#include <stdlib.h>
#include "model.h"
size_t checked_size(unsigned int, size_t);
int {configure}(Context *context, Config *config) {{
    if ({guard}) return 0;
    context->{field} = config->{field};
    return 1;
}}
int initialize(Context *context) {{
    context->block_count = context->{field} / 4;
    context->capacity = context->block_count + context->block_count / 2;
    context->buffer = {allocation};
    return context->buffer != 0;
}}
void emit(Context *context, const int *input, unsigned int count) {{
    int *cursor = context->buffer;
    unsigned int remaining = count;
    while (remaining--) {{
        *cursor++ = *input++;
    }}
}}
"""


def _graph(
    tmp_path: Path,
    source: str,
    header: str | None = None,
) -> CAnalysisGraph:
    (tmp_path / "model.h").write_text(header or _header(), encoding="utf-8")
    (tmp_path / "codec.c").write_text(source, encoding="utf-8")
    return build_c_analysis_graph(tmp_path, ["codec.c", "model.h"])


def test_signed_nonzero_domain_reaches_allocation_and_independent_write_bound(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path, _source())

    chain = graph.signed_allocation_write_chains[0]
    obligation = next(
        item for item in graph.invariant_obligations
        if item.kind is InvariantObligationKind.INTEGER_MEMORY_RELATION
        and "source_signed=1" in item.structural_facts
        and "source_domain=nonzero" in item.structural_facts
    )

    assert chain.source_signed
    assert chain.source_domain == "nonzero"
    assert chain.guard_state is GuardState.PARTIAL
    assert chain.independent_write_bound
    assert chain.narrowing_or_wrap
    assert chain.write_unit == 1
    assert chain.boundary_cases == (
        "negative",
        "zero",
        "largest_valid",
        "narrowing_boundary",
        "allocation_overflow",
    )
    assert len(obligation.target_node_ids) == 3


def test_source_backed_nonnegative_domain_closes_fixed_control(tmp_path: Path) -> None:
    graph = _graph(tmp_path, _source(guard="config->rate <= 0"))

    chain = graph.signed_allocation_write_chains[0]

    assert chain.source_domain == "nonnegative"
    assert chain.guard_state is GuardState.DOMINATES
    assert chain.score == 15


def test_checked_arithmetic_is_recorded_without_shortcutting_source_domain(
    tmp_path: Path,
) -> None:
    graph = _graph(tmp_path, _source(checked=True))

    chain = graph.signed_allocation_write_chains[0]

    assert chain.checked_arithmetic
    assert chain.source_domain == "nonzero"
    assert chain.guard_state is GuardState.PARTIAL


def test_unsigned_field_does_not_create_signed_source_chain(tmp_path: Path) -> None:
    graph = _graph(tmp_path, _source(), _header(signed=False))

    assert graph.signed_allocation_write_chains == ()


def test_semantic_identity_survives_file_function_field_and_local_renames(
    tmp_path: Path,
) -> None:
    first = _graph(tmp_path, _source())
    first_obligation = next(
        item for item in first.invariant_obligations
        if "source_domain=nonzero" in item.structural_facts
        and "source_signed=1" in item.structural_facts
    )

    renamed_dir = tmp_path / "renamed"
    renamed_dir.mkdir()
    renamed_header = _header(field="frequency")
    renamed_source = (
        _source(
            guard="!config->frequency",
            field="frequency",
            configure="apply_settings",
        )
        .replace('"model.h"', '"types.h"')
        .replace("cursor", "write_head")
        .replace("remaining", "frames_left")
    )
    (renamed_dir / "types.h").write_text(renamed_header, encoding="utf-8")
    (renamed_dir / "writer.c").write_text(renamed_source, encoding="utf-8")
    renamed = build_c_analysis_graph(renamed_dir, ["types.h", "writer.c"])
    renamed_obligation = next(
        item for item in renamed.invariant_obligations
        if "source_domain=nonzero" in item.structural_facts
        and "source_signed=1" in item.structural_facts
    )

    assert first_obligation.obligation_id == renamed_obligation.obligation_id
    assert first_obligation.evidence_ranges != renamed_obligation.evidence_ranges


def test_detector_contains_no_calibration_repository_or_symbol_identity() -> None:
    module = (
        Path(__file__).parents[1]
        / "src/vulnhunt_agent/analysis/signed_memory.py"
    ).read_text(encoding="utf-8")

    for forbidden in (
        "WavPack",
        "wavpack",
        "sample_rate",
        "WavpackPackSamples",
        "pack_utils.c",
    ):
        assert forbidden not in module
