from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.binary_analysis import (
    BinaryRangeAnalysisReport,
    BinaryRangeGuardStatus,
    BinaryVulnerabilityClass,
    GhidraJSONAdapter,
    analyze_binary_candidates,
    analyze_composite_ranges,
    discover_imageio_parsers,
)

_SNAPSHOT = "sha256:" + "7" * 64
_UUID = "72345678-1234-5678-9ABC-DEF012345678"
_BASE = 0x100001000


def _instruction(
    address: int,
    operation: str,
    *,
    result: str | None = None,
    inputs: list[str] | None = None,
    target: str | None = None,
    tags: list[str] | None = None,
    width: int | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "address": hex(address),
        "op": operation,
        "inputs": inputs or [],
        "text": operation,
    }
    if result is not None:
        value["result"] = result
    if target is not None:
        value["target"] = target
    if tags is not None:
        value["tags"] = tags
    if width is not None:
        value["width"] = width
    return value


def _block(
    name: str,
    start: int,
    instructions: list[dict[str, Any]],
    *,
    successors: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "start": hex(start),
        "size": 0x80,
        "successors": successors or [],
        "instructions": instructions,
    }


def _branch(address: int, condition: str, target: int) -> dict[str, Any]:
    return _instruction(
        address,
        "branch",
        inputs=[f"v_ram_{target:x}_1", condition],
        tags=["conditional_branch", f"branch_target:{target:x}"],
    )


def _ir(blocks: list[dict[str, Any]]):
    payload = {
        "schema_version": "ghidra-imageio-export-v1",
        "decompiler_version": "12.1.2",
        "snapshot_sha256": _SNAPSHOT,
        "image": {
            "name": "ImageIO",
            "uuid": _UUID,
            "architecture": "arm64",
            "base_address": "0x100000000",
        },
        "imports": [],
        "strings": [],
        "functions": [
            {
                "entry": hex(_BASE),
                "size": 0x800,
                "name": "decode_sgi_rle",
                "parameters": [],
                "pseudocode": "void decode_sgi_rle(void) { /* fixture */ }",
                "blocks": blocks,
            }
        ],
    }
    return GhidraJSONAdapter().normalize(
        payload,
        expected_snapshot_sha256=_SNAPSHOT,
        created_at=datetime(2026, 7, 31, 9, 0, tzinfo=UTC),
    )


def _table_setup(start: int) -> list[dict[str, Any]]:
    return [
        _instruction(
            start,
            "call",
            inputs=["session", "offset_table", "const_200", "table_size"],
            target="getBytesAtOffset",
            tags=[
                "decoder_entry",
                "input_buffer_operand:1",
                "read_session_input",
                "scalar_role:offset:2",
                "scalar_role:requested_length:3",
            ],
        ),
        _instruction(
            start + 4,
            "call",
            inputs=["session", "length_table", "const_300", "table_size"],
            target="getBytesAtOffset",
            tags=[
                "input_buffer_operand:1",
                "read_session_input",
                "scalar_role:offset:2",
                "scalar_role:requested_length:3",
            ],
        ),
        _instruction(
            start + 8,
            "load",
            result="offset",
            inputs=["ram", "offset_table"],
            width=32,
        ),
        _instruction(
            start + 12,
            "load",
            result="length",
            inputs=["ram", "length_table"],
            width=32,
        ),
    ]


def _range_call(address: int, *, length: str = "length") -> dict[str, Any]:
    return _instruction(
        address,
        "call",
        result="actual_length",
        inputs=["session", "destination", "offset", length],
        target="getBytesAtOffset",
        tags=[
            "input_buffer_operand:1",
            "read_session_input",
            "scalar_role:offset:2",
            "scalar_role:requested_length:3",
        ],
    )


def _reject_guard(
    start: int,
    *,
    combined: bool,
    capacity_for_length: str = "capacity",
    wrapping: bool = False,
) -> list[dict[str, Any]]:
    instructions = [
        _instruction(
            start,
            "compare",
            result="bad_offset",
            inputs=["capacity", "offset"],
            tags=["comparison:unsigned_less_equal"],
        ),
        _instruction(
            start + 4,
            "compare",
            result="bad_length",
            inputs=[capacity_for_length, "length"],
            tags=["comparison:unsigned_less_equal"],
        ),
        _instruction(
            start + 8,
            "boolean_or",
            result="bad_fields",
            inputs=["bad_offset", "bad_length"],
        ),
    ]
    condition = "bad_fields"
    if combined:
        instructions.extend(
            [
                _instruction(
                    start + 12,
                    "add",
                    result="range_end",
                    inputs=["offset", "length"],
                    tags=["arithmetic_may_wrap"] if wrapping else None,
                    width=32,
                ),
                _instruction(
                    start + 16,
                    "compare",
                    result="bad_range",
                    inputs=["capacity", "range_end"],
                    tags=["comparison:unsigned_less"],
                ),
                _instruction(
                    start + 20,
                    "boolean_or",
                    result="bad_any",
                    inputs=["bad_fields", "bad_range"],
                ),
            ]
        )
        condition = "bad_any"
    return [*instructions, _branch(start + 24, condition, _BASE + 0x300)]


def _simple_reject_fixture(
    *,
    combined: bool,
    capacity_for_length: str = "capacity",
    wrapping: bool = False,
) -> list[dict[str, Any]]:
    guard = _BASE + 0x100
    call = _BASE + 0x200
    reject = _BASE + 0x300
    return [
        _block(
            "entry",
            _BASE,
            _table_setup(_BASE),
            successors=["guard"],
        ),
        _block(
            "guard",
            guard,
            _reject_guard(
                guard,
                combined=combined,
                capacity_for_length=capacity_for_length,
                wrapping=wrapping,
            ),
            successors=["call", "reject"],
        ),
        _block("call", call, [_range_call(call)]),
        _block("reject", reject, [_instruction(reject, "return")]),
    ]


def _report(blocks: list[dict[str, Any]]) -> BinaryRangeAnalysisReport:
    ir = _ir(blocks)
    return analyze_composite_ranges(ir, discover_imageio_parsers(ir))


def _final_call(report: BinaryRangeAnalysisReport):
    return next(item for item in report.calls if item.address == _BASE + 0x200)


def test_individual_checks_only_emit_composite_range_gap() -> None:
    ir = _ir(_simple_reject_fixture(combined=False))
    discovery = discover_imageio_parsers(ir)
    report = analyze_composite_ranges(ir, discovery)
    call = _final_call(report)

    assert call.guard_status is BinaryRangeGuardStatus.INDIVIDUAL_ONLY
    assert call.available_capacity == "capacity"
    assert call.combined_check_address is None
    assert len(report.findings) == 1
    assert (
        report.findings[0].vulnerability_class
        is BinaryVulnerabilityClass.COMPOSITE_RANGE_GAP
    )
    combined = analyze_binary_candidates(ir, discovery)
    assert BinaryVulnerabilityClass.COMPOSITE_RANGE_GAP in {
        item.vulnerability_class for item in combined.findings
    }


def test_checked_addition_suppresses_composite_gap() -> None:
    report = _report(_simple_reject_fixture(combined=True))
    call = _final_call(report)

    assert call.guard_status is BinaryRangeGuardStatus.SAFE_COMBINED
    assert call.combined_check_address == _BASE + 0x110
    assert report.findings == ()


def test_overflow_safe_subtraction_form_is_recognized() -> None:
    guard = _BASE + 0x100
    call = _BASE + 0x200
    reject = _BASE + 0x300
    blocks = [
        _block("entry", _BASE, _table_setup(_BASE), successors=["guard"]),
        _block(
            "guard",
            guard,
            [
                _instruction(
                    guard,
                    "compare",
                    result="offset_ok",
                    inputs=["offset", "capacity"],
                    tags=["comparison:unsigned_less_equal"],
                ),
                _instruction(
                    guard + 4,
                    "subtract",
                    result="remaining",
                    inputs=["capacity", "offset"],
                ),
                _instruction(
                    guard + 8,
                    "compare",
                    result="length_ok",
                    inputs=["length", "remaining"],
                    tags=["comparison:unsigned_less_equal"],
                ),
                _instruction(
                    guard + 12,
                    "boolean_and",
                    result="range_ok",
                    inputs=["offset_ok", "length_ok"],
                ),
                _branch(guard + 16, "range_ok", call),
            ],
            successors=["call", "reject"],
        ),
        _block("call", call, [_range_call(call)]),
        _block("reject", reject, [_instruction(reject, "return")]),
    ]

    report = _report(blocks)

    assert _final_call(report).guard_status is BinaryRangeGuardStatus.SAFE_COMBINED
    assert report.findings == ()


def test_explicitly_wrapping_addition_does_not_suppress_gap() -> None:
    report = _report(_simple_reject_fixture(combined=True, wrapping=True))

    assert _final_call(report).guard_status is BinaryRangeGuardStatus.INDIVIDUAL_ONLY
    assert len(report.findings) == 1


def test_bypass_around_combined_guard_retains_candidate() -> None:
    individual = _BASE + 0x100
    choice = _BASE + 0x180
    combined = _BASE + 0x1C0
    call = _BASE + 0x200
    reject = _BASE + 0x300
    blocks = [
        _block("entry", _BASE, _table_setup(_BASE), successors=["individual"]),
        _block(
            "individual",
            individual,
            _reject_guard(individual, combined=False),
            successors=["choice", "reject"],
        ),
        _block(
            "choice",
            choice,
            [_branch(choice, "bypass_flag", call)],
            successors=["call", "combined"],
        ),
        _block(
            "combined",
            combined,
            [
                _instruction(
                    combined,
                    "add",
                    result="range_end",
                    inputs=["offset", "length"],
                ),
                _instruction(
                    combined + 4,
                    "compare",
                    result="bad_range",
                    inputs=["capacity", "range_end"],
                    tags=["comparison:unsigned_less"],
                ),
                _branch(combined + 8, "bad_range", reject),
            ],
            successors=["call", "reject"],
        ),
        _block("call", call, [_range_call(call)]),
        _block("reject", reject, [_instruction(reject, "return")]),
    ]

    report = _report(blocks)

    assert _final_call(report).guard_status is BinaryRangeGuardStatus.INDIVIDUAL_ONLY
    assert len(report.findings) == 1


def test_loop_validation_guard_controls_post_loop_read() -> None:
    guard = _BASE + 0x100
    latch = _BASE + 0x180
    call = _BASE + 0x200
    reject = _BASE + 0x300
    blocks = [
        _block(
            "entry",
            _BASE,
            [*_table_setup(_BASE), _branch(_BASE + 16, "zero_count", call)],
            successors=["call", "guard"],
        ),
        _block(
            "guard",
            guard,
            _reject_guard(guard, combined=True),
            successors=["latch", "reject"],
        ),
        _block(
            "latch",
            latch,
            [_branch(latch, "more_entries", guard)],
            successors=["call", "guard"],
        ),
        _block("call", call, [_range_call(call)]),
        _block("reject", reject, [_instruction(reject, "return")]),
    ]

    report = _report(blocks)

    assert _final_call(report).guard_status is BinaryRangeGuardStatus.SAFE_COMBINED
    assert report.findings == ()


def test_distinct_capacities_do_not_form_a_gap_candidate() -> None:
    report = _report(
        _simple_reject_fixture(
            combined=False,
            capacity_for_length="other_capacity",
        )
    )

    assert (
        _final_call(report).guard_status
        is BinaryRangeGuardStatus.INSUFFICIENT_EVIDENCE
    )
    assert report.findings == ()


def test_clamped_length_is_respected() -> None:
    guard = _BASE + 0x100
    call = _BASE + 0x200
    reject = _BASE + 0x300
    blocks = [
        _block("entry", _BASE, _table_setup(_BASE), successors=["guard"]),
        _block(
            "guard",
            guard,
            [
                *_reject_guard(guard, combined=False),
            ],
            successors=["clamp", "reject"],
        ),
        _block(
            "clamp",
            _BASE + 0x180,
            [
                _instruction(
                    _BASE + 0x180,
                    "subtract",
                    result="remaining",
                    inputs=["capacity", "offset"],
                ),
                _instruction(
                    _BASE + 0x184,
                    "phi",
                    result="clamped_length",
                    inputs=["length", "remaining"],
                ),
            ],
            successors=["call"],
        ),
        _block("call", call, [_range_call(call, length="clamped_length")]),
        _block("reject", reject, [_instruction(reject, "return")]),
    ]

    report = _report(blocks)

    assert _final_call(report).guard_status is BinaryRangeGuardStatus.LENGTH_CLAMPED
    assert report.findings == ()


def test_unrelated_input_scalar_does_not_borrow_another_lengths_guard() -> None:
    guard = _BASE + 0x100
    call = _BASE + 0x200
    reject = _BASE + 0x300
    blocks = [
        _block(
            "entry",
            _BASE,
            [
                *_table_setup(_BASE),
                _instruction(
                    _BASE + 16,
                    "call",
                    inputs=["session", "other_table", "const_400", "table_size"],
                    target="getBytesAtOffset",
                    tags=[
                        "input_buffer_operand:1",
                        "read_session_input",
                        "scalar_role:offset:2",
                        "scalar_role:requested_length:3",
                    ],
                ),
                _instruction(
                    _BASE + 20,
                    "load",
                    result="other_length",
                    inputs=["ram", "other_table"],
                ),
            ],
            successors=["guard"],
        ),
        _block(
            "guard",
            guard,
            _reject_guard(guard, combined=False),
            successors=["call", "reject"],
        ),
        _block("call", call, [_range_call(call, length="other_length")]),
        _block("reject", reject, [_instruction(reject, "return")]),
    ]

    report = _report(blocks)

    assert (
        _final_call(report).guard_status
        is BinaryRangeGuardStatus.INSUFFICIENT_EVIDENCE
    )
    assert report.findings == ()


def test_untyped_or_duplicate_range_roles_are_ignored() -> None:
    call = _BASE + 0x200
    blocks = [
        _block(
            "entry",
            _BASE,
            _table_setup(_BASE),
            successors=["calls"],
        ),
        _block(
            "calls",
            call,
            [
                _instruction(
                    call,
                    "call",
                    inputs=["session", "destination", "offset", "length"],
                    target="getBytesAtOffset",
                    tags=["input_buffer_operand:1"],
                ),
                _instruction(
                    call + 4,
                    "call",
                    inputs=["session", "destination", "offset", "length"],
                    target="getBytesAtOffset",
                    tags=[
                        "input_buffer_operand:1",
                        "scalar_role:offset:2",
                        "scalar_role:requested_length:2",
                    ],
                ),
            ],
        )
    ]

    report = _report(blocks)

    assert all(item.address < call for item in report.calls)
    assert report.findings == ()


def test_broad_range_reader_substring_is_not_summarized() -> None:
    call = _BASE + 0x200
    blocks = [
        _block("entry", _BASE, _table_setup(_BASE), successors=["calls"]),
        _block(
            "calls",
            call,
            [
                _instruction(
                    call,
                    "call",
                    inputs=["session", "destination", "offset", "length"],
                    target="getBytesAtOffsetUnchecked",
                    tags=[
                        "input_buffer_operand:1",
                        "read_session_input",
                        "scalar_role:offset:2",
                        "scalar_role:requested_length:3",
                    ],
                )
            ],
        ),
    ]

    report = _report(blocks)

    assert all(item.address != call for item in report.calls)


def test_range_report_is_deterministic_and_tamper_evident() -> None:
    blocks = _simple_reject_fixture(combined=False)
    first = _report(blocks)
    second = _report(blocks)

    assert first.report_sha256 == second.report_sha256
    payload = first.model_dump(mode="json")
    final = next(index for index, item in enumerate(payload["calls"]) if item["address"] == _BASE + 0x200)
    payload["calls"][final]["available_capacity"] = "tampered"
    with pytest.raises(ValidationError):
        BinaryRangeAnalysisReport.model_validate(payload)
