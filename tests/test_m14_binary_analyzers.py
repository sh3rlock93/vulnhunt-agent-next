from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.binary_analysis import (
    BinaryAnalysisReport,
    BinaryAnalyzerLimits,
    BinaryVulnerabilityClass,
    GhidraJSONAdapter,
    analyze_binary_candidates,
    discover_imageio_parsers,
)

_SNAPSHOT = "sha256:" + "4" * 64
_UUID = "32345678-1234-5678-9ABC-DEF012345678"


def _instruction(
    address: int,
    op: str,
    *,
    result: str | None = None,
    inputs: list[str] | None = None,
    target: str | None = None,
    tags: list[str] | None = None,
    constants: list[int] | None = None,
    width: int | None = None,
    signed: bool | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "address": hex(address),
        "op": op,
        "inputs": inputs or [],
        "text": op,
    }
    if result is not None:
        value["result"] = result
    if target is not None:
        value["target"] = target
    if tags:
        value["tags"] = tags
    if constants:
        value["constants"] = constants
    if width is not None:
        value["width"] = width
    if signed is not None:
        value["signed"] = signed
    return value


def _function(
    address: int,
    name: str,
    instructions: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "entry": hex(address),
        "size": 256,
        "name": name,
        "parameters": [],
        "pseudocode": f"void {name}(void) {{ /* normalized */ }}",
        "blocks": [
            {
                "name": "entry",
                "start": hex(address),
                "size": 256,
                "successors": [],
                "instructions": instructions,
            }
        ],
    }


def _normalized_ir(*, version: str = "11.4"):
    base = 0x100001000
    functions = [
        _function(
            base,
            "sub_integer",
            [
                _instruction(base, "param", result="length", tags=["input_length"]),
                _instruction(
                    base + 4,
                    "mul",
                    result="bytes",
                    inputs=["length"],
                    constants=[4],
                ),
                _instruction(
                    base + 8,
                    "alloc",
                    result="buffer",
                    inputs=["bytes"],
                    target="malloc",
                ),
            ],
        ),
        _function(
            base + 0x1000,
            "sub_guarded",
            [
                _instruction(base + 0x1000, "param", result="length", tags=["input_length"]),
                _instruction(
                    base + 0x1004,
                    "mul",
                    result="bytes",
                    inputs=["length"],
                    constants=[8],
                ),
                _instruction(base + 0x1008, "cmp", inputs=["bytes", "maximum"]),
                _instruction(
                    base + 0x100C,
                    "alloc",
                    result="buffer",
                    inputs=["bytes"],
                    target="malloc",
                ),
            ],
        ),
        _function(
            base + 0x2000,
            "sub_offset",
            [
                _instruction(
                    base + 0x2000,
                    "param",
                    result="offset",
                    tags=["input_offset"],
                ),
                _instruction(
                    base + 0x2004,
                    "param",
                    result="length",
                    tags=["input_length"],
                ),
                _instruction(
                    base + 0x2008,
                    "add",
                    result="end",
                    inputs=["offset", "length"],
                ),
                _instruction(base + 0x200C, "load", result="value", inputs=["end"]),
            ],
        ),
        _function(
            base + 0x3000,
            "sub_copy",
            [
                _instruction(
                    base + 0x3000,
                    "param",
                    result="alloc_size",
                    tags=["input_length"],
                ),
                _instruction(
                    base + 0x3004,
                    "param",
                    result="copy_length",
                    tags=["input_length"],
                ),
                _instruction(
                    base + 0x3008,
                    "alloc",
                    result="buffer",
                    inputs=["alloc_size"],
                    target="malloc",
                ),
                _instruction(
                    base + 0x300C,
                    "copy",
                    inputs=["buffer", "data", "copy_length"],
                    target="memcpy",
                ),
            ],
        ),
        _function(
            base + 0x4000,
            "sub_lifetime",
            [
                _instruction(
                    base + 0x4000,
                    "param",
                    result="pointer",
                    tags=["input_data"],
                ),
                _instruction(base + 0x4004, "free", inputs=["pointer"], target="free"),
                _instruction(base + 0x4008, "load", result="value", inputs=["pointer"]),
            ],
        ),
        _function(
            base + 0x5000,
            "sub_safe_copy",
            [
                _instruction(
                    base + 0x5000,
                    "param",
                    result="length",
                    tags=["input_length"],
                ),
                _instruction(
                    base + 0x5004,
                    "alloc",
                    result="buffer",
                    inputs=["length"],
                    target="malloc",
                ),
                _instruction(
                    base + 0x5008,
                    "copy",
                    inputs=["buffer", "data", "length"],
                    target="memcpy",
                ),
            ],
        ),
    ]
    payload = {
        "schema_version": "ghidra-imageio-export-v1",
        "decompiler_version": version,
        "snapshot_sha256": _SNAPSHOT,
        "image": {
            "name": "ImageIO",
            "uuid": _UUID,
            "architecture": "arm64",
            "base_address": "0x100000000",
        },
        "imports": ["malloc", "memcpy", "free"],
        "strings": [],
        "functions": functions,
    }
    return GhidraJSONAdapter().normalize(
        payload,
        expected_snapshot_sha256=_SNAPSHOT,
        created_at=datetime(2026, 7, 30, 4, 0, tzinfo=UTC),
    )


def _single_function_ir(instructions: list[dict[str, Any]]):
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
        "functions": [_function(0x100001000, "decode_tiff", instructions)],
    }
    return GhidraJSONAdapter().normalize(
        payload,
        expected_snapshot_sha256=_SNAPSHOT,
        created_at=datetime(2026, 7, 31, 3, 0, tzinfo=UTC),
    )


def _block(
    name: str,
    start: int,
    successors: list[str],
    instructions: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "name": name,
        "start": hex(start),
        "size": 0x20,
        "successors": successors,
        "instructions": instructions,
    }


def _cfg_ir(blocks: list[dict[str, Any]]):
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
                "entry": hex(0x100001000),
                "size": 0x200,
                "name": "decode_tiff",
                "parameters": [],
                "pseudocode": "void decode_tiff(void) { /* cfg fixture */ }",
                "blocks": blocks,
            }
        ],
    }
    return GhidraJSONAdapter().normalize(
        payload,
        expected_snapshot_sha256=_SNAPSHOT,
        created_at=datetime(2026, 7, 31, 3, 30, tzinfo=UTC),
    )


def _conditional_branch(
    address: int,
    *,
    condition: str,
    true_target: int,
) -> dict[str, Any]:
    return _instruction(
        address,
        "branch",
        inputs=[f"v_ram_{true_target:x}_1", condition],
        tags=["conditional_branch", f"branch_target:{true_target:x}"],
    )


def _integer_guard_cfg(
    *,
    threshold: int,
    bypass: bool = False,
    compared_variable: str = "length",
    comparison_kind: str = "unsigned_less_equal",
):
    base = 0x100001000
    checked = base + 0x40
    rejected = base + 0x80
    sink = base + 0xC0
    entry_instructions = [
        _instruction(base, "param", result="length", tags=["input_length"]),
        _instruction(base + 4, "param", result="other"),
        _instruction(
            base + 8,
            "cmp",
            result="condition",
            inputs=[compared_variable, f"const_{threshold:x}"],
            constants=[threshold],
            tags=[f"comparison:{comparison_kind}"],
        ),
        _conditional_branch(base + 12, condition="condition", true_target=checked),
    ]
    if bypass:
        blocks = [
            _block("entry", base, ["checked", "rejected"], entry_instructions),
            _block(
                "checked",
                checked,
                ["sink"],
                [_instruction(checked, "branch", inputs=[f"v_ram_{sink:x}_1"])],
            ),
            _block(
                "rejected",
                rejected,
                ["sink"],
                [_instruction(rejected, "branch", inputs=[f"v_ram_{sink:x}_1"])],
            ),
            _block(
                "sink",
                sink,
                [],
                [
                    _instruction(
                        sink,
                        "int_mult",
                        result="bytes",
                        inputs=["length"],
                        constants=[4],
                        width=64,
                        signed=False,
                    ),
                    _instruction(
                        sink + 4,
                        "alloc",
                        result="buffer",
                        inputs=["bytes"],
                        target="malloc",
                    ),
                ],
            ),
        ]
    else:
        blocks = [
            _block("entry", base, ["checked", "rejected"], entry_instructions),
            _block(
                "checked",
                checked,
                [],
                [
                    _instruction(
                        checked,
                        "int_mult",
                        result="bytes",
                        inputs=["length"],
                        constants=[4],
                        width=64,
                        signed=False,
                    ),
                    _instruction(
                        checked + 4,
                        "alloc",
                        result="buffer",
                        inputs=["bytes"],
                        target="malloc",
                    ),
                ],
            ),
            _block(
                "rejected",
                rejected,
                [],
                [_instruction(rejected, "ret")],
            ),
        ]
    return _cfg_ir(blocks)


def test_analyzers_emit_only_supported_static_candidate_classes() -> None:
    ir = _normalized_ir()
    discovery = discover_imageio_parsers(ir)
    report = analyze_binary_candidates(ir, discovery)

    assert {item.vulnerability_class for item in report.findings} == {
        BinaryVulnerabilityClass.INTEGER_OVERFLOW,
        BinaryVulnerabilityClass.OFFSET_LENGTH_OOB,
        BinaryVulnerabilityClass.ALLOCATION_COPY_MISMATCH,
        BinaryVulnerabilityClass.USE_AFTER_FREE,
    }
    assert all(item.status == "static_candidate" for item in report.findings)
    assert {item.function_name for item in report.findings} == {
        "sub_integer",
        "sub_guarded",
        "sub_offset",
        "sub_copy",
        "sub_lifetime",
    }


def test_noncontrolling_compare_is_not_a_guard_but_same_copy_length_is_safe() -> None:
    ir = _normalized_ir()
    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    finding_functions = {item.function_name for item in report.findings}
    assert "sub_guarded" in finding_functions
    assert "sub_safe_copy" not in finding_functions


def test_dominating_range_guard_suppresses_integer_overflow_candidate() -> None:
    maximum_input = ((1 << 64) - 1) // 4
    ir = _integer_guard_cfg(threshold=maximum_input)

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert report.findings == ()


def test_guard_with_bypass_path_does_not_suppress_integer_overflow() -> None:
    maximum_input = ((1 << 64) - 1) // 4
    ir = _integer_guard_cfg(threshold=maximum_input, bypass=True)

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert len(report.findings) == 1
    assert report.findings[0].vulnerability_class is BinaryVulnerabilityClass.INTEGER_OVERFLOW


@pytest.mark.parametrize(
    ("threshold", "compared_variable"),
    [
        ((1 << 64) - 1, "length"),
        (((1 << 64) - 1) // 4, "other"),
    ],
)
def test_wrong_range_or_irrelevant_comparison_does_not_suppress_finding(
    threshold: int,
    compared_variable: str,
) -> None:
    ir = _integer_guard_cfg(
        threshold=threshold,
        compared_variable=compared_variable,
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert len(report.findings) == 1
    assert report.findings[0].vulnerability_class is BinaryVulnerabilityClass.INTEGER_OVERFLOW


def test_signed_size_comparison_does_not_suppress_unsigned_overflow() -> None:
    maximum_input = ((1 << 64) - 1) // 4
    ir = _integer_guard_cfg(
        threshold=maximum_input,
        comparison_kind="signed_less_equal",
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert len(report.findings) == 1
    assert report.findings[0].vulnerability_class is BinaryVulnerabilityClass.INTEGER_OVERFLOW


def test_dominating_copy_length_guard_suppresses_allocation_mismatch() -> None:
    base = 0x100001000
    checked = base + 0x40
    rejected = base + 0x80
    ir = _cfg_ir(
        [
            _block(
                "entry",
                base,
                ["checked", "rejected"],
                [
                    _instruction(
                        base,
                        "param",
                        result="alloc_size",
                        tags=["input_length"],
                    ),
                    _instruction(
                        base + 4,
                        "param",
                        result="copy_length",
                        tags=["input_length"],
                    ),
                    _instruction(
                        base + 8,
                        "cmp",
                        result="condition",
                        inputs=["copy_length", "alloc_size"],
                        tags=["comparison:unsigned_less_equal"],
                    ),
                    _conditional_branch(
                        base + 12,
                        condition="condition",
                        true_target=checked,
                    ),
                ],
            ),
            _block(
                "checked",
                checked,
                [],
                [
                    _instruction(
                        checked,
                        "alloc",
                        result="buffer",
                        inputs=["alloc_size"],
                        target="malloc",
                    ),
                    _instruction(
                        checked + 4,
                        "copy",
                        inputs=["buffer", "source", "copy_length"],
                        target="memcpy",
                    ),
                ],
            ),
            _block("rejected", rejected, [], [_instruction(rejected, "ret")]),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert report.findings == ()


def test_reversed_copy_guard_uses_non_taken_safe_edge() -> None:
    base = 0x100001000
    checked = base + 0x40
    rejected = base + 0x80
    ir = _cfg_ir(
        [
            _block(
                "entry",
                base,
                ["checked", "rejected"],
                [
                    _instruction(
                        base,
                        "param",
                        result="alloc_size",
                        tags=["input_length"],
                    ),
                    _instruction(
                        base + 4,
                        "param",
                        result="copy_length",
                        tags=["input_length"],
                    ),
                    _instruction(
                        base + 8,
                        "cmp",
                        result="condition",
                        inputs=["alloc_size", "copy_length"],
                        tags=["comparison:unsigned_less"],
                    ),
                    _conditional_branch(
                        base + 12,
                        condition="condition",
                        true_target=rejected,
                    ),
                ],
            ),
            _block(
                "checked",
                checked,
                [],
                [
                    _instruction(
                        checked,
                        "alloc",
                        result="buffer",
                        inputs=["alloc_size"],
                        target="malloc",
                    ),
                    _instruction(
                        checked + 4,
                        "copy",
                        inputs=["buffer", "source", "copy_length"],
                        target="memcpy",
                    ),
                ],
            ),
            _block("rejected", rejected, [], [_instruction(rejected, "ret")]),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert report.findings == ()


def test_pointer_address_formation_is_not_integer_overflow() -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(base, "param", result="data", tags=["input_data"]),
            _instruction(base + 4, "param", result="index", tags=["input_length"]),
            _instruction(
                base + 8,
                "int_add",
                result="address",
                inputs=["data", "index"],
                tags=["pointer_arithmetic"],
            ),
            _instruction(base + 12, "load", result="value", inputs=["address"]),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert report.findings == ()


def test_pointer_offset_plus_length_retains_oob_candidate() -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(base, "param", result="offset", tags=["input_offset"]),
            _instruction(base + 4, "param", result="length", tags=["input_length"]),
            _instruction(
                base + 8,
                "int_add",
                result="end",
                inputs=["offset", "length"],
                tags=["pointer_arithmetic"],
            ),
            _instruction(base + 12, "load", result="value", inputs=["end"]),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert len(report.findings) == 1
    assert report.findings[0].vulnerability_class is BinaryVulnerabilityClass.OFFSET_LENGTH_OOB


@pytest.mark.parametrize("parameter_tags", [[], ["decoder_entry"]])
def test_parameter_without_explicit_input_tag_is_not_tainted(
    parameter_tags: list[str],
) -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(base, "param", result="param_1", tags=parameter_tags),
            _instruction(
                base + 4,
                "int_add",
                result="address",
                inputs=["param_1"],
                constants=[24],
            ),
            _instruction(base + 8, "load", result="value", inputs=["address"]),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert report.findings == ()


def test_typed_api_result_propagates_through_cast_to_size_sink() -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(
                base,
                "call",
                result="length32",
                target="_CFDataGetLength",
                tags=["input_length", "source_api:cf_data_length"],
            ),
            _instruction(
                base + 4,
                "cast",
                result="length",
                inputs=["length32"],
            ),
            _instruction(
                base + 8,
                "int_mult",
                result="bytes",
                inputs=["length"],
                constants=[4],
            ),
            _instruction(
                base + 12,
                "alloc",
                result="buffer",
                inputs=["bytes"],
                target="malloc",
            ),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert len(report.findings) == 1
    assert report.findings[0].vulnerability_class is BinaryVulnerabilityClass.INTEGER_OVERFLOW


def test_provider_length_result_retains_pointer_offset_oob_detection() -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(base, "param", result="offset", tags=["input_offset"]),
            _instruction(
                base + 4,
                "call",
                result="length",
                target="_CGImageProviderGetSize",
                tags=["input_length", "source_api:image_provider_length"],
            ),
            _instruction(
                base + 8,
                "int_add",
                result="end",
                inputs=["offset", "length"],
                tags=["pointer_arithmetic"],
            ),
            _instruction(base + 12, "load", result="value", inputs=["end"]),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert len(report.findings) == 1
    assert report.findings[0].vulnerability_class is BinaryVulnerabilityClass.OFFSET_LENGTH_OOB


@pytest.mark.parametrize(
    ("operation", "inputs"),
    [
        ("load", ["const_space", "end"]),
        ("store", ["const_space", "end", "value"]),
    ],
)
def test_ghidra_memory_address_operand_retains_oob_detection(
    operation: str,
    inputs: list[str],
) -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(base, "param", result="offset", tags=["input_offset"]),
            _instruction(base + 4, "param", result="length", tags=["input_length"]),
            _instruction(
                base + 8,
                "int_add",
                result="end",
                inputs=["offset", "length"],
                tags=["pointer_arithmetic"],
            ),
            _instruction(base + 12, operation, result="value", inputs=inputs),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert len(report.findings) == 1
    assert report.findings[0].vulnerability_class is BinaryVulnerabilityClass.OFFSET_LENGTH_OOB


def test_ghidra_store_value_is_not_treated_as_an_address_sink() -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(base, "param", result="length", tags=["input_length"]),
            _instruction(
                base + 4,
                "int_mult",
                result="bytes",
                inputs=["length"],
                constants=[4],
            ),
            _instruction(
                base + 8,
                "store",
                inputs=["const_space", "destination", "bytes"],
            ),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert report.findings == ()


@pytest.mark.parametrize(
    ("target", "inputs"),
    [
        ("realloc", ["old_buffer", "bytes"]),
        ("_malloc_type_realloc", ["old_buffer", "bytes", "type_cookie"]),
        ("CFAllocatorAllocate", ["allocator", "bytes", "hint"]),
        ("malloc_zone_malloc", ["zone", "bytes"]),
        ("__ImageIO_Malloc", ["bytes", "alignment", "metadata"]),
    ],
)
def test_typed_allocator_size_operand_detects_integer_overflow(
    target: str,
    inputs: list[str],
) -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(base, "param", result="length", tags=["input_length"]),
            _instruction(
                base + 4,
                "int_mult",
                result="bytes",
                inputs=["length"],
                constants=[8],
            ),
            _instruction(
                base + 8,
                "alloc",
                result="buffer",
                inputs=inputs,
                target=target,
            ),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert len(report.findings) == 1
    assert report.findings[0].vulnerability_class is BinaryVulnerabilityClass.INTEGER_OVERFLOW


def test_malloc_type_cookie_is_not_treated_as_allocation_size() -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(base, "param", result="length", tags=["input_length"]),
            _instruction(
                base + 4,
                "int_mult",
                result="type_cookie",
                inputs=["length"],
                constants=[8],
            ),
            _instruction(
                base + 8,
                "alloc",
                result="buffer",
                inputs=["safe_size", "type_cookie"],
                target="_malloc_type_malloc",
            ),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert report.findings == ()


def test_calloc_composite_capacity_is_not_guessed_from_one_operand() -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(base, "param", result="length", tags=["input_length"]),
            _instruction(
                base + 4,
                "int_mult",
                result="count",
                inputs=["length"],
                constants=[8],
            ),
            _instruction(
                base + 8,
                "alloc",
                result="buffer",
                inputs=["count", "element_size", "type_cookie"],
                target="_malloc_type_calloc",
            ),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert report.findings == ()


def test_bcopy_uses_second_operand_as_destination() -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(base, "param", result="alloc_size", tags=["input_length"]),
            _instruction(base + 4, "param", result="copy_length", tags=["input_length"]),
            _instruction(
                base + 8,
                "alloc",
                result="buffer",
                inputs=["alloc_size"],
                target="malloc",
            ),
            _instruction(
                base + 12,
                "copy",
                inputs=["source", "buffer", "copy_length"],
                target="bcopy",
            ),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert len(report.findings) == 1
    assert (
        report.findings[0].vulnerability_class
        is BinaryVulnerabilityClass.ALLOCATION_COPY_MISMATCH
    )


def test_bcopy_destination_address_retains_oob_detection() -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(base, "param", result="offset", tags=["input_offset"]),
            _instruction(base + 4, "param", result="length", tags=["input_length"]),
            _instruction(
                base + 8,
                "int_add",
                result="destination",
                inputs=["offset", "length"],
                tags=["pointer_arithmetic"],
            ),
            _instruction(
                base + 12,
                "copy",
                inputs=["source", "destination", "safe_length"],
                target="bcopy",
            ),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert len(report.findings) == 1
    assert report.findings[0].vulnerability_class is BinaryVulnerabilityClass.OFFSET_LENGTH_OOB


def test_imageio_malloc_cold_helper_is_not_an_allocator_size_sink() -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(base, "param", result="length", tags=["input_length"]),
            _instruction(
                base + 4,
                "int_mult",
                result="bytes",
                inputs=["length"],
                constants=[8],
            ),
            _instruction(
                base + 8,
                "alloc",
                result="buffer",
                inputs=["bytes"],
                target="__ImageIO_Malloc.cold.1",
            ),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert report.findings == ()


def test_name_only_memcpy_wrapper_does_not_acquire_copy_roles() -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(base, "param", result="alloc_size", tags=["input_length"]),
            _instruction(base + 4, "param", result="copy_length", tags=["input_length"]),
            _instruction(
                base + 8,
                "alloc",
                result="buffer",
                inputs=["alloc_size"],
                target="malloc",
            ),
            _instruction(
                base + 12,
                "copy",
                inputs=["buffer", "source", "copy_length"],
                target="custom_memcpy_wrapper",
            ),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert report.findings == ()


@pytest.mark.parametrize("call_tags", [[], ["decoder_entry"]])
def test_call_result_without_explicit_input_tag_is_not_tainted(
    call_tags: list[str],
) -> None:
    base = 0x100001000
    ir = _single_function_ir(
        [
            _instruction(
                base,
                "call",
                result="length",
                target="untrusted_name_only",
                tags=call_tags,
            ),
            _instruction(
                base + 4,
                "int_mult",
                result="bytes",
                inputs=["length"],
                constants=[4],
            ),
            _instruction(
                base + 8,
                "alloc",
                result="buffer",
                inputs=["bytes"],
                target="malloc",
            ),
        ]
    )

    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert report.findings == ()


def test_use_after_free_is_ordered_first_by_severity() -> None:
    ir = _normalized_ir()
    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))

    assert report.findings[0].vulnerability_class is BinaryVulnerabilityClass.USE_AFTER_FREE
    assert report.findings[0].severity.value == "critical"


def test_analyzer_limits_are_fail_bounded() -> None:
    ir = _normalized_ir()
    report = analyze_binary_candidates(
        ir,
        discover_imageio_parsers(ir),
        limits=BinaryAnalyzerLimits(maximum_findings=1),
    )
    assert len(report.findings) == 1


def test_analysis_rejects_discovery_from_different_ir() -> None:
    first = _normalized_ir(version="11.4")
    second = _normalized_ir(version="11.5")

    with pytest.raises(ValueError, match="not bound"):
        analyze_binary_candidates(first, discover_imageio_parsers(second))


def test_analysis_report_rejects_tampered_finding() -> None:
    ir = _normalized_ir()
    report = analyze_binary_candidates(ir, discover_imageio_parsers(ir))
    payload = report.model_dump(mode="json")
    payload["findings"][0]["summary"] = "tampered"

    with pytest.raises(ValidationError, match="digest does not match"):
        BinaryAnalysisReport.model_validate(payload)
