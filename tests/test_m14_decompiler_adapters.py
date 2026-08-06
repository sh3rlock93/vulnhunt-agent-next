from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.binary_analysis import (
    BinaryNinjaJSONAdapter,
    GhidraJSONAdapter,
    IROperation,
    NormalizedBinaryIR,
    load_decompiler_export,
)

_SNAPSHOT = "sha256:" + "1" * 64
_IMAGE_UUID = "12345678-1234-5678-9ABC-DEF012345678"
_NOW = datetime(2026, 7, 30, 2, 0, tzinfo=UTC)


def _ghidra_export() -> dict[str, object]:
    return {
        "schema_version": "ghidra-imageio-export-v1",
        "decompiler_version": "11.4",
        "snapshot_sha256": _SNAPSHOT,
        "image": {
            "name": "ImageIO",
            "uuid": _IMAGE_UUID.lower(),
            "architecture": "arm64",
            "base_address": "0x100000000",
        },
        "imports": ["memcpy", "malloc", "memcpy"],
        "strings": [
            {"address": "0x100003000", "value": "DNG", "references": ["0x100001004"]}
        ],
        "functions": [
            {
                "entry": "0x100001000",
                "size": 64,
                "name": "decode_dng",
                "parameters": ["length", "data"],
                "pseudocode": "void decode_dng(void *data, size_t length) { ... }",
                "blocks": [
                    {
                        "name": "entry",
                        "start": "0x100001000",
                        "size": 32,
                        "successors": ["exit"],
                        "instructions": [
                            {
                                "address": "0x100001000",
                                "op": "param",
                                "result": "length",
                                "inputs": [],
                                "tags": ["input_length"],
                                "text": "length = param",
                            },
                            {
                                "address": "0x100001004",
                                "op": "int_mult",
                                "result": "bytes",
                                "inputs": ["length"],
                                "constants": [4],
                                "width": 64,
                                "signed": False,
                                "text": "bytes = length * 4",
                            },
                            {
                                "address": "0x100001008",
                                "op": "alloc",
                                "result": "buffer",
                                "inputs": ["bytes"],
                                "target": "malloc",
                                "text": "buffer = malloc(bytes)",
                            },
                        ],
                    },
                    {
                        "name": "exit",
                        "start": "0x100001020",
                        "size": 32,
                        "successors": [],
                        "instructions": [
                            {
                                "address": "0x100001020",
                                "op": "ret",
                                "inputs": [],
                                "text": "return",
                            }
                        ],
                    },
                ],
            }
        ],
    }


def _binary_ninja_export() -> dict[str, object]:
    return {
        "format": "binary-ninja-imageio-export-v1",
        "version": "4.2",
        "source_snapshot": _SNAPSHOT,
        "binary": {
            "filename": "ImageIO",
            "uuid": _IMAGE_UUID,
            "arch": "arm64",
            "start": 0x100000000,
        },
        "externals": ["malloc", "memcpy"],
        "data_strings": [
            {"start": 0x100003000, "text": "DNG", "code_refs": [0x100001004]}
        ],
        "routines": [
            {
                "start": 0x100001000,
                "length": 64,
                "display_name": "decode_dng",
                "arguments": ["data", "length"],
                "pseudocode": "void decode_dng(void *data, size_t length) { ... }",
                "basic_blocks": [
                    {
                        "index": 0,
                        "start": 0x100001000,
                        "length": 32,
                        "outgoing": [1],
                        "high_level_il": [
                            {
                                "address": 0x100001000,
                                "operation": "parameter",
                                "result": "length",
                                "sources": [],
                                "tags": ["input_length"],
                                "text": "length = param",
                            },
                            {
                                "address": 0x100001004,
                                "operation": "mul",
                                "result": "bytes",
                                "sources": ["length"],
                                "constants": [4],
                                "width": 64,
                                "signed": False,
                                "text": "bytes = length * 4",
                            },
                            {
                                "address": 0x100001008,
                                "operation": "allocate",
                                "result": "buffer",
                                "sources": ["bytes"],
                                "target": "malloc",
                                "text": "buffer = malloc(bytes)",
                            },
                        ],
                    },
                    {
                        "index": 1,
                        "start": 0x100001020,
                        "length": 32,
                        "outgoing": [],
                        "high_level_il": [
                            {
                                "address": 0x100001020,
                                "operation": "return",
                                "sources": [],
                                "text": "return",
                            }
                        ],
                    },
                ],
            }
        ],
    }


def _coverage_function(address: int, name: str) -> dict[str, object]:
    return {
        "entry": hex(address),
        "size": 32,
        "name": name,
        "parameters": [],
        "pseudocode": "",
        "blocks": [
            {
                "name": "entry",
                "start": hex(address),
                "size": 32,
                "successors": [],
                "instructions": [
                    {
                        "address": hex(address),
                        "op": "unknown",
                        "inputs": [],
                        "text": "bounded placeholder",
                    }
                ],
            }
        ],
    }


def _coverage_export() -> dict[str, object]:
    payload = _ghidra_export()
    payload["schema_version"] = "ghidra-imageio-export-v2"
    payload["functions"] = [
        _coverage_function(0x100000100, "read_sgi"),
        _coverage_function(0x100900100, "FUN_100900100"),
    ]
    payload["function_coverage"] = {
        "schema_version": "ghidra-function-coverage-v1",
        "snapshot_sha256": _SNAPSHOT,
        "maximum_functions": 1,
        "maximum_evidence_functions": 8,
        "callgraph_depth": 2,
        "warnings": ["function_export_cap_saturated"],
        "functions": [
            {
                "entry": "0x100000100",
                "size": 32,
                "name": "read_sgi",
                "direct_strings": ["public.sgi-image"],
                "callers": [],
                "callees": ["0x100900100"],
                "selected": True,
                "selection_tier": "mandatory",
                "selection_reasons": ["name_marker:read", "name_marker:sgi"],
            },
            {
                "entry": "0x100001000",
                "size": 32,
                "name": "generic_unreferenced",
                "direct_strings": [],
                "callers": [],
                "callees": [],
                "selected": False,
                "selection_reasons": [],
                "omission_reason": "fallback_cap_reached",
            },
            {
                "entry": "0x100900100",
                "size": 32,
                "name": "FUN_100900100",
                "direct_strings": ["decode SGI RLE compressed"],
                "callers": ["0x100000100"],
                "callees": [],
                "selected": True,
                "selection_tier": "mandatory",
                "selection_reasons": ["string_marker:rle", "string_marker:sgi"],
            },
        ],
    }
    return payload


def _stack_probe_export(*, tagged: bool = True) -> dict[str, object]:
    payload = _ghidra_export()
    payload["functions"] = [
        {
            "entry": "0x100001000",
            "size": 64,
            "name": "read_large_frame",
            "parameters": ["this", "destination", "offset", "length"],
            "pseudocode": "probe_result = (*probe)(); sink(probe_result.hi, length);",
            "blocks": [
                {
                    "name": "entry",
                    "start": "0x100001000",
                    "size": 64,
                    "successors": [],
                    "instructions": [
                        {
                            "address": "0x100001000",
                            "op": "param",
                            "result": parameter,
                            "inputs": [],
                            "text": f"{parameter} = parameter",
                        }
                        for parameter in ("this", "destination", "offset", "length")
                    ]
                    + [
                        {
                            "address": "0x100001010",
                            "op": "call",
                            "result": "probe_result",
                            "inputs": [],
                            "target": "DAT_probe",
                            "width": 128,
                            "tags": (
                                ["abi:argument_preserving_stack_probe"] if tagged else []
                            ),
                            "text": "CALLIND probe",
                        },
                        {
                            "address": "0x100001010",
                            "op": "cast",
                            "result": "saved_x0",
                            "inputs": ["probe_result", "const_0"],
                            "constants": [0],
                            "width": 64,
                            "text": "SUBPIECE probe_result, 0",
                        },
                        {
                            "address": "0x100001010",
                            "op": "cast",
                            "result": "saved_x1",
                            "inputs": ["probe_result", "const_8"],
                            "constants": [8],
                            "width": 64,
                            "text": "SUBPIECE probe_result, 8",
                        },
                        {
                            "address": "0x100001018",
                            "op": "call",
                            "result": "written",
                            "inputs": ["saved_x1", "length"],
                            "target": "read_bytes",
                            "width": 64,
                            "text": "CALL read_bytes(saved_x1, length)",
                        },
                    ],
                }
            ],
        }
    ]
    return payload


@pytest.mark.parametrize(
    ("adapter", "payload", "engine"),
    [
        (GhidraJSONAdapter(), _ghidra_export(), "ghidra"),
        (BinaryNinjaJSONAdapter(), _binary_ninja_export(), "binary_ninja"),
    ],
)
def test_adapters_normalize_addresses_control_flow_and_operations(
    adapter: GhidraJSONAdapter | BinaryNinjaJSONAdapter,
    payload: dict[str, object],
    engine: str,
) -> None:
    ir = adapter.normalize(payload, expected_snapshot_sha256=_SNAPSHOT, created_at=_NOW)

    assert ir.decompiler_engine.value == engine
    assert ir.image_uuid == _IMAGE_UUID
    assert ir.imports == ("malloc", "memcpy")
    assert ir.strings[0].referenced_at == (0x100001004,)
    function = ir.functions[0]
    assert function.parameters == ("data", "length")
    assert [item.operation for item in function.blocks[0].instructions] == [
        IROperation.PARAMETER,
        IROperation.MULTIPLY,
        IROperation.ALLOCATE,
    ]
    assert function.blocks[0].successors == (function.blocks[1].block_id,)
    assert function.pseudocode_sha256.startswith("sha256:")


def test_tagged_stack_probe_restores_argument_register_aliases() -> None:
    ir = GhidraJSONAdapter().normalize(
        _stack_probe_export(), expected_snapshot_sha256=_SNAPSHOT, created_at=_NOW
    )
    instructions = ir.functions[0].blocks[0].instructions
    by_result = {item.result: item for item in instructions if item.result is not None}

    assert by_result["saved_x0"].operands[0] == "this"
    assert by_result["saved_x1"].operands[0] == "destination"
    assert by_result["saved_x0"].tags == ("abi:preserved_argument",)
    assert "stack-probe preserved argument: destination" in by_result["saved_x1"].text


def test_untagged_indirect_call_does_not_restore_argument_aliases() -> None:
    ir = GhidraJSONAdapter().normalize(
        _stack_probe_export(tagged=False),
        expected_snapshot_sha256=_SNAPSHOT,
        created_at=_NOW,
    )
    instructions = ir.functions[0].blocks[0].instructions
    by_result = {item.result: item for item in instructions if item.result is not None}

    assert by_result["saved_x0"].operands[0] == "probe_result"
    assert by_result["saved_x1"].operands[0] == "probe_result"
    assert "abi:preserved_argument" not in by_result["saved_x1"].tags


def test_normalized_ir_identity_excludes_creation_time() -> None:
    adapter = GhidraJSONAdapter()
    first = adapter.normalize(_ghidra_export(), expected_snapshot_sha256=_SNAPSHOT, created_at=_NOW)
    second = adapter.normalize(
        _ghidra_export(),
        expected_snapshot_sha256=_SNAPSHOT,
        created_at=_NOW + timedelta(hours=2),
    )

    assert first.created_at != second.created_at
    assert first.ir_sha256 == second.ir_sha256


def test_v2_coverage_preserves_mandatory_xref_seeds_beyond_fallback_cap() -> None:
    ir = GhidraJSONAdapter().normalize(
        _coverage_export(), expected_snapshot_sha256=_SNAPSHOT, created_at=_NOW
    )

    assert {item.name for item in ir.functions} == {"read_sgi", "FUN_100900100"}
    assert ir.function_coverage is not None
    assert ir.function_coverage.maximum_functions == 1
    assert ir.function_coverage.selected_function_count == 2
    assert ir.function_coverage.cap_saturated is True
    by_name = {item.name: item for item in ir.function_coverage.functions}
    assert by_name["FUN_100900100"].direct_strings == (
        "decode SGI RLE compressed",
    )
    assert by_name["generic_unreferenced"].selected is False
    assert by_name["generic_unreferenced"].omission_reason == "fallback_cap_reached"


def test_exporter_promotes_range_reader_direct_callees_before_evidence_cap() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "tools" / "ghidra" / "ExportImageIOIR.java"
    ).read_text(encoding="utf-8")

    closure = source.index("for (CoverageRow boundary : rangeReaderBoundaries)")
    exclusivity = source.index("callee.callers.size() != 1", closure)
    reason = source.index("range_reader_exclusive_callee:seed=", exclusivity)
    evidence_cap = source.index("if (frontier.size() > maximumEvidence)", reason)

    assert closure < exclusivity < reason < evidence_cap
    assert "for (long target : boundary.callees)" in source[closure:evidence_cap]
    assert "!callee.callers.contains(boundary.entry())" in source[closure:evidence_cap]
    assert 'callee.selectionTier = "mandatory"' in source[closure:evidence_cap]
    assert "frontier.sort(Comparator.comparingLong(CoverageRow::entry))" in source[
        closure:evidence_cap
    ]


def test_exporter_promotes_parser_owner_constructors_before_evidence_cap() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "tools" / "ghidra" / "ExportImageIOIR.java"
    ).read_text(encoding="utf-8")

    owners = source.index("TreeSet<String> parserOwners")
    promotion = source.index("for (CoverageRow row : rows)", owners + 1)
    constructor = source.index("isOwnerConstructor(row.function, owner)", promotion)
    reason = source.index("parser_owner_constructor:owner=", constructor)
    evidence_cap = source.index("if (frontier.size() > maximumEvidence)", reason)
    helper = source.index("private boolean isOwnerConstructor")

    assert owners < promotion < constructor < reason < evidence_cap < helper
    assert 'row.selectionTier = "mandatory"' in source[reason:evidence_cap]
    assert "function.getName().equals(leaf)" in source[helper:]


def test_exporter_requires_exact_arm64e_stack_probe_sequence() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "tools" / "ghidra" / "ExportImageIOIR.java"
    ).read_text(encoding="utf-8")

    start = source.index("private boolean isArgumentPreservingStackProbe")
    stop = source.index("private void appendDirectCalleeAddressTag", start)
    contract = source[start:stop]

    assert 'mnemonic.equals("CALLIND")' in contract
    assert 'machineInstruction(call, "BLRAA", "x16", "x17")' in contract
    assert 'machineInstruction(load, "LDR", "x16", "[x17]")' in contract
    assert 'machineInstruction(add, "ADD", "x17", "x17")' in contract
    assert 'machineInstruction(page, "ADRP", "x17")' in contract
    assert 'machineInstruction(allocate, "SUB", "sp", "sp")' in contract
    assert 'tags.add("abi:argument_preserving_stack_probe")' in source


def test_coverage_manifest_is_deterministic_and_digest_bound() -> None:
    adapter = GhidraJSONAdapter()
    first = adapter.normalize(
        _coverage_export(), expected_snapshot_sha256=_SNAPSHOT, created_at=_NOW
    )
    second = adapter.normalize(
        _coverage_export(), expected_snapshot_sha256=_SNAPSHOT, created_at=_NOW
    )
    assert first.function_coverage == second.function_coverage
    assert first.ir_sha256 == second.ir_sha256

    changed_payload = copy.deepcopy(_coverage_export())
    coverage = cast(dict[str, Any], changed_payload["function_coverage"])
    functions = cast(list[dict[str, Any]], coverage["functions"])
    functions[2]["direct_strings"] = ["decode SGI RLE changed UTI"]
    changed = adapter.normalize(
        changed_payload, expected_snapshot_sha256=_SNAPSHOT, created_at=_NOW
    )
    assert changed.function_coverage is not None
    assert first.function_coverage is not None
    assert changed.function_coverage.coverage_sha256 != (
        first.function_coverage.coverage_sha256
    )
    assert changed.ir_sha256 != first.ir_sha256

    reason_payload = copy.deepcopy(_coverage_export())
    reason_coverage = cast(dict[str, Any], reason_payload["function_coverage"])
    reason_functions = cast(list[dict[str, Any]], reason_coverage["functions"])
    reason_functions[2]["selection_reasons"] = [
        "string_marker:decode",
        "string_marker:rle",
        "string_marker:sgi",
    ]
    reason_changed = adapter.normalize(
        reason_payload, expected_snapshot_sha256=_SNAPSHOT, created_at=_NOW
    )
    assert reason_changed.function_coverage is not None
    assert reason_changed.function_coverage.coverage_sha256 != (
        first.function_coverage.coverage_sha256
    )

    xref_payload = copy.deepcopy(_coverage_export())
    xref_coverage = cast(dict[str, Any], xref_payload["function_coverage"])
    xref_functions = cast(list[dict[str, Any]], xref_coverage["functions"])
    xref_functions[2]["callers"] = ["0x100000100", "0x100000120"]
    xref_changed = adapter.normalize(
        xref_payload, expected_snapshot_sha256=_SNAPSHOT, created_at=_NOW
    )
    assert xref_changed.function_coverage is not None
    assert xref_changed.function_coverage.coverage_sha256 != (
        first.function_coverage.coverage_sha256
    )


def test_v3_virtual_method_reference_is_normalized_and_digest_bound() -> None:
    payload = _coverage_export()
    payload["schema_version"] = "ghidra-imageio-export-v3"
    payload["virtual_methods"] = [
        {
            "owner": "SGIReadPlugin",
            "vtable_symbol": "SGIReadPlugin::vtable",
            "vtable_address": "0x200000000",
            "address_point": "0x200000010",
            "slot_offset": 0xD8,
            "reference_address": "0x2000000e8",
            "target_entry": "0x100000100",
        }
    ]
    adapter = GhidraJSONAdapter()

    first = adapter.normalize(payload, expected_snapshot_sha256=_SNAPSHOT, created_at=_NOW)
    second = adapter.normalize(payload, expected_snapshot_sha256=_SNAPSHOT, created_at=_NOW)

    assert first.virtual_methods == second.virtual_methods
    assert first.virtual_methods[0].owner == "SGIReadPlugin"
    assert first.virtual_methods[0].slot_offset == 0xD8
    assert first.virtual_methods[0].reference_address == 0x2000000E8
    assert first.virtual_methods[0].target_function_id == first.functions[0].function_id
    assert first.ir_sha256 == second.ir_sha256

    changed = copy.deepcopy(payload)
    virtual_methods = cast(list[dict[str, Any]], changed["virtual_methods"])
    virtual_methods[0]["slot_offset"] = 0xE0
    virtual_methods[0]["reference_address"] = "0x2000000f0"
    changed_ir = adapter.normalize(
        changed, expected_snapshot_sha256=_SNAPSHOT, created_at=_NOW
    )
    assert changed_ir.ir_sha256 != first.ir_sha256


def test_v3_virtual_method_reference_rejects_misaligned_slot() -> None:
    payload = _coverage_export()
    payload["schema_version"] = "ghidra-imageio-export-v3"
    payload["virtual_methods"] = [
        {
            "owner": "SGIReadPlugin",
            "vtable_symbol": "SGIReadPlugin::vtable",
            "vtable_address": "0x200000000",
            "address_point": "0x200000010",
            "slot_offset": 3,
            "reference_address": "0x200000013",
            "target_entry": "0x100000100",
        }
    ]

    with pytest.raises(ValidationError, match="pointer aligned"):
        GhidraJSONAdapter().normalize(payload, expected_snapshot_sha256=_SNAPSHOT)


def test_v3_virtual_method_reference_rejects_absent_target() -> None:
    payload = _coverage_export()
    payload["schema_version"] = "ghidra-imageio-export-v3"
    payload["virtual_methods"] = [
        {
            "owner": "SGIReadPlugin",
            "vtable_symbol": "SGIReadPlugin::vtable",
            "vtable_address": "0x200000000",
            "address_point": "0x200000010",
            "slot_offset": 0xD8,
            "reference_address": "0x2000000e8",
            "target_entry": "0x1000ffff0",
        }
    ]

    with pytest.raises(ValidationError, match="absent or mismatched function"):
        GhidraJSONAdapter().normalize(payload, expected_snapshot_sha256=_SNAPSHOT)


def test_v2_export_must_exactly_match_coverage_selection() -> None:
    payload = _coverage_export()
    functions = cast(list[dict[str, Any]], payload["functions"])
    functions.pop()

    with pytest.raises(ValueError, match="do not match the coverage selection"):
        GhidraJSONAdapter().normalize(payload, expected_snapshot_sha256=_SNAPSHOT)


def test_normalized_ir_rejects_tampered_instruction() -> None:
    ir = GhidraJSONAdapter().normalize(
        _ghidra_export(), expected_snapshot_sha256=_SNAPSHOT, created_at=_NOW
    )
    payload = ir.model_dump(mode="json")
    payload["functions"][0]["blocks"][0]["instructions"][1]["constants"] = [8]

    with pytest.raises(ValidationError, match="digest does not match"):
        NormalizedBinaryIR.model_validate(payload)


def test_adapter_rejects_snapshot_mismatch_and_unknown_successor() -> None:
    adapter = GhidraJSONAdapter()
    with pytest.raises(ValueError, match="not bound"):
        adapter.normalize(_ghidra_export(), expected_snapshot_sha256="sha256:" + "2" * 64)

    payload = _ghidra_export()
    functions = cast(list[dict[str, Any]], payload["functions"])
    functions[0]["blocks"][0]["successors"] = ["missing"]
    with pytest.raises(ValueError, match="unknown successor"):
        adapter.normalize(payload, expected_snapshot_sha256=_SNAPSHOT)


def test_unknown_operation_is_preserved_without_guessing() -> None:
    payload = _ghidra_export()
    functions = cast(list[dict[str, Any]], payload["functions"])
    instruction = functions[0]["blocks"][0]["instructions"][1]
    instruction["op"] = "FLOAT_NEGATE"
    ir = GhidraJSONAdapter().normalize(payload, expected_snapshot_sha256=_SNAPSHOT)

    normalized = ir.functions[0].blocks[0].instructions[1]
    assert normalized.operation is IROperation.UNKNOWN
    assert "source_op:float_negate" in normalized.tags


def test_ghidra_indirect_preserves_address_taken_call_output_dependency() -> None:
    payload = _ghidra_export()
    functions = cast(list[dict[str, Any]], payload["functions"])
    functions[0]["blocks"] = [
        {
            "name": "entry",
            "start": "0x100001000",
            "size": 32,
            "successors": [],
            "instructions": [
                {
                    "address": "0x100001000",
                    "op": "int_sub",
                    "result": "out_extent_ptr",
                    "inputs": ["sp", "const_ffffffffffffff58"],
                    "tags": ["pointer_arithmetic"],
                    "text": "PTRSUB sp, 0xffffffffffffff58",
                },
                {
                    "address": "0x100001008",
                    "op": "alloc",
                    "result": "buffer",
                    "inputs": ["bytes", "alignment", "out_extent_ptr"],
                    "target": "__ImageIO_Malloc",
                    "text": "buffer = __ImageIO_Malloc(bytes, alignment, &extent)",
                },
                {
                    "address": "0x100001008",
                    "op": "INDIRECT",
                    "result": (
                        "local_a8_stack_ffffffffffffff58_8_100001008_6260"
                    ),
                    "inputs": ["extent_before_call", "const_e3"],
                    "width": 64,
                    "text": "INDIRECT extent",
                },
            ],
        }
    ]
    functions[0]["pseudocode"] = (
        "buffer = __ImageIO_Malloc(bytes, alignment, &local_a8);"
    )

    ir = GhidraJSONAdapter().normalize(payload, expected_snapshot_sha256=_SNAPSHOT)
    instructions = ir.functions[0].blocks[0].instructions
    effect = next(item for item in instructions if item.operation is IROperation.INDIRECT)

    assert effect.operands == (
        "extent_before_call",
        "const_e3",
        "out_extent_ptr",
        "buffer",
    )
    assert "source_op:indirect" in effect.tags
    assert "side_effect:address_taken_out_parameter" in effect.tags
    assert "out_parameter_index:2" in effect.tags
    assert "address-taken call output argument 2: out_extent_ptr" in effect.text


def test_file_loader_rejects_symlink_and_loads_regular_json(tmp_path: Path) -> None:
    export = tmp_path / "ghidra.json"
    export.write_text(json.dumps(_ghidra_export()), encoding="utf-8")
    loaded = load_decompiler_export(
        export,
        adapter=GhidraJSONAdapter(),
        expected_snapshot_sha256=_SNAPSHOT,
        created_at=_NOW,
    )
    assert loaded.image_name == "ImageIO"

    linked = tmp_path / "linked.json"
    linked.symlink_to(export)
    with pytest.raises(ValueError, match="non-symlink"):
        load_decompiler_export(
            linked,
            adapter=GhidraJSONAdapter(),
            expected_snapshot_sha256=_SNAPSHOT,
        )
