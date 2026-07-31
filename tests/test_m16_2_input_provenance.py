from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.binary_analysis import (
    BinaryProvenanceReport,
    BinaryScalarUseKind,
    GhidraJSONAdapter,
    IROperation,
    analyze_input_scalar_provenance,
    discover_imageio_parsers,
)

_SNAPSHOT = "sha256:" + "6" * 64
_UUID = "62345678-1234-5678-9ABC-DEF012345678"
_BASE = 0x100001000


def _instruction(
    address: int,
    operation: str,
    *,
    result: str | None = None,
    inputs: list[str] | None = None,
    target: str | None = None,
    tags: list[str] | None = None,
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
                "size": 0x400,
                "name": "decode_SGI_RLEcompressed",
                "parameters": [],
                "pseudocode": "void decode_SGI_RLEcompressed(void) { /* fixture */ }",
                "blocks": blocks,
            }
        ],
    }
    return GhidraJSONAdapter().normalize(
        payload,
        expected_snapshot_sha256=_SNAPSHOT,
        created_at=datetime(2026, 7, 31, 8, 0, tzinfo=UTC),
    )


def _report(blocks: list[dict[str, Any]]) -> BinaryProvenanceReport:
    ir = _ir(blocks)
    return analyze_input_scalar_provenance(ir, discover_imageio_parsers(ir))


def test_read_session_scalars_survive_swaps_phi_and_cross_block_roles() -> None:
    merge = _BASE + 0x100
    report = _report(
        [
            _block(
                "entry",
                _BASE,
                [
                    _instruction(
                        _BASE,
                        "call",
                        inputs=["session", "header", "file_offset", "header_size"],
                        target="IIOImageReadSessionGetBytesAtOffset",
                        tags=[
                            "decoder_entry",
                            "input_buffer_operand:1",
                            "read_session_input",
                            "scalar_role:offset:2",
                            "scalar_role:requested_length:3",
                        ],
                    ),
                    _instruction(
                        _BASE + 4,
                        "int_add",
                        result="offset_address",
                        inputs=["header"],
                        tags=["pointer_arithmetic"],
                    ),
                    _instruction(
                        _BASE + 8,
                        "load",
                        result="raw_offset",
                        inputs=["ram", "offset_address"],
                    ),
                    _instruction(
                        _BASE + 12,
                        "byte_swap",
                        result="swapped_offset",
                        inputs=["raw_offset"],
                    ),
                    _instruction(
                        _BASE + 16,
                        "int_add",
                        result="length_address",
                        inputs=["header"],
                        tags=["pointer_arithmetic"],
                    ),
                    _instruction(
                        _BASE + 20,
                        "load",
                        result="raw_length",
                        inputs=["ram", "length_address"],
                    ),
                    _instruction(
                        _BASE + 24,
                        "bswap",
                        result="swapped_length",
                        inputs=["raw_length"],
                    ),
                ],
                successors=["merge"],
            ),
            _block(
                "merge",
                merge,
                [
                    _instruction(
                        merge,
                        "phi",
                        result="merged_offset",
                        inputs=["swapped_offset"],
                    ),
                    _instruction(
                        merge + 4,
                        "bool_and",
                        result="bounded_length",
                        inputs=["swapped_length", "mask"],
                    ),
                    _instruction(
                        merge + 8,
                        "compare",
                        result="within_file",
                        inputs=["merged_offset", "file_size"],
                    ),
                    _instruction(
                        merge + 12,
                        "call",
                        inputs=["session", "pixels", "merged_offset", "bounded_length"],
                        target="IIOImageReadSessionGetBytesAtOffset",
                        tags=[
                            "input_buffer_operand:1",
                            "read_session_input",
                            "scalar_role:offset:2",
                            "scalar_role:requested_length:3",
                        ],
                    ),
                ],
            ),
        ]
    )

    flows = {item.variable: item for item in report.flows}
    assert flows["raw_offset"].source_identities == (
        f"input_source:read_session:{_BASE:x}",
    )
    assert flows["swapped_offset"].uses[0].kind is BinaryScalarUseKind.TRANSFORM
    assert {item.kind for item in flows["merged_offset"].uses} == {
        BinaryScalarUseKind.COMPARISON,
        BinaryScalarUseKind.RANGE_OFFSET,
    }
    assert flows["bounded_length"].uses[0].kind is BinaryScalarUseKind.REQUESTED_LENGTH
    assert flows["swapped_length"].uses[0].operation is IROperation.BOOLEAN_AND


def test_alias_preserves_input_pointer_but_unrelated_reassignment_kills_it() -> None:
    report = _report(
        [
            _block(
                "entry",
                _BASE,
                [
                    _instruction(
                        _BASE,
                        "parameter",
                        result="source",
                        tags=["decoder_entry", "input_data"],
                    ),
                    _instruction(
                        _BASE + 4,
                        "assign",
                        result="alias",
                        inputs=["source"],
                    ),
                    _instruction(
                        _BASE + 8,
                        "load",
                        result="first_scalar",
                        inputs=["ram", "alias"],
                    ),
                    _instruction(
                        _BASE + 12,
                        "assign",
                        result="alias",
                        inputs=["unrelated_heap"],
                    ),
                    _instruction(
                        _BASE + 16,
                        "load",
                        result="not_input",
                        inputs=["ram", "alias"],
                    ),
                ],
            )
        ]
    )

    assert {item.variable for item in report.flows} == {"first_scalar"}


@pytest.mark.parametrize(
    "instructions",
    [
        [
            _instruction(
                _BASE,
                "parameter",
                result="source",
                tags=["decoder_entry"],
            ),
            _instruction(
                _BASE + 4,
                "load",
                result="value",
                inputs=["ram", "source"],
            ),
        ],
        [
            _instruction(_BASE, "parameter", result="global", tags=["decoder_entry"]),
            _instruction(
                _BASE + 4,
                "load",
                result="value",
                inputs=["ram", "global"],
            ),
        ],
        [
            _instruction(
                _BASE,
                "call",
                inputs=["session", "output", "offset", "length"],
                target="IIOImageReadSessionGetBytesAtOffset",
                tags=["decoder_entry"],
            ),
            _instruction(
                _BASE + 4,
                "load",
                result="value",
                inputs=["ram", "output"],
            ),
        ],
    ],
)
def test_untyped_memory_and_decoder_names_do_not_create_input_scalars(
    instructions: list[dict[str, Any]],
) -> None:
    report = _report([_block("entry", _BASE, instructions)])

    assert report.flows == ()


def test_variable_name_does_not_assign_a_length_role() -> None:
    report = _report(
        [
            _block(
                "entry",
                _BASE,
                [
                    _instruction(
                        _BASE,
                        "call",
                        inputs=["session", "header", "offset", "length"],
                        target="IIOImageReadSessionGetBytesAtOffset",
                        tags=[
                            "decoder_entry",
                            "input_buffer_operand:1",
                            "read_session_input",
                        ],
                    ),
                    _instruction(
                        _BASE + 4,
                        "load",
                        result="requested_length",
                        inputs=["ram", "header"],
                    ),
                    _instruction(
                        _BASE + 8,
                        "call",
                        inputs=["requested_length"],
                        target="untyped_consumer",
                    ),
                ],
            )
        ]
    )

    flow = next(item for item in report.flows if item.variable == "requested_length")
    assert BinaryScalarUseKind.REQUESTED_LENGTH not in {item.kind for item in flow.uses}


def test_provenance_digest_is_deterministic_and_tamper_evident() -> None:
    blocks = [
        _block(
            "entry",
            _BASE,
            [
                _instruction(
                    _BASE,
                    "parameter",
                    result="input",
                    tags=["decoder_entry", "input_data"],
                ),
                _instruction(
                    _BASE + 4,
                    "load",
                    result="scalar",
                    inputs=["ram", "input"],
                ),
            ],
        )
    ]
    first = _report(blocks)
    second = _report(blocks)

    assert first.report_sha256 == second.report_sha256
    payload = first.model_dump(mode="json")
    payload["flows"][0]["variable"] = "tampered"
    with pytest.raises(ValidationError):
        BinaryProvenanceReport.model_validate(payload)
