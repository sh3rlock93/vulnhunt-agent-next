from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.binary_analysis import (
    BinaryFormatFamily,
    GhidraJSONAdapter,
    ImageIOEntryRoute,
    ImageIOParserDiscovery,
    ParserDiscoveryLimits,
    ParserEvidenceKind,
    discover_imageio_parsers,
)

_SNAPSHOT = "sha256:" + "3" * 64
_UUID = "22345678-1234-5678-9ABC-DEF012345678"


def _instruction(
    address: int,
    op: str,
    *,
    result: str | None = None,
    inputs: list[str] | None = None,
    target: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "address": hex(address),
        "op": op,
        "inputs": inputs or [],
        "text": op,
    }
    if result is not None:
        item["result"] = result
    if target is not None:
        item["target"] = target
    if tags:
        item["tags"] = tags
    return item


def _function(
    address: int,
    name: str,
    instructions: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "entry": hex(address),
        "size": 64,
        "name": name,
        "parameters": [],
        "pseudocode": f"void {name}(void) {{}}",
        "blocks": [
            {
                "name": "entry",
                "start": hex(address),
                "size": 64,
                "successors": [],
                "instructions": instructions,
            }
        ],
    }


def _ir():
    payload = {
        "schema_version": "ghidra-imageio-export-v1",
        "decompiler_version": "11.4",
        "snapshot_sha256": _SNAPSHOT,
        "image": {
            "name": "ImageIO",
            "uuid": _UUID,
            "architecture": "arm64",
            "base_address": "0x100000000",
        },
        "imports": ["CGDataProviderCopyData", "malloc"],
        "strings": [
            {
                "address": "0x100009000",
                "value": "Digital Negative (DNG) directory",
                "references": ["0x100001004"],
            }
        ],
        "functions": [
            _function(
                0x100000000,
                "public_wrapper",
                [_instruction(0x100000000, "call", target="sub_100001000")],
            ),
            _function(
                0x100001000,
                "sub_100001000",
                [
                    _instruction(
                        0x100001000,
                        "param",
                        result="data",
                        tags=["input_data"],
                    ),
                    _instruction(
                        0x100001004,
                        "call",
                        target="CGDataProviderCopyData",
                    ),
                    _instruction(0x100001008, "call", target="sub_100002000"),
                ],
            ),
            _function(
                0x100002000,
                "sub_100002000",
                [_instruction(0x100002000, "call", target="memcpy")],
            ),
            _function(
                0x100003000,
                "unrelated_allocator",
                [_instruction(0x100003000, "call", target="malloc")],
            ),
        ],
    }
    return GhidraJSONAdapter().normalize(
        payload,
        expected_snapshot_sha256=_SNAPSHOT,
        created_at=datetime(2026, 7, 30, 3, 0, tzinfo=UTC),
    )


def test_discovery_combines_strings_input_apis_and_callgraph() -> None:
    discovery = discover_imageio_parsers(_ir())
    by_name = {item.function_name: item for item in discovery.candidates}

    assert discovery.direct_seed_count == 1
    assert set(by_name) == {"public_wrapper", "sub_100001000", "sub_100002000"}
    seed = by_name["sub_100001000"]
    assert BinaryFormatFamily.RAW_DNG in seed.format_families
    assert ImageIOEntryRoute.DATA_PROVIDER in seed.entry_routes
    assert seed.callgraph_distance == 0
    assert {item.kind for item in seed.evidence} >= {
        ParserEvidenceKind.FORMAT_STRING,
        ParserEvidenceKind.INPUT_MARKER,
        ParserEvidenceKind.API_CALL,
    }
    assert by_name["sub_100002000"].callgraph_distance == 1
    assert BinaryFormatFamily.RAW_DNG in by_name["sub_100002000"].format_families
    assert by_name["public_wrapper"].callgraph_distance == 1


def test_discovery_does_not_promote_isolated_memory_sink() -> None:
    discovery = discover_imageio_parsers(_ir())
    assert "unrelated_allocator" not in {
        item.function_name for item in discovery.candidates
    }


def test_discovery_depth_zero_keeps_only_direct_seeds() -> None:
    discovery = discover_imageio_parsers(
        _ir(),
        limits=ParserDiscoveryLimits(maximum_callgraph_depth=0),
    )
    assert [item.function_name for item in discovery.candidates] == ["sub_100001000"]


def test_discovery_is_deterministic_and_candidate_limit_preserves_top_score() -> None:
    ir = _ir()
    first = discover_imageio_parsers(
        ir,
        limits=ParserDiscoveryLimits(maximum_candidates=1),
    )
    second = discover_imageio_parsers(
        ir,
        limits=ParserDiscoveryLimits(maximum_candidates=1),
    )

    assert first == second
    assert len(first.candidates) == 1
    assert first.candidates[0].function_name == "sub_100001000"


def test_discovery_model_rejects_tampered_score() -> None:
    discovery = discover_imageio_parsers(_ir())
    payload = discovery.model_dump(mode="json")
    payload["candidates"][0]["discovery_score"] += 1

    with pytest.raises(ValidationError, match="score does not match"):
        ImageIOParserDiscovery.model_validate(payload)
