from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.binary_analysis import (
    BinaryContextPlan,
    BinaryFunctionRanking,
    BinaryRankingPolicy,
    BinaryVulnerabilityClass,
    GhidraJSONAdapter,
    analyze_binary_candidates,
    discover_imageio_parsers,
    pack_ranked_binary_contexts,
    rank_binary_functions,
)

_SNAPSHOT = "sha256:" + "5" * 64
_UUID = "42345678-1234-5678-9ABC-DEF012345678"


def _instruction(
    address: int,
    op: str,
    *,
    result: str | None = None,
    inputs: list[str] | None = None,
    target: str | None = None,
    tags: list[str] | None = None,
    constants: list[int] | None = None,
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
    if constants:
        item["constants"] = constants
    return item


def _function(
    address: int,
    name: str,
    instructions: list[dict[str, Any]],
    *,
    pseudocode: str,
) -> dict[str, Any]:
    return {
        "entry": hex(address),
        "size": 256,
        "name": name,
        "parameters": [],
        "pseudocode": pseudocode,
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


def _pipeline_inputs():
    base = 0x100001000
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
        "imports": ["free", "malloc"],
        "strings": [],
        "functions": [
            _function(
                base,
                "sub_lifetime",
                [
                    _instruction(base, "param", result="pointer", tags=["input_data"]),
                    _instruction(base + 4, "free", inputs=["pointer"], target="free"),
                    _instruction(base + 8, "load", result="value", inputs=["pointer"]),
                ],
                pseudocode="release(pointer); return *pointer;",
            ),
            _function(
                base + 0x1000,
                "sub_integer",
                [
                    _instruction(
                        base + 0x1000,
                        "param",
                        result="length",
                        tags=["input_length"],
                    ),
                    _instruction(
                        base + 0x1004,
                        "mul",
                        result="bytes",
                        inputs=["length"],
                        constants=[16],
                    ),
                    _instruction(
                        base + 0x1008,
                        "alloc",
                        result="buffer",
                        inputs=["bytes"],
                        target="malloc",
                    ),
                ],
                pseudocode="A" * 6000,
            ),
            _function(
                base + 0x2000,
                "sub_clean",
                [
                    _instruction(
                        base + 0x2000,
                        "param",
                        result="length",
                        tags=["input_length"],
                    ),
                    _instruction(base + 0x2004, "cmp", inputs=["length", "maximum"]),
                    _instruction(base + 0x2008, "return", inputs=[]),
                ],
                pseudocode="if (length <= maximum) return;",
            ),
        ],
    }
    ir = GhidraJSONAdapter().normalize(
        payload,
        expected_snapshot_sha256=_SNAPSHOT,
        created_at=datetime(2026, 7, 30, 5, 0, tzinfo=UTC),
    )
    discovery = discover_imageio_parsers(ir)
    report = analyze_binary_candidates(ir, discovery)
    return ir, discovery, report


def test_ranking_prioritizes_critical_then_high_then_clean_candidate() -> None:
    ir, discovery, report = _pipeline_inputs()
    ranking = rank_binary_functions(ir, discovery, report)

    assert [item.function_name for item in ranking.entries] == [
        "sub_lifetime",
        "sub_integer",
        "sub_clean",
    ]
    assert [item.rank for item in ranking.entries] == [1, 2, 3]
    assert all(
        item.priority_score == sum(component.score for component in item.components)
        for item in ranking.entries
    )
    top_finding = next(
        item for item in report.findings if item.finding_id in ranking.entries[0].finding_ids
    )
    assert top_finding.vulnerability_class is BinaryVulnerabilityClass.USE_AFTER_FREE


def test_context_packer_preserves_ranking_order_and_byte_budget() -> None:
    ir, discovery, report = _pipeline_inputs()
    policy = BinaryRankingPolicy(
        context_budget_bytes=700,
        maximum_segment_bytes=620,
        maximum_packs=10,
        maximum_pseudocode_bytes=5000,
    )
    ranking = rank_binary_functions(ir, discovery, report, policy=policy)
    plan = pack_ranked_binary_contexts(
        ir,
        discovery,
        report,
        ranking,
        policy=policy,
    )

    flattened = [segment for pack in plan.packs for segment in pack.segments]
    assert [segment.function_id for segment in flattened] == [
        item.function_id for item in ranking.entries
    ]
    assert [segment.rank for segment in flattened] == [1, 2, 3]
    assert all(pack.content_bytes <= 700 for pack in plan.packs)
    assert plan.omitted_function_ids == ()

    overflow_segment = next(item for item in flattened if item.function_name == "sub_integer")
    overflow_finding = next(
        item for item in report.findings if item.function_name == "sub_integer"
    )
    assert overflow_segment.truncated is True
    assert overflow_finding.finding_id in overflow_segment.content
    assert f"0x{overflow_finding.sink_address:x}" in overflow_segment.content


def test_pack_limit_omits_only_a_ranking_suffix_without_dropping_top() -> None:
    ir, discovery, report = _pipeline_inputs()
    policy = BinaryRankingPolicy(
        context_budget_bytes=512,
        maximum_segment_bytes=512,
        maximum_packs=1,
    )
    ranking = rank_binary_functions(ir, discovery, report, policy=policy)
    plan = pack_ranked_binary_contexts(
        ir,
        discovery,
        report,
        ranking,
        policy=policy,
    )

    assert plan.packed_function_ids == (ranking.entries[0].function_id,)
    assert plan.omitted_function_ids == tuple(
        item.function_id for item in ranking.entries[1:]
    )
    assert plan.packed_function_ids + plan.omitted_function_ids == plan.ranked_function_ids


def test_ranking_model_rejects_reordered_output() -> None:
    ir, discovery, report = _pipeline_inputs()
    ranking = rank_binary_functions(ir, discovery, report)
    payload = ranking.model_dump(mode="json")
    payload["entries"][0], payload["entries"][1] = (
        payload["entries"][1],
        payload["entries"][0],
    )

    with pytest.raises(ValidationError, match="ranks must be contiguous"):
        BinaryFunctionRanking.model_validate(payload)


def test_context_plan_model_rejects_non_prefix_partition() -> None:
    ir, discovery, report = _pipeline_inputs()
    policy = BinaryRankingPolicy(
        context_budget_bytes=512,
        maximum_segment_bytes=512,
        maximum_packs=1,
    )
    ranking = rank_binary_functions(ir, discovery, report, policy=policy)
    plan = pack_ranked_binary_contexts(
        ir,
        discovery,
        report,
        ranking,
        policy=policy,
    )
    payload = plan.model_dump(mode="json")
    payload["omitted_function_ids"] = list(reversed(payload["omitted_function_ids"]))

    with pytest.raises(ValidationError, match="partition the ranking"):
        BinaryContextPlan.model_validate(payload)
