from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from vulnhunt_agent.macos.binary_analysis import (
    BinaryEvidenceCapsulePolicy,
    BinaryEvidenceFactKind,
    CapsuleIncompleteReason,
    CapsuleProofStatus,
    CodeHuntAdmissionPolicy,
    GhidraJSONAdapter,
    admit_code_hunt_roots,
    analyze_binary_candidates,
    build_binary_evidence_capsules,
    discover_imageio_parsers,
    rank_binary_functions,
)

_SNAPSHOT = "sha256:" + "8" * 64
_UUID = "82345678-1234-5678-9ABC-DEF012345678"


def _instruction(
    address: int,
    op: str,
    *,
    result: str | None = None,
    inputs: list[str] | None = None,
    target: str | None = None,
    tags: list[str] | None = None,
    text: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "address": hex(address),
        "op": op,
        "inputs": inputs or [],
        "text": text or op,
    }
    if result is not None:
        payload["result"] = result
    if target is not None:
        payload["target"] = target
    if tags:
        payload["tags"] = tags
    return payload


def _function(
    address: int,
    name: str,
    instructions: list[dict[str, Any]],
    pseudocode: str,
) -> dict[str, Any]:
    return {
        "entry": hex(address),
        "size": 0x1000,
        "name": name,
        "parameters": [],
        "pseudocode": pseudocode,
        "blocks": [
            {
                "name": "entry",
                "start": hex(address),
                "size": 0x1000,
                "successors": [],
                "instructions": instructions,
            }
        ],
    }


def _pipeline(*, extra_sink_loads: int = 0, recursive: bool = False):
    entry = 0x100001000
    convert = 0x100003000
    sink = 0x100005000
    entry_instructions = [
        _instruction(entry, "param", result="data", tags=["input_data"]),
        _instruction(entry + 4, "param", result="length", tags=["input_length"]),
        _instruction(
            entry + 8,
            "cmp",
            inputs=["length", "maximum"],
            text="length <= maximum",
        ),
        _instruction(entry + 12, "branch", inputs=["length"]),
        _instruction(
            entry + 16,
            "call",
            result="safe_length",
            inputs=["length"],
            target="convert_length",
        ),
        _instruction(
            entry + 20,
            "call",
            inputs=["data", "safe_length"],
            target="consume_rows",
        ),
        _instruction(entry + 24, "return"),
    ]
    sink_instructions = [
        _instruction(sink, "param", result="buffer"),
        _instruction(sink + 4, "param", result="size"),
        _instruction(sink + 8, "store", inputs=["buffer", "size"]),
    ]
    sink_instructions.extend(
        _instruction(
            sink + 12 + index * 4,
            "load",
            result=f"byte_{index}",
            inputs=["buffer"],
        )
        for index in range(extra_sink_loads)
    )
    if recursive:
        sink_instructions.append(
            _instruction(
                sink + 12 + extra_sink_loads * 4,
                "call",
                inputs=["buffer", "size"],
                target="decode_png_entry",
            )
        )
    sink_instructions.append(
        _instruction(sink + 16 + extra_sink_loads * 4, "return")
    )
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
        "imports": [],
        "strings": [],
        "functions": [
            _function(
                entry,
                "decode_png_entry",
                entry_instructions,
                "if (length <= maximum) safe_length = convert_length(length); "
                "decode_png_sink(data, safe_length);",
            ),
            _function(
                convert,
                "convert_length",
                [
                    _instruction(convert, "param", result="length"),
                    _instruction(
                        convert + 4,
                        "mul",
                        result="bytes",
                        inputs=["length", "pixel_size"],
                        tags=["source_op:INT_MULT"],
                    ),
                    _instruction(convert + 8, "return", inputs=["bytes"]),
                ],
                "return length * pixel_size;",
            ),
            _function(
                sink,
                "consume_rows",
                sink_instructions,
                "buffer[size] = value;" + " load(buffer);" * extra_sink_loads,
            ),
        ],
    }
    ir = GhidraJSONAdapter().normalize(
        payload,
        expected_snapshot_sha256=_SNAPSHOT,
        created_at=datetime(2026, 8, 4, tzinfo=UTC),
    )
    discovery = discover_imageio_parsers(ir)
    report = analyze_binary_candidates(ir, discovery)
    ranking = rank_binary_functions(ir, discovery, report)
    admission = admit_code_hunt_roots(
        ir,
        discovery,
        report,
        ranking,
        policy=CodeHuntAdmissionPolicy(require_function_coverage=False),
    )
    return ir, report, admission


def _sink_capsule(capsule_set):
    return next(
        item
        for item in capsule_set.capsules
        if item.functions[0].function_name == "consume_rows"
    )


def test_interprocedural_capsule_retains_source_conversion_guard_and_sink() -> None:
    ir, report, admission = _pipeline()
    capsule = _sink_capsule(build_binary_evidence_capsules(ir, report, admission))

    names = {item.function_name for item in capsule.functions}
    assert names == {"decode_png_entry", "convert_length", "consume_rows"}
    kinds = {item.kind for item in capsule.facts}
    assert {
        BinaryEvidenceFactKind.INPUT_SOURCE,
        BinaryEvidenceFactKind.DATAFLOW,
        BinaryEvidenceFactKind.GUARD,
        BinaryEvidenceFactKind.SECURITY_SINK,
    }.issubset(kinds)
    source_functions = {
        item.function_id
        for item in capsule.facts
        if item.kind is BinaryEvidenceFactKind.INPUT_SOURCE
    }
    caller = next(item for item in capsule.functions if item.function_name == "decode_png_entry")
    assert source_functions == {caller.function_id}
    assert capsule.proof_status is CapsuleProofStatus.PROOF_CAPABLE
    assert all(
        any(
            fact.function_id == function.function_id
            for fact in capsule.facts
        )
        for function in capsule.functions
    )


def test_caller_guard_and_callee_return_remain_connected_to_callsites() -> None:
    ir, report, admission = _pipeline()
    capsule = _sink_capsule(build_binary_evidence_capsules(ir, report, admission))

    guard = next(item for item in capsule.facts if item.kind is BinaryEvidenceFactKind.GUARD)
    caller = next(item for item in capsule.functions if item.function_name == "decode_png_entry")
    assert guard.function_id == caller.function_id

    conversion_edge = next(
        item
        for item in capsule.call_edges
        if next(
            function.function_name
            for function in capsule.functions
            if function.function_id == item.callee_function_id
        )
        == "convert_length"
    )
    sink_edge = next(
        item
        for item in capsule.call_edges
        if next(
            function.function_name
            for function in capsule.functions
            if function.function_id == item.callee_function_id
        )
        == "consume_rows"
    )
    assert conversion_edge.return_result == "safe_length"
    assert "safe_length" in sink_edge.arguments
    assert any(
        item.kind is BinaryEvidenceFactKind.RETURN_USE
        and "bytes" in item.operands
        for item in capsule.facts
    )


def test_recursive_call_graph_terminates_at_declared_bounds() -> None:
    ir, report, admission = _pipeline(recursive=True)
    policy = BinaryEvidenceCapsulePolicy(maximum_call_depth=2, maximum_functions=3)
    first = build_binary_evidence_capsules(ir, report, admission, policy=policy)
    second = build_binary_evidence_capsules(ir, report, admission, policy=policy)

    assert first == second
    assert all(len(item.functions) <= 3 for item in first.capsules)
    assert all(max(function.call_depth for function in item.functions) <= 2 for item in first.capsules)


def test_oversized_required_evidence_is_explicitly_proof_incomplete() -> None:
    ir, report, admission = _pipeline(extra_sink_loads=120)
    policy = BinaryEvidenceCapsulePolicy(
        maximum_evidence_bytes=16 * 1024,
        maximum_instructions_per_function=32,
        maximum_pseudocode_bytes_per_function=4096,
    )
    capsule = _sink_capsule(
        build_binary_evidence_capsules(ir, report, admission, policy=policy)
    )

    assert capsule.evidence_bytes <= 16 * 1024
    assert capsule.proof_status is CapsuleProofStatus.PROOF_INCOMPLETE
    assert (
        CapsuleIncompleteReason.REQUIRED_INSTRUCTIONS_OMITTED
        in capsule.proof_incomplete_reasons
    )
    assert capsule.omissions


def test_shared_callee_is_deduplicated_while_callsites_are_preserved() -> None:
    ir, report, admission = _pipeline()
    capsule = _sink_capsule(build_binary_evidence_capsules(ir, report, admission))

    ids = [item.function_id for item in capsule.functions]
    assert len(ids) == len(set(ids))
    edge_ids = [item.edge_id for item in capsule.call_edges]
    assert len(edge_ids) == len(set(edge_ids))
    assert len(capsule.call_edges) == 2
