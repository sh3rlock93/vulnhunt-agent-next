from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from vulnhunt_agent.core.llm import LLMResponse
from vulnhunt_agent.domain.schemas import (
    BudgetPolicy,
    BudgetUsage,
    ProviderPreflightCode,
    ProviderPreflightResult,
)
from vulnhunt_agent.macos.binary_analysis import (
    BinaryCodeContextPolicy,
    BinaryCodeContextEdgeResolution,
    BinaryCodeContextRejection,
    BinaryCodeContextRequest,
    BinaryCodeContextRequestKind,
    BinaryCodeContextStatus,
    BinaryEvidenceCapsulePolicy,
    BinaryEvidenceFactKind,
    CodeHuntAdmissionPolicy,
    DecompilerContextTerminalStatus,
    DecompilerHunterAssessment,
    DecompilerHunterDisposition,
    GhidraJSONAdapter,
    admit_code_hunt_roots,
    analyze_binary_candidates,
    build_binary_evidence_capsules,
    build_decompiler_hunter_plan,
    continue_decompiler_hunter_session,
    create_binary_research_scope,
    discover_imageio_parsers,
    load_decompiler_hunter_packet,
    rank_binary_functions,
    resolve_binary_code_context,
    select_context_continuation_roots,
)

_SNAPSHOT = "sha256:" + "b" * 64
_UUID = "B2345678-1234-5678-9ABC-DEF012345678"


def _instruction(
    address: int,
    operation: str,
    *,
    result: str | None = None,
    inputs: list[str] | None = None,
    target: str | None = None,
    tags: list[str] | None = None,
    constants: list[int] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "address": hex(address),
        "op": operation,
        "inputs": inputs or [],
        "text": f"{result or ''} {operation} {' '.join(inputs or [])}".strip(),
    }
    if result is not None:
        value["result"] = result
    if target is not None:
        value["target"] = target
    if tags:
        value["tags"] = tags
    if constants:
        value["constants"] = constants
    return value


def _function(address: int, name: str, instructions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "entry": hex(address),
        "size": 0x100,
        "name": name,
        "parameters": [],
        "pseudocode": "\n".join(item["text"] for item in instructions),
        "blocks": [
            {
                "name": "entry",
                "start": hex(address),
                "size": 0x100,
                "successors": [],
                "instructions": instructions,
            }
        ],
    }


def _fixture(
    tmp_path,
    *,
    extra_functions: list[dict[str, Any]] | None = None,
    virtual_methods: list[dict[str, Any]] | None = None,
):
    caller = 0x100001000
    worker = 0x100002000
    sink = 0x100003000
    payload: dict[str, Any] = {
        "schema_version": (
            "ghidra-imageio-export-v3"
            if virtual_methods is not None
            else "ghidra-imageio-export-v1"
        ),
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
                caller,
                "decode_png_entry",
                [
                    _instruction(caller, "param", result="length", tags=["input_length"]),
                    _instruction(caller + 4, "cmp", inputs=["length", "limit"]),
                    _instruction(caller + 8, "branch", inputs=["length"]),
                    _instruction(
                        caller + 12,
                        "call",
                        result="ok",
                        inputs=["length"],
                        target="decode_png_rows",
                    ),
                    _instruction(caller + 16, "return", inputs=["ok"]),
                ],
            ),
            _function(
                worker,
                "decode_png_rows",
                [
                    _instruction(worker, "param", result="length", tags=["input_length"]),
                    _instruction(worker + 4, "load", result="header", inputs=["input"]),
                    *(
                        _instruction(
                            worker + 8 + index * 4,
                            "assign",
                            result=f"tmp{index}",
                            inputs=["header"],
                        )
                        for index in range(14)
                    ),
                    _instruction(
                        worker + 64,
                        "store",
                        inputs=["destination", *(f"tmp{index}" for index in range(14))],
                    ),
                    _instruction(worker + 68, "mul", result="bytes", inputs=["length", "stride"]),
                    _instruction(
                        worker + 72,
                        "call",
                        result="written",
                        inputs=["bytes"],
                        target="write_png_rows",
                    ),
                    _instruction(worker + 76, "return", inputs=["written"]),
                ],
            ),
            _function(
                sink,
                "write_png_rows",
                [
                    _instruction(sink, "param", result="bytes"),
                    _instruction(sink + 4, "store", inputs=["destination", "bytes"]),
                    _instruction(sink + 8, "return"),
                ],
            ),
            *(extra_functions or []),
        ],
    }
    if virtual_methods is not None:
        payload["virtual_methods"] = virtual_methods
        selected_functions = payload["functions"]
        payload["function_coverage"] = {
            "schema_version": "ghidra-function-coverage-v1",
            "snapshot_sha256": _SNAPSHOT,
            "maximum_functions": len(selected_functions),
            "maximum_evidence_functions": len(selected_functions),
            "callgraph_depth": 0,
            "warnings": [],
            "functions": [
                {
                    "entry": function["entry"],
                    "size": function["size"],
                    "name": function["name"],
                    "direct_strings": [],
                    "callers": [],
                    "callees": [],
                    "selected": True,
                    "selection_tier": "fallback",
                    "selection_reasons": ["parser_score_fallback:0"],
                }
                for function in selected_functions
            ],
        }
    worker_instructions = payload["functions"][1]["blocks"][0]["instructions"]
    payload["functions"][1]["blocks"] = [
        {
            "name": f"block-{index}",
            "start": instruction["address"],
            "size": 4,
            "successors": [],
            "instructions": [instruction],
        }
        for index, instruction in enumerate(worker_instructions)
    ]
    payload["functions"][1]["pseudocode"] += "\n" + "x" * 16_000
    ir = GhidraJSONAdapter().normalize(
        payload,
        expected_snapshot_sha256=_SNAPSHOT,
        created_at=datetime(2026, 8, 5, tzinfo=UTC),
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
    capsules = build_binary_evidence_capsules(
        ir,
        report,
        admission,
        policy=BinaryEvidenceCapsulePolicy(
            maximum_functions=1,
            maximum_evidence_bytes=32 * 1024,
            maximum_instructions_per_function=8,
        ),
    )
    scope = create_binary_research_scope(
        snapshot_sha256=_SNAPSHOT,
        authorization_basis="lawfully installed analyst-controlled image",
    )
    plan = build_decompiler_hunter_plan(
        store_root=tmp_path,
        run_id="m17-context-test",
        ir=ir,
        capsule_set=capsules,
        scope=scope,
        budget=BudgetPolicy(max_hunter_sessions=16),
        provider_preflight=ProviderPreflightResult(
            transport="openai_api",
            model_id="test-model",
            ready=True,
            code=ProviderPreflightCode.READY,
        ),
    )
    worker_function = next(item for item in ir.functions if item.name == "decode_png_rows")
    caller_function = next(item for item in ir.functions if item.name == "decode_png_entry")
    sink_function = next(item for item in ir.functions if item.name == "write_png_rows")
    work_item = next(
        item
        for item in plan.routing.work_items
        if item.target_node_ids == (worker_function.function_id,)
    )
    packet = load_decompiler_hunter_packet(store_root=tmp_path, work_item=work_item)
    return ir, packet, caller_function, worker_function, sink_function


def _virtual_dispatch_functions(*, selector_hint: bool = True) -> list[dict[str, Any]]:
    caller_address = 0x100004000
    target_address = 0x100005000
    sibling_address = 0x100006000
    indirect = _instruction(
        caller_address + 0x24,
        "call",
        result="status",
        inputs=["this", "arg1", "arg2", "arg3", "arg4", "arg5"],
        target="0x4040",
    )
    indirect["text"] = "CALLIND (register, 0x4040, 8)"
    caller = {
        "entry": hex(caller_address),
        "size": 0x80,
        "name": "callDecodeImage" if selector_hint else "routePlugin",
        "parameters": ["this", "arg1", "arg2", "arg3", "arg4", "arg5"],
        "pseudocode": (
            "decodeImageImp dispatch with a checked mode"
            if selector_hint
            else "generic plugin dispatch"
        ),
        "blocks": [
            {
                "name": "entry",
                "start": hex(caller_address),
                "size": 0x20,
                "successors": ["dispatch", "reject"],
                "instructions": [
                    _instruction(
                        caller_address,
                        "cmp",
                        result="allowed",
                        inputs=["mode", "const_1"],
                        constants=[1],
                    ),
                    _instruction(caller_address + 4, "branch", inputs=["allowed"]),
                ],
            },
            {
                "name": "dispatch",
                "start": hex(caller_address + 0x20),
                "size": 0x20,
                "successors": [],
                "instructions": [
                    _instruction(
                        caller_address + 0x20,
                        "add",
                        result="slot",
                        inputs=["vtable", "const_d8"],
                        constants=[0xD8],
                    ),
                    indirect,
                    _instruction(caller_address + 0x28, "return", inputs=["status"]),
                ],
            },
            {
                "name": "reject",
                "start": hex(caller_address + 0x40),
                "size": 0x20,
                "successors": [],
                "instructions": [_instruction(caller_address + 0x40, "return")],
            },
        ],
    }
    target = _function(
        target_address,
        "decodeImageImp",
        [_instruction(target_address, "store", inputs=["destination", "bytes"])],
    )
    target["parameters"] = ["arg1", "arg2", "arg3", "arg4", "arg5"]
    target["pseudocode"] = (
        "/* virtual OSStatus KTXReadPlugin::decodeImageImp(arg1, arg2, arg3, arg4, arg5) */"
    )
    sibling = _function(
        sibling_address,
        "decodeImageImp",
        [_instruction(sibling_address, "return")],
    )
    sibling["parameters"] = ["arg1", "arg2", "arg3", "arg4", "arg5"]
    sibling["pseudocode"] = (
        "/* virtual OSStatus PNGReadPlugin::decodeImageImp(arg1, arg2, arg3, arg4, arg5) */"
    )
    return [caller, target, sibling]


def _virtual_method_reference(*, slot_offset: int = 0xD8) -> dict[str, Any]:
    address_point = 0x200000010
    return {
        "owner": "KTXReadPlugin",
        "vtable_symbol": "KTXReadPlugin::vtable",
        "vtable_address": "0x200000000",
        "address_point": hex(address_point),
        "slot_offset": slot_offset,
        "reference_address": hex(address_point + slot_offset),
        "target_entry": "0x100005000",
    }


def _needs(packet, request: BinaryCodeContextRequest) -> DecompilerHunterAssessment:
    return DecompilerHunterAssessment(
        work_id=packet.work_id,
        root_id=packet.root_id,
        capsule_sha256=packet.capsule.capsule_sha256,
        admission_rank=packet.admission_rank,
        disposition=DecompilerHunterDisposition.NEEDS_CODE_CONTEXT,
        summary="One bounded frozen-IR relationship is needed.",
        context_requests=(request,),
        evidence_ids=request.evidence_ids,
    )


def _request(packet, kind, *, function_id: str, related: str | None = None, **kwargs):
    return BinaryCodeContextRequest(
        request_id=f"codectx-{kind.value.replace('_', '-')}",
        kind=kind,
        rationale="Resolve one address-backed proof obligation.",
        function_id=function_id,
        related_function_id=related,
        evidence_ids=(packet.allowed_evidence_ids[0],),
        **kwargs,
    )


def _not_vulnerable(packet, response) -> dict[str, Any]:
    guard = next(item for item in response.facts if item.kind is BinaryEvidenceFactKind.GUARD)
    return {
        "schema_version": "decompiler-hunter-assessment-v1",
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "capsule_sha256": packet.capsule.capsule_sha256,
        "admission_rank": packet.admission_rank,
        "disposition": "not_vulnerable",
        "summary": "The recovered direct caller rejects the unsafe length.",
        "hypotheses": [],
        "context_requests": [],
        "safe_path_analysis": "The cited caller comparison dominates the callsite.",
        "safe_path_evidence_ids": [guard.fact_id],
        "evidence_ids": [guard.fact_id],
        "unresolved_questions": [],
    }


def _needs_again(packet, response, request) -> dict[str, Any]:
    evidence = response.facts[0].fact_id
    updated = request.model_copy(
        update={
            "request_id": request.request_id + "-again",
            "evidence_ids": (evidence,),
        }
    )
    return {
        "schema_version": "decompiler-hunter-assessment-v1",
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "capsule_sha256": packet.capsule.capsule_sha256,
        "admission_rank": packet.admission_rank,
        "disposition": "needs_code_context",
        "summary": "The same slice was requested again.",
        "hypotheses": [],
        "context_requests": [updated.model_dump(mode="json")],
        "safe_path_analysis": "",
        "safe_path_evidence_ids": [],
        "evidence_ids": [evidence],
        "unresolved_questions": [],
    }


def _needs_next(packet, response, request) -> dict[str, Any]:
    evidence = response.facts[0].fact_id
    updated = request.model_copy(update={"evidence_ids": (evidence,)})
    return {
        "schema_version": "decompiler-hunter-assessment-v1",
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "capsule_sha256": packet.capsule.capsule_sha256,
        "admission_rank": packet.admission_rank,
        "disposition": "needs_code_context",
        "summary": "One final bounded proof relationship remains.",
        "hypotheses": [],
        "context_requests": [updated.model_dump(mode="json")],
        "safe_path_analysis": "",
        "safe_path_evidence_ids": [],
        "evidence_ids": [evidence],
        "unresolved_questions": [],
    }


def _hypothesis(packet, response, sink_function) -> dict[str, Any]:
    source = next(
        item for item in packet.capsule.facts if item.kind is BinaryEvidenceFactKind.INPUT_SOURCE
    )
    path = next(
        item for item in packet.capsule.facts if item.kind is BinaryEvidenceFactKind.CALLSITE
    )
    sink = next(
        item for item in response.facts if item.kind is BinaryEvidenceFactKind.SECURITY_SINK
    )
    return {
        "schema_version": "decompiler-hunter-assessment-v1",
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "capsule_sha256": packet.capsule.capsule_sha256,
        "admission_rank": packet.admission_rank,
        "disposition": "code_hypothesis",
        "summary": "Input-derived bytes reach the recovered callee store.",
        "hypotheses": [
            {
                "hypothesis_id": "codehypothesis-callee-store",
                "title": "Unchecked byte count reaches row store",
                "vulnerability_class": "out_of_bounds_write",
                "parser_reachability": "The admitted decoder calls the recovered row writer.",
                "attacker_control": "The cited length parameter is input-derived.",
                "width_signedness": "The multiplication width remains decompiler-derived.",
                "call_path_function_ids": [
                    packet.capsule.root_function_id,
                    sink_function.function_id,
                ],
                "cfg_path_addresses": [source.address, path.address, sink.address],
                "guard_analysis": "No guard fact exists in the supplied worker/callee path.",
                "no_applicable_guard": True,
                "security_relation": "The byte count must not exceed destination capacity.",
                "impact": "The recovered store may address beyond the row destination.",
                "contradicting_evidence": "A caller precondition may still constrain the root.",
                "decompiler_uncertainty": "Recovered types may not match machine widths.",
                "confidence": 0.7,
                "falsification_condition": "A dominating byte-capacity guard falsifies the claim.",
                "source_evidence_ids": [source.fact_id],
                "path_evidence_ids": [path.fact_id],
                "guard_evidence_ids": [],
                "sink_evidence_ids": [sink.fact_id],
                "contradicting_evidence_ids": [],
            }
        ],
        "context_requests": [],
        "safe_path_analysis": "",
        "safe_path_evidence_ids": [],
        "evidence_ids": sorted([source.fact_id, path.fact_id, sink.fact_id]),
        "unresolved_questions": [],
    }


class _FakeClient:
    model_id = "test-model"
    transport = "openai_api"

    def __init__(self, responses: list[str]):
        self.responses = responses
        self.calls = 0

    async def chat(
        self,
        messages: list[dict],
        system: str | None = None,
        tools: list[dict] | None = None,
        max_tokens: int | None = None,
        cache_system: bool = False,
        cache_tools: bool = False,
        cache_last_user: bool = False,
    ) -> LLMResponse:
        self.calls += 1
        value = self.responses.pop(0)
        return LLMResponse(
            text=value,
            input_tokens=120,
            output_tokens=40,
            cache_read_tokens=0,
            cache_write_tokens=0,
            stop_reason="end_turn",
            content_blocks=[{"text": value}],
        )


def _initial_usage(packet) -> BudgetUsage:
    return BudgetUsage(
        run_id="m17-context-test",
        work_id=packet.work_id,
        scope="hunter",
        model_id="test-model",
        transport="openai_api",
        sessions=1,
        calls=1,
        iterations=1,
        input_tokens=100,
        output_tokens=20,
    )


def test_virtual_selector_caller_recovers_dispatch_and_dominating_guard(tmp_path) -> None:
    ir, packet, _, _, _ = _fixture(
        tmp_path,
        extra_functions=_virtual_dispatch_functions(),
    )
    target = next(item for item in ir.functions if item.start_address == 0x100005000)
    caller = next(item for item in ir.functions if item.start_address == 0x100004000)
    request = _request(
        packet,
        BinaryCodeContextRequestKind.DIRECT_CALLER,
        function_id=target.function_id,
        related=caller.function_id,
        maximum_bytes=32 * 1024,
    )

    response = resolve_binary_code_context(ir=ir, packet=packet, request=request)

    assert response.status is BinaryCodeContextStatus.RESOLVED
    assert tuple(item.function_id for item in response.functions) == (caller.function_id,)
    assert len(response.call_edges) == 1
    edge = response.call_edges[0]
    assert edge.resolution is BinaryCodeContextEdgeResolution.VIRTUAL_SELECTOR
    assert edge.selector == "decodeImageImp"
    assert edge.dispatch_candidate_count == 2
    assert edge.callsite_address == 0x100004024
    assert edge.dominating_guard_block_ids
    included_blocks = {
        block.block_id for function in response.functions for block in function.blocks
    }
    assert set(edge.dominating_guard_block_ids).issubset(included_blocks)
    assert any(
        item.kind is BinaryEvidenceFactKind.GUARD and item.address == 0x100004000
        for item in response.facts
    )
    assert any(
        0xD8 in instruction.constants
        for function in response.functions
        for block in function.blocks
        for instruction in block.instructions
    )
    assert response.evidence_bytes <= 32 * 1024


def test_virtual_vtable_caller_binds_exact_owner_and_slot(tmp_path) -> None:
    ir, packet, _, _, _ = _fixture(
        tmp_path,
        extra_functions=_virtual_dispatch_functions(),
        virtual_methods=[_virtual_method_reference()],
    )
    target = next(item for item in ir.functions if item.start_address == 0x100005000)
    caller = next(item for item in ir.functions if item.start_address == 0x100004000)
    request = _request(
        packet,
        BinaryCodeContextRequestKind.DIRECT_CALLER,
        function_id=target.function_id,
        related=caller.function_id,
        maximum_bytes=32 * 1024,
    )

    first = resolve_binary_code_context(ir=ir, packet=packet, request=request)
    second = resolve_binary_code_context(ir=ir, packet=packet, request=request)

    assert first == second
    assert len(first.call_edges) == 1
    edge = first.call_edges[0]
    assert edge.resolution is BinaryCodeContextEdgeResolution.VIRTUAL_VTABLE
    assert edge.selector == "decodeImageImp"
    assert edge.dispatch_candidate_count == 1
    assert edge.receiver_owner == "KTXReadPlugin"
    assert edge.vtable_symbol == "KTXReadPlugin::vtable"
    assert edge.vtable_address == 0x200000000
    assert edge.vtable_address_point == 0x200000010
    assert edge.vtable_slot_offset == 0xD8
    assert edge.vtable_reference_address == 0x2000000E8


def test_virtual_vtable_mismatched_slot_remains_selector_only(tmp_path) -> None:
    ir, packet, _, _, _ = _fixture(
        tmp_path,
        extra_functions=_virtual_dispatch_functions(),
        virtual_methods=[_virtual_method_reference(slot_offset=0xE0)],
    )
    target = next(item for item in ir.functions if item.start_address == 0x100005000)
    caller = next(item for item in ir.functions if item.start_address == 0x100004000)
    request = _request(
        packet,
        BinaryCodeContextRequestKind.DIRECT_CALLER,
        function_id=target.function_id,
        related=caller.function_id,
    )

    response = resolve_binary_code_context(ir=ir, packet=packet, request=request)

    edge = response.call_edges[0]
    assert edge.resolution is BinaryCodeContextEdgeResolution.VIRTUAL_SELECTOR
    assert edge.dispatch_candidate_count == 2
    assert edge.receiver_owner is None
    assert edge.vtable_slot_offset is None


def test_virtual_selector_caller_requires_a_frozen_selector_hint(tmp_path) -> None:
    ir, packet, _, _, _ = _fixture(
        tmp_path,
        extra_functions=_virtual_dispatch_functions(selector_hint=False),
    )
    target = next(item for item in ir.functions if item.start_address == 0x100005000)
    caller = next(item for item in ir.functions if item.start_address == 0x100004000)
    request = _request(
        packet,
        BinaryCodeContextRequestKind.DIRECT_CALLER,
        function_id=target.function_id,
        related=caller.function_id,
    )

    response = resolve_binary_code_context(ir=ir, packet=packet, request=request)

    assert response.status is BinaryCodeContextStatus.UNAVAILABLE
    assert response.rejection is BinaryCodeContextRejection.PROOF_UNAVAILABLE


def test_direct_caller_remains_an_exact_edge(tmp_path) -> None:
    ir, packet, caller, worker, _ = _fixture(tmp_path)
    request = _request(
        packet,
        BinaryCodeContextRequestKind.DIRECT_CALLER,
        function_id=worker.function_id,
        related=caller.function_id,
    )

    response = resolve_binary_code_context(ir=ir, packet=packet, request=request)

    assert response.call_edges[0].resolution is BinaryCodeContextEdgeResolution.DIRECT
    assert response.call_edges[0].selector is None
    assert response.call_edges[0].dispatch_candidate_count == 1


@pytest.mark.asyncio
async def test_missing_caller_guard_withdraws_false_hypothesis_and_resumes(tmp_path) -> None:
    ir, packet, caller, worker, _ = _fixture(tmp_path)
    request = _request(
        packet,
        BinaryCodeContextRequestKind.DIRECT_CALLER,
        function_id=worker.function_id,
        related=caller.function_id,
    )
    response = resolve_binary_code_context(ir=ir, packet=packet, request=request)
    assert response.status is BinaryCodeContextStatus.RESOLVED
    assert any(item.kind is BinaryEvidenceFactKind.GUARD for item in response.facts)
    client = _FakeClient([json.dumps(_not_vulnerable(packet, response))])

    result = await continue_decompiler_hunter_session(
        store_root=tmp_path,
        ir=ir,
        packet=packet,
        initial_assessment=_needs(packet, request),
        initial_usage=_initial_usage(packet),
        client=client,
    )
    resumed_client = _FakeClient([])
    resumed = await continue_decompiler_hunter_session(
        store_root=tmp_path,
        ir=ir,
        packet=packet,
        initial_assessment=_needs(packet, request),
        initial_usage=_initial_usage(packet),
        client=resumed_client,
    )

    assert result.terminal_status is DecompilerContextTerminalStatus.COMPLETED
    assert result.terminal_assessment.disposition is DecompilerHunterDisposition.NOT_VULNERABLE
    assert result.sessions == 1 and result.model_calls == 2
    assert result.chain_sha256 == resumed.chain_sha256
    assert client.calls == 1 and resumed_client.calls == 0


@pytest.mark.asyncio
async def test_missing_callee_sink_completes_code_hypothesis(tmp_path) -> None:
    ir, packet, _, worker, sink = _fixture(tmp_path)
    request = _request(
        packet,
        BinaryCodeContextRequestKind.DIRECT_CALLEE,
        function_id=worker.function_id,
        related=sink.function_id,
    )
    response = resolve_binary_code_context(ir=ir, packet=packet, request=request)
    assert any(item.kind is BinaryEvidenceFactKind.SECURITY_SINK for item in response.facts)
    client = _FakeClient([json.dumps(_hypothesis(packet, response, sink))])

    result = await continue_decompiler_hunter_session(
        store_root=tmp_path,
        ir=ir,
        packet=packet,
        initial_assessment=_needs(packet, request),
        initial_usage=_initial_usage(packet),
        client=client,
    )

    assert result.terminal_status is DecompilerContextTerminalStatus.COMPLETED
    assert result.terminal_assessment.disposition is DecompilerHunterDisposition.CODE_HYPOTHESIS
    assert result.entries[0].usage is not None
    assert result.entries[0].usage.sessions == 0


@pytest.mark.asyncio
async def test_one_root_can_close_a_proof_on_third_continuation(tmp_path) -> None:
    metadata = _function(
        0x100007000,
        "decode_metadata",
        [
            _instruction(0x100007000, "param", result="metadata"),
            _instruction(
                0x100007004,
                "assign",
                result="metadata_copy",
                inputs=["metadata"],
            ),
            _instruction(0x100007008, "return", inputs=["metadata_copy"]),
        ],
    )
    ir, packet, _caller, worker, sink = _fixture(tmp_path, extra_functions=[metadata])
    metadata_function = next(item for item in ir.functions if item.name == "decode_metadata")
    first = _request(
        packet,
        BinaryCodeContextRequestKind.EXACT_FUNCTION,
        function_id=metadata_function.function_id,
    ).model_copy(update={"request_id": "codectx-worker-proof"})
    first_response = resolve_binary_code_context(ir=ir, packet=packet, request=first)
    second = _request(
        packet,
        BinaryCodeContextRequestKind.DEFINITION_USE_CHAIN,
        function_id=worker.function_id,
        variable="tmp13",
    ).model_copy(update={"request_id": "codectx-late-definition"})
    second_response = resolve_binary_code_context(ir=ir, packet=packet, request=second)
    third = _request(
        packet,
        BinaryCodeContextRequestKind.DIRECT_CALLEE,
        function_id=worker.function_id,
        related=sink.function_id,
    ).model_copy(update={"request_id": "codectx-final-callee"})
    third_response = resolve_binary_code_context(ir=ir, packet=packet, request=third)
    client = _FakeClient(
        [
            json.dumps(_needs_next(packet, first_response, second)),
            json.dumps(_needs_next(packet, second_response, third)),
            json.dumps(_hypothesis(packet, third_response, sink)),
        ]
    )

    result = await continue_decompiler_hunter_session(
        store_root=tmp_path,
        ir=ir,
        packet=packet,
        initial_assessment=_needs(packet, first),
        initial_usage=_initial_usage(packet),
        client=client,
        policy=BinaryCodeContextPolicy(
            maximum_continuations_per_root=3,
            maximum_total_evidence_bytes=288 * 1024,
        ),
    )

    assert len(result.entries) == 3
    assert result.terminal_status is DecompilerContextTerminalStatus.COMPLETED
    assert result.terminal_assessment.disposition is DecompilerHunterDisposition.CODE_HYPOTHESIS
    assert result.sessions == 1
    assert result.model_calls == 4
    assert client.calls == 3


def test_typed_broker_resolves_block_defuse_and_return_use(tmp_path) -> None:
    ir, packet, _, worker, sink = _fixture(tmp_path)
    worker_block = worker.blocks[0]
    requests = (
        _request(packet, BinaryCodeContextRequestKind.EXACT_FUNCTION, function_id=sink.function_id),
        _request(
            packet,
            BinaryCodeContextRequestKind.BASIC_BLOCK_NEIGHBORHOOD,
            function_id=worker.function_id,
            block_id=worker_block.block_id,
        ),
        _request(
            packet,
            BinaryCodeContextRequestKind.DEFINITION_USE_CHAIN,
            function_id=worker.function_id,
            variable="tmp13",
        ),
        _request(
            packet,
            BinaryCodeContextRequestKind.CALLSITE_RETURN_USE,
            function_id=worker.function_id,
            address=worker.start_address + 72,
        ),
    )
    statuses = tuple(
        resolve_binary_code_context(ir=ir, packet=packet, request=item).status for item in requests
    )
    assert statuses == (
        BinaryCodeContextStatus.RESOLVED,
        BinaryCodeContextStatus.UNAVAILABLE,
        BinaryCodeContextStatus.RESOLVED,
        BinaryCodeContextStatus.UNAVAILABLE,
    )
    block_response = resolve_binary_code_context(
        ir=ir,
        packet=packet,
        request=requests[1],
    )
    defuse_response = resolve_binary_code_context(
        ir=ir,
        packet=packet,
        request=requests[2],
    )
    assert block_response.rejection is BinaryCodeContextRejection.PROOF_UNAVAILABLE
    late_definition = next(
        instruction
        for function in defuse_response.functions
        for block in function.blocks
        for instruction in block.instructions
        if instruction.result == "tmp13"
    )
    assert late_definition.address == worker.start_address + 60


def test_definition_use_request_binds_multiple_independent_proof_anchors(tmp_path) -> None:
    ir, packet, _, worker, _ = _fixture(tmp_path)
    request = BinaryCodeContextRequest(
        request_id="codectx-multi-anchor-proof",
        kind=BinaryCodeContextRequestKind.DEFINITION_USE_CHAIN,
        rationale="Resolve both independent values and their shared sink.",
        function_id=worker.function_id,
        address=worker.start_address + 28,
        variable="tmp12",
        supporting_addresses=tuple(
            worker.start_address + offset for offset in (32, 36, 40, 44, 48, 52, 56, 60)
        ),
        supporting_variables=("tmp12", "tmp13"),
        evidence_ids=(packet.allowed_evidence_ids[0],),
        maximum_bytes=12 * 1024,
    )

    response = resolve_binary_code_context(ir=ir, packet=packet, request=request)
    instructions = tuple(
        instruction
        for function in response.functions
        for block in function.blocks
        for instruction in block.instructions
    )

    assert response.status is BinaryCodeContextStatus.RESOLVED
    assert any(item.result == "tmp12" for item in instructions)
    assert any(item.result == "tmp13" for item in instructions)
    combined_addresses = {
        instruction.address
        for function in packet.capsule.functions
        for block in function.blocks
        for instruction in block.instructions
    } | {item.address for item in instructions}
    assert set((request.address, *request.supporting_addresses)).issubset(combined_addresses)


def test_supporting_anchors_are_rejected_for_non_definition_use_request(tmp_path) -> None:
    _, packet, _, worker, _ = _fixture(tmp_path)
    with pytest.raises(ValidationError, match="require a definition/use request"):
        BinaryCodeContextRequest(
            request_id="codectx-invalid-supporting-anchor",
            kind=BinaryCodeContextRequestKind.EXACT_FUNCTION,
            rationale="Invalid mixed request.",
            function_id=worker.function_id,
            supporting_variables=("tmp13",),
            evidence_ids=(packet.allowed_evidence_ids[0],),
        )


def test_definition_use_request_recovers_bounded_cross_function_field_provenance(
    tmp_path,
) -> None:
    prepare = _function(
        0x100004000,
        "prepareGeometry",
        [
            _instruction(0x100004000, "param", result="this"),
            _instruction(
                0x100004004,
                "add",
                result="width_field",
                inputs=["this", "const_114"],
                constants=[0x114],
            ),
            _instruction(
                0x100004008,
                "store",
                inputs=["width_field", "parsed_width"],
            ),
            _instruction(
                0x10000400C,
                "add",
                result="height_field",
                inputs=["this", "const_118"],
                constants=[0x118],
            ),
            _instruction(
                0x100004010,
                "store",
                inputs=["height_field", "parsed_height"],
            ),
            *[
                _instruction(
                    0x100004014 + index * 4,
                    "unknown",
                    result=f"field_filler_{index}",
                )
                for index in range(50)
            ],
            _instruction(
                0x1000040DC,
                "load",
                result="parsed_width_value",
                inputs=["width_field"],
            ),
            _instruction(
                0x1000040E0,
                "compare",
                result="is_supported_format",
                inputs=["parsed_width_value", "const_140b"],
                constants=[0x140B],
            ),
            _instruction(0x1000040E4, "return"),
        ],
    )
    prepare["pseudocode"] = (
        "/* IIOReadPlugin::prepareGeometry(InfoRec*) */\n" + prepare["pseudocode"]
    )
    unrelated = _function(
        0x100005000,
        "initialize",
        [
            _instruction(0x100005000, "param", result="this"),
            _instruction(
                0x100005004,
                "add",
                result="wrong_width_field",
                inputs=["this", "const_114"],
                constants=[0x114],
            ),
            _instruction(
                0x100005008,
                "store",
                inputs=["wrong_width_field", "unrelated_width"],
            ),
            _instruction(0x10000500C, "return"),
        ],
    )
    unrelated["pseudocode"] = (
        "/* OtherReadPlugin::initialize(IIODictionary*) */\n" + unrelated["pseudocode"]
    )
    ir, packet, _, worker, _ = _fixture(
        tmp_path,
        extra_functions=[prepare, unrelated],
    )
    prepare_function = next(item for item in ir.functions if item.start_address == 0x100004000)
    unrelated_function = next(item for item in ir.functions if item.start_address == 0x100005000)
    request = BinaryCodeContextRequest(
        request_id="codectx-object-field-provenance",
        kind=BinaryCodeContextRequestKind.DEFINITION_USE_CHAIN,
        rationale="Recover frozen writers and guards for the decoder-state fields.",
        function_id=worker.function_id,
        variable="tmp13",
        supporting_field_offsets=(0x114, 0x118),
        evidence_ids=(packet.allowed_evidence_ids[0],),
        maximum_bytes=32 * 1024,
    )

    response = resolve_binary_code_context(ir=ir, packet=packet, request=request)
    response_ids = {item.function_id for item in response.functions}
    response_addresses = {
        instruction.address
        for function in response.functions
        for block in function.blocks
        for instruction in block.instructions
    }

    assert response.status is BinaryCodeContextStatus.RESOLVED
    assert prepare_function.function_id in response_ids
    assert unrelated_function.function_id not in response_ids
    assert {0x100004004, 0x10000400C, 0x1000040E0}.issubset(response_addresses)


def test_definition_use_request_retains_phi_predecessor_origins(tmp_path) -> None:
    phi_function = _function(
        0x100006000,
        "decode_phi_rows",
        [
            _instruction(0x100006000, "param", result="destination"),
            _instruction(
                0x100006004,
                "assign",
                result="initial_pointer",
                inputs=["destination"],
            ),
            _instruction(
                0x100006008,
                "phi",
                result="row_pointer",
                inputs=["initial_pointer", "next_pointer"],
            ),
            _instruction(0x10000600C, "store", inputs=["row_pointer", "pixel"]),
            _instruction(
                0x100006010,
                "ptradd",
                result="next_pointer",
                inputs=["row_pointer", "const_8"],
            ),
            _instruction(0x100006014, "return"),
        ],
    )
    ir, packet, _, _, _ = _fixture(tmp_path, extra_functions=[phi_function])
    target = next(item for item in ir.functions if item.start_address == 0x100006000)
    request = BinaryCodeContextRequest(
        request_id="codectx-phi-pointer-origin",
        kind=BinaryCodeContextRequestKind.DEFINITION_USE_CHAIN,
        rationale="Retain both incoming pointer definitions for the loop phi.",
        function_id=target.function_id,
        variable="row_pointer",
        evidence_ids=(packet.allowed_evidence_ids[0],),
        maximum_bytes=8 * 1024,
    )

    response = resolve_binary_code_context(ir=ir, packet=packet, request=request)
    results = {
        instruction.result
        for function in response.functions
        for block in function.blocks
        for instruction in block.instructions
    }

    assert response.status is BinaryCodeContextStatus.RESOLVED
    assert {"initial_pointer", "next_pointer", "row_pointer"}.issubset(results)


def test_supporting_field_offsets_are_rejected_for_non_definition_use_request(
    tmp_path,
) -> None:
    _, packet, _, worker, _ = _fixture(tmp_path)
    with pytest.raises(ValidationError, match="require a definition/use request"):
        BinaryCodeContextRequest(
            request_id="codectx-invalid-field-provenance",
            kind=BinaryCodeContextRequestKind.EXACT_FUNCTION,
            rationale="Invalid field request.",
            function_id=worker.function_id,
            supporting_field_offsets=(0x114,),
            evidence_ids=(packet.allowed_evidence_ids[0],),
        )


def test_invalid_duplicate_out_of_image_file_and_budget_requests_are_rejected(tmp_path) -> None:
    ir, packet, caller, worker, _ = _fixture(tmp_path)
    request = _request(
        packet,
        BinaryCodeContextRequestKind.DIRECT_CALLER,
        function_id=worker.function_id,
        related=caller.function_id,
    )
    response = resolve_binary_code_context(ir=ir, packet=packet, request=request)
    assert response.status is BinaryCodeContextStatus.RESOLVED

    with pytest.raises(ValidationError, match="extra"):
        BinaryCodeContextRequest.model_validate(
            {
                **request.model_dump(mode="json"),
                "path": "/tmp/arbitrary-file",
            }
        )

    outside = request.model_copy(
        update={
            "request_id": "codectx-outside-image",
            "function_id": "fn_ffffffffffffffffffff",
        }
    )
    outside_response = resolve_binary_code_context(ir=ir, packet=packet, request=outside)
    assert outside_response.rejection is BinaryCodeContextRejection.OUTSIDE_FROZEN_IMAGE

    over_budget = resolve_binary_code_context(
        ir=ir,
        packet=packet,
        request=request,
        policy=BinaryCodeContextPolicy(maximum_total_evidence_bytes=16 * 1024),
    )
    assert over_budget.rejection is BinaryCodeContextRejection.EVIDENCE_BUDGET_EXCEEDED


@pytest.mark.asyncio
async def test_repeated_context_is_rejected_without_another_paid_call(tmp_path) -> None:
    ir, packet, caller, worker, _ = _fixture(tmp_path)
    request = _request(
        packet,
        BinaryCodeContextRequestKind.DIRECT_CALLER,
        function_id=worker.function_id,
        related=caller.function_id,
    )
    response = resolve_binary_code_context(ir=ir, packet=packet, request=request)
    client = _FakeClient([json.dumps(_needs_again(packet, response, request))])

    result = await continue_decompiler_hunter_session(
        store_root=tmp_path,
        ir=ir,
        packet=packet,
        initial_assessment=_needs(packet, request),
        initial_usage=_initial_usage(packet),
        client=client,
    )

    assert result.terminal_status is DecompilerContextTerminalStatus.REVIEWER_INCONCLUSIVE
    assert len(result.entries) == 2
    assert result.entries[-1].response.rejection is BinaryCodeContextRejection.DUPLICATE_REQUEST
    assert result.model_calls == 2
    assert client.calls == 1


@pytest.mark.asyncio
async def test_circular_caller_callee_request_is_rejected(tmp_path) -> None:
    ir, packet, caller, worker, _ = _fixture(tmp_path)
    first = _request(
        packet,
        BinaryCodeContextRequestKind.DIRECT_CALLER,
        function_id=worker.function_id,
        related=caller.function_id,
    )
    response = resolve_binary_code_context(ir=ir, packet=packet, request=first)
    evidence = response.facts[0].fact_id
    circular = BinaryCodeContextRequest(
        request_id="codectx-circular-callee",
        kind=BinaryCodeContextRequestKind.DIRECT_CALLEE,
        rationale="Reverse the just-resolved edge.",
        function_id=caller.function_id,
        related_function_id=worker.function_id,
        evidence_ids=(evidence,),
    )
    second_payload = {
        "schema_version": "decompiler-hunter-assessment-v1",
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "capsule_sha256": packet.capsule.capsule_sha256,
        "admission_rank": packet.admission_rank,
        "disposition": "needs_code_context",
        "summary": "The inverse edge was requested.",
        "hypotheses": [],
        "context_requests": [circular.model_dump(mode="json")],
        "safe_path_analysis": "",
        "safe_path_evidence_ids": [],
        "evidence_ids": [evidence],
        "unresolved_questions": [],
    }
    client = _FakeClient([json.dumps(second_payload)])

    result = await continue_decompiler_hunter_session(
        store_root=tmp_path,
        ir=ir,
        packet=packet,
        initial_assessment=_needs(packet, first),
        initial_usage=_initial_usage(packet),
        client=client,
    )

    assert result.entries[-1].response.rejection is BinaryCodeContextRejection.CIRCULAR_REQUEST
    assert result.terminal_status is DecompilerContextTerminalStatus.REVIEWER_INCONCLUSIVE


def test_root_selection_preserves_order_and_caps_six(tmp_path) -> None:
    _, packet, _, worker, _ = _fixture(tmp_path)
    request = _request(
        packet,
        BinaryCodeContextRequestKind.EXACT_FUNCTION,
        function_id=worker.function_id,
    )
    assessments = tuple(
        _needs(
            packet.model_copy(update={"work_id": f"work_{index:064x}"}),
            request,
        )
        for index in range(1, 9)
    )
    admitted, deferred = select_context_continuation_roots(assessments)
    assert admitted == tuple(f"work_{index:064x}" for index in range(1, 7))
    assert deferred == tuple(f"work_{index:064x}" for index in range(7, 9))
