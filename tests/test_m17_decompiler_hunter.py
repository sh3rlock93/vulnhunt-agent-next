from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from vulnhunt_agent.core.llm import LLMResponse
from vulnhunt_agent.domain.schemas import (
    BudgetPolicy,
    ProviderPreflightCode,
    ProviderPreflightResult,
    RunRecord,
)
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.macos.binary_analysis import (
    BinaryCodeContextRequestKind,
    BinaryEvidenceFactKind,
    CodeHuntAdmissionPolicy,
    DecompilerHunterAgent,
    DecompilerHunterAssessment,
    DecompilerHunterDisposition,
    GhidraJSONAdapter,
    admit_code_hunt_roots,
    analyze_binary_candidates,
    build_binary_evidence_capsules,
    build_decompiler_hunter_plan,
    create_binary_research_scope,
    discover_imageio_parsers,
    execute_decompiler_hunter_plan,
    load_decompiler_hunter_packet,
    rank_binary_functions,
    validate_decompiler_hunter_assessment,
)

_SNAPSHOT = "sha256:" + "a" * 64
_UUID = "A2345678-1234-5678-9ABC-DEF012345678"


def _instruction(
    address: int,
    operation: str,
    *,
    result: str | None = None,
    inputs: list[str] | None = None,
    target: str | None = None,
    tags: list[str] | None = None,
    text: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "address": hex(address),
        "op": operation,
        "inputs": inputs or [],
        "text": text or operation,
    }
    if result is not None:
        value["result"] = result
    if target is not None:
        value["target"] = target
    if tags:
        value["tags"] = tags
    return value


def _function(
    address: int,
    name: str,
    instructions: list[dict[str, Any]],
    pseudocode: str,
) -> dict[str, Any]:
    return {
        "entry": hex(address),
        "size": 0x100,
        "name": name,
        "parameters": [],
        "pseudocode": pseudocode,
        "blocks": [{
            "name": "entry",
            "start": hex(address),
            "size": 0x100,
            "successors": [],
            "instructions": instructions,
        }],
    }


def _pipeline():
    entry = 0x100001000
    convert = 0x100002000
    sink = 0x100003000
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
                [
                    _instruction(entry, "param", result="data", tags=["input_data"]),
                    _instruction(
                        entry + 4,
                        "param",
                        result="length",
                        tags=["input_length"],
                    ),
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
                        result="byte_count",
                        inputs=["length"],
                        target="convert_length",
                    ),
                    _instruction(
                        entry + 20,
                        "call",
                        inputs=["data", "byte_count"],
                        target="consume_rows",
                    ),
                    _instruction(entry + 24, "return"),
                ],
                "if (length <= maximum) consume_rows(data, convert_length(length));",
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
                    ),
                    _instruction(convert + 8, "return", inputs=["bytes"]),
                ],
                "return length * pixel_size;",
            ),
            _function(
                sink,
                "consume_rows",
                [
                    _instruction(sink, "param", result="buffer"),
                    _instruction(sink + 4, "param", result="size"),
                    _instruction(sink + 8, "store", inputs=["buffer", "size"]),
                    _instruction(sink + 12, "return"),
                ],
                "buffer[size] = value;",
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
    capsules = build_binary_evidence_capsules(ir, report, admission)
    capsule = next(
        value for value in capsules.capsules
        if value.functions[0].function_name == "consume_rows"
    )
    return ir, report, capsules, capsule


def _preflight(*, transport: str = "openai_api") -> ProviderPreflightResult:
    return ProviderPreflightResult(
        transport=transport,
        model_id="test-model",
        ready=True,
        code=ProviderPreflightCode.READY,
    )


def _plan(tmp_path, *, transport: str = "openai_api", sessions: int = 16):
    ir, report, capsules, capsule = _pipeline()
    scope = create_binary_research_scope(
        snapshot_sha256=_SNAPSHOT,
        authorization_basis="lawfully installed analyst-controlled image",
    )
    plan = build_decompiler_hunter_plan(
        store_root=tmp_path,
        run_id="m17-hunter-test",
        ir=ir,
        capsule_set=capsules,
        scope=scope,
        budget=BudgetPolicy(max_hunter_sessions=sessions),
        provider_preflight=_preflight(transport=transport),
    )
    target = next(
        item for item in plan.routing.work_items
        if load_decompiler_hunter_packet(store_root=tmp_path, work_item=item).root_id
        == capsule.root_id
    )
    packet = load_decompiler_hunter_packet(store_root=tmp_path, work_item=target)
    return ir, report, plan, target, packet


def _hypothesis_assessment(packet) -> dict[str, Any]:
    by_kind: dict[BinaryEvidenceFactKind, list] = {}
    for fact in packet.capsule.facts:
        by_kind.setdefault(fact.kind, []).append(fact)
    source = by_kind[BinaryEvidenceFactKind.INPUT_SOURCE][0]
    path = next(
        fact for kind in (
            BinaryEvidenceFactKind.DATAFLOW,
            BinaryEvidenceFactKind.CALLSITE,
            BinaryEvidenceFactKind.RETURN_USE,
        )
        for fact in by_kind.get(kind, [])
    )
    guard = by_kind[BinaryEvidenceFactKind.GUARD][0]
    sink = by_kind[BinaryEvidenceFactKind.SECURITY_SINK][0]
    addresses = tuple(dict.fromkeys((source.address, path.address, guard.address, sink.address)))
    return {
        "schema_version": "decompiler-hunter-assessment-v1",
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "capsule_sha256": packet.capsule.capsule_sha256,
        "admission_rank": packet.admission_rank,
        "disposition": "code_hypothesis",
        "summary": "Input-derived length reaches an address-backed memory sink.",
        "hypotheses": [{
            "hypothesis_id": "codehypothesis-length-mismatch",
            "title": "Input length can exceed the protected byte relation",
            "vulnerability_class": "out_of_bounds_write",
            "parser_reachability": "The admitted parser route supplies input bytes.",
            "attacker_control": "The length is derived from parser input.",
            "width_signedness": "The decompiler shows an unsigned-width conversion uncertainty.",
            "call_path_function_ids": tuple(
                function.function_id for function in packet.capsule.functions
            ),
            "cfg_path_addresses": addresses,
            "guard_analysis": "The cited comparison bounds length but not the converted bytes.",
            "no_applicable_guard": False,
            "security_relation": "Converted byte count must not exceed the destination extent.",
            "impact": "An address-backed store may exceed the destination boundary.",
            "contradicting_evidence": "The length comparison is present and may constrain reachability.",
            "decompiler_uncertainty": "Recovered types may differ from machine-level widths.",
            "confidence": 0.71,
            "falsification_condition": "A dominating byte-count guard would falsify the claim.",
            "source_evidence_ids": (source.fact_id,),
            "path_evidence_ids": (path.fact_id,),
            "guard_evidence_ids": (guard.fact_id,),
            "sink_evidence_ids": (sink.fact_id,),
            "contradicting_evidence_ids": (),
        }],
        "context_requests": [],
        "safe_path_analysis": "",
        "safe_path_evidence_ids": [],
        "evidence_ids": tuple(sorted({
            source.fact_id,
            path.fact_id,
            guard.fact_id,
            sink.fact_id,
        })),
        "unresolved_questions": ["Does machine-level width preserve the inferred relation?"],
    }


class _FakeClient:
    def __init__(self, responses: list[str], *, transport: str):
        self.model_id = "test-model"
        self.transport = transport
        self.responses = list(responses)
        self.calls: list[dict] = []

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
        self.calls.append({
            "messages": messages,
            "system": system,
            "tools": tools,
            "max_tokens": max_tokens,
            "cache_system": cache_system,
            "cache_tools": cache_tools,
            "cache_last_user": cache_last_user,
        })
        value = self.responses.pop(0)
        return LLMResponse(
            text=value,
            input_tokens=100,
            output_tokens=30,
            cache_read_tokens=0,
            cache_write_tokens=0,
            stop_reason="end_turn",
            content_blocks=[{"text": value}],
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["openai_api", "codex_subscription"])
async def test_hunter_accepts_no_finding_code_hypothesis_for_both_transports(
    tmp_path,
    transport: str,
) -> None:
    _, report, _, work_item, packet = _plan(tmp_path, transport=transport)
    assert report.findings == ()
    response = json.dumps(_hypothesis_assessment(packet))
    client = _FakeClient([response], transport=transport)

    assessment, usage, _ = await DecompilerHunterAgent(client).analyze(work_item, packet)

    assert assessment.disposition is DecompilerHunterDisposition.CODE_HYPOTHESIS
    assert usage.calls == 1
    assert usage.transport == transport
    assert client.calls[0]["system"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("source", "source"),
        ("address", "invented address"),
        ("function", "unknown function"),
        ("guard", "guard"),
    ],
)
def test_unsupported_hypothesis_evidence_is_rejected(tmp_path, mutation: str, message: str) -> None:
    _, _, _, _, packet = _plan(tmp_path)
    payload = _hypothesis_assessment(packet)
    hypothesis = payload["hypotheses"][0]
    if mutation == "source":
        hypothesis["source_evidence_ids"] = hypothesis["sink_evidence_ids"]
    elif mutation == "address":
        hypothesis["cfg_path_addresses"] = (*hypothesis["cfg_path_addresses"], 0xDEADBEEF)
    elif mutation == "function":
        hypothesis["call_path_function_ids"] = (*hypothesis["call_path_function_ids"], "fn_ffffffffffffffffffff")
    else:
        hypothesis["guard_evidence_ids"] = ()
        hypothesis["no_applicable_guard"] = True

    with pytest.raises(ValueError, match=message):
        validate_decompiler_hunter_assessment(
            packet,
            DecompilerHunterAssessment.model_validate(payload),
        )


def test_not_vulnerable_requires_cited_guard_or_failure_path(tmp_path) -> None:
    _, _, _, _, packet = _plan(tmp_path)
    payload = _hypothesis_assessment(packet)
    payload.update({
        "disposition": "not_vulnerable",
        "hypotheses": [],
        "summary": "No vulnerable path was established.",
        "safe_path_analysis": "The route returns safely.",
        "safe_path_evidence_ids": [payload["hypotheses"][0]["source_evidence_ids"][0]],
        "context_requests": [],
    })
    assessment = DecompilerHunterAssessment.model_validate(payload)
    with pytest.raises(ValueError, match="guard or failure"):
        validate_decompiler_hunter_assessment(packet, assessment)


def test_context_requests_are_typed_and_frozen_ir_bound(tmp_path) -> None:
    _, _, _, _, packet = _plan(tmp_path)
    fact_id = packet.allowed_evidence_ids[0]
    payload = {
        "schema_version": "decompiler-hunter-assessment-v1",
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "capsule_sha256": packet.capsule.capsule_sha256,
        "admission_rank": packet.admission_rank,
        "disposition": "needs_code_context",
        "summary": "A direct caller is required to evaluate its precondition.",
        "hypotheses": [],
        "context_requests": [{
            "request_id": "codectx-direct-caller",
            "kind": BinaryCodeContextRequestKind.DIRECT_CALLER.value,
            "rationale": "Recover a frozen caller-side guard.",
            "function_id": "fn_ffffffffffffffffffff",
            "evidence_ids": [fact_id],
        }],
        "safe_path_analysis": "",
        "safe_path_evidence_ids": [],
        "evidence_ids": [fact_id],
        "unresolved_questions": [],
    }
    assessment = DecompilerHunterAssessment.model_validate(payload)
    with pytest.raises(ValueError, match="outside the frozen IR"):
        validate_decompiler_hunter_assessment(packet, assessment)


def test_unsafe_dynamic_or_exploit_output_is_rejected(tmp_path) -> None:
    _, _, _, _, packet = _plan(tmp_path)
    payload = _hypothesis_assessment(packet)
    payload["summary"] = "Start a fuzzer and generate an input to obtain exploit code."
    assessment = DecompilerHunterAssessment.model_validate(payload)
    with pytest.raises(ValueError, match="prohibited"):
        validate_decompiler_hunter_assessment(packet, assessment)


@pytest.mark.asyncio
async def test_json_repair_preserves_work_order_and_usage(tmp_path) -> None:
    _, _, plan, work_item, packet = _plan(tmp_path)
    invalid = _hypothesis_assessment(packet)
    invalid["work_id"] = "work_" + "f" * 64
    valid = _hypothesis_assessment(packet)
    client = _FakeClient(
        [json.dumps(invalid), json.dumps(valid)],
        transport="openai_api",
    )

    assessment, usage, raw = await DecompilerHunterAgent(client).analyze(work_item, packet)

    assert assessment.work_id == plan.routing.work_items[packet.admission_rank - 1].work_id
    assert usage.calls == 2
    assert len(raw) == 2
    assert "Validation error:" in client.calls[1]["messages"][-1]["content"][0]["text"]
    assert "Preserve work_id" in client.calls[1]["messages"][-1]["content"][0]["text"]
    assert "lexicographically" in client.calls[1]["messages"][-1]["content"][0]["text"]


@pytest.mark.asyncio
async def test_repair_explains_that_direct_callee_cannot_carry_proof_anchors(
    tmp_path,
) -> None:
    _, _, _, work_item, packet = _plan(tmp_path)
    fact_id = packet.allowed_evidence_ids[0]
    function_id = packet.frozen_function_ids[0]
    address = packet.known_addresses[0]
    base = {
        "schema_version": "decompiler-hunter-assessment-v1",
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "capsule_sha256": packet.capsule.capsule_sha256,
        "admission_rank": packet.admission_rank,
        "disposition": "needs_code_context",
        "summary": "The omitted callee body is required to resolve the length relation.",
        "hypotheses": [],
        "safe_path_analysis": "",
        "safe_path_evidence_ids": [],
        "evidence_ids": [fact_id],
        "unresolved_questions": ["Does the callee clamp the requested length?"],
    }
    invalid = {
        **base,
        "context_requests": [
            {
                "request_id": "codectx-invalid-direct-callee",
                "kind": "direct_callee",
                "rationale": "Recover the omitted transfer implementation.",
                "function_id": function_id,
                "supporting_addresses": [address],
                "evidence_ids": [fact_id],
            }
        ],
    }
    repaired = {
        **base,
        "context_requests": [
            {
                "request_id": "codectx-repaired-direct-callee",
                "kind": "direct_callee",
                "rationale": "Recover a bounded direct callee from frozen IR.",
                "function_id": function_id,
                "evidence_ids": [fact_id],
            }
        ],
    }
    client = _FakeClient(
        [json.dumps(invalid), json.dumps(repaired)],
        transport="codex_subscription",
    )

    assessment, usage, raw = await DecompilerHunterAgent(client).analyze(work_item, packet)

    repair_prompt = client.calls[1]["messages"][-1]["content"][0]["text"]
    assert assessment.context_requests[0].kind is BinaryCodeContextRequestKind.DIRECT_CALLEE
    assert usage.calls == 2
    assert len(raw) == 2
    assert "Validation error:" in repair_prompt
    assert "supporting proof anchors require a definition/use request" in repair_prompt


def test_plan_admits_exact_budget_prefix_without_reordering(tmp_path) -> None:
    _, _, plan, _, _ = _plan(tmp_path, sessions=1)
    ordered = tuple(item.work_id for item in plan.routing.work_items)
    assert plan.admitted_work_ids == ordered[:1]
    assert plan.deferred_work_ids == ordered[1:]
    assert len(plan.admitted_work_ids) <= 16


@pytest.mark.asyncio
async def test_durable_execution_persists_usage_and_resumes_without_paid_call(tmp_path) -> None:
    _, _, plan, _, _ = _plan(tmp_path, sessions=1)
    first_item = plan.admitted_work_items[0]
    packet = load_decompiler_hunter_packet(store_root=tmp_path, work_item=first_item)
    client = _FakeClient(
        [json.dumps(_hypothesis_assessment(packet))],
        transport="openai_api",
    )
    database = tmp_path / "run.db"
    with SqliteRepository(database) as repository:
        repository.save_run(RunRecord(
            run_id=plan.run_id,
            source_snapshot=_SNAPSHOT,
            config={"milestone": "m17-4"},
        ))
    budget = BudgetPolicy(
        max_hunter_sessions=1,
        max_input_tokens=200_000,
        max_output_tokens=20_000,
        max_wall_clock_minutes=5,
    )

    runs = await execute_decompiler_hunter_plan(
        plan=plan,
        store_root=tmp_path,
        database=database,
        client=client,
        budget=budget,
    )
    resumed = await execute_decompiler_hunter_plan(
        plan=plan,
        store_root=tmp_path,
        database=database,
        client=_FakeClient([], transport="openai_api"),
        budget=budget,
    )

    assert len(runs) == 1
    assert resumed == ()
    with SqliteRepository(database, read_only=True) as repository:
        usage = repository.list_budget_usage(plan.run_id, scope="hunter")
    assert len(usage) == 1
    assert usage[0].work_id == first_item.work_id
