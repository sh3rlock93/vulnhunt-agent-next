from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from vulnhunt_agent.core.llm import LLMResponse
from vulnhunt_agent.scheduling.budget import BudgetExceededError
from vulnhunt_agent.macos.binary_analysis import (
    BinaryEvidenceCapsulePolicy,
    BinaryEvidenceFactKind,
    CodeHuntAdmissionPolicy,
    DecompilerHunterAssessment,
    DecompilerHunterDisposition,
    GhidraJSONAdapter,
    admit_code_hunt_roots,
    analyze_binary_candidates,
    build_binary_evidence_capsules,
    create_binary_research_scope,
    discover_imageio_parsers,
    rank_binary_functions,
)
from vulnhunt_agent.macos.binary_analysis.code_reviewer import (
    CODE_REVIEWER_SYSTEM_PROMPT,
    BinaryCodeReviewerDisposition,
    BinaryCodeReviewerObligation,
    BinaryCodeReviewerPacket,
    BinaryCodeReviewerVerdict,
    ReviewerProofStatus,
    StaticProofObligation,
    StaticReportabilityStatus,
    build_binary_code_reviewer_packet,
    decide_static_reportability,
    run_binary_code_review,
    validate_binary_code_reviewer_verdict,
)
from vulnhunt_agent.macos.binary_analysis.decompiler_hunter import (
    DECOMPILER_HUNTER_SYSTEM_PROMPT,
    BinaryCodeContextRequestKind,
    DecompilerHunterPacket,
    DecompilerVulnerabilityClass,
)

_SNAPSHOT = "sha256:" + "d" * 64
_UUID = "D2345678-1234-5678-9ABC-DEF012345678"


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
        "text": text or f"{result or ''} {operation} {' '.join(inputs or [])}".strip(),
    }
    if result is not None:
        value["result"] = result
    if target is not None:
        value["target"] = target
    if tags:
        value["tags"] = tags
    return value


def _function(address: int, name: str, instructions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "entry": hex(address),
        "size": 0x100,
        "name": name,
        "parameters": [],
        "pseudocode": "\n".join(item["text"] for item in instructions),
        "blocks": [{
            "name": "entry",
            "start": hex(address),
            "size": 0x100,
            "successors": [],
            "instructions": instructions,
        }],
    }


def _fixture(*, guarded_caller: bool = False, maximum_capsule_functions: int = 8):
    entry = 0x100001000
    root = 0x100002000
    helper = 0x100003000
    caller_instructions = [
        _instruction(entry, "param", result="input", tags=["input_data"]),
        _instruction(entry + 4, "param", result="length", tags=["input_length"]),
    ]
    if guarded_caller:
        caller_instructions.extend((
            _instruction(entry + 8, "cmp", inputs=["length", "capacity"]),
            _instruction(entry + 12, "branch", inputs=["length"]),
        ))
    caller_instructions.extend((
        _instruction(entry + 16, "call", inputs=["input", "length"], target="decode_rows"),
        _instruction(entry + 20, "return"),
    ))
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
            _function(entry, "decode_png_entry", caller_instructions),
            _function(root, "decode_rows", [
                _instruction(root, "param", result="input", tags=["input_data"]),
                _instruction(root + 4, "param", result="length", tags=["input_length"]),
                _instruction(root + 8, "mul", result="bytes", inputs=["length", "stride"]),
                _instruction(root + 12, "call", result="buffer", inputs=["bytes"], target="malloc"),
                _instruction(root + 16, "store", inputs=["buffer", "input", "bytes"]),
                _instruction(root + 20, "call", inputs=["buffer", "input", "bytes"], target="copy_rows"),
                _instruction(root + 24, "return"),
            ]),
            _function(helper, "copy_rows", [
                _instruction(helper, "param", result="buffer"),
                _instruction(helper + 4, "param", result="input"),
                _instruction(helper + 8, "param", result="bytes"),
                _instruction(helper + 12, "store", inputs=["buffer", "input", "bytes"]),
                _instruction(helper + 16, "return"),
            ]),
        ],
    }
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
        policy=BinaryEvidenceCapsulePolicy(maximum_functions=maximum_capsule_functions),
    )
    capsule = next(item for item in capsules.capsules if item.functions[0].function_name == "decode_rows")
    scope = create_binary_research_scope(
        snapshot_sha256=_SNAPSHOT,
        authorization_basis="lawfully installed analyst-controlled image",
    )
    work_id = "work_" + "4" * 64
    packet_payload = {
        "schema_version": "decompiler-hunter-packet-v1",
        "prompt_version": "decompiler-imageio-hunter-v1",
        "work_id": work_id,
        "root_id": capsule.root_id,
        "admission_rank": capsule.admission_rank,
        "capsule_set_sha256": capsules.capsule_set_sha256,
        "scope": scope.model_dump(mode="json"),
        "capsule": capsule.model_dump(mode="json"),
        "frozen_function_ids": tuple(sorted(item.function_id for item in ir.functions)),
        "known_function_ids": tuple(item.function_id for item in capsule.functions),
        "known_block_ids": tuple(sorted({
            block.block_id for function in capsule.functions for block in function.blocks
        })),
        "known_addresses": tuple(sorted({
            instruction.address
            for function in capsule.functions
            for block in function.blocks
            for instruction in block.instructions
        })),
        "allowed_evidence_ids": tuple(sorted(item.fact_id for item in capsule.facts)),
        "allowed_context_kinds": tuple(item.value for item in BinaryCodeContextRequestKind),
        "image_execution_allowed": False,
        "input_generation_allowed": False,
        "fuzzer_allowed": False,
        "vm_allowed": False,
        "network_allowed": False,
        "shell_allowed": False,
        "exploit_output_allowed": False,
    }
    from vulnhunt_agent.macos.binary_analysis.decompiler_hunter import _digest

    packet = DecompilerHunterPacket(**packet_payload, packet_sha256=_digest(packet_payload))
    facts: dict[BinaryEvidenceFactKind, list] = {}
    for fact in capsule.facts:
        facts.setdefault(fact.kind, []).append(fact)
    source = facts[BinaryEvidenceFactKind.INPUT_SOURCE][0]
    path = next(
        value for kind in (
            BinaryEvidenceFactKind.DATAFLOW,
            BinaryEvidenceFactKind.CALLSITE,
            BinaryEvidenceFactKind.RETURN_USE,
        ) for value in facts.get(kind, [])
    )
    sink = facts[BinaryEvidenceFactKind.SECURITY_SINK][-1]
    guards = tuple(fact.fact_id for fact in facts.get(BinaryEvidenceFactKind.GUARD, []))
    hypothesis = {
        "hypothesis_id": "codehypothesis-row-byte-overflow",
        "title": "Unchecked row byte calculation reaches a store",
        "vulnerability_class": DecompilerVulnerabilityClass.OUT_OF_BOUNDS_WRITE.value,
        "parser_reachability": "The parser entry calls the admitted row decoder.",
        "attacker_control": "Input-derived length participates in byte calculation.",
        "width_signedness": "The multiplication is recovered at machine width.",
        "call_path_function_ids": tuple(item.function_id for item in capsule.functions),
        "cfg_path_addresses": tuple(dict.fromkeys((source.address, path.address, sink.address))),
        "guard_analysis": (
            "The caller guard dominates the root call." if guards
            else "No applicable guard fact was recovered in the complete path."
        ),
        "no_applicable_guard": not bool(guards),
        "security_relation": "Written bytes must not exceed the allocated destination extent.",
        "impact": "The address-backed store may exceed the destination buffer.",
        "contradicting_evidence": (
            "The caller guard may reject the unsafe length." if guards else "No contradiction recovered."
        ),
        "decompiler_uncertainty": "Recovered types may be incomplete.",
        "confidence": 0.86,
        "falsification_condition": "A dominating capacity guard disproves the path.",
        "source_evidence_ids": (source.fact_id,),
        "path_evidence_ids": (path.fact_id,),
        "guard_evidence_ids": guards,
        "sink_evidence_ids": (sink.fact_id,),
        "contradicting_evidence_ids": guards,
    }
    assessment = DecompilerHunterAssessment(
        work_id=work_id,
        root_id=capsule.root_id,
        capsule_sha256=capsule.capsule_sha256,
        admission_rank=capsule.admission_rank,
        disposition=DecompilerHunterDisposition.CODE_HYPOTHESIS,
        summary="One address-backed code hypothesis requires independent review.",
        hypotheses=(hypothesis,),
        evidence_ids=tuple(sorted({source.fact_id, path.fact_id, sink.fact_id, *guards})),
    )
    reviewer_packet = build_binary_code_reviewer_packet(
        ir=ir,
        hunter_packet=packet,
        hunter_assessment=assessment,
        product_version="26.5.2",
        build_version="25F84",
    )
    return ir, packet, assessment, reviewer_packet


def _verdict(packet, *, disposition="accept", prose="Independent evidence is complete"):
    hypothesis = packet.hypothesis
    evidence_by_obligation = {
        StaticProofObligation.FROZEN_TARGET: (),
        StaticProofObligation.REACHABLE_PARSER_ROUTE: hypothesis.source_evidence_ids,
        StaticProofObligation.ATTACKER_CONTROLLED_SOURCE: hypothesis.source_evidence_ids,
        StaticProofObligation.FEASIBLE_PATH: hypothesis.path_evidence_ids,
        StaticProofObligation.SECURITY_RELATION: tuple(sorted(set(
            hypothesis.path_evidence_ids + hypothesis.sink_evidence_ids
        ))),
        StaticProofObligation.GUARD_ANALYSIS: hypothesis.guard_evidence_ids,
        StaticProofObligation.SECURITY_SINK_AND_IMPACT: hypothesis.sink_evidence_ids,
        StaticProofObligation.CONTRADICTION_REVIEW: tuple(sorted(set(
            hypothesis.guard_evidence_ids + hypothesis.contradicting_evidence_ids
        ))),
        StaticProofObligation.INDEPENDENT_ACCEPTANCE: (),
    }
    status = ReviewerProofStatus.PROVEN
    obligations = tuple(BinaryCodeReviewerObligation(
        obligation=item,
        status=status,
        analysis=f"{prose}: {item.value}",
        evidence_ids=evidence_by_obligation[item],
    ) for item in StaticProofObligation)
    return BinaryCodeReviewerVerdict(
        reviewer_session_id=packet.reviewer_session_id,
        work_id=packet.work_id,
        root_id=packet.root_id,
        hypothesis_id=hypothesis.hypothesis_id,
        capsule_sha256=packet.capsule_sha256,
        context_chain_sha256=packet.context_chain_sha256,
        disposition=disposition,
        summary=prose,
        obligations=obligations,
        conservative_impact="Potential out-of-bounds write; exploitability remains unknown.",
        reviewer_confidence=0.91,
    )


def _needs_context_verdict(packet) -> BinaryCodeReviewerVerdict:
    accepted = _verdict(packet)
    obligations = list(accepted.obligations)
    index = tuple(StaticProofObligation).index(StaticProofObligation.GUARD_ANALYSIS)
    obligations[index] = BinaryCodeReviewerObligation(
        obligation=StaticProofObligation.GUARD_ANALYSIS,
        status=ReviewerProofStatus.UNKNOWN,
        analysis="The direct caller precondition is not present in the initial capsule.",
    )
    source_id = packet.hypothesis.source_evidence_ids[0]
    return BinaryCodeReviewerVerdict(
        reviewer_session_id=packet.reviewer_session_id,
        work_id=packet.work_id,
        root_id=packet.root_id,
        hypothesis_id=packet.hypothesis.hypothesis_id,
        capsule_sha256=packet.capsule_sha256,
        context_chain_sha256=packet.context_chain_sha256,
        disposition=BinaryCodeReviewerDisposition.NEEDS_CODE_CONTEXT,
        summary="One direct caller slice is required.",
        obligations=tuple(obligations),
        context_request={
            "request_id": "codectx-reviewer-direct-caller",
            "kind": "direct_caller",
            "rationale": "Recover the caller-side precondition from frozen IR.",
            "function_id": packet.hypothesis.call_path_function_ids[0],
            "evidence_ids": [source_id],
            "maximum_bytes": 32768,
        },
        minimal_missing_evidence=("direct caller precondition",),
        conservative_impact="Potential write mismatch remains unproven.",
        reviewer_confidence=0.55,
    )


class _FakeClient:
    model_id = "test-model"
    transport = "openai_api"

    def __init__(self, responses: list[str] | None = None, *, error: Exception | None = None):
        self.responses = list(responses or [])
        self.error = error
        self.calls: list[dict[str, Any]] = []

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
        self.calls.append({"messages": messages, "system": system})
        if self.error is not None:
            raise self.error
        value = self.responses.pop(0)
        return LLMResponse(
            text=value,
            input_tokens=200,
            output_tokens=80,
            cache_read_tokens=0,
            cache_write_tokens=0,
            stop_reason="end_turn",
            content_blocks=[{"text": value}],
        )


@pytest.mark.asyncio
async def test_valid_fixture_requires_fresh_reviewer_and_becomes_reportable(tmp_path) -> None:
    ir, hunter_packet, assessment, packet = _fixture()
    client = _FakeClient([json.dumps(_verdict(packet).model_dump(mode="json"))])

    result = await run_binary_code_review(
        store_root=tmp_path,
        ir=ir,
        hunter_packet=hunter_packet,
        hunter_assessment=assessment,
        product_version="26.5.2",
        build_version="25F84",
        run_id="m17-review-test",
        client=client,
    )
    resumed = await run_binary_code_review(
        store_root=tmp_path,
        ir=ir,
        hunter_packet=hunter_packet,
        hunter_assessment=assessment,
        product_version="26.5.2",
        build_version="25F84",
        run_id="m17-review-test",
        client=_FakeClient([]),
    )

    assert result.decision.status is StaticReportabilityStatus.REPORTABLE_STATIC
    assert result.result_sha256 == resumed.result_sha256
    assert result.reviewer_session_id != hunter_packet.work_id.replace("work_", "review_")
    assert result.usage.scope == "reviewer" and result.usage.sessions == 1
    assert client.calls[0]["system"] == CODE_REVIEWER_SYSTEM_PROMPT
    assert CODE_REVIEWER_SYSTEM_PROMPT != DECOMPILER_HUNTER_SYSTEM_PROMPT
    assert "Hunter conversation" not in client.calls[0]["messages"][0]["content"][0]["text"]
    assert result.image_executions == result.fuzzer_invocations == result.vm_boots == 0
    assert result.report.dynamic_reproduction is False
    assert result.report.apple_submission_ready is False
    raw_files = tuple(tmp_path.rglob("raw-response-01.txt"))
    assert len(raw_files) == 1 and "reviewers" in raw_files[0].parts


def test_neither_hunter_nor_reviewer_can_set_reportability() -> None:
    _, _, assessment, packet = _fixture()
    hunter_payload = assessment.model_dump(mode="json")
    hunter_payload["reportable_static"] = True
    with pytest.raises(ValidationError, match="extra"):
        DecompilerHunterAssessment.model_validate(hunter_payload)

    verdict_payload = _verdict(packet).model_dump(mode="json")
    verdict_payload["reportable_static"] = True
    with pytest.raises(ValidationError, match="extra"):
        BinaryCodeReviewerVerdict.model_validate(verdict_payload)


def test_patched_dominating_guard_is_reviewer_rejected() -> None:
    _, _, _, packet = _fixture(guarded_caller=True)
    accepted = _verdict(packet)
    guard_id = packet.hypothesis.guard_evidence_ids[0]
    obligations = list(accepted.obligations)
    index = tuple(StaticProofObligation).index(StaticProofObligation.GUARD_ANALYSIS)
    obligations[index] = BinaryCodeReviewerObligation(
        obligation=StaticProofObligation.GUARD_ANALYSIS,
        status=ReviewerProofStatus.DISPROVEN,
        analysis="The cited dominating combined-range guard rejects the unsafe path.",
        evidence_ids=(guard_id,),
    )
    verdict = accepted.model_copy(update={
        "disposition": BinaryCodeReviewerDisposition.REJECT,
        "obligations": tuple(obligations),
        "summary": "The caller guard disproves the claimed path.",
    })
    verdict = BinaryCodeReviewerVerdict.model_validate(verdict.model_dump(mode="json"))

    decision = decide_static_reportability(packet, verdict)

    assert decision.status is StaticReportabilityStatus.REVIEWER_REJECTED


def test_hallucinated_evidence_hard_fails_and_uncited_sink_cannot_be_reportable() -> None:
    _, _, _, packet = _fixture()
    verdict = _verdict(packet)
    obligations = list(verdict.obligations)
    sink_index = tuple(StaticProofObligation).index(
        StaticProofObligation.SECURITY_SINK_AND_IMPACT
    )
    obligations[sink_index] = obligations[sink_index].model_copy(
        update={"evidence_ids": ("codefact_ffffffffffffffffffff",)}
    )
    hallucinated = verdict.model_copy(update={"obligations": tuple(obligations)})
    with pytest.raises(ValueError, match="outside its packet"):
        validate_binary_code_reviewer_verdict(packet, hallucinated)

    obligations[sink_index] = obligations[sink_index].model_copy(update={"evidence_ids": ()})
    with pytest.raises(ValueError, match="requires cited evidence"):
        BinaryCodeReviewerVerdict.model_validate(
            verdict.model_copy(update={"obligations": tuple(obligations)}).model_dump(mode="json")
        )


@pytest.mark.asyncio
async def test_provider_error_is_inconclusive_never_accepted(tmp_path) -> None:
    ir, hunter_packet, assessment, _ = _fixture()
    result = await run_binary_code_review(
        store_root=tmp_path,
        ir=ir,
        hunter_packet=hunter_packet,
        hunter_assessment=assessment,
        product_version="26.5.2",
        build_version="25F84",
        run_id="m17-review-error",
        client=_FakeClient(error=RuntimeError("provider unavailable")),
    )

    assert result.verdict is None
    assert result.decision.status is StaticReportabilityStatus.REVIEWER_INCONCLUSIVE
    assert result.usage.sessions == 1 and result.usage.calls == 0
    assert result.terminal_reason == "provider_error:RuntimeError"


@pytest.mark.asyncio
async def test_budget_exhaustion_is_inconclusive_never_accepted(tmp_path) -> None:
    ir, hunter_packet, assessment, _ = _fixture()
    result = await run_binary_code_review(
        store_root=tmp_path,
        ir=ir,
        hunter_packet=hunter_packet,
        hunter_assessment=assessment,
        product_version="26.5.2",
        build_version="25F84",
        run_id="m17-review-budget",
        client=_FakeClient(error=BudgetExceededError("max_input_tokens")),
    )

    assert result.decision.status is StaticReportabilityStatus.REVIEWER_INCONCLUSIVE
    assert result.terminal_reason == "budget:max_input_tokens"


@pytest.mark.asyncio
async def test_one_reviewer_context_slice_uses_same_frozen_broker(tmp_path) -> None:
    ir, hunter_packet, assessment, packet = _fixture(maximum_capsule_functions=1)
    needs = _needs_context_verdict(packet)
    accepted = _verdict(packet, prose="Caller evidence was independently considered")
    client = _FakeClient([
        json.dumps(needs.model_dump(mode="json")),
        json.dumps(accepted.model_dump(mode="json")),
    ])

    result = await run_binary_code_review(
        store_root=tmp_path,
        ir=ir,
        hunter_packet=hunter_packet,
        hunter_assessment=assessment,
        product_version="26.5.2",
        build_version="25F84",
        run_id="m17-review-context",
        client=client,
    )

    assert result.reviewer_context_response is not None
    assert result.reviewer_context_response.status.value == "resolved"
    assert result.decision.status is StaticReportabilityStatus.REPORTABLE_STATIC
    assert result.usage.sessions == 1 and result.usage.calls == 2
    assert len(client.calls) == 2


def test_unknown_attacker_control_and_alias_uncertainty_stay_inconclusive() -> None:
    _, _, _, packet = _fixture()
    accepted = _verdict(packet)
    obligations = list(accepted.obligations)
    index = tuple(StaticProofObligation).index(
        StaticProofObligation.ATTACKER_CONTROLLED_SOURCE
    )
    obligations[index] = BinaryCodeReviewerObligation(
        obligation=StaticProofObligation.ATTACKER_CONTROLLED_SOURCE,
        status=ReviewerProofStatus.UNKNOWN,
        analysis="Alias recovery cannot prove that the value is input-controlled.",
        evidence_ids=packet.hypothesis.source_evidence_ids,
    )
    verdict = BinaryCodeReviewerVerdict(
        **{
            **accepted.model_dump(mode="json"),
            "disposition": BinaryCodeReviewerDisposition.INCONCLUSIVE.value,
            "obligations": tuple(item.model_dump(mode="json") for item in obligations),
            "minimal_missing_evidence": ("input alias provenance",),
            "reviewer_confidence": 0.62,
        }
    )

    decision = decide_static_reportability(packet, verdict)

    assert decision.status is StaticReportabilityStatus.REVIEWER_INCONCLUSIVE


def test_decision_ignores_irrelevant_prose_but_changes_with_evidence_digest() -> None:
    _, _, _, packet = _fixture()
    first = _verdict(packet, prose="First independent wording")
    second = _verdict(packet, prose="Different independent wording")

    decision_a = decide_static_reportability(packet, first)
    decision_b = decide_static_reportability(packet, second)
    changed_packet = packet.model_copy(update={
        "context_chain_sha256": "sha256:" + "9" * 64,
    })
    changed_payload = changed_packet.model_dump(mode="json", exclude={"packet_sha256"})
    from vulnhunt_agent.macos.binary_analysis.code_reviewer import _digest

    changed_packet = BinaryCodeReviewerPacket.model_validate({
        **changed_payload,
        "packet_sha256": _digest(changed_payload),
    })
    changed_verdict = second.model_copy(update={
        "context_chain_sha256": changed_packet.context_chain_sha256,
    })
    decision_c = decide_static_reportability(changed_packet, changed_verdict)

    assert decision_a.evidence_decision_sha256 == decision_b.evidence_decision_sha256
    assert decision_a.decision_sha256 == decision_b.decision_sha256
    assert decision_c.evidence_decision_sha256 != decision_a.evidence_decision_sha256
