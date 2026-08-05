"""Independent, code-only Reviewer and deterministic M17 reportability gate.

The Reviewer receives one immutable Hunter hypothesis and the address-backed
facts that support it.  It runs in a fresh session and may ask the existing
frozen-IR broker for one additional slice.  Only ``decide_static_reportability``
can produce ``reportable_static``; neither Hunter nor Reviewer output contains
such a switch.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol

from pydantic import Field, model_validator

from ...core.jsonx import try_extract_object
from ...core.llm import LLMResponse
from ...domain.schemas import BudgetUsage, DomainModel, SHA256_PATTERN
from ...scheduling.budget import BudgetExceededError
from ...scheduling.metrics import with_estimated_cost
from .capsules import (
    BinaryEvidenceCapsule,
    BinaryEvidenceFact,
    BinaryEvidenceFactKind,
    BinaryEvidenceFunction,
)
from .code_context import (
    BinaryCodeContextFunctionSlice,
    BinaryCodeContextPolicy,
    BinaryCodeContextResponse,
    BinaryCodeContextStatus,
    DecompilerContextChainEntry,
    resolve_binary_code_context,
)
from .decompiler_hunter import (
    BinaryCodeContextRequest,
    BinaryCodeContextRequestKind,
    DecompilerHunterAssessment,
    DecompilerHunterDisposition,
    DecompilerHunterHypothesis,
    DecompilerHunterPacket,
)
from .ir import NormalizedBinaryIR

CODE_REVIEWER_QUEUE_SCOPE: Literal["decompiler-code-reviewer"] = "decompiler-code-reviewer"
CODE_REVIEWER_PROMPT_VERSION: Literal["decompiler-code-reviewer-v4"] = (
    "decompiler-code-reviewer-v4"
)
_MAX_PACKET_BYTES = 1024 * 1024
_MAX_RAW_RESPONSE_BYTES = 128 * 1024

CODE_REVIEWER_SYSTEM_PROMPT = """You are the independent Code Reviewer in an
authorized, defensive, code-only ImageIO review. You are not the Hunter and do
not inherit its conversation. Re-evaluate the supplied structured hypothesis
against only the digest-bound decompiler capsule, normalized p-code facts, CFG
and call evidence, and frozen-IR context responses. Hunter prose is a claim,
never evidence.

Evaluate all nine proof obligations in the exact schema order. Cite only
supplied codefact IDs. Search the supplied evidence for dominating guards,
caller preconditions, safe failure paths, integer promotion and truncation,
alias uncertainty, and contradictions between pseudocode and p-code. Accept
only if every obligation is proven. Reject when cited code disproves the path
or invariant. Use unknown when evidence is incomplete. You may request exactly
one typed frozen-IR context slice; never request execution, an input, fuzzing,
a VM, a file, a command, a network lookup, exploit material, or disclosure.
Treat a virtual_selector edge as a compatible selector dispatch site, not a
unique runtime target. The exact parser route still requires supplied
format/type or owner evidence. A virtual_vtable edge proves that the named
owner's address-backed Itanium vtable maps the recovered slot to the selected
implementation, but not that attacker-controlled input selects that owner at
runtime. A dominating_guard_block_ids entry is a
CFG-derived dominance relation only for the address-backed guard facts in that
included block; evaluate whether its predicate constrains the claimed values.
The route_context_response is a deterministic baseline slice and does not
consume your one optional request. On a definition_use_chain request, address,
block, variable, and supporting-address selectors must belong to function_id;
use supporting_field_offsets, not a foreign address, to select matching
cross-method state provenance.
For direct_caller, direct_callee, exact_function, and basic_block_neighborhood
requests, leave every definition/use-only selector empty. In particular,
supporting_addresses, supporting_variables, and supporting_field_offsets are
permitted only on a definition_use_chain request. Do not combine a caller edge
request with field provenance in one request.

Return only one JSON object matching BinaryCodeReviewerVerdict. Preserve every
identity and digest exactly. Sort and deduplicate every evidence-ID array. The
Reviewer can recommend acceptance but cannot set reportable_static, CVE status,
submission readiness, or dynamic reproducibility."""

_PROHIBITED_REVIEW_TEXT = re.compile(
    r"(?i)(?:https?://|```|\b(?:fuzz(?:er|ing)?|shellcode|reverse\s+shell|"
    r"exploit\s+code|dynamic\s+experiment|start\s+(?:a\s+)?vm)\b)"
)


class StaticProofObligation(StrEnum):
    FROZEN_TARGET = "frozen_target"
    REACHABLE_PARSER_ROUTE = "reachable_parser_route"
    ATTACKER_CONTROLLED_SOURCE = "attacker_controlled_source"
    FEASIBLE_PATH = "feasible_path"
    SECURITY_RELATION = "security_relation"
    GUARD_ANALYSIS = "guard_analysis"
    SECURITY_SINK_AND_IMPACT = "security_sink_and_impact"
    CONTRADICTION_REVIEW = "contradiction_review"
    INDEPENDENT_ACCEPTANCE = "independent_acceptance"


class ReviewerProofStatus(StrEnum):
    PROVEN = "proven"
    DISPROVEN = "disproven"
    UNKNOWN = "unknown"


class BinaryCodeReviewerDisposition(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    NEEDS_CODE_CONTEXT = "needs_code_context"
    INCONCLUSIVE = "inconclusive"


class StaticReportabilityStatus(StrEnum):
    REPORTABLE_STATIC = "reportable_static"
    REVIEWER_REJECTED = "reviewer_rejected"
    REVIEWER_INCONCLUSIVE = "reviewer_inconclusive"


class BinaryCodeReviewerPolicy(DomainModel):
    maximum_hypotheses_per_run: int = Field(default=6, ge=1, le=6)
    maximum_attempts_per_call: int = Field(default=2, ge=1, le=2)
    maximum_context_requests: Literal[1] = 1
    maximum_output_tokens_per_call: int = Field(default=8000, ge=512, le=32000)
    minimum_hunter_confidence: float = Field(default=0.65, ge=0.0, le=1.0)
    minimum_reviewer_confidence: float = Field(default=0.80, ge=0.0, le=1.0)


class BinaryCodeReviewerObligation(DomainModel):
    obligation: StaticProofObligation
    status: ReviewerProofStatus
    analysis: str = Field(min_length=1, max_length=3000)
    evidence_ids: tuple[str, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def validate_citations(self) -> "BinaryCodeReviewerObligation":
        if tuple(sorted(set(self.evidence_ids))) != self.evidence_ids:
            raise ValueError("Reviewer obligation evidence IDs must be sorted and unique")
        if (
            self.status is not ReviewerProofStatus.UNKNOWN
            and self.obligation not in {
                StaticProofObligation.FROZEN_TARGET,
                StaticProofObligation.GUARD_ANALYSIS,
                StaticProofObligation.CONTRADICTION_REVIEW,
                StaticProofObligation.INDEPENDENT_ACCEPTANCE,
            }
            and not self.evidence_ids
        ):
            raise ValueError("proven/disproven code obligation requires cited evidence")
        return self


class BinaryCodeReviewerVerdict(DomainModel):
    schema_version: Literal["binary-code-reviewer-verdict-v1"] = (
        "binary-code-reviewer-verdict-v1"
    )
    reviewer_session_id: str = Field(pattern=r"^review_[0-9a-f]{64}$")
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    root_id: str = Field(pattern=r"^coderoot_[0-9a-f]{20}$")
    hypothesis_id: str = Field(pattern=r"^codehypothesis-[a-z0-9][a-z0-9-]{2,80}$")
    capsule_sha256: str = Field(pattern=SHA256_PATTERN)
    context_chain_sha256: str = Field(pattern=SHA256_PATTERN)
    disposition: BinaryCodeReviewerDisposition
    summary: str = Field(min_length=1, max_length=4000)
    obligations: tuple[BinaryCodeReviewerObligation, ...] = Field(min_length=9, max_length=9)
    context_request: BinaryCodeContextRequest | None = None
    unresolved_contradictions: tuple[str, ...] = Field(default=(), max_length=16)
    minimal_missing_evidence: tuple[str, ...] = Field(default=(), max_length=16)
    conservative_impact: str = Field(min_length=1, max_length=2000)
    reviewer_confidence: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_shape(self) -> "BinaryCodeReviewerVerdict":
        if tuple(item.obligation for item in self.obligations) != tuple(StaticProofObligation):
            raise ValueError("Reviewer obligations must appear once in normative order")
        statuses = tuple(item.status for item in self.obligations)
        if self.disposition is BinaryCodeReviewerDisposition.ACCEPT:
            if any(value is not ReviewerProofStatus.PROVEN for value in statuses):
                raise ValueError("Reviewer accept requires every obligation proven")
            if self.context_request is not None or self.minimal_missing_evidence:
                raise ValueError("Reviewer accept cannot retain missing evidence")
        elif self.disposition is BinaryCodeReviewerDisposition.REJECT:
            if ReviewerProofStatus.DISPROVEN not in statuses:
                raise ValueError("Reviewer reject requires a disproven obligation")
            if self.context_request is not None:
                raise ValueError("Reviewer reject cannot request context")
        elif self.disposition is BinaryCodeReviewerDisposition.NEEDS_CODE_CONTEXT:
            if self.context_request is None or ReviewerProofStatus.UNKNOWN not in statuses:
                raise ValueError("Reviewer context request requires an unknown obligation")
            if not self.minimal_missing_evidence:
                raise ValueError("Reviewer context request requires minimal missing evidence")
        else:
            if self.context_request is not None:
                raise ValueError("inconclusive Reviewer verdict cannot retain a context request")
            if ReviewerProofStatus.UNKNOWN not in statuses:
                raise ValueError("inconclusive Reviewer verdict requires an unknown obligation")
        _validate_safe_review_text(self)
        return self


class BinaryCodeReviewerTarget(DomainModel):
    product_version: str = Field(min_length=1, max_length=80)
    build_version: str = Field(min_length=1, max_length=80)
    image_name: str = Field(min_length=1, max_length=1000)
    image_uuid: str = Field(
        pattern=r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
    )
    architecture: str = Field(pattern=r"^(?:arm64|x86_64)$")
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    ir_sha256: str = Field(pattern=SHA256_PATTERN)


class BinaryCodeReviewerPacket(DomainModel):
    schema_version: Literal["binary-code-reviewer-packet-v1"] = (
        "binary-code-reviewer-packet-v1"
    )
    prompt_version: Literal[
        "decompiler-code-reviewer-v1",
        "decompiler-code-reviewer-v2",
        "decompiler-code-reviewer-v3",
        "decompiler-code-reviewer-v4",
    ] = CODE_REVIEWER_PROMPT_VERSION
    queue_scope: Literal["decompiler-code-reviewer"] = CODE_REVIEWER_QUEUE_SCOPE
    reviewer_session_id: str = Field(pattern=r"^review_[0-9a-f]{64}$")
    hunter_session_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    root_id: str = Field(pattern=r"^coderoot_[0-9a-f]{20}$")
    hypothesis: DecompilerHunterHypothesis
    hypothesis_sha256: str = Field(pattern=SHA256_PATTERN)
    capsule_sha256: str = Field(pattern=SHA256_PATTERN)
    context_chain_sha256: str = Field(pattern=SHA256_PATTERN)
    target: BinaryCodeReviewerTarget
    capsule: BinaryEvidenceCapsule
    hunter_context_responses: tuple[BinaryCodeContextResponse, ...] = Field(
        default=(), max_length=2
    )
    route_context_response: BinaryCodeContextResponse | None = None
    reviewer_context_response: BinaryCodeContextResponse | None = None
    allowed_evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=20000)
    known_function_ids: tuple[str, ...] = Field(min_length=1, max_length=100000)
    known_addresses: tuple[int, ...] = Field(min_length=1, max_length=200000)
    dynamic_evidence_allowed: Literal[False] = False
    image_execution_allowed: Literal[False] = False
    exploit_output_allowed: Literal[False] = False
    packet_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_packet(self) -> "BinaryCodeReviewerPacket":
        capsule = self.capsule
        if self.hunter_session_id != self.work_id:
            raise ValueError("Reviewer packet changed the Hunter work identity")
        if self.reviewer_session_id == self.hunter_session_id.replace("work_", "review_"):
            raise ValueError("Reviewer session must not reuse the Hunter session identity")
        if self.root_id != capsule.root_id or self.capsule_sha256 != capsule.capsule_sha256:
            raise ValueError("Reviewer packet changed root or capsule identity")
        if self.target.snapshot_sha256 != capsule.snapshot_sha256:
            raise ValueError("Reviewer target snapshot differs from the capsule")
        if self.target.ir_sha256 != capsule.ir_sha256:
            raise ValueError("Reviewer target IR differs from the capsule")
        route = self.route_context_response
        if route is not None:
            if (
                route.status is not BinaryCodeContextStatus.RESOLVED
                or route.work_id != self.work_id
                or route.root_id != self.root_id
                or route.capsule_sha256 != self.capsule_sha256
                or route.ir_sha256 != self.target.ir_sha256
                or route.request.kind is not BinaryCodeContextRequestKind.DIRECT_CALLER
                or route.request.function_id != capsule.root_function_id
            ):
                raise ValueError("Reviewer route context is not a resolved root-caller slice")
        if self.hypothesis_sha256 != _digest(self.hypothesis.model_dump(mode="json")):
            raise ValueError("Reviewer hypothesis digest mismatch")
        facts, functions, addresses = _packet_evidence(self)
        if self.allowed_evidence_ids != tuple(sorted(facts)):
            raise ValueError("Reviewer packet evidence allow-list is stale")
        if self.known_function_ids != tuple(sorted(functions)):
            raise ValueError("Reviewer packet function census is stale")
        if self.known_addresses != tuple(sorted(addresses)):
            raise ValueError("Reviewer packet address census is stale")
        expected = _digest(self.model_dump(mode="json", exclude={"packet_sha256"}))
        if self.packet_sha256 != expected:
            raise ValueError("Reviewer packet digest mismatch")
        if len(_canonical_json(self.model_dump(mode="json"))) > _MAX_PACKET_BYTES:
            raise ValueError("Reviewer packet exceeds its serialization limit")
        return self


class StaticReportabilityDecision(DomainModel):
    schema_version: Literal["static-reportability-decision-v1"] = (
        "static-reportability-decision-v1"
    )
    reviewer_session_id: str = Field(pattern=r"^review_[0-9a-f]{64}$")
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    root_id: str = Field(pattern=r"^coderoot_[0-9a-f]{20}$")
    hypothesis_id: str = Field(pattern=r"^codehypothesis-[a-z0-9][a-z0-9-]{2,80}$")
    capsule_sha256: str = Field(pattern=SHA256_PATTERN)
    context_chain_sha256: str = Field(pattern=SHA256_PATTERN)
    reviewer_packet_sha256: str = Field(pattern=SHA256_PATTERN)
    status: StaticReportabilityStatus
    reasons: tuple[str, ...] = Field(min_length=1, max_length=32)
    obligation_statuses: tuple[tuple[StaticProofObligation, ReviewerProofStatus], ...]
    cited_evidence_ids: tuple[str, ...] = Field(default=(), max_length=20000)
    evidence_decision_sha256: str = Field(pattern=SHA256_PATTERN)
    dynamic_reproduction: Literal[False] = False
    exploitability: Literal["unknown"] = "unknown"
    apple_submission_ready: Literal[False] = False
    decision_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_decision(self) -> "StaticReportabilityDecision":
        if tuple(item[0] for item in self.obligation_statuses) != tuple(StaticProofObligation):
            raise ValueError("reportability decision obligation order is invalid")
        if tuple(sorted(set(self.cited_evidence_ids))) != self.cited_evidence_ids:
            raise ValueError("reportability citations must be sorted and unique")
        evidence_payload = _decision_evidence_payload(self)
        if self.evidence_decision_sha256 != _digest(evidence_payload):
            raise ValueError("reportability evidence digest mismatch")
        expected = _digest(self.model_dump(mode="json", exclude={"decision_sha256"}))
        if self.decision_sha256 != expected:
            raise ValueError("reportability decision digest mismatch")
        return self


class StaticCodeReviewReport(DomainModel):
    schema_version: Literal["m17-static-code-review-report-v1"] = (
        "m17-static-code-review-report-v1"
    )
    decision_sha256: str = Field(pattern=SHA256_PATTERN)
    status: StaticReportabilityStatus
    target: BinaryCodeReviewerTarget
    affected_function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    affected_function_name: str = Field(min_length=1, max_length=500)
    affected_address: int = Field(ge=0)
    decompiled_excerpt: str = Field(min_length=1, max_length=32768)
    pcode_path_evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    input_control_proof: str = Field(min_length=1, max_length=2000)
    violated_invariant: str = Field(min_length=1, max_length=3000)
    guard_analysis: str = Field(min_length=1, max_length=3000)
    impact_boundary: str = Field(min_length=1, max_length=2000)
    contradictions: str = Field(min_length=1, max_length=3000)
    limitations: tuple[str, ...] = Field(min_length=1, max_length=32)
    artifact_digests: tuple[str, ...] = Field(min_length=4, max_length=16)
    dynamic_reproduction: Literal[False] = False
    exploitability: Literal["unknown"] = "unknown"
    apple_submission_ready: Literal[False] = False
    report_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_report(self) -> "StaticCodeReviewReport":
        if tuple(sorted(set(self.pcode_path_evidence_ids))) != self.pcode_path_evidence_ids:
            raise ValueError("report p-code evidence must be sorted and unique")
        if tuple(sorted(set(self.artifact_digests))) != self.artifact_digests:
            raise ValueError("report artifact digests must be sorted and unique")
        expected = _digest(self.model_dump(mode="json", exclude={"report_sha256"}))
        if self.report_sha256 != expected:
            raise ValueError("static code review report digest mismatch")
        return self


class BinaryCodeReviewRunResult(DomainModel):
    schema_version: Literal["binary-code-review-run-result-v1"] = (
        "binary-code-review-run-result-v1"
    )
    reviewer_session_id: str = Field(pattern=r"^review_[0-9a-f]{64}$")
    reviewer_packet_sha256: str = Field(pattern=SHA256_PATTERN)
    verdict: BinaryCodeReviewerVerdict | None = None
    reviewer_context_response: BinaryCodeContextResponse | None = None
    decision: StaticReportabilityDecision
    report: StaticCodeReviewReport
    usage: BudgetUsage
    raw_response_sha256s: tuple[str, ...] = Field(default=(), max_length=4)
    terminal_reason: str = Field(min_length=1, max_length=1000)
    reviewer_sessions: Literal[1] = 1
    image_executions: Literal[0] = 0
    generated_inputs: Literal[0] = 0
    dynamic_experiments: Literal[0] = 0
    fuzzer_invocations: Literal[0] = 0
    vm_boots: Literal[0] = 0
    result_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_result(self) -> "BinaryCodeReviewRunResult":
        if self.usage.scope != "reviewer" or self.usage.sessions != 1:
            raise ValueError("Code Reviewer result requires one fresh Reviewer session")
        if self.decision.reviewer_session_id != self.reviewer_session_id:
            raise ValueError("Reviewer result changed session identity")
        if self.report.decision_sha256 != self.decision.decision_sha256:
            raise ValueError("Reviewer report is bound to another decision")
        expected = _digest(self.model_dump(mode="json", exclude={"result_sha256"}))
        if self.result_sha256 != expected:
            raise ValueError("Code Reviewer result digest mismatch")
        return self


class BinaryCodeReviewerModelClient(Protocol):
    model_id: str

    async def chat(
        self,
        messages: list[dict],
        system: str | None = None,
        tools: list[dict] | None = None,
        max_tokens: int | None = None,
        cache_system: bool = False,
        cache_tools: bool = False,
        cache_last_user: bool = False,
    ) -> LLMResponse: ...


class BinaryCodeReviewerDeferred(RuntimeError):
    def __init__(
        self,
        reason: str,
        *,
        raw: tuple[str, ...] = (),
        calls: int = 0,
        totals: dict[str, int] | None = None,
    ) -> None:
        self.reason = reason
        self.raw = raw
        self.calls = calls
        self.totals = totals or _zero_totals()
        super().__init__(f"Code Reviewer deferred: {reason}")


@dataclass
class BinaryCodeReviewerAgent:
    client: BinaryCodeReviewerModelClient
    policy: BinaryCodeReviewerPolicy

    async def analyze(
        self,
        packet: BinaryCodeReviewerPacket,
    ) -> tuple[BinaryCodeReviewerVerdict, tuple[str, ...], dict[str, int]]:
        messages: list[dict] = [{
            "role": "user",
            "content": [{
                "text": (
                    "# Independent code-review packet\n"
                    + json.dumps(packet.model_dump(mode="json"), indent=2)
                    + "\n\n# Required response JSON Schema\n"
                    + json.dumps(BinaryCodeReviewerVerdict.model_json_schema(), indent=2)
                )
            }],
        }]
        totals = _zero_totals()
        raw: list[str] = []
        validation_error = "response was not a JSON object"
        for _ in range(self.policy.maximum_attempts_per_call):
            try:
                response = await self.client.chat(
                    messages=messages,
                    system=CODE_REVIEWER_SYSTEM_PROMPT,
                    max_tokens=self.policy.maximum_output_tokens_per_call,
                    cache_system=True,
                )
            except BudgetExceededError as exc:
                raise BinaryCodeReviewerDeferred(
                    f"budget:{exc.reason}", raw=tuple(raw), calls=len(raw), totals=totals
                ) from exc
            except Exception as exc:
                raise BinaryCodeReviewerDeferred(
                    f"provider_error:{type(exc).__name__}",
                    raw=tuple(raw),
                    calls=len(raw),
                    totals=totals,
                ) from exc
            raw.append(response.text[:_MAX_RAW_RESPONSE_BYTES])
            for name in totals:
                totals[name] += int(getattr(response, name))
            parsed = try_extract_object(response.text)
            try:
                if parsed is not None:
                    verdict = BinaryCodeReviewerVerdict.model_validate(parsed)
                    validate_binary_code_reviewer_verdict(packet, verdict)
                    return verdict, tuple(raw), totals
            except ValueError as exc:
                validation_error = str(exc)[:1000]
            messages.extend((
                {"role": "assistant", "content": response.content_blocks},
                {"role": "user", "content": [{"text": (
                    "Return only schema-valid JSON. Preserve reviewer_session_id, work_id, "
                    "root_id, hypothesis_id, capsule_sha256, and context_chain_sha256. "
                    "Use all nine obligations in normative order and cite only allowed "
                    "codefact IDs. Do not set reportability or request dynamic work."
                    f" The previous response failed validation: {validation_error}"
                )}]},
            ))
        raise BinaryCodeReviewerDeferred(
            "invalid_model_response", raw=tuple(raw), calls=len(raw), totals=totals
        )


def _resolve_reviewer_route_context(
    *,
    ir: NormalizedBinaryIR,
    hunter_packet: DecompilerHunterPacket,
    hypothesis: DecompilerHunterHypothesis,
    context_entries: tuple[DecompilerContextChainEntry, ...],
) -> BinaryCodeContextResponse | None:
    if any(
        edge.callee_function_id == hunter_packet.capsule.root_function_id
        for entry in context_entries
        for edge in entry.response.call_edges
    ):
        return None
    request = BinaryCodeContextRequest(
        request_id="codectx-reviewer-root-route",
        kind=BinaryCodeContextRequestKind.DIRECT_CALLER,
        rationale=(
            "Recover one deterministic frozen caller/parser-dispatch slice for the admitted root."
        ),
        function_id=hunter_packet.capsule.root_function_id,
        evidence_ids=(hypothesis.source_evidence_ids[0],),
        maximum_bytes=32 * 1024,
    )
    response = resolve_binary_code_context(
        ir=ir,
        packet=hunter_packet,
        request=request,
        prior_entries=context_entries,
    )
    return response if response.status is BinaryCodeContextStatus.RESOLVED else None


def build_binary_code_reviewer_packet(
    *,
    ir: NormalizedBinaryIR,
    hunter_packet: DecompilerHunterPacket,
    hunter_assessment: DecompilerHunterAssessment,
    context_entries: tuple[DecompilerContextChainEntry, ...] = (),
    context_chain_sha256: str | None = None,
    hypothesis_id: str | None = None,
    product_version: str,
    build_version: str,
    route_context_response: BinaryCodeContextResponse | None = None,
    reviewer_context_response: BinaryCodeContextResponse | None = None,
) -> BinaryCodeReviewerPacket:
    """Build one immutable packet without carrying Hunter conversation history."""

    if ir.ir_sha256 != hunter_packet.capsule.ir_sha256:
        raise ValueError("Reviewer IR differs from the Hunter capsule")
    if hunter_assessment.disposition is not DecompilerHunterDisposition.CODE_HYPOTHESIS:
        raise ValueError("only terminal code hypotheses may enter independent review")
    selected = tuple(
        item for item in hunter_assessment.hypotheses
        if hypothesis_id is None or item.hypothesis_id == hypothesis_id
    )
    if len(selected) != 1:
        raise ValueError("Reviewer packet requires exactly one selected hypothesis")
    hypothesis = selected[0]
    responses = tuple(item.response for item in context_entries)
    expected_chain = (
        context_entries[-1].chain_sha256
        if context_entries
        else _digest(hunter_assessment.model_dump(mode="json"))
    )
    chain = context_chain_sha256 or expected_chain
    if chain != expected_chain:
        raise ValueError("Reviewer context-chain digest differs from supplied entries")
    if any(item.status is not BinaryCodeContextStatus.RESOLVED for item in responses):
        raise ValueError("Reviewer packet cannot include unresolved Hunter context")
    if route_context_response is None:
        route_context_response = _resolve_reviewer_route_context(
            ir=ir,
            hunter_packet=hunter_packet,
            hypothesis=hypothesis,
            context_entries=context_entries,
        )
    session_payload = {
        "role": CODE_REVIEWER_QUEUE_SCOPE,
        "work_id": hunter_packet.work_id,
        "hypothesis_id": hypothesis.hypothesis_id,
        "capsule_sha256": hunter_packet.capsule.capsule_sha256,
        "context_chain_sha256": chain,
    }
    reviewer_session_id = "review_" + hashlib.sha256(_canonical_json(session_payload)).hexdigest()
    target = BinaryCodeReviewerTarget(
        product_version=product_version,
        build_version=build_version,
        image_name=ir.image_name,
        image_uuid=ir.image_uuid,
        architecture=ir.architecture.value,
        snapshot_sha256=ir.snapshot_sha256,
        ir_sha256=ir.ir_sha256,
    )
    base = {
        "schema_version": "binary-code-reviewer-packet-v1",
        "prompt_version": CODE_REVIEWER_PROMPT_VERSION,
        "queue_scope": CODE_REVIEWER_QUEUE_SCOPE,
        "reviewer_session_id": reviewer_session_id,
        "hunter_session_id": hunter_packet.work_id,
        "work_id": hunter_packet.work_id,
        "root_id": hunter_packet.root_id,
        "hypothesis": hypothesis.model_dump(mode="json"),
        "hypothesis_sha256": _digest(hypothesis.model_dump(mode="json")),
        "capsule_sha256": hunter_packet.capsule.capsule_sha256,
        "context_chain_sha256": chain,
        "target": target.model_dump(mode="json"),
        "capsule": hunter_packet.capsule.model_dump(mode="json"),
        "hunter_context_responses": tuple(item.model_dump(mode="json") for item in responses),
        "route_context_response": (
            route_context_response.model_dump(mode="json")
            if route_context_response is not None
            else None
        ),
        "reviewer_context_response": (
            reviewer_context_response.model_dump(mode="json")
            if reviewer_context_response is not None else None
        ),
        "dynamic_evidence_allowed": False,
        "image_execution_allowed": False,
        "exploit_output_allowed": False,
    }
    provisional = BinaryCodeReviewerPacket.model_construct(
        **{
            **base,
            "hypothesis": hypothesis,
            "target": target,
            "capsule": hunter_packet.capsule,
            "hunter_context_responses": responses,
            "route_context_response": route_context_response,
            "reviewer_context_response": reviewer_context_response,
        },
        allowed_evidence_ids=(),
        known_function_ids=(),
        known_addresses=(),
        packet_sha256="sha256:" + "0" * 64,
    )
    facts, functions, addresses = _packet_evidence(provisional)
    payload = {
        **base,
        "allowed_evidence_ids": tuple(sorted(facts)),
        "known_function_ids": tuple(sorted(functions)),
        "known_addresses": tuple(sorted(addresses)),
    }
    return BinaryCodeReviewerPacket(**payload, packet_sha256=_digest(payload))


def validate_binary_code_reviewer_verdict(
    packet: BinaryCodeReviewerPacket,
    verdict: BinaryCodeReviewerVerdict,
) -> None:
    identity = (
        verdict.reviewer_session_id,
        verdict.work_id,
        verdict.root_id,
        verdict.hypothesis_id,
        verdict.capsule_sha256,
        verdict.context_chain_sha256,
    )
    expected = (
        packet.reviewer_session_id,
        packet.work_id,
        packet.root_id,
        packet.hypothesis.hypothesis_id,
        packet.capsule_sha256,
        packet.context_chain_sha256,
    )
    if identity != expected:
        raise ValueError("Code Reviewer verdict changed immutable review identity")
    cited = {
        evidence_id
        for obligation in verdict.obligations
        for evidence_id in obligation.evidence_ids
    }
    facts, functions, addresses = _packet_evidence(packet)
    if not cited.issubset(facts):
        raise ValueError("Code Reviewer cited evidence outside its packet")
    if any(
        facts[item].function_id not in functions or facts[item].address not in addresses
        for item in cited
    ):
        raise ValueError("Code Reviewer cited evidence without an address-backed function")
    if verdict.context_request is not None:
        request = verdict.context_request
        if not set(request.evidence_ids).issubset(facts):
            raise ValueError("Reviewer context request cites unknown evidence")
        if request.function_id is not None and request.function_id not in packet.known_function_ids:
            raise ValueError("Reviewer context request cites unknown function")
        if (
            request.related_function_id is not None
            and request.related_function_id not in packet.known_function_ids
        ):
            raise ValueError("Reviewer context request cites unknown related function")
        if request.address is not None and request.address not in packet.known_addresses:
            raise ValueError("Reviewer context request cites unknown address")
        if request.kind is BinaryCodeContextRequestKind.DEFINITION_USE_CHAIN:
            target_slices = tuple(
                item
                for item in _packet_function_slices(packet)
                if item.function_id == request.function_id
            )
            target_addresses = {
                instruction.address
                for function in target_slices
                for block in function.blocks
                for instruction in block.instructions
            }
            selected_addresses = {
                address
                for address in (request.address, *request.supporting_addresses)
                if address is not None
            }
            if not selected_addresses.issubset(target_addresses):
                raise ValueError(
                    "definition/use request address selectors must belong to function_id"
                )
            target_blocks = {
                block.block_id for function in target_slices for block in function.blocks
            }
            if request.block_id is not None and request.block_id not in target_blocks:
                raise ValueError("definition/use request block must belong to function_id")
            target_variables = {
                value
                for function in target_slices
                for block in function.blocks
                for instruction in block.instructions
                for value in (instruction.result, *instruction.operands)
                if value is not None
            }
            selected_variables = {
                value
                for value in (request.variable, *request.supporting_variables)
                if value is not None
            }
            if not selected_variables.issubset(target_variables):
                raise ValueError(
                    "definition/use request variable selectors must belong to function_id"
                )


def decide_static_reportability(
    packet: BinaryCodeReviewerPacket,
    verdict: BinaryCodeReviewerVerdict | None,
    *,
    policy: BinaryCodeReviewerPolicy | None = None,
    terminal_reason: str | None = None,
) -> StaticReportabilityDecision:
    """Apply the evidence-bound gate; model prose is intentionally excluded."""

    active = policy or BinaryCodeReviewerPolicy()
    reasons: list[str] = []
    obligation_statuses: tuple[tuple[StaticProofObligation, ReviewerProofStatus], ...]
    citations: tuple[str, ...]
    if verdict is None:
        obligation_statuses = tuple(
            (item, ReviewerProofStatus.UNKNOWN) for item in StaticProofObligation
        )
        citations = ()
        reasons.append(terminal_reason or "independent Reviewer verdict unavailable")
        status = StaticReportabilityStatus.REVIEWER_INCONCLUSIVE
    else:
        validate_binary_code_reviewer_verdict(packet, verdict)
        obligation_statuses = tuple(
            (item.obligation, item.status) for item in verdict.obligations
        )
        citations = tuple(sorted({
            evidence_id
            for item in verdict.obligations
            for evidence_id in item.evidence_ids
        }))
        checks = _reportability_checks(packet, verdict, active)
        reasons.extend(checks)
        if verdict.disposition is BinaryCodeReviewerDisposition.REJECT or any(
            item.status is ReviewerProofStatus.DISPROVEN for item in verdict.obligations
        ):
            status = StaticReportabilityStatus.REVIEWER_REJECTED
        elif not checks:
            status = StaticReportabilityStatus.REPORTABLE_STATIC
            reasons.append("all nine independently cited static proof obligations passed")
        else:
            status = StaticReportabilityStatus.REVIEWER_INCONCLUSIVE
    evidence_payload = {
        "reviewer_session_id": packet.reviewer_session_id,
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "hypothesis_id": packet.hypothesis.hypothesis_id,
        "capsule_sha256": packet.capsule_sha256,
        "context_chain_sha256": packet.context_chain_sha256,
        "reviewer_packet_sha256": packet.packet_sha256,
        "status": status.value,
        "obligation_statuses": tuple((a.value, b.value) for a, b in obligation_statuses),
        "cited_evidence_ids": citations,
    }
    payload = {
        "schema_version": "static-reportability-decision-v1",
        "reviewer_session_id": packet.reviewer_session_id,
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "hypothesis_id": packet.hypothesis.hypothesis_id,
        "capsule_sha256": packet.capsule_sha256,
        "context_chain_sha256": packet.context_chain_sha256,
        "reviewer_packet_sha256": packet.packet_sha256,
        "status": status.value,
        "reasons": tuple(reasons),
        "obligation_statuses": tuple((a.value, b.value) for a, b in obligation_statuses),
        "cited_evidence_ids": citations,
        "evidence_decision_sha256": _digest(evidence_payload),
        "dynamic_reproduction": False,
        "exploitability": "unknown",
        "apple_submission_ready": False,
    }
    return StaticReportabilityDecision(**payload, decision_sha256=_digest(payload))


def build_static_code_review_report(
    packet: BinaryCodeReviewerPacket,
    decision: StaticReportabilityDecision,
    verdict: BinaryCodeReviewerVerdict | None,
) -> StaticCodeReviewReport:
    capsule = packet.capsule
    root = next(item for item in capsule.functions if item.function_id == capsule.root_function_id)
    hypothesis = packet.hypothesis
    facts, _, _ = _packet_evidence(packet)
    path_ids = tuple(sorted(set(
        hypothesis.source_evidence_ids
        + hypothesis.path_evidence_ids
        + hypothesis.guard_evidence_ids
        + hypothesis.sink_evidence_ids
    )))
    affected = min(facts[item].address for item in hypothesis.sink_evidence_ids)
    limitations = [
        "decompiler output is lossy and is not Apple's original source",
        "no image was executed and no dynamic reproduction was performed",
    ]
    if verdict is None:
        limitations.append("independent Reviewer output was unavailable")
    elif verdict.minimal_missing_evidence:
        limitations.extend(verdict.minimal_missing_evidence)
    payload = {
        "schema_version": "m17-static-code-review-report-v1",
        "decision_sha256": decision.decision_sha256,
        "status": decision.status.value,
        "target": packet.target.model_dump(mode="json"),
        "affected_function_id": root.function_id,
        "affected_function_name": root.function_name,
        "affected_address": affected,
        "decompiled_excerpt": root.pseudocode_excerpt[:32768] or "pseudocode unavailable",
        "pcode_path_evidence_ids": path_ids,
        "input_control_proof": hypothesis.attacker_control,
        "violated_invariant": hypothesis.security_relation,
        "guard_analysis": hypothesis.guard_analysis,
        "impact_boundary": (
            verdict.conservative_impact if verdict is not None else hypothesis.impact
        ),
        "contradictions": (
            "; ".join(verdict.unresolved_contradictions)
            if verdict is not None and verdict.unresolved_contradictions
            else hypothesis.contradicting_evidence
        ),
        "limitations": tuple(limitations),
        "artifact_digests": tuple(sorted({
            packet.target.snapshot_sha256,
            packet.target.ir_sha256,
            packet.capsule_sha256,
            packet.context_chain_sha256,
            packet.hypothesis_sha256,
            packet.packet_sha256,
            decision.evidence_decision_sha256,
        })),
        "dynamic_reproduction": False,
        "exploitability": "unknown",
        "apple_submission_ready": False,
    }
    return StaticCodeReviewReport(**payload, report_sha256=_digest(payload))


async def run_binary_code_review(
    *,
    store_root: Path,
    ir: NormalizedBinaryIR,
    hunter_packet: DecompilerHunterPacket,
    hunter_assessment: DecompilerHunterAssessment,
    context_entries: tuple[DecompilerContextChainEntry, ...] = (),
    context_chain_sha256: str | None = None,
    hypothesis_id: str | None = None,
    product_version: str,
    build_version: str,
    run_id: str,
    client: BinaryCodeReviewerModelClient,
    policy: BinaryCodeReviewerPolicy | None = None,
    context_policy: BinaryCodeContextPolicy | None = None,
) -> BinaryCodeReviewRunResult:
    """Run/resume one fresh independent Reviewer session and persist its audit trail."""

    active = policy or BinaryCodeReviewerPolicy()
    packet = build_binary_code_reviewer_packet(
        ir=ir,
        hunter_packet=hunter_packet,
        hunter_assessment=hunter_assessment,
        context_entries=context_entries,
        context_chain_sha256=context_chain_sha256,
        hypothesis_id=hypothesis_id,
        product_version=product_version,
        build_version=build_version,
    )
    directory = _review_directory(store_root, packet)
    result_path = directory / "result.json"
    if result_path.exists():
        result = BinaryCodeReviewRunResult.model_validate_json(_read_file(result_path))
        persisted_packet_path = directory / "continued-packet.json"
        if persisted_packet_path.exists():
            persisted_packet = BinaryCodeReviewerPacket.model_validate_json(
                _read_file(persisted_packet_path)
            )
        else:
            persisted_packet = packet
        if result.reviewer_packet_sha256 != persisted_packet.packet_sha256:
            raise RuntimeError("persisted Reviewer result belongs to another evidence packet")
        return result
    _write_private_json(directory / "packet.json", packet.model_dump(mode="json"))
    if packet.route_context_response is not None:
        _write_private_json(
            directory / "route-context-response.json",
            packet.route_context_response.model_dump(mode="json"),
        )
    agent = BinaryCodeReviewerAgent(client, active)
    raw: list[str] = []
    totals = _zero_totals()
    verdict: BinaryCodeReviewerVerdict | None = None
    reviewer_context: BinaryCodeContextResponse | None = None
    terminal_reason = "independent Reviewer completed"
    try:
        verdict, first_raw, first_totals = await agent.analyze(packet)
        raw.extend(first_raw)
        _add_totals(totals, first_totals)
        if verdict.disposition is BinaryCodeReviewerDisposition.NEEDS_CODE_CONTEXT:
            assert verdict.context_request is not None
            reviewer_context = resolve_binary_code_context(
                ir=ir,
                packet=hunter_packet,
                request=verdict.context_request,
                prior_entries=context_entries,
                policy=context_policy,
            )
            _write_private_json(
                directory / "reviewer-context-response.json",
                reviewer_context.model_dump(mode="json"),
            )
            if reviewer_context.status is BinaryCodeContextStatus.RESOLVED:
                continued = build_binary_code_reviewer_packet(
                    ir=ir,
                    hunter_packet=hunter_packet,
                    hunter_assessment=hunter_assessment,
                    context_entries=context_entries,
                    context_chain_sha256=context_chain_sha256,
                    hypothesis_id=packet.hypothesis.hypothesis_id,
                    product_version=product_version,
                    build_version=build_version,
                    route_context_response=packet.route_context_response,
                    reviewer_context_response=reviewer_context,
                )
                verdict, next_raw, next_totals = await agent.analyze(continued)
                raw.extend(next_raw)
                _add_totals(totals, next_totals)
                packet = continued
                _write_private_json(directory / "continued-packet.json", packet.model_dump(mode="json"))
                if verdict.disposition is BinaryCodeReviewerDisposition.NEEDS_CODE_CONTEXT:
                    terminal_reason = "Reviewer exhausted its single frozen-IR context request"
            else:
                terminal_reason = "Reviewer context could not be recovered: " + reviewer_context.detail
        decision = decide_static_reportability(
            packet,
            verdict,
            policy=active,
            terminal_reason=terminal_reason,
        )
    except BinaryCodeReviewerDeferred as exc:
        raw.extend(exc.raw)
        _add_totals(totals, exc.totals)
        terminal_reason = exc.reason
        verdict = None
        decision = decide_static_reportability(
            packet,
            None,
            policy=active,
            terminal_reason=terminal_reason,
        )
    usage = _reviewer_usage(run_id, hunter_packet.work_id, client, len(raw), totals)
    report = build_static_code_review_report(packet, decision, verdict)
    for index, response in enumerate(raw, start=1):
        _write_private_bytes(
            directory / f"raw-response-{index:02d}.txt",
            response.encode()[:_MAX_RAW_RESPONSE_BYTES],
        )
    payload = {
        "schema_version": "binary-code-review-run-result-v1",
        "reviewer_session_id": packet.reviewer_session_id,
        "reviewer_packet_sha256": packet.packet_sha256,
        "verdict": verdict.model_dump(mode="json") if verdict is not None else None,
        "reviewer_context_response": (
            reviewer_context.model_dump(mode="json") if reviewer_context is not None else None
        ),
        "decision": decision.model_dump(mode="json"),
        "report": report.model_dump(mode="json"),
        "usage": usage.model_dump(mode="json"),
        "raw_response_sha256s": tuple(_digest(item) for item in raw),
        "terminal_reason": terminal_reason,
        "reviewer_sessions": 1,
        "image_executions": 0,
        "generated_inputs": 0,
        "dynamic_experiments": 0,
        "fuzzer_invocations": 0,
        "vm_boots": 0,
    }
    result = BinaryCodeReviewRunResult(**payload, result_sha256=_digest(payload))
    _write_private_json(directory / "decision.json", decision.model_dump(mode="json"))
    _write_private_json(directory / "report.json", report.model_dump(mode="json"))
    _write_private_json(result_path, result.model_dump(mode="json"))
    return result


def select_code_reviewer_hypotheses(
    assessments: tuple[DecompilerHunterAssessment, ...],
    *,
    policy: BinaryCodeReviewerPolicy | None = None,
) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]:
    active = policy or BinaryCodeReviewerPolicy()
    candidates = tuple(
        (assessment.work_id, hypothesis.hypothesis_id)
        for assessment in assessments
        if assessment.disposition is DecompilerHunterDisposition.CODE_HYPOTHESIS
        for hypothesis in assessment.hypotheses
    )
    maximum = active.maximum_hypotheses_per_run
    return candidates[:maximum], candidates[maximum:]


def _reportability_checks(
    packet: BinaryCodeReviewerPacket,
    verdict: BinaryCodeReviewerVerdict,
    policy: BinaryCodeReviewerPolicy,
) -> list[str]:
    reasons: list[str] = []
    if verdict.disposition is not BinaryCodeReviewerDisposition.ACCEPT:
        reasons.append("independent Reviewer did not accept the code proof")
    if any(item.status is not ReviewerProofStatus.PROVEN for item in verdict.obligations):
        reasons.append("one or more static proof obligations remain unproven")
    if verdict.context_request is not None:
        reasons.append("Reviewer has an unresolved code-context request")
    if verdict.minimal_missing_evidence:
        reasons.append("Reviewer recorded missing evidence")
    if verdict.unresolved_contradictions:
        reasons.append("Reviewer recorded unresolved contradictions")
    if packet.hypothesis.confidence < policy.minimum_hunter_confidence:
        reasons.append("Hunter confidence is below the static threshold")
    if verdict.reviewer_confidence < policy.minimum_reviewer_confidence:
        reasons.append("Reviewer confidence is below the static threshold")
    obligations = {item.obligation: set(item.evidence_ids) for item in verdict.obligations}
    hypothesis = packet.hypothesis
    required = {
        StaticProofObligation.REACHABLE_PARSER_ROUTE: set(hypothesis.source_evidence_ids),
        StaticProofObligation.ATTACKER_CONTROLLED_SOURCE: set(hypothesis.source_evidence_ids),
        StaticProofObligation.FEASIBLE_PATH: set(hypothesis.path_evidence_ids),
        StaticProofObligation.SECURITY_RELATION: set(
            hypothesis.path_evidence_ids + hypothesis.sink_evidence_ids
        ),
        StaticProofObligation.GUARD_ANALYSIS: set(hypothesis.guard_evidence_ids),
        StaticProofObligation.SECURITY_SINK_AND_IMPACT: set(hypothesis.sink_evidence_ids),
        StaticProofObligation.CONTRADICTION_REVIEW: set(
            hypothesis.guard_evidence_ids + hypothesis.contradicting_evidence_ids
        ),
    }
    for obligation, required_ids in required.items():
        if not required_ids.issubset(obligations[obligation]):
            reasons.append(f"{obligation.value} lacks the Hunter path's cited code evidence")
    facts, _, _ = _packet_evidence(packet)
    source_ids = obligations[StaticProofObligation.ATTACKER_CONTROLLED_SOURCE]
    sink_ids = obligations[StaticProofObligation.SECURITY_SINK_AND_IMPACT]
    path_ids = obligations[StaticProofObligation.FEASIBLE_PATH]
    guard_ids = obligations[StaticProofObligation.GUARD_ANALYSIS]
    if not source_ids or {facts[item].kind for item in source_ids} != {
        BinaryEvidenceFactKind.INPUT_SOURCE
    }:
        reasons.append("attacker-control proof is not exclusively input-source evidence")
    if not sink_ids or {facts[item].kind for item in sink_ids} != {
        BinaryEvidenceFactKind.SECURITY_SINK
    }:
        reasons.append("impact proof is not exclusively security-sink evidence")
    if not {facts[item].kind for item in path_ids}.intersection({
        BinaryEvidenceFactKind.DATAFLOW,
        BinaryEvidenceFactKind.CALLSITE,
        BinaryEvidenceFactKind.RETURN_USE,
    }):
        reasons.append("feasible path lacks address-backed data/call flow")
    if any(facts[item].kind is not BinaryEvidenceFactKind.GUARD for item in guard_ids):
        reasons.append("guard analysis cites non-guard evidence")
    return reasons


def _packet_function_slices(
    packet: BinaryCodeReviewerPacket,
) -> tuple[BinaryEvidenceFunction | BinaryCodeContextFunctionSlice, ...]:
    functions: list[BinaryEvidenceFunction | BinaryCodeContextFunctionSlice] = list(
        packet.capsule.functions
    )
    for response in (
        *packet.hunter_context_responses,
        packet.route_context_response,
        packet.reviewer_context_response,
    ):
        if response is not None:
            functions.extend(response.functions)
    return tuple(functions)


def _packet_evidence(
    packet: BinaryCodeReviewerPacket,
) -> tuple[dict[str, BinaryEvidenceFact], set[str], set[int]]:
    capsule = packet.capsule
    facts = {item.fact_id: item for item in capsule.facts}
    functions = {item.function_id for item in _packet_function_slices(packet)}
    addresses = {
        instruction.address
        for function in _packet_function_slices(packet)
        for block in function.blocks
        for instruction in block.instructions
    }
    for response in (
        *packet.hunter_context_responses,
        packet.route_context_response,
        packet.reviewer_context_response,
    ):
        if response is None:
            continue
        facts.update((item.fact_id, item) for item in response.facts)
    return facts, functions, addresses


def _decision_evidence_payload(decision: StaticReportabilityDecision) -> dict[str, object]:
    return {
        "reviewer_session_id": decision.reviewer_session_id,
        "work_id": decision.work_id,
        "root_id": decision.root_id,
        "hypothesis_id": decision.hypothesis_id,
        "capsule_sha256": decision.capsule_sha256,
        "context_chain_sha256": decision.context_chain_sha256,
        "reviewer_packet_sha256": decision.reviewer_packet_sha256,
        "status": decision.status.value,
        "obligation_statuses": tuple((a.value, b.value) for a, b in decision.obligation_statuses),
        "cited_evidence_ids": decision.cited_evidence_ids,
    }


def _validate_safe_review_text(verdict: BinaryCodeReviewerVerdict) -> None:
    values = [
        verdict.summary,
        verdict.conservative_impact,
        *verdict.unresolved_contradictions,
        *verdict.minimal_missing_evidence,
        *(item.analysis for item in verdict.obligations),
    ]
    if verdict.context_request is not None:
        values.append(verdict.context_request.rationale)
    for value in values:
        if any(ord(character) < 32 and character not in "\n\r\t" for character in value):
            raise ValueError("Code Reviewer output contains unsafe control characters")
        if _PROHIBITED_REVIEW_TEXT.search(value):
            raise ValueError("Code Reviewer output contains prohibited dynamic/exploit content")


def _reviewer_usage(
    run_id: str,
    work_id: str,
    client: BinaryCodeReviewerModelClient,
    calls: int,
    totals: dict[str, int],
) -> BudgetUsage:
    return with_estimated_cost(BudgetUsage(
        run_id=run_id,
        work_id=work_id,
        scope="reviewer",
        model_id=str(client.model_id),
        transport=str(getattr(client, "transport", "test_or_legacy")),
        sessions=1,
        calls=calls,
        iterations=calls,
        input_tokens=totals["input_tokens"],
        output_tokens=totals["output_tokens"],
        cache_read_tokens=totals["cache_read_tokens"],
        cache_write_tokens=totals["cache_write_tokens"],
    ))


def _review_directory(store_root: Path, packet: BinaryCodeReviewerPacket) -> Path:
    root = store_root.expanduser().resolve(strict=True)
    if not root.is_dir() or any((item / ".git").exists() for item in (root, *root.parents)):
        raise ValueError("Code Reviewer store must be a private directory outside Git")
    return (
        root / "reviewers" / packet.work_id / packet.hypothesis.hypothesis_id
        / packet.reviewer_session_id
    )


def _read_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_PACKET_BYTES:
        raise RuntimeError(f"unsafe or oversized Code Reviewer artifact: {path}")
    return path.read_bytes()


def _write_private_json(path: Path, payload: object) -> None:
    _write_private_bytes(path, json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n")


def _write_private_bytes(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise RuntimeError("Code Reviewer artifact may not be a symbolic link")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    if path.exists():
        if not path.is_file() or path.read_bytes() != payload:
            raise FileExistsError("immutable Code Reviewer artifact contains other data")
        return
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _zero_totals() -> dict[str, int]:
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
    }


def _add_totals(target: dict[str, int], source: dict[str, int]) -> None:
    for name in target:
        target[name] += source[name]


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(payload: object) -> str:
    if isinstance(payload, str):
        value = payload.encode()
    else:
        value = _canonical_json(payload)
    return "sha256:" + hashlib.sha256(value).hexdigest()
