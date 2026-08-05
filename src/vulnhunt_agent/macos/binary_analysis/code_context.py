"""Bounded frozen-IR context continuation for M17 decompiler Hunters.

The broker in this module is deliberately not a search or decompilation API.
It can only answer a typed request by selecting a small, deterministic slice
from the exact ``NormalizedBinaryIR`` already bound to the Hunter packet.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol

from pydantic import Field, model_validator

from ...core.jsonx import try_extract_object
from ...core.llm import LLMResponse
from ...domain.schemas import BudgetUsage, DomainModel, SHA256_PATTERN
from ...scheduling.metrics import with_estimated_cost
from .capsules import BinaryEvidenceFact, BinaryEvidenceFactKind
from .decompiler_hunter import (
    DECOMPILER_HUNTER_SYSTEM_PROMPT,
    BinaryCodeContextRequest,
    BinaryCodeContextRequestKind,
    DecompilerHunterAssessment,
    DecompilerHunterDisposition,
    DecompilerHunterHypothesis,
    DecompilerHunterPacket,
    validate_decompiler_hunter_safe_output,
)
from .ir import (
    IRBasicBlock,
    IRFunction,
    IRInstruction,
    IROperation,
    IRVirtualMethodReference,
    NormalizedBinaryIR,
)

DECOMPILER_CONTEXT_PROMPT_VERSION: Literal["decompiler-code-context-v7"] = (
    "decompiler-code-context-v7"
)
_MAX_RAW_RESPONSE_BYTES = 128 * 1024
_MAX_PACKET_BYTES = 768 * 1024
_MEMORY_SINKS = frozenset(
    {
        IROperation.ALLOCATE,
        IROperation.COPY,
        IROperation.FREE,
        IROperation.LOAD,
        IROperation.STORE,
    }
)
_INPUT_CALLEE_MARKERS = (
    "copybytes",
    "dataprovider",
    "getbytes",
    "readbytes",
    "read_data",
)

DECOMPILER_CONTEXT_SYSTEM_PROMPT = (
    DECOMPILER_HUNTER_SYSTEM_PROMPT
    + """

This is a continuation of the same root session, not a new hunt. The packet
contains the original evidence and one or more deterministic responses from
the frozen-IR context broker. Re-evaluate the prior assessment using all cited
facts. A newly supplied caller guard may require not_vulnerable; a newly
supplied callee sink may complete a code_hypothesis. If one more slice is
strictly required, return needs_code_context with exactly one typed request.
Never treat a rejected or unavailable response as evidence that a guard is
absent. When one proof obligation spans independent allocation and destination
expressions in the same function, encode every required secondary variable in
supporting_variables and every sink/guard address in supporting_addresses of a
single definition_use_chain request. Natural-language rationale does not expand
the broker selection. When proof depends on decoder-state fields written or
validated in other methods, put their numeric object offsets in
supporting_field_offsets on that same request. The broker will recover only
frozen normalized-IR accesses to those offsets; prose field names or offsets do
not select evidence. A direct_callee request must set only function_id and the
address-backed related_function_id; leave block_id, address, variable,
supporting_addresses, supporting_variables, and supporting_field_offsets empty.
A call edge marked virtual_selector proves a compatible
selector dispatch site, not a unique runtime target; retain its candidate count
and require format/owner evidence before claiming the exact implementation is
reachable. A virtual_vtable edge additionally proves that the target owner's
address-backed Itanium vtable contains the selected function at the recovered
slot. It does not by itself prove that attacker-controlled input selects that
owner at runtime. Dominating guard block IDs are CFG-derived and may be used
only with their supplied address-backed guard facts. Return only the
DecompilerHunterAssessment JSON object."""
)


class BinaryCodeContextStatus(StrEnum):
    RESOLVED = "resolved"
    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"


class BinaryCodeContextEdgeResolution(StrEnum):
    DIRECT = "direct"
    VIRTUAL_SELECTOR = "virtual_selector"
    VIRTUAL_VTABLE = "virtual_vtable"


class BinaryCodeContextRejection(StrEnum):
    DUPLICATE_REQUEST = "duplicate_request"
    CIRCULAR_REQUEST = "circular_request"
    OUTSIDE_FROZEN_IMAGE = "outside_frozen_image"
    UNKNOWN_TARGET = "unknown_target"
    UNSUPPORTED_REQUEST = "unsupported_request"
    EVIDENCE_BUDGET_EXCEEDED = "evidence_budget_exceeded"
    PROOF_UNAVAILABLE = "proof_unavailable"


class DecompilerContextTerminalStatus(StrEnum):
    COMPLETED = "completed"
    REVIEWER_INCONCLUSIVE = "reviewer_inconclusive"


class BinaryCodeContextPolicy(DomainModel):
    maximum_roots_per_run: int = Field(default=6, ge=1, le=6)
    maximum_continuations_per_root: int = Field(default=3, ge=1, le=3)
    maximum_total_evidence_bytes: int = Field(
        default=288 * 1024,
        ge=16 * 1024,
        le=288 * 1024,
    )
    maximum_blocks_per_response: int = Field(default=20, ge=1, le=32)
    maximum_instructions_per_response: int = Field(default=320, ge=8, le=512)
    maximum_pseudocode_bytes_per_function: int = Field(default=8 * 1024, ge=0, le=32 * 1024)
    maximum_attempts_per_continuation: int = Field(default=2, ge=1, le=2)
    maximum_output_tokens_per_call: int = Field(default=8000, ge=512, le=32000)


class BinaryCodeContextFunctionSlice(DomainModel):
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    function_name: str = Field(min_length=1, max_length=500)
    start_address: int = Field(ge=0)
    end_address: int = Field(ge=0)
    pseudocode_excerpt: str = Field(default="", max_length=32768)
    pseudocode_sha256: str = Field(pattern=SHA256_PATTERN)
    pseudocode_truncated: bool
    blocks: tuple[IRBasicBlock, ...] = Field(min_length=1, max_length=32)
    omitted_block_ids: tuple[str, ...] = Field(default=(), max_length=10000)

    @model_validator(mode="after")
    def validate_slice(self) -> "BinaryCodeContextFunctionSlice":
        if tuple(sorted(self.blocks, key=lambda item: item.start_address)) != self.blocks:
            raise ValueError("context blocks must preserve address order")
        if tuple(sorted(set(self.omitted_block_ids))) != self.omitted_block_ids:
            raise ValueError("context omitted blocks must be sorted and unique")
        if {item.block_id for item in self.blocks}.intersection(self.omitted_block_ids):
            raise ValueError("context included and omitted blocks overlap")
        return self


class BinaryCodeContextEdge(DomainModel):
    caller_function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    callee_function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    callsite_address: int = Field(ge=0)
    arguments: tuple[str, ...] = Field(default=(), max_length=32)
    return_result: str | None = Field(default=None, min_length=1, max_length=160)
    resolution: BinaryCodeContextEdgeResolution = BinaryCodeContextEdgeResolution.DIRECT
    selector: str | None = Field(default=None, pattern=r"^[~A-Za-z_][A-Za-z0-9_]{0,159}$")
    dispatch_candidate_count: int = Field(default=1, ge=1, le=10000)
    receiver_owner: str | None = Field(default=None, min_length=1, max_length=500)
    vtable_symbol: str | None = Field(default=None, min_length=1, max_length=1000)
    vtable_address: int | None = Field(default=None, ge=0)
    vtable_address_point: int | None = Field(default=None, ge=0)
    vtable_slot_offset: int | None = Field(default=None, ge=0, le=64 * 1024)
    vtable_reference_address: int | None = Field(default=None, ge=0)
    dominating_guard_block_ids: tuple[str, ...] = Field(default=(), max_length=16)

    @model_validator(mode="after")
    def validate_resolution(self) -> "BinaryCodeContextEdge":
        if tuple(sorted(set(self.dominating_guard_block_ids))) != self.dominating_guard_block_ids:
            raise ValueError("context-edge dominating guard blocks must be sorted and unique")
        vtable_metadata = (
            self.receiver_owner,
            self.vtable_symbol,
            self.vtable_address,
            self.vtable_address_point,
            self.vtable_slot_offset,
            self.vtable_reference_address,
        )
        if self.resolution is BinaryCodeContextEdgeResolution.DIRECT:
            if (
                self.selector is not None
                or self.dispatch_candidate_count != 1
                or any(item is not None for item in vtable_metadata)
            ):
                raise ValueError("direct context edge cannot carry virtual-dispatch metadata")
        elif self.resolution is BinaryCodeContextEdgeResolution.VIRTUAL_SELECTOR:
            if any(item is not None for item in vtable_metadata):
                raise ValueError("selector-only context edge cannot carry vtable metadata")
            if self.selector is None:
                raise ValueError("virtual-selector context edge requires a selector")
        else:
            if self.selector is None or any(item is None for item in vtable_metadata):
                raise ValueError("virtual-vtable context edge requires complete binding metadata")
            if self.dispatch_candidate_count != 1:
                raise ValueError("virtual-vtable context edge must bind one implementation")
            assert self.vtable_reference_address is not None
            assert self.vtable_address_point is not None
            assert self.vtable_slot_offset is not None
            if self.vtable_reference_address != (
                self.vtable_address_point + self.vtable_slot_offset
            ):
                raise ValueError(
                    "virtual-vtable reference does not match its address point and slot"
                )
        return self


class BinaryCodeContextResponse(DomainModel):
    schema_version: Literal["binary-code-context-response-v1"] = "binary-code-context-response-v1"
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    root_id: str = Field(pattern=r"^coderoot_[0-9a-f]{20}$")
    capsule_sha256: str = Field(pattern=SHA256_PATTERN)
    ir_sha256: str = Field(pattern=SHA256_PATTERN)
    request: BinaryCodeContextRequest
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    status: BinaryCodeContextStatus
    rejection: BinaryCodeContextRejection | None = None
    detail: str = Field(min_length=1, max_length=1000)
    functions: tuple[BinaryCodeContextFunctionSlice, ...] = Field(default=(), max_length=8)
    call_edges: tuple[BinaryCodeContextEdge, ...] = Field(default=(), max_length=64)
    facts: tuple[BinaryEvidenceFact, ...] = Field(default=(), max_length=4096)
    omissions: tuple[str, ...] = Field(default=(), max_length=128)
    evidence_bytes: int = Field(ge=0, le=96 * 1024)
    response_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_response(self) -> "BinaryCodeContextResponse":
        expected_request = _digest(self.request.model_dump(mode="json"))
        if self.request_sha256 != expected_request:
            raise ValueError("context response request digest mismatch")
        if self.status is BinaryCodeContextStatus.RESOLVED:
            if self.rejection is not None or not self.functions or not self.facts:
                raise ValueError("resolved context requires functions and facts")
        elif self.rejection is None or self.functions or self.call_edges or self.facts:
            raise ValueError("rejected/unavailable context may not contain code evidence")
        function_ids = {item.function_id for item in self.functions}
        instruction_addresses = {
            (function.function_id, instruction.address)
            for function in self.functions
            for block in function.blocks
            for instruction in block.instructions
        }
        if any(
            edge.caller_function_id not in function_ids
            and edge.callee_function_id not in function_ids
            for edge in self.call_edges
        ):
            raise ValueError("context edge has no endpoint in its function slices")
        if any(
            (edge.caller_function_id, edge.callsite_address) not in instruction_addresses
            and edge.caller_function_id in function_ids
            for edge in self.call_edges
        ):
            raise ValueError("context edge lacks an included address-backed callsite")
        included_blocks = {
            (function.function_id, block.block_id)
            for function in self.functions
            for block in function.blocks
        }
        if any(
            (edge.caller_function_id, block_id) not in included_blocks
            for edge in self.call_edges
            for block_id in edge.dominating_guard_block_ids
            if edge.caller_function_id in function_ids
        ):
            raise ValueError("context edge lacks an included dominating guard block")
        instructions_by_key = {
            (function.function_id, instruction.address): instruction
            for function in self.functions
            for block in function.blocks
            for instruction in block.instructions
            if instruction.operation is IROperation.CALL
        }
        if any(
            edge.resolution is not BinaryCodeContextEdgeResolution.DIRECT
            and "CALLIND"
            not in instructions_by_key[
                (edge.caller_function_id, edge.callsite_address)
            ].text.upper()
            for edge in self.call_edges
            if (edge.caller_function_id, edge.callsite_address) in instructions_by_key
        ):
            raise ValueError("virtual edge lacks an included indirect callsite")
        fact_order = tuple(
            sorted(
                self.facts,
                key=lambda item: (
                    item.address,
                    item.instruction_index,
                    item.function_id,
                    item.kind.value,
                ),
            )
        )
        if fact_order != self.facts or len({item.fact_id for item in self.facts}) != len(
            self.facts
        ):
            raise ValueError("context facts must be canonically ordered and unique")
        expected_bytes = _context_evidence_bytes(
            self.functions,
            self.call_edges,
            self.facts,
            self.omissions,
        )
        if self.evidence_bytes != expected_bytes:
            raise ValueError("context evidence byte accounting mismatch")
        expected = _digest(self.model_dump(mode="json", exclude={"response_sha256"}))
        if self.response_sha256 != expected:
            raise ValueError("context response digest mismatch")
        return self


class DecompilerContinuationPacket(DomainModel):
    schema_version: Literal["decompiler-continuation-packet-v1"] = (
        "decompiler-continuation-packet-v1"
    )
    prompt_version: Literal[
        "decompiler-code-context-v2",
        "decompiler-code-context-v3",
        "decompiler-code-context-v4",
        "decompiler-code-context-v5",
        "decompiler-code-context-v6",
        "decompiler-code-context-v7",
    ] = DECOMPILER_CONTEXT_PROMPT_VERSION
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    root_id: str = Field(pattern=r"^coderoot_[0-9a-f]{20}$")
    admission_rank: int = Field(ge=1, le=100000)
    capsule_sha256: str = Field(pattern=SHA256_PATTERN)
    ir_sha256: str = Field(pattern=SHA256_PATTERN)
    continuation_ordinal: int = Field(ge=1, le=3)
    previous_chain_sha256: str = Field(pattern=SHA256_PATTERN)
    base_packet: DecompilerHunterPacket
    prior_assessment: DecompilerHunterAssessment
    context_responses: tuple[BinaryCodeContextResponse, ...] = Field(min_length=1, max_length=3)
    total_evidence_bytes: int = Field(ge=1, le=288 * 1024)
    packet_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_packet(self) -> "DecompilerContinuationPacket":
        identity = (
            self.work_id,
            self.root_id,
            self.admission_rank,
            self.capsule_sha256,
            self.ir_sha256,
        )
        expected = (
            self.base_packet.work_id,
            self.base_packet.root_id,
            self.base_packet.admission_rank,
            self.base_packet.capsule.capsule_sha256,
            self.base_packet.capsule.ir_sha256,
        )
        if identity != expected:
            raise ValueError("continuation packet changed the root-session identity")
        if self.continuation_ordinal != len(self.context_responses):
            raise ValueError("continuation ordinal differs from its response chain")
        if any(
            item.status is not BinaryCodeContextStatus.RESOLVED for item in self.context_responses
        ):
            raise ValueError("model continuation may contain only resolved context")
        evidence = self.base_packet.capsule.evidence_bytes + sum(
            item.evidence_bytes for item in self.context_responses
        )
        if self.total_evidence_bytes != evidence:
            raise ValueError("continuation total evidence accounting mismatch")
        expected_digest = _digest(self.model_dump(mode="json", exclude={"packet_sha256"}))
        if self.packet_sha256 != expected_digest:
            raise ValueError("continuation packet digest mismatch")
        if len(_canonical_json(self.model_dump(mode="json"))) > _MAX_PACKET_BYTES:
            raise ValueError("continuation packet exceeds serialization limit")
        return self


class DecompilerContextChainEntry(DomainModel):
    schema_version: Literal["decompiler-context-chain-entry-v1"] = (
        "decompiler-context-chain-entry-v1"
    )
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    root_id: str = Field(pattern=r"^coderoot_[0-9a-f]{20}$")
    ordinal: int = Field(ge=1, le=3)
    previous_chain_sha256: str = Field(pattern=SHA256_PATTERN)
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    response: BinaryCodeContextResponse
    assessment: DecompilerHunterAssessment | None = None
    usage: BudgetUsage | None = None
    raw_response_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    chain_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_entry(self) -> "DecompilerContextChainEntry":
        if self.request_sha256 != self.response.request_sha256:
            raise ValueError("chain request and response digests differ")
        if (self.assessment is None) != (
            self.response.status is not BinaryCodeContextStatus.RESOLVED
        ):
            raise ValueError("only resolved context may carry a continuation assessment")
        if (self.usage is None) != (self.assessment is None):
            raise ValueError("continuation usage and assessment must be persisted together")
        if self.usage is not None:
            if self.usage.work_id != self.work_id or self.usage.sessions != 0:
                raise ValueError("continuation usage must remain in the originating session")
        expected = _digest(self.model_dump(mode="json", exclude={"chain_sha256"}))
        if self.chain_sha256 != expected:
            raise ValueError("context chain digest mismatch")
        return self


class DecompilerContextRunResult(DomainModel):
    schema_version: Literal["decompiler-context-run-result-v1"] = "decompiler-context-run-result-v1"
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    root_id: str = Field(pattern=r"^coderoot_[0-9a-f]{20}$")
    initial_assessment_sha256: str = Field(pattern=SHA256_PATTERN)
    terminal_status: DecompilerContextTerminalStatus
    terminal_assessment: DecompilerHunterAssessment
    entries: tuple[DecompilerContextChainEntry, ...] = Field(max_length=3)
    total_evidence_bytes: int = Field(ge=1, le=288 * 1024)
    sessions: Literal[1] = 1
    model_calls: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    chain_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_result(self) -> "DecompilerContextRunResult":
        if self.entries:
            for index, entry in enumerate(self.entries, start=1):
                if entry.ordinal != index:
                    raise ValueError("context chain entries are not contiguous")
                previous = (
                    self.initial_assessment_sha256
                    if index == 1
                    else self.entries[index - 2].chain_sha256
                )
                if entry.previous_chain_sha256 != previous:
                    raise ValueError("context chain predecessor digest mismatch")
            expected_chain = self.entries[-1].chain_sha256
        else:
            expected_chain = self.initial_assessment_sha256
        if self.chain_sha256 != expected_chain:
            raise ValueError("context result head digest mismatch")
        if self.terminal_status is DecompilerContextTerminalStatus.COMPLETED:
            if (
                self.terminal_assessment.disposition
                is DecompilerHunterDisposition.NEEDS_CODE_CONTEXT
            ):
                raise ValueError("completed context run still requests context")
        return self


class DecompilerContinuationModelClient(Protocol):
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


@dataclass(frozen=True)
class _RawEdge:
    caller: IRFunction
    callee: IRFunction
    instruction: IRInstruction
    resolution: BinaryCodeContextEdgeResolution = BinaryCodeContextEdgeResolution.DIRECT
    selector: str | None = None
    dispatch_candidate_count: int = 1
    receiver_owner: str | None = None
    vtable_symbol: str | None = None
    vtable_address: int | None = None
    vtable_address_point: int | None = None
    vtable_slot_offset: int | None = None
    vtable_reference_address: int | None = None
    dominating_guard_block_ids: tuple[str, ...] = ()


@dataclass
class DecompilerContinuationAgent:
    client: DecompilerContinuationModelClient
    policy: BinaryCodeContextPolicy

    async def analyze(
        self,
        packet: DecompilerContinuationPacket,
        *,
        run_id: str,
    ) -> tuple[DecompilerHunterAssessment, BudgetUsage, tuple[str, ...]]:
        messages: list[dict] = [
            {
                "role": "user",
                "content": [
                    {
                        "text": (
                            "# Same-session frozen-IR continuation packet\n"
                            + json.dumps(packet.model_dump(mode="json"), indent=2)
                            + "\n\n# Required response JSON Schema\n"
                            + json.dumps(DecompilerHunterAssessment.model_json_schema(), indent=2)
                        )
                    }
                ],
            }
        ]
        totals = {
            name: 0
            for name in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens")
        }
        raw: list[str] = []
        validation_errors: list[str] = []
        for _ in range(self.policy.maximum_attempts_per_continuation):
            response = await self.client.chat(
                messages=messages,
                system=DECOMPILER_CONTEXT_SYSTEM_PROMPT,
                max_tokens=self.policy.maximum_output_tokens_per_call,
                cache_system=True,
            )
            for name in totals:
                totals[name] += int(getattr(response, name))
            raw.append(response.text[:_MAX_RAW_RESPONSE_BYTES])
            parsed = try_extract_object(response.text)
            try:
                if parsed is not None:
                    assessment = DecompilerHunterAssessment.model_validate(parsed)
                    validate_continuation_assessment(packet, assessment)
                    usage = with_estimated_cost(
                        BudgetUsage(
                            run_id=run_id,
                            work_id=packet.work_id,
                            scope="hunter",
                            model_id=str(self.client.model_id),
                            transport=str(getattr(self.client, "transport", "test_or_legacy")),
                            sessions=0,
                            calls=len(raw),
                            iterations=len(raw),
                            **totals,
                        )
                    )
                    return assessment, usage, tuple(raw)
            except ValueError as exc:
                validation_errors.append(str(exc)[:1000])
            if parsed is None:
                validation_errors.append("response did not contain a JSON object")
            messages.extend(
                (
                    {"role": "assistant", "content": response.content_blocks},
                    {
                        "role": "user",
                        "content": [
                            {
                                "text": (
                                    "Return only schema-valid JSON for the same work_id/root/capsule/rank. "
                                    "Cite only facts, functions, blocks, variables, and addresses in the "
                                    "continuation packet. Sort evidence-ID, supporting-address, and "
                                    "supporting-variable, and supporting-field-offset arrays and remove "
                                    "duplicates. If more context is "
                                    "needed, request exactly one permitted frozen-IR slice."
                                )
                            }
                        ],
                    },
                )
            )
        detail = validation_errors[-1] if validation_errors else "unknown validation error"
        raise ValueError("continuation model response remained invalid after one repair: " + detail)


def resolve_binary_code_context(
    *,
    ir: NormalizedBinaryIR,
    packet: DecompilerHunterPacket,
    request: BinaryCodeContextRequest,
    prior_entries: Sequence[DecompilerContextChainEntry] = (),
    policy: BinaryCodeContextPolicy | None = None,
) -> BinaryCodeContextResponse:
    """Resolve one typed request without I/O beyond the supplied frozen objects."""

    active = policy or BinaryCodeContextPolicy()
    _validate_frozen_bindings(ir, packet)
    request_sha = _digest(request.model_dump(mode="json"))
    functions = {item.function_id: item for item in ir.functions}
    known_facts = {
        item.fact_id
        for item in (
            *packet.capsule.facts,
            *(fact for entry in prior_entries for fact in entry.response.facts),
        )
    }
    previous_fingerprints = {_request_fingerprint(item.response.request) for item in prior_entries}
    fingerprint = _request_fingerprint(request)
    if fingerprint in previous_fingerprints:
        return _empty_response(
            packet,
            ir,
            request,
            BinaryCodeContextStatus.REJECTED,
            BinaryCodeContextRejection.DUPLICATE_REQUEST,
            "the same frozen-IR slice was already requested",
        )
    if _is_circular(request, prior_entries):
        return _empty_response(
            packet,
            ir,
            request,
            BinaryCodeContextStatus.REJECTED,
            BinaryCodeContextRejection.CIRCULAR_REQUEST,
            "the request reverses an already resolved caller/callee edge",
        )
    target_ids = tuple(
        value for value in (request.function_id, request.related_function_id) if value is not None
    )
    if any(identifier not in functions for identifier in target_ids):
        return _empty_response(
            packet,
            ir,
            request,
            BinaryCodeContextStatus.REJECTED,
            BinaryCodeContextRejection.OUTSIDE_FROZEN_IMAGE,
            "the request cites a function outside the frozen normalized IR",
        )
    target = functions.get(request.function_id or "")
    if request.block_id is not None and (
        target is None or request.block_id not in {item.block_id for item in target.blocks}
    ):
        return _empty_response(
            packet,
            ir,
            request,
            BinaryCodeContextStatus.REJECTED,
            BinaryCodeContextRejection.UNKNOWN_TARGET,
            "the request cites a block outside its target function",
        )
    requested_addresses = tuple(
        address
        for address in (request.address, *request.supporting_addresses)
        if address is not None
    )
    known_target_addresses = (
        {instruction.address for block in target.blocks for instruction in block.instructions}
        if target is not None
        else set()
    )
    if any(address not in known_target_addresses for address in requested_addresses):
        return _empty_response(
            packet,
            ir,
            request,
            BinaryCodeContextStatus.REJECTED,
            BinaryCodeContextRejection.UNKNOWN_TARGET,
            "the request cites an address outside its target function",
        )
    remaining = (
        active.maximum_total_evidence_bytes
        - packet.capsule.evidence_bytes
        - sum(item.response.evidence_bytes for item in prior_entries)
    )
    maximum = min(request.maximum_bytes, remaining, 96 * 1024)
    if maximum < 1024:
        return _empty_response(
            packet,
            ir,
            request,
            BinaryCodeContextStatus.REJECTED,
            BinaryCodeContextRejection.EVIDENCE_BUDGET_EXCEEDED,
            "the root has no remaining frozen-evidence budget",
        )
    edges = _recover_edges(ir)
    selected, selected_edges, focus, unavailable = _select_context(
        request,
        functions=functions,
        edges=edges,
        virtual_methods=ir.virtual_methods,
    )
    if unavailable is not None:
        return _empty_response(
            packet,
            ir,
            request,
            BinaryCodeContextStatus.UNAVAILABLE,
            BinaryCodeContextRejection.PROOF_UNAVAILABLE,
            unavailable,
        )
    slices, omissions = _build_slices(
        selected,
        focus=focus,
        anchors=_request_anchor_addresses(request, selected),
        phi_origin_anchors=_request_phi_origin_anchor_addresses(request, selected),
        variable_anchors=_request_variable_anchor_addresses(request, selected),
        field_guard_anchors=_request_field_guard_anchor_addresses(request, selected),
        policy=active,
    )
    slices, deduplication_omissions = _remove_known_evidence(
        slices,
        packet,
        prior_entries,
        preserved_keys={
            (
                item.caller.function_id,
                item.instruction.address,
                item.instruction.index,
            )
            for item in selected_edges
        },
    )
    omissions = tuple(sorted(set((*omissions, *deduplication_omissions))))
    facts = _facts_for_slices(slices, excluded=known_facts)
    if not facts:
        return _empty_response(
            packet,
            ir,
            request,
            BinaryCodeContextStatus.UNAVAILABLE,
            BinaryCodeContextRejection.PROOF_UNAVAILABLE,
            "the requested slice contains no new address-backed facts",
        )
    response_function_ids = {item.function_id for item in slices}
    response_instruction_addresses = {
        (function.function_id, instruction.address)
        for function in slices
        for block in function.blocks
        for instruction in block.instructions
    }
    response_block_ids = {
        (function.function_id, block.block_id)
        for function in slices
        for block in function.blocks
    }
    selected_edge_keys = {
        (
            item.caller.function_id,
            item.callee.function_id,
            item.instruction.address,
        )
        for item in selected_edges
    }
    response_edge_candidates = (
        *selected_edges,
        *(
            item
            for item in edges
            if (item.caller.function_id, item.instruction.address)
            in response_instruction_addresses
            and "read_session_input" in item.instruction.tags
            and (
                item.caller.function_id,
                item.callee.function_id,
                item.instruction.address,
            )
            not in selected_edge_keys
        ),
    )[:64]
    response_edges = tuple(
        sorted(
            (
                BinaryCodeContextEdge(
                    caller_function_id=item.caller.function_id,
                    callee_function_id=item.callee.function_id,
                    callsite_address=item.instruction.address,
                    arguments=item.instruction.operands,
                    return_result=item.instruction.result,
                    resolution=item.resolution,
                    selector=item.selector,
                    dispatch_candidate_count=item.dispatch_candidate_count,
                    receiver_owner=item.receiver_owner,
                    vtable_symbol=item.vtable_symbol,
                    vtable_address=item.vtable_address,
                    vtable_address_point=item.vtable_address_point,
                    vtable_slot_offset=item.vtable_slot_offset,
                    vtable_reference_address=item.vtable_reference_address,
                    dominating_guard_block_ids=tuple(
                        block_id
                        for block_id in item.dominating_guard_block_ids
                        if (item.caller.function_id, block_id) in response_block_ids
                    ),
                )
                for item in response_edge_candidates
                if item.caller.function_id not in response_function_ids
                or (item.caller.function_id, item.instruction.address)
                in response_instruction_addresses
            ),
            key=lambda item: (
                item.callsite_address,
                item.caller_function_id,
                item.callee_function_id,
            ),
        )
    )
    slices, response_edges, facts, omissions = _fit_response_budget(
        slices,
        response_edges,
        facts,
        omissions,
        maximum=maximum,
        protected_instruction_keys=(
            _protected_request_instruction_keys(
                request,
                selected,
                selected_edges,
            )
            | {
                (
                    item.caller.function_id,
                    item.instruction.address,
                    item.instruction.index,
                )
                for item in response_edge_candidates
                if item.caller.function_id in response_function_ids
            }
        ),
    )
    if not slices or not facts:
        return _empty_response(
            packet,
            ir,
            request,
            BinaryCodeContextStatus.REJECTED,
            BinaryCodeContextRejection.EVIDENCE_BUDGET_EXCEEDED,
            "the requested address-backed definition/use evidence cannot fit its budget",
        )
    if not _request_evidence_retained(
        packet,
        request,
        slices,
        selected,
        prior_entries,
        response_edges,
    ):
        return _empty_response(
            packet,
            ir,
            request,
            BinaryCodeContextStatus.UNAVAILABLE,
            BinaryCodeContextRejection.PROOF_UNAVAILABLE,
            "the bounded response contains no new evidence for the exact requested target",
        )
    payload = {
        "schema_version": "binary-code-context-response-v1",
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "capsule_sha256": packet.capsule.capsule_sha256,
        "ir_sha256": ir.ir_sha256,
        "request": request.model_dump(mode="json"),
        "request_sha256": request_sha,
        "status": BinaryCodeContextStatus.RESOLVED.value,
        "rejection": None,
        "detail": "resolved deterministically from the packet-bound frozen normalized IR",
        "functions": tuple(item.model_dump(mode="json") for item in slices),
        "call_edges": tuple(item.model_dump(mode="json") for item in response_edges),
        "facts": tuple(item.model_dump(mode="json") for item in facts),
        "omissions": omissions,
        "evidence_bytes": _context_evidence_bytes(slices, response_edges, facts, omissions),
    }
    return BinaryCodeContextResponse(**payload, response_sha256=_digest(payload))


async def continue_decompiler_hunter_session(
    *,
    store_root: Path,
    ir: NormalizedBinaryIR,
    packet: DecompilerHunterPacket,
    initial_assessment: DecompilerHunterAssessment,
    initial_usage: BudgetUsage,
    client: DecompilerContinuationModelClient,
    policy: BinaryCodeContextPolicy | None = None,
) -> DecompilerContextRunResult:
    """Continue one persisted Hunter root at most three times and resume by chain digest."""

    active = policy or BinaryCodeContextPolicy()
    _validate_frozen_bindings(ir, packet)
    _validate_initial_identity(packet, initial_assessment, initial_usage)
    directory = _context_directory(store_root, packet.work_id)
    initial_sha = _digest(initial_assessment.model_dump(mode="json"))
    entries = list(_load_entries(directory, packet, initial_sha))
    terminal_path = directory / "result.json"
    if terminal_path.exists():
        return DecompilerContextRunResult.model_validate_json(_read_file(terminal_path))
    current = entries[-1].assessment if entries else initial_assessment
    if current is None:
        raise RuntimeError("resolved context chain lost its assessment")
    for ordinal in range(len(entries) + 1, active.maximum_continuations_per_root + 1):
        if current.disposition is not DecompilerHunterDisposition.NEEDS_CODE_CONTEXT:
            break
        if len(current.context_requests) != 1:
            result = _make_result(
                packet,
                initial_assessment,
                initial_usage,
                tuple(entries),
                current,
                DecompilerContextTerminalStatus.REVIEWER_INCONCLUSIVE,
            )
            _write_private_json(terminal_path, result.model_dump(mode="json"))
            return result
        request = current.context_requests[0]
        response = resolve_binary_code_context(
            ir=ir,
            packet=packet,
            request=request,
            prior_entries=entries,
            policy=active,
        )
        previous = initial_sha if not entries else entries[-1].chain_sha256
        if response.status is not BinaryCodeContextStatus.RESOLVED:
            entry = _make_entry(
                packet=packet,
                ordinal=ordinal,
                previous=previous,
                response=response,
            )
            _persist_entry(directory, entry, ())
            entries.append(entry)
            result = _make_result(
                packet,
                initial_assessment,
                initial_usage,
                tuple(entries),
                current,
                DecompilerContextTerminalStatus.REVIEWER_INCONCLUSIVE,
            )
            _write_private_json(terminal_path, result.model_dump(mode="json"))
            return result
        responses = tuple(item.response for item in entries) + (response,)
        continuation_packet = _make_continuation_packet(
            packet=packet,
            prior_assessment=current,
            responses=responses,
            ordinal=ordinal,
            previous=previous,
        )
        assessment, usage, raw = await DecompilerContinuationAgent(client, active).analyze(
            continuation_packet,
            run_id=initial_usage.run_id,
        )
        entry = _make_entry(
            packet=packet,
            ordinal=ordinal,
            previous=previous,
            response=response,
            assessment=assessment,
            usage=usage,
            raw=raw,
        )
        _persist_entry(directory, entry, raw)
        entries.append(entry)
        current = assessment
    terminal = (
        DecompilerContextTerminalStatus.REVIEWER_INCONCLUSIVE
        if current.disposition is DecompilerHunterDisposition.NEEDS_CODE_CONTEXT
        else DecompilerContextTerminalStatus.COMPLETED
    )
    result = _make_result(
        packet,
        initial_assessment,
        initial_usage,
        tuple(entries),
        current,
        terminal,
    )
    _write_private_json(terminal_path, result.model_dump(mode="json"))
    return result


def select_context_continuation_roots(
    assessments: Sequence[DecompilerHunterAssessment],
    *,
    policy: BinaryCodeContextPolicy | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Preserve assessment order and select at most six roots needing context."""

    active = policy or BinaryCodeContextPolicy()
    candidates = tuple(
        item.work_id
        for item in assessments
        if item.disposition is DecompilerHunterDisposition.NEEDS_CODE_CONTEXT
    )
    return candidates[: active.maximum_roots_per_run], candidates[active.maximum_roots_per_run :]


def validate_continuation_assessment(
    packet: DecompilerContinuationPacket,
    assessment: DecompilerHunterAssessment,
) -> None:
    base = packet.base_packet
    if (
        assessment.work_id != base.work_id
        or assessment.root_id != base.root_id
        or assessment.capsule_sha256 != base.capsule.capsule_sha256
        or assessment.admission_rank != base.admission_rank
    ):
        raise ValueError("continuation assessment changed root-session identity")
    facts = {item.fact_id: item for item in base.capsule.facts}
    functions = set(base.known_function_ids)
    blocks = set(base.known_block_ids)
    addresses = set(base.known_addresses)
    variables: set[str] = set()
    for response in packet.context_responses:
        facts.update((item.fact_id, item) for item in response.facts)
        for function in response.functions:
            functions.add(function.function_id)
            for block in function.blocks:
                blocks.add(block.block_id)
                for instruction in block.instructions:
                    addresses.add(instruction.address)
                    variables.update(
                        value for value in (instruction.result, *instruction.operands) if value
                    )
    cited = set(assessment.evidence_ids) | set(assessment.safe_path_evidence_ids)
    for hypothesis in assessment.hypotheses:
        citations = (
            hypothesis.source_evidence_ids
            + hypothesis.path_evidence_ids
            + hypothesis.guard_evidence_ids
            + hypothesis.sink_evidence_ids
            + hypothesis.contradicting_evidence_ids
        )
        cited.update(citations)
        _validate_combined_hypothesis(base, facts, functions, addresses, hypothesis)
    for request in assessment.context_requests:
        cited.update(request.evidence_ids)
        if request.kind not in base.allowed_context_kinds:
            raise ValueError("continuation requested an unsupported context kind")
        if request.function_id is not None and request.function_id not in base.frozen_function_ids:
            raise ValueError("continuation requested a function outside frozen IR")
        if (
            request.related_function_id is not None
            and request.related_function_id not in base.frozen_function_ids
        ):
            raise ValueError("continuation requested a related function outside frozen IR")
        if request.block_id is not None and request.block_id not in blocks:
            raise ValueError("continuation requested an unknown block")
        if request.address is not None and request.address not in addresses:
            raise ValueError("continuation requested an unknown address")
        if any(address not in addresses for address in request.supporting_addresses):
            raise ValueError("continuation requested an unknown supporting address")
        if (
            request.variable is not None
            and request.variable not in variables
            and not _base_has_variable(base, request.variable)
        ):
            raise ValueError("continuation requested an unknown variable")
        if any(
            variable not in variables and not _base_has_variable(base, variable)
            for variable in request.supporting_variables
        ):
            raise ValueError("continuation requested an unknown supporting variable")
    if not cited.issubset(facts):
        raise ValueError("continuation cited evidence outside supplied frozen context")
    if assessment.disposition is DecompilerHunterDisposition.NEEDS_CODE_CONTEXT:
        if len(assessment.context_requests) != 1:
            raise ValueError("continuation must request exactly one context slice")
    if assessment.disposition is DecompilerHunterDisposition.NOT_VULNERABLE:
        kinds = {facts[item].kind for item in assessment.safe_path_evidence_ids}
        if not kinds.intersection(
            {BinaryEvidenceFactKind.GUARD, BinaryEvidenceFactKind.RETURN_USE}
        ):
            raise ValueError("not_vulnerable requires cited guard or return-use evidence")
    validate_decompiler_hunter_safe_output(assessment)


def _validate_combined_hypothesis(
    base: DecompilerHunterPacket,
    facts: Mapping[str, BinaryEvidenceFact],
    functions: set[str],
    addresses: set[int],
    hypothesis: DecompilerHunterHypothesis,
) -> None:
    all_ids = (
        hypothesis.source_evidence_ids
        + hypothesis.path_evidence_ids
        + hypothesis.guard_evidence_ids
        + hypothesis.sink_evidence_ids
        + hypothesis.contradicting_evidence_ids
    )
    if any(identifier not in facts for identifier in all_ids):
        raise ValueError("continuation hypothesis cites unknown evidence")
    base_fact_ids = set(base.allowed_evidence_ids)
    if base.capsule.proof_status.value == "proof_incomplete" and set(all_ids).issubset(
        base_fact_ids
    ):
        raise ValueError("proof-incomplete continuation must cite newly supplied context")
    if {facts[item].kind for item in hypothesis.source_evidence_ids} != {
        BinaryEvidenceFactKind.INPUT_SOURCE
    }:
        raise ValueError("continuation source citations must be input-source facts")
    if not {facts[item].kind for item in hypothesis.path_evidence_ids}.intersection(
        {
            BinaryEvidenceFactKind.DATAFLOW,
            BinaryEvidenceFactKind.CALLSITE,
            BinaryEvidenceFactKind.RETURN_USE,
        }
    ):
        raise ValueError("continuation hypothesis lacks an address-backed path")
    if {facts[item].kind for item in hypothesis.sink_evidence_ids} != {
        BinaryEvidenceFactKind.SECURITY_SINK
    }:
        raise ValueError("continuation sink citations must be security-sink facts")
    if any(
        facts[item].kind is not BinaryEvidenceFactKind.GUARD
        for item in hypothesis.guard_evidence_ids
    ):
        raise ValueError("continuation guard citations must be guard facts")
    if not set(hypothesis.call_path_function_ids).issubset(functions):
        raise ValueError("continuation hypothesis cites an unknown function")
    if base.capsule.root_function_id not in hypothesis.call_path_function_ids:
        raise ValueError("continuation hypothesis omits the admitted root")
    if not set(hypothesis.cfg_path_addresses).issubset(addresses):
        raise ValueError("continuation hypothesis cites an unknown address")
    guard_ids = {
        identifier
        for identifier, fact in facts.items()
        if fact.kind is BinaryEvidenceFactKind.GUARD
    }
    if hypothesis.no_applicable_guard and guard_ids:
        raise ValueError("continuation hypothesis ignored supplied guard evidence")


def _select_context(
    request: BinaryCodeContextRequest,
    *,
    functions: Mapping[str, IRFunction],
    edges: tuple[_RawEdge, ...],
    virtual_methods: tuple[IRVirtualMethodReference, ...],
) -> tuple[tuple[IRFunction, ...], tuple[_RawEdge, ...], dict[str, set[int]], str | None]:
    function = functions.get(request.function_id or "")
    if function is None:
        return (), (), {}, "the requested function is not present in the frozen IR"
    focus: dict[str, set[int]] = defaultdict(set)
    selected_edges: tuple[_RawEdge, ...] = ()
    selected: tuple[IRFunction, ...]
    if request.kind is BinaryCodeContextRequestKind.EXACT_FUNCTION:
        selected = (function,)
    elif request.kind is BinaryCodeContextRequestKind.DIRECT_CALLER:
        matches = tuple(item for item in edges if item.callee.function_id == function.function_id)
        if request.related_function_id:
            matches = tuple(
                item for item in matches if item.caller.function_id == request.related_function_id
            )
        if not matches:
            callers = tuple(functions.values())
            if request.related_function_id:
                callers = tuple(
                    item for item in callers if item.function_id == request.related_function_id
                )
            matches = _recover_virtual_callers(
                function,
                callers,
                tuple(functions.values()),
                virtual_methods,
            )
        if not matches:
            return (), (), {}, "no matching direct caller was recovered in frozen IR"
        selected_edges = matches[:8]
        selected = _unique_functions(tuple(item.caller for item in selected_edges))
        for item in selected_edges:
            focus[item.caller.function_id].add(item.instruction.address)
            focus[item.caller.function_id].update(
                _guard_addresses_for_blocks(
                    item.caller,
                    item.dominating_guard_block_ids,
                )
            )
    elif request.kind is BinaryCodeContextRequestKind.DIRECT_CALLEE:
        matches = tuple(item for item in edges if item.caller.function_id == function.function_id)
        if request.related_function_id:
            matches = tuple(
                item for item in matches if item.callee.function_id == request.related_function_id
            )
            if not matches:
                related = functions[request.related_function_id]
                virtual = _recover_virtual_callers(
                    related,
                    (function,),
                    tuple(functions.values()),
                    virtual_methods,
                )
                matches = tuple(
                    item for item in virtual if item.caller.function_id == function.function_id
                )
        if not matches:
            return (), (), {}, "no matching direct callee was recovered in frozen IR"
        selected_edges = matches[:8]
        selected = _unique_functions(tuple(item.callee for item in selected_edges))
        for item in selected_edges:
            focus[item.callee.function_id].add(item.callee.start_address)
    elif request.kind is BinaryCodeContextRequestKind.BASIC_BLOCK_NEIGHBORHOOD:
        block = next((item for item in function.blocks if item.block_id == request.block_id), None)
        if block is None:
            return (), (), {}, "the requested block is not part of the requested function"
        focus[function.function_id].add(block.start_address)
        selected = (function,)
    elif request.kind is BinaryCodeContextRequestKind.DEFINITION_USE_CHAIN:
        variables = (request.variable or "", *request.supporting_variables)
        variable_addresses = set().union(
            *(_definition_use_addresses(function, variable) for variable in variables)
        )
        if not variable_addresses:
            return (), (), {}, "the requested variable has no definition/use in frozen IR"
        focus[function.function_id].update(variable_addresses)
        if request.address is not None:
            focus[function.function_id].add(request.address)
        focus[function.function_id].update(request.supporting_addresses)
        if request.block_id is not None:
            requested_block = next(
                item for item in function.blocks if item.block_id == request.block_id
            )
            focus[function.function_id].add(requested_block.start_address)
        selected = (function,)
        if request.supporting_field_offsets:
            field_functions, field_focus, field_error = _select_object_field_provenance(
                function,
                tuple(functions.values()),
                request.supporting_field_offsets,
            )
            if field_error is not None:
                return (), (), {}, field_error
            selected = _unique_functions((function, *field_functions))
            for function_id, addresses in field_focus.items():
                focus[function_id].update(addresses)
        selected_edges = tuple(
            item
            for item in edges
            if item.caller.function_id == function.function_id
            and item.instruction.address in focus[function.function_id]
        )[:64]
    elif request.kind is BinaryCodeContextRequestKind.CALLSITE_RETURN_USE:
        call = next(
            (
                instruction
                for block in function.blocks
                for instruction in block.instructions
                if instruction.address == request.address
                and instruction.operation is IROperation.CALL
            ),
            None,
        )
        if call is None or call.result is None:
            return (), (), {}, "the requested address is not a result-producing callsite"
        focus[function.function_id].add(call.address)
        for block in function.blocks:
            for instruction in block.instructions:
                if call.result in instruction.operands or instruction.result == call.result:
                    focus[function.function_id].add(instruction.address)
        selected = (function,)
        selected_edges = tuple(
            item
            for item in edges
            if item.caller.function_id == function.function_id
            and item.instruction.address == call.address
        )
    else:
        return (), (), {}, "unsupported context request kind"
    return selected, selected_edges, focus, None


def _select_object_field_provenance(
    root: IRFunction,
    functions: tuple[IRFunction, ...],
    offsets: tuple[int, ...],
) -> tuple[tuple[IRFunction, ...], dict[str, set[int]], str | None]:
    """Select bounded cross-function field writers/guards from frozen IR only."""

    candidates: list[tuple[IRFunction, dict[int, set[int]]]] = []
    for function in functions:
        accesses = _object_field_accesses(function, offsets)
        if accesses:
            candidates.append((function, accesses))
    root_owner = _qualified_owner(root)

    def candidate_priority(
        item: tuple[IRFunction, dict[int, set[int]]],
        offset: int,
    ) -> tuple[int, int, int, int, int, int, str]:
        function, accesses = item
        lowered = function.name.lower()
        lifecycle = {
            "initialize": 5,
            "willdecode": 6,
            "preparegeometry": 6,
            "parse": 3,
            "readheader": 3,
        }.get(lowered, 0)
        owner_match = int(bool(root_owner) and _qualified_owner(function) == root_owner)
        instructions = tuple(
            instruction
            for block in function.blocks
            for instruction in block.instructions
            if instruction.address in set().union(*accesses.values())
        )
        writes = sum(item.operation is IROperation.STORE for item in instructions)
        input_sources = sum(_is_input_source(item) for item in instructions)
        stage_match = int(
            (offset in {0x114, 0x118} and lowered == "preparegeometry")
            or (offset in {0x140, 0x142} and lowered == "willdecode")
        )
        return (
            owner_match,
            stage_match,
            lifecycle,
            len(accesses),
            int(writes > 0),
            int(input_sources > 0),
            function.function_id,
        )

    chosen: list[tuple[IRFunction, dict[int, set[int]]]] = []
    missing = []
    for offset in offsets:
        ranked = sorted(
            candidates,
            key=lambda item: candidate_priority(item, offset),
            reverse=True,
        )
        match = next(
            (
                item
                for item in ranked
                if item[0].function_id != root.function_id and offset in item[1]
            ),
            None,
        )
        if match is None:
            missing.append(offset)
            continue
        if all(existing[0].function_id != match[0].function_id for existing in chosen):
            chosen.append(match)
    if missing:
        rendered = ", ".join(f"0x{offset:x}" for offset in missing)
        return (), {}, f"no cross-function frozen-IR access was recovered for fields {rendered}"
    focus: dict[str, set[int]] = defaultdict(set)
    for function, accesses in chosen:
        focus[function.function_id].update(set().union(*accesses.values()))
    return tuple(item[0] for item in chosen), focus, None


def _object_field_accesses(
    function: IRFunction,
    offsets: tuple[int, ...],
) -> dict[int, set[int]]:
    instructions = tuple(
        instruction for block in function.blocks for instruction in block.instructions
    )
    object_parameters = _object_parameters(instructions)
    if not object_parameters:
        return {}
    accesses: dict[int, set[int]] = defaultdict(set)
    requested = set(offsets)
    for instruction in instructions:
        if (
            instruction.operation is not IROperation.ADD
            or instruction.result is None
            or not set(instruction.operands).intersection(object_parameters)
        ):
            continue
        for offset in requested.intersection(instruction.constants):
            accesses[offset].add(instruction.address)
            accesses[offset].update(
                _field_pointer_closure_addresses(
                    instructions,
                    instruction.result,
                    object_parameters,
                )
            )
    return dict(accesses)


def _object_field_pointer_addresses(
    function: IRFunction,
    offsets: tuple[int, ...],
) -> dict[int, set[int]]:
    instructions = tuple(
        instruction for block in function.blocks for instruction in block.instructions
    )
    object_parameters = _object_parameters(instructions)
    requested = set(offsets)
    result: dict[int, set[int]] = defaultdict(set)
    for instruction in instructions:
        if (
            instruction.operation is IROperation.ADD
            and instruction.result is not None
            and bool(set(instruction.operands).intersection(object_parameters))
        ):
            for offset in requested.intersection(instruction.constants):
                result[offset].add(instruction.address)
    return dict(result)


def _object_field_guard_anchor_addresses(
    function: IRFunction,
    offsets: tuple[int, ...],
) -> set[int]:
    instructions = tuple(
        instruction for block in function.blocks for instruction in block.instructions
    )
    accesses = _object_field_accesses(function, offsets)
    anchors: set[int] = set()
    for addresses in accesses.values():
        comparisons = tuple(
            sorted(
                (
                    instruction
                    for instruction in instructions
                    if instruction.address in addresses
                    and instruction.operation is IROperation.COMPARE
                ),
                key=lambda item: (item.address, item.index),
            )
        )
        enum_comparisons = tuple(
            item for item in comparisons if any(constant >= 0x1000 for constant in item.constants)
        )
        if enum_comparisons:
            anchors.update(item.address for item in enum_comparisons[:8])
        elif comparisons:
            anchors.add(comparisons[0].address)
            anchors.add(comparisons[-1].address)
    return anchors


def _object_parameters(instructions: tuple[IRInstruction, ...]) -> set[str]:
    parameters = tuple(
        item.result
        for item in instructions
        if item.operation is IROperation.PARAMETER and item.result is not None
    )
    if not parameters:
        return set()
    return {"this"} if "this" in parameters else {parameters[0]}


def _field_pointer_closure_addresses(
    instructions: tuple[IRInstruction, ...],
    seed: str,
    object_parameters: set[str],
) -> set[int]:
    variables = {seed}
    selected: set[tuple[int, int]] = set()
    for _ in range(6):
        changed = False
        for instruction in instructions:
            result_match = instruction.result in variables
            operand_match = bool(set(instruction.operands).intersection(variables))
            if not result_match and not operand_match:
                continue
            key = (instruction.address, instruction.index)
            if key not in selected:
                selected.add(key)
                changed = True
            before = len(variables)
            if result_match:
                variables.update(
                    value
                    for value in instruction.operands
                    if value not in object_parameters and not value.startswith("const_")
                )
            if operand_match and instruction.result is not None:
                variables.add(instruction.result)
            changed = changed or len(variables) != before
        if not changed or len(selected) >= 128:
            break
    return {address for address, _ in selected}


def _qualified_owner(function: IRFunction) -> str:
    match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)::[~A-Za-z_]", function.pseudocode)
    return match.group(1) if match is not None else ""


def _build_slices(
    functions: tuple[IRFunction, ...],
    *,
    focus: Mapping[str, set[int]],
    anchors: Mapping[str, set[int]],
    phi_origin_anchors: Mapping[str, set[int]],
    variable_anchors: Mapping[str, set[int]],
    field_guard_anchors: Mapping[str, set[int]],
    policy: BinaryCodeContextPolicy,
) -> tuple[tuple[BinaryCodeContextFunctionSlice, ...], tuple[str, ...]]:
    slices: list[BinaryCodeContextFunctionSlice] = []
    omissions: list[str] = []
    for function_index, function in enumerate(functions[:8]):
        target_addresses = focus.get(function.function_id, set())
        anchor_addresses = anchors.get(function.function_id, set())
        phi_origin_anchor_addresses = phi_origin_anchors.get(function.function_id, set())
        variable_anchor_addresses = variable_anchors.get(function.function_id, set())
        field_guard_anchor_addresses = field_guard_anchors.get(function.function_id, set())
        anchor_indices = {
            index
            for index, block in enumerate(function.blocks)
            if any(
                block.start_address <= address < block.end_address for address in anchor_addresses
            )
        }
        variable_anchor_indices = {
            index
            for index, block in enumerate(function.blocks)
            if any(
                block.start_address <= address < block.end_address
                for address in variable_anchor_addresses
            )
        }
        phi_origin_anchor_indices = {
            index
            for index, block in enumerate(function.blocks)
            if any(
                block.start_address <= address < block.end_address
                for address in phi_origin_anchor_addresses
            )
        }
        field_guard_anchor_indices = {
            index
            for index, block in enumerate(function.blocks)
            if any(
                block.start_address <= address < block.end_address
                for address in field_guard_anchor_addresses
            )
        }
        direct_indices = {
            index
            for index, block in enumerate(function.blocks)
            if any(
                block.start_address <= address < block.end_address for address in target_addresses
            )
        }
        neighbor_indices: set[int] = set()
        if direct_indices:
            for index in direct_indices:
                if index > 0:
                    neighbor_indices.add(index - 1)
                if index + 1 < len(function.blocks):
                    neighbor_indices.add(index + 1)
        signal_indices = {
            index
            for index, block in enumerate(function.blocks)
            if any(_is_signal(item) for item in block.instructions)
        }

        def block_priority(index: int) -> tuple[int, int]:
            if index in anchor_indices:
                priority = 0
            elif index in phi_origin_anchor_indices:
                priority = 1
            elif index in field_guard_anchor_indices:
                priority = 2
            elif index in variable_anchor_indices:
                priority = 3
            elif index in direct_indices:
                priority = 4
            elif index in neighbor_indices or index in signal_indices:
                priority = 5
            else:
                priority = 6
            return priority, function.blocks[index].start_address

        selected_indices = sorted(
            range(len(function.blocks)),
            key=block_priority,
        )[: policy.maximum_blocks_per_response]
        remaining_instructions = (
            policy.maximum_instructions_per_response
            if function_index == 0
            else min(96, policy.maximum_instructions_per_response)
        )
        bounded_blocks: list[IRBasicBlock] = []
        for index in selected_indices:
            if remaining_instructions <= 0:
                break
            block = function.blocks[index]
            per_block_limit = 64 if function_index == 0 else 48
            instructions = _bounded_instructions(
                block.instructions,
                target_addresses,
                min(remaining_instructions, per_block_limit),
                priority_targets=(
                    anchor_addresses
                    | phi_origin_anchor_addresses
                    | variable_anchor_addresses
                    | field_guard_anchor_addresses
                ),
            )
            if not instructions:
                continue
            bounded_blocks.append(
                IRBasicBlock(
                    block_id=block.block_id,
                    start_address=block.start_address,
                    end_address=block.end_address,
                    instructions=instructions,
                    successors=block.successors,
                )
            )
            remaining_instructions -= len(instructions)
        if not bounded_blocks:
            continue
        bounded_blocks.sort(key=lambda item: item.start_address)
        pseudocode, truncated = _bounded_text(
            function.pseudocode,
            policy.maximum_pseudocode_bytes_per_function,
        )
        included = {item.block_id for item in bounded_blocks}
        omitted = tuple(
            sorted(item.block_id for item in function.blocks if item.block_id not in included)
        )
        if omitted:
            omissions.append(f"{function.function_id}: omitted {len(omitted)} non-selected blocks")
        if truncated:
            omissions.append(
                f"{function.function_id}: pseudocode truncated; normalized IR retained"
            )
        slices.append(
            BinaryCodeContextFunctionSlice(
                function_id=function.function_id,
                function_name=function.name,
                start_address=function.start_address,
                end_address=function.end_address,
                pseudocode_excerpt=pseudocode,
                pseudocode_sha256=function.pseudocode_sha256,
                pseudocode_truncated=truncated,
                blocks=tuple(bounded_blocks),
                omitted_block_ids=omitted,
            )
        )
    return tuple(slices), tuple(sorted(set(omissions)))


def _bounded_instructions(
    instructions: tuple[IRInstruction, ...],
    targets: set[int],
    maximum: int,
    *,
    priority_targets: set[int] | None = None,
) -> tuple[IRInstruction, ...]:
    if len(instructions) <= maximum:
        return instructions
    priority_targets = priority_targets or set()
    target_indices = {index for index, item in enumerate(instructions) if item.address in targets}
    priority_target_indices = {
        index for index, item in enumerate(instructions) if item.address in priority_targets
    }
    signal_indices = {index for index, item in enumerate(instructions) if _is_signal(item)}

    def priority(index: int) -> tuple[int, int, int, int]:
        instruction = instructions[index]
        signal_rank = int(index not in signal_indices)
        unknown_rank = int(instruction.operation is IROperation.UNKNOWN)
        if index in priority_target_indices:
            return 0, signal_rank, unknown_rank, index
        if index in target_indices:
            return 1, signal_rank, unknown_rank, index
        distance = (
            min(abs(index - target) for target in target_indices)
            if target_indices
            else len(instructions)
        )
        if distance <= 3:
            return 2, distance, signal_rank, index
        if index in signal_indices:
            return 3, 0, unknown_rank, index
        return 4, distance, unknown_rank, index

    chosen = sorted(sorted(range(len(instructions)), key=priority)[:maximum])
    return tuple(instructions[index] for index in chosen)


def _definition_use_addresses(function: IRFunction, variable: str) -> set[int]:
    """Recover a bounded intra-function definition/use closure for one IR variable."""

    instructions = tuple(
        instruction for block in function.blocks for instruction in block.instructions
    )
    variables = {variable}
    selected: set[tuple[int, int]] = set()
    for _ in range(4):
        changed = False
        for instruction in instructions:
            result_match = instruction.result in variables
            operand_match = bool(set(instruction.operands).intersection(variables))
            if not result_match and not operand_match:
                continue
            key = (instruction.address, instruction.index)
            if key not in selected:
                selected.add(key)
                changed = True
            before = len(variables)
            if result_match:
                variables.update(instruction.operands)
            if operand_match and instruction.result is not None:
                variables.add(instruction.result)
            changed = changed or len(variables) != before
        if not changed or len(selected) >= 256:
            break
    return {address for address, _ in selected}


def _facts_for_slices(
    slices: tuple[BinaryCodeContextFunctionSlice, ...],
    *,
    excluded: set[str],
) -> tuple[BinaryEvidenceFact, ...]:
    facts = []
    for function in slices:
        for block in function.blocks:
            for instruction in block.instructions:
                fact = _fact(function.function_id, block.block_id, instruction)
                if fact.fact_id not in excluded:
                    facts.append(fact)
    return tuple(
        sorted(
            {item.fact_id: item for item in facts}.values(),
            key=lambda item: (
                item.address,
                item.instruction_index,
                item.function_id,
                item.kind.value,
            ),
        )
    )


def _remove_known_evidence(
    slices: tuple[BinaryCodeContextFunctionSlice, ...],
    packet: DecompilerHunterPacket,
    prior_entries: Sequence[DecompilerContextChainEntry],
    *,
    preserved_keys: set[tuple[str, int, int]] | None = None,
) -> tuple[tuple[BinaryCodeContextFunctionSlice, ...], tuple[str, ...]]:
    preserved_keys = preserved_keys or set()
    known_keys = {
        (function.function_id, instruction.address, instruction.index)
        for function in (
            *packet.capsule.functions,
            *(function for entry in prior_entries for function in entry.response.functions),
        )
        for block in function.blocks
        for instruction in block.instructions
    }
    known_function_ids = {
        function.function_id
        for function in (
            *packet.capsule.functions,
            *(function for entry in prior_entries for function in entry.response.functions),
        )
    }
    deduplicated = 0
    result = []
    for function in slices:
        blocks = []
        for block in function.blocks:
            instructions = tuple(
                instruction
                for instruction in block.instructions
                if (function.function_id, instruction.address, instruction.index) not in known_keys
                or (function.function_id, instruction.address, instruction.index)
                in preserved_keys
            )
            deduplicated += len(block.instructions) - len(instructions)
            if instructions:
                blocks.append(block.model_copy(update={"instructions": instructions}))
        if not blocks:
            continue
        updates: dict[str, object] = {"blocks": tuple(blocks)}
        if function.function_id in known_function_ids:
            updates.update(
                {
                    "pseudocode_excerpt": "",
                    "pseudocode_truncated": True,
                }
            )
        result.append(function.model_copy(update=updates))
    omissions = (
        (f"deduplicated {deduplicated} instructions already present in the context chain",)
        if deduplicated
        else ()
    )
    return tuple(result), omissions


def _fit_response_budget(
    slices: tuple[BinaryCodeContextFunctionSlice, ...],
    edges: tuple[BinaryCodeContextEdge, ...],
    facts: tuple[BinaryEvidenceFact, ...],
    omissions: tuple[str, ...],
    *,
    maximum: int,
    protected_instruction_keys: set[tuple[str, int, int]],
) -> tuple[
    tuple[BinaryCodeContextFunctionSlice, ...],
    tuple[BinaryCodeContextEdge, ...],
    tuple[BinaryEvidenceFact, ...],
    tuple[str, ...],
]:
    current = slices
    current_omissions = list(omissions)
    if _context_evidence_bytes(current, edges, facts, tuple(current_omissions)) <= maximum:
        return current, edges, facts, tuple(current_omissions)
    stripped = []
    for item in current:
        stripped.append(
            item.model_copy(
                update={
                    "pseudocode_excerpt": "",
                    "pseudocode_truncated": True,
                }
            )
        )
    current = tuple(stripped)
    current_omissions.append("response byte budget omitted pseudocode; normalized IR retained")
    current_omissions.append("response byte budget may omit lower-priority instructions")
    while (
        facts
        and _context_evidence_bytes(current, edges, facts, tuple(sorted(set(current_omissions))))
        > maximum
    ):
        candidates = tuple(
            item
            for item in facts
            if (item.function_id, item.address, item.instruction_index)
            not in protected_instruction_keys
        )
        if not candidates:
            return (), (), (), tuple(sorted(set(current_omissions)))
        drop = max(candidates, key=_fact_drop_priority)
        facts = tuple(item for item in facts if item.fact_id != drop.fact_id)
        trimmed = []
        for function in current:
            blocks = []
            for block in function.blocks:
                instructions = tuple(
                    item
                    for item in block.instructions
                    if not (
                        function.function_id == drop.function_id
                        and item.address == drop.address
                        and item.index == drop.instruction_index
                    )
                )
                if instructions:
                    blocks.append(block.model_copy(update={"instructions": instructions}))
            if blocks:
                trimmed.append(function.model_copy(update={"blocks": tuple(blocks)}))
        current = tuple(trimmed)
    return current, edges, facts, tuple(sorted(set(current_omissions)))


def _fact_drop_priority(fact: BinaryEvidenceFact) -> tuple[int, int, int]:
    priority = {
        BinaryEvidenceFactKind.UNKNOWN: 4,
        BinaryEvidenceFactKind.DATAFLOW: 3,
        BinaryEvidenceFactKind.RETURN_USE: 2,
        BinaryEvidenceFactKind.CALLSITE: 2,
        BinaryEvidenceFactKind.GUARD: 1,
        BinaryEvidenceFactKind.INPUT_SOURCE: 0,
        BinaryEvidenceFactKind.SECURITY_SINK: 0,
    }[fact.kind]
    return priority, fact.address, fact.instruction_index


def _request_evidence_retained(
    packet: DecompilerHunterPacket,
    request: BinaryCodeContextRequest,
    slices: tuple[BinaryCodeContextFunctionSlice, ...],
    selected_functions: tuple[IRFunction, ...],
    prior_entries: Sequence[DecompilerContextChainEntry] = (),
    edges: tuple[BinaryCodeContextEdge, ...] = (),
) -> bool:
    instructions = tuple(
        instruction
        for function in slices
        for block in function.blocks
        for instruction in block.instructions
    )
    base_instructions = tuple(
        instruction
        for function in packet.capsule.functions
        for block in function.blocks
        for instruction in block.instructions
    )
    prior_instructions = tuple(
        instruction
        for entry in prior_entries
        for function in entry.response.functions
        for block in function.blocks
        for instruction in block.instructions
    )
    combined = base_instructions + prior_instructions + instructions
    requested_addresses = tuple(
        address
        for address in (request.address, *request.supporting_addresses)
        if address is not None
    )
    if any(
        not any(item.address == address for item in combined) for address in requested_addresses
    ):
        return False
    requested_variables = tuple(
        variable
        for variable in (request.variable, *request.supporting_variables)
        if variable is not None
    )
    for variable in requested_variables:
        definitions = tuple(item for item in combined if item.result == variable)
        uses = tuple(item for item in combined if variable in item.operands)
        if not definitions or not uses:
            return False
    combined_keys = {
        (function.function_id, instruction.address, instruction.index)
        for function in (
            *packet.capsule.functions,
            *(function for entry in prior_entries for function in entry.response.functions),
            *slices,
        )
        for block in function.blocks
        for instruction in block.instructions
    }
    for function in selected_functions:
        if function.function_id != request.function_id:
            continue
        definitions_by_result: dict[str, list[IRInstruction]] = defaultdict(list)
        for block in function.blocks:
            for instruction in block.instructions:
                if instruction.result is not None:
                    definitions_by_result[instruction.result].append(instruction)
        for variable in requested_variables:
            for definition in definitions_by_result.get(variable, ()):
                if definition.operation is not IROperation.PHI:
                    continue
                for operand in definition.operands:
                    origins = definitions_by_result.get(operand, ())
                    if origins and not any(
                        (function.function_id, item.address, item.index) in combined_keys
                        for item in origins
                    ):
                        return False
    if request.supporting_field_offsets:
        response_addresses: dict[str, set[int]] = defaultdict(set)
        for function in (
            *(function for entry in prior_entries for function in entry.response.functions),
            *slices,
        ):
            response_addresses[function.function_id].update(
                instruction.address
                for block in function.blocks
                for instruction in block.instructions
            )
        for offset in request.supporting_field_offsets:
            if not any(
                bool(
                    _object_field_pointer_addresses(function, (offset,)).get(offset, set())
                    & response_addresses.get(function.function_id, set())
                )
                for function in selected_functions
                if function.function_id != request.function_id
            ):
                return False
    if request.kind is BinaryCodeContextRequestKind.CALLSITE_RETURN_USE:
        call = next(
            (
                item
                for item in combined
                if item.address == request.address
                and item.operation is IROperation.CALL
                and item.result is not None
            ),
            None,
        )
        if call is None or not any(call.result in item.operands for item in instructions):
            return False
    response_block_ids = {
        block.block_id
        for function in (
            *(function for entry in prior_entries for function in entry.response.functions),
            *slices,
        )
        for block in function.blocks
    }
    if request.kind is BinaryCodeContextRequestKind.BASIC_BLOCK_NEIGHBORHOOD:
        if request.block_id not in response_block_ids:
            return False
    elif (
        request.block_id is not None
        and request.block_id not in response_block_ids
        and request.block_id not in packet.known_block_ids
    ):
        return False
    if request.kind is BinaryCodeContextRequestKind.DIRECT_CALLER and not any(
        item.callee_function_id == request.function_id
        and (
            request.related_function_id is None
            or item.caller_function_id == request.related_function_id
        )
        for item in edges
    ):
        return False
    if request.kind is BinaryCodeContextRequestKind.DIRECT_CALLEE and not any(
        item.caller_function_id == request.function_id
        and (
            request.related_function_id is None
            or item.callee_function_id == request.related_function_id
        )
        for item in edges
    ):
        return False
    return True


def _protected_request_instruction_keys(
    request: BinaryCodeContextRequest,
    functions: tuple[IRFunction, ...],
    edges: tuple[_RawEdge, ...] = (),
) -> set[tuple[str, int, int]]:
    protected: set[tuple[str, int, int]] = set()
    requested_variables = {
        variable
        for variable in (request.variable, *request.supporting_variables)
        if variable is not None
    }
    if requested_variables:
        if request.kind is BinaryCodeContextRequestKind.DEFINITION_USE_CHAIN:
            for function in functions:
                protected.update(
                    (function.function_id, address, index)
                    for address, index in _definition_use_core_instruction_keys(
                        function,
                        requested_variables,
                        requested_addresses={
                            address
                            for address in (request.address, *request.supporting_addresses)
                            if address is not None
                        },
                    )
                )
        else:
            protected.update(
                (function.function_id, instruction.address, instruction.index)
                for function in functions
                for block in function.blocks
                for instruction in block.instructions
                if instruction.result in requested_variables
                or bool(set(instruction.operands).intersection(requested_variables))
            )
        for function in functions:
            protected.update(
                (function.function_id, address, index)
                for address, index in _direct_phi_origin_instruction_keys(
                    function, requested_variables
                )
            )
    if request.supporting_field_offsets:
        for offset in request.supporting_field_offsets:
            direct_function = next(
                (
                    (function, min(addresses))
                    for function in functions
                    if function.function_id != request.function_id
                    if (
                        addresses := _object_field_pointer_addresses(function, (offset,)).get(
                            offset, set()
                        )
                    )
                ),
                None,
            )
            if direct_function is None:
                continue
            function, direct_address = direct_function
            protected.update(
                (function.function_id, instruction.address, instruction.index)
                for block in function.blocks
                for instruction in block.instructions
                if instruction.address == direct_address
                and instruction.operation is IROperation.ADD
                and offset in instruction.constants
            )
            guard_addresses = _object_field_guard_anchor_addresses(function, (offset,))
            guard_address = min(guard_addresses) if guard_addresses else None
            protected.update(
                (function.function_id, instruction.address, instruction.index)
                for block in function.blocks
                for instruction in block.instructions
                if instruction.address == guard_address
                and instruction.operation is IROperation.COMPARE
            )
    requested_addresses = {
        address
        for address in (request.address, *request.supporting_addresses)
        if address is not None
    }
    if requested_addresses:
        for address in sorted(requested_addresses):
            matches = sorted(
                (
                    (function.function_id, instruction)
                    for function in functions
                    for block in function.blocks
                    for instruction in block.instructions
                    if instruction.address == address
                ),
                key=lambda item: (
                    not _is_signal(item[1]),
                    item[1].operation is IROperation.UNKNOWN,
                    item[1].index,
                    item[0],
                ),
            )
            protected.update(
                (function_id, instruction.address, instruction.index)
                for function_id, instruction in _preferred_address_matches(matches)
            )
    for edge in edges:
        protected.add(
            (
                edge.caller.function_id,
                edge.instruction.address,
                edge.instruction.index,
            )
        )
        protected.update(
            (edge.caller.function_id, instruction.address, instruction.index)
            for block in edge.caller.blocks
            if block.block_id in edge.dominating_guard_block_ids
            for instruction in block.instructions
            if instruction.operation in {IROperation.COMPARE, IROperation.BRANCH}
        )
        if edge.resolution in {
            BinaryCodeContextEdgeResolution.VIRTUAL_SELECTOR,
            BinaryCodeContextEdgeResolution.VIRTUAL_VTABLE,
        }:
            protected.update(_virtual_dispatch_support_keys(edge))
    return protected


def _virtual_dispatch_support_keys(edge: _RawEdge) -> set[tuple[str, int, int]]:
    block = next(
        (
            item
            for item in edge.caller.blocks
            if any(
                instruction.address == edge.instruction.address
                and instruction.index == edge.instruction.index
                for instruction in item.instructions
            )
        ),
        None,
    )
    if block is None:
        return set()
    preceding = sorted(
        {item.address for item in block.instructions if item.address < edge.instruction.address}
    )
    support_address = preceding[-1] if preceding else edge.instruction.address
    return {
        (edge.caller.function_id, item.address, item.index)
        for item in block.instructions
        if item.address == support_address
    }


def _request_anchor_addresses(
    request: BinaryCodeContextRequest,
    functions: tuple[IRFunction, ...],
) -> dict[str, set[int]]:
    anchors: dict[str, set[int]] = defaultdict(set)
    for function in functions:
        if request.address is not None:
            anchors[function.function_id].add(request.address)
        anchors[function.function_id].update(request.supporting_addresses)
        if request.block_id is not None:
            block = next(
                (item for item in function.blocks if item.block_id == request.block_id),
                None,
            )
            if block is not None:
                anchors[function.function_id].add(block.start_address)
    return anchors


def _request_phi_origin_anchor_addresses(
    request: BinaryCodeContextRequest,
    functions: tuple[IRFunction, ...],
) -> dict[str, set[int]]:
    anchors: dict[str, set[int]] = defaultdict(set)
    requested_variables = {
        variable
        for variable in (request.variable, *request.supporting_variables)
        if variable is not None
    }
    for function in functions:
        anchors[function.function_id].update(
            address
            for address, _ in _direct_phi_origin_instruction_keys(function, requested_variables)
        )
    return anchors


def _request_field_guard_anchor_addresses(
    request: BinaryCodeContextRequest,
    functions: tuple[IRFunction, ...],
) -> dict[str, set[int]]:
    anchors: dict[str, set[int]] = defaultdict(set)
    if not request.supporting_field_offsets:
        return anchors
    for function in functions:
        anchors[function.function_id].update(
            _object_field_guard_anchor_addresses(function, request.supporting_field_offsets)
        )
    return anchors


def _request_variable_anchor_addresses(
    request: BinaryCodeContextRequest,
    functions: tuple[IRFunction, ...],
) -> dict[str, set[int]]:
    anchors: dict[str, set[int]] = defaultdict(set)
    requested_variables = {
        variable
        for variable in (request.variable, *request.supporting_variables)
        if variable is not None
    }
    if not requested_variables:
        return anchors
    requested_addresses = {
        address
        for address in (request.address, *request.supporting_addresses)
        if address is not None
    }
    for function in functions:
        anchors[function.function_id].update(
            address
            for address, _ in _definition_use_core_instruction_keys(
                function,
                requested_variables,
                requested_addresses=requested_addresses,
            )
        )
    return anchors


def _definition_use_core_instruction_keys(
    function: IRFunction,
    variables: set[str],
    *,
    requested_addresses: set[int],
) -> set[tuple[int, int]]:
    """Select the minimum deterministic proof core for requested SSA values."""

    instructions = tuple(
        instruction for block in function.blocks for instruction in block.instructions
    )
    keys = _direct_phi_origin_instruction_keys(function, variables)
    for variable in sorted(variables):
        definitions = tuple(item for item in instructions if item.result == variable)
        keys.update((item.address, item.index) for item in definitions)
        uses = tuple(item for item in instructions if variable in item.operands)
        if uses:
            best = min(
                uses,
                key=lambda item: (
                    item.address not in requested_addresses,
                    item.operation
                    not in {
                        IROperation.ALLOCATE,
                        IROperation.COPY,
                        IROperation.STORE,
                        IROperation.CALL,
                    },
                    item.operation is not IROperation.COMPARE,
                    item.operation is IROperation.UNKNOWN,
                    item.address,
                    item.index,
                ),
            )
            keys.add((best.address, best.index))
    return keys


def _preferred_address_matches(
    matches: Sequence[tuple[str, IRInstruction]],
) -> tuple[tuple[str, IRInstruction], ...]:
    signals = tuple(item for item in matches if _is_signal(item[1]))
    return signals[:2] if signals else tuple(matches[:1])


def _direct_phi_origin_instruction_keys(
    function: IRFunction,
    variables: set[str],
) -> set[tuple[int, int]]:
    by_result: dict[str, list[IRInstruction]] = defaultdict(list)
    for block in function.blocks:
        for instruction in block.instructions:
            if instruction.result is not None:
                by_result[instruction.result].append(instruction)
    keys: set[tuple[int, int]] = set()
    for variable in variables:
        for instruction in by_result.get(variable, ()):
            if instruction.operation is not IROperation.PHI:
                continue
            keys.add((instruction.address, instruction.index))
            for operand in instruction.operands:
                keys.update((item.address, item.index) for item in by_result.get(operand, ()))
    return keys


def _recover_edges(ir: NormalizedBinaryIR) -> tuple[_RawEdge, ...]:
    by_name: dict[str, list[IRFunction]] = defaultdict(list)
    by_address = {item.start_address: item for item in ir.functions}
    for function in ir.functions:
        by_name[function.name].append(function)
        by_name[function.name.lstrip("_")].append(function)
    edges = []
    for caller in ir.functions:
        for block in caller.blocks:
            for instruction in block.instructions:
                if instruction.operation is not IROperation.CALL or not instruction.callee:
                    continue
                callee = _resolve_callee(instruction, by_name, by_address)
                if callee is not None:
                    edges.append(
                        _RawEdge(
                            caller,
                            callee,
                            instruction,
                            dominating_guard_block_ids=_dominating_guard_block_ids(
                                caller,
                                instruction.address,
                            ),
                        )
                    )
    return tuple(
        sorted(
            edges,
            key=lambda item: (
                item.instruction.address,
                item.caller.function_id,
                item.callee.function_id,
            ),
        )
    )


def _recover_virtual_callers(
    callee: IRFunction,
    callers: tuple[IRFunction, ...],
    functions: tuple[IRFunction, ...],
    virtual_methods: tuple[IRVirtualMethodReference, ...],
) -> tuple[_RawEdge, ...]:
    """Recover a bounded selector-compatible dispatch edge from frozen IR.

    Ghidra represents C++ virtual calls as ``CALLIND`` with a register-shaped
    target such as ``0x4040``.  This fallback is intentionally narrower than a
    speculative callgraph: the requested target must have an address-backed
    class-qualified method declaration, the caller must name the selector, and
    the indirect call must have the target method's receiver-plus-argument arity.
    """

    selector = callee.name
    if not _is_declared_selector_method(callee, selector) or not callee.parameters:
        return ()
    candidate_count = sum(
        1
        for item in functions
        if item.name == selector
        and len(item.parameters) == len(callee.parameters)
        and _is_declared_selector_method(item, selector)
    )
    if candidate_count == 0:
        return ()
    target_owner = _declared_method_owner(callee, selector)
    target_vtables = tuple(
        item
        for item in virtual_methods
        if item.target_function_id == callee.function_id and item.owner == target_owner
    )
    expected_arguments = len(callee.parameters) + 1
    edges: list[_RawEdge] = []
    for caller in callers:
        if caller.function_id == callee.function_id or not _caller_names_selector(
            caller,
            selector,
        ):
            continue
        for block in caller.blocks:
            for instruction in block.instructions:
                if not _is_indirect_call(instruction):
                    continue
                if len(instruction.operands) != expected_arguments:
                    continue
                if instruction.operands[0] not in caller.parameters:
                    continue
                slot_offset = _virtual_dispatch_slot_offset(caller, instruction)
                bindings = tuple(
                    item for item in target_vtables if item.slot_offset == slot_offset
                )
                binding = bindings[0] if len(bindings) == 1 else None
                edges.append(
                    _RawEdge(
                        caller=caller,
                        callee=callee,
                        instruction=instruction,
                        resolution=(
                            BinaryCodeContextEdgeResolution.VIRTUAL_VTABLE
                            if binding is not None
                            else BinaryCodeContextEdgeResolution.VIRTUAL_SELECTOR
                        ),
                        selector=selector,
                        dispatch_candidate_count=(1 if binding is not None else candidate_count),
                        receiver_owner=None if binding is None else binding.owner,
                        vtable_symbol=None if binding is None else binding.vtable_symbol,
                        vtable_address=None if binding is None else binding.vtable_address,
                        vtable_address_point=(
                            None if binding is None else binding.address_point
                        ),
                        vtable_slot_offset=None if binding is None else binding.slot_offset,
                        vtable_reference_address=(
                            None if binding is None else binding.reference_address
                        ),
                        dominating_guard_block_ids=_dominating_guard_block_ids(
                            caller,
                            instruction.address,
                        ),
                    )
                )
    return tuple(
        sorted(
            edges,
            key=lambda item: (
                item.instruction.address,
                item.caller.function_id,
                item.callee.function_id,
            ),
        )[:8]
    )


def _is_declared_selector_method(function: IRFunction, selector: str) -> bool:
    return _declared_method_owner(function, selector) is not None


def _declared_method_owner(function: IRFunction, selector: str) -> str | None:
    escaped = re.escape(selector)
    match = re.search(
        rf"\b([A-Za-z_][A-Za-z0-9_:]*)::{escaped}\s*\(",
        function.pseudocode[:1200],
    )
    return None if match is None else match.group(1)


def _virtual_dispatch_slot_offset(
    caller: IRFunction,
    instruction: IRInstruction,
) -> int | None:
    block = next(
        (
            item
            for item in caller.blocks
            if any(
                candidate.address == instruction.address
                and candidate.index == instruction.index
                for candidate in item.instructions
            )
        ),
        None,
    )
    if block is None:
        return None
    preceding = sorted(
        {item.address for item in block.instructions if item.address < instruction.address}
    )
    if not preceding:
        return None
    support_address = preceding[-1]
    candidates = {
        constant
        for item in block.instructions
        if item.address == support_address and item.operation is IROperation.ADD
        for constant in item.constants
        if 0 <= constant <= 64 * 1024 and constant % 8 == 0
    }
    return next(iter(candidates)) if len(candidates) == 1 else None


def _caller_names_selector(function: IRFunction, selector: str) -> bool:
    if re.search(rf"(?<![A-Za-z0-9_]){re.escape(selector)}(?![A-Za-z0-9_])", function.pseudocode):
        return True
    caller_family = _selector_family(function.name)
    selector_family = _selector_family(selector)
    return bool(caller_family and caller_family == selector_family)


def _selector_family(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]", "", value.lower())
    for prefix in ("call", "invoke", "dispatch"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    if normalized.endswith("imp"):
        normalized = normalized[:-3]
    return normalized


def _is_indirect_call(instruction: IRInstruction) -> bool:
    return (
        instruction.operation is IROperation.CALL
        and instruction.callee is not None
        and "CALLIND" in instruction.text.upper()
        and instruction.callee.lower().startswith("0x")
    )


def _dominating_guard_block_ids(function: IRFunction, address: int) -> tuple[str, ...]:
    target = next(
        (
            block
            for block in function.blocks
            if any(instruction.address == address for instruction in block.instructions)
        ),
        None,
    )
    if target is None:
        return ()
    by_id = {item.block_id: item for item in function.blocks}
    entry = function.blocks[0].block_id
    reachable = {entry}
    pending = [entry]
    while pending:
        current = pending.pop()
        for successor in by_id[current].successors:
            if successor not in reachable:
                reachable.add(successor)
                pending.append(successor)
    if target.block_id not in reachable:
        return ()
    predecessors: dict[str, set[str]] = {identifier: set() for identifier in reachable}
    for block in function.blocks:
        if block.block_id not in reachable:
            continue
        for successor in block.successors:
            if successor in reachable:
                predecessors[successor].add(block.block_id)
    dominators = {
        identifier: ({entry} if identifier == entry else set(reachable)) for identifier in reachable
    }
    changed = True
    while changed:
        changed = False
        for identifier in sorted(reachable - {entry}):
            incoming = predecessors[identifier]
            shared = (
                set.intersection(*(dominators[item] for item in incoming)) if incoming else set()
            )
            updated = {identifier, *shared}
            if updated != dominators[identifier]:
                dominators[identifier] = updated
                changed = True
    guards = [
        identifier
        for identifier in dominators[target.block_id] - {target.block_id}
        if any(
            instruction.operation in {IROperation.COMPARE, IROperation.BRANCH}
            for instruction in by_id[identifier].instructions
        )
    ]
    nearest = sorted(
        guards,
        key=lambda identifier: (
            -len(dominators[identifier]),
            -by_id[identifier].start_address,
            identifier,
        ),
    )[:8]
    return tuple(sorted(nearest))


def _guard_addresses_for_blocks(
    function: IRFunction,
    block_ids: tuple[str, ...],
) -> set[int]:
    selected = set(block_ids)
    return {
        instruction.address
        for block in function.blocks
        if block.block_id in selected
        for instruction in block.instructions
        if instruction.operation in {IROperation.COMPARE, IROperation.BRANCH}
    }


def _resolve_callee(
    instruction: IRInstruction,
    by_name: Mapping[str, list[IRFunction]],
    by_address: Mapping[int, IRFunction],
) -> IRFunction | None:
    tagged_addresses = []
    for tag in instruction.tags:
        if not tag.startswith("callee_address:"):
            continue
        try:
            tagged_addresses.append(int(tag.removeprefix("callee_address:"), 16))
        except ValueError:
            return None
    if tagged_addresses:
        if len(set(tagged_addresses)) != 1:
            return None
        return by_address.get(tagged_addresses[0])
    name = instruction.callee or ""
    candidates = {
        item.function_id: item for key in {name, name.lstrip("_")} for item in by_name.get(key, [])
    }
    if len(candidates) == 1:
        return next(iter(candidates.values()))
    lowered = name.lower()
    for prefix in ("fun_", "sub_"):
        if lowered.startswith(prefix):
            try:
                return by_address.get(int(lowered.removeprefix(prefix), 16))
            except ValueError:
                return None
    return None


def _fact(function_id: str, block_id: str, instruction: IRInstruction) -> BinaryEvidenceFact:
    kind = _fact_kind(instruction)
    fact_id = (
        "codefact_"
        + hashlib.sha256(
            f"{function_id}:{instruction.address:x}:{instruction.index}:{kind.value}".encode()
        ).hexdigest()[:20]
    )
    return BinaryEvidenceFact(
        fact_id=fact_id,
        kind=kind,
        function_id=function_id,
        block_id=block_id,
        address=instruction.address,
        instruction_index=instruction.index,
        operation=instruction.operation,
        result=instruction.result,
        operands=instruction.operands,
        callee=instruction.callee,
        detail=(
            f"{kind.value} {instruction.operation.value} evidence at "
            f"0x{instruction.address:x}:{instruction.index}"
        ),
    )


def _fact_kind(instruction: IRInstruction) -> BinaryEvidenceFactKind:
    if _is_input_source(instruction):
        return BinaryEvidenceFactKind.INPUT_SOURCE
    if instruction.operation in _MEMORY_SINKS:
        return BinaryEvidenceFactKind.SECURITY_SINK
    if instruction.operation in {IROperation.COMPARE, IROperation.BRANCH}:
        return BinaryEvidenceFactKind.GUARD
    if instruction.operation is IROperation.CALL:
        return BinaryEvidenceFactKind.CALLSITE
    if instruction.operation is IROperation.RETURN:
        return BinaryEvidenceFactKind.RETURN_USE
    if instruction.operation is IROperation.UNKNOWN:
        return BinaryEvidenceFactKind.UNKNOWN
    return BinaryEvidenceFactKind.DATAFLOW


def _is_input_source(instruction: IRInstruction) -> bool:
    if any(
        tag.startswith("input") or (tag.startswith("source") and not tag.startswith("source_op:"))
        for tag in instruction.tags
    ):
        return True
    return bool(
        instruction.callee
        and any(marker in instruction.callee.lower() for marker in _INPUT_CALLEE_MARKERS)
    )


def _is_signal(instruction: IRInstruction) -> bool:
    return _is_input_source(instruction) or instruction.operation in {
        *_MEMORY_SINKS,
        IROperation.CALL,
        IROperation.COMPARE,
        IROperation.BRANCH,
        IROperation.RETURN,
    }


def _empty_response(
    packet: DecompilerHunterPacket,
    ir: NormalizedBinaryIR,
    request: BinaryCodeContextRequest,
    status: BinaryCodeContextStatus,
    rejection: BinaryCodeContextRejection,
    detail: str,
) -> BinaryCodeContextResponse:
    payload = {
        "schema_version": "binary-code-context-response-v1",
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "capsule_sha256": packet.capsule.capsule_sha256,
        "ir_sha256": ir.ir_sha256,
        "request": request.model_dump(mode="json"),
        "request_sha256": _digest(request.model_dump(mode="json")),
        "status": status.value,
        "rejection": rejection.value,
        "detail": detail,
        "functions": (),
        "call_edges": (),
        "facts": (),
        "omissions": (),
        "evidence_bytes": _context_evidence_bytes((), (), (), ()),
    }
    return BinaryCodeContextResponse(**payload, response_sha256=_digest(payload))


def _make_continuation_packet(
    *,
    packet: DecompilerHunterPacket,
    prior_assessment: DecompilerHunterAssessment,
    responses: tuple[BinaryCodeContextResponse, ...],
    ordinal: int,
    previous: str,
) -> DecompilerContinuationPacket:
    payload = {
        "schema_version": "decompiler-continuation-packet-v1",
        "prompt_version": DECOMPILER_CONTEXT_PROMPT_VERSION,
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "admission_rank": packet.admission_rank,
        "capsule_sha256": packet.capsule.capsule_sha256,
        "ir_sha256": packet.capsule.ir_sha256,
        "continuation_ordinal": ordinal,
        "previous_chain_sha256": previous,
        "base_packet": packet.model_dump(mode="json"),
        "prior_assessment": prior_assessment.model_dump(mode="json"),
        "context_responses": tuple(item.model_dump(mode="json") for item in responses),
        "total_evidence_bytes": packet.capsule.evidence_bytes
        + sum(item.evidence_bytes for item in responses),
    }
    return DecompilerContinuationPacket(**payload, packet_sha256=_digest(payload))


def _make_entry(
    *,
    packet: DecompilerHunterPacket,
    ordinal: int,
    previous: str,
    response: BinaryCodeContextResponse,
    assessment: DecompilerHunterAssessment | None = None,
    usage: BudgetUsage | None = None,
    raw: tuple[str, ...] = (),
) -> DecompilerContextChainEntry:
    payload = {
        "schema_version": "decompiler-context-chain-entry-v1",
        "work_id": packet.work_id,
        "root_id": packet.root_id,
        "ordinal": ordinal,
        "previous_chain_sha256": previous,
        "request_sha256": response.request_sha256,
        "response": response.model_dump(mode="json"),
        "assessment": assessment.model_dump(mode="json") if assessment else None,
        "usage": usage.model_dump(mode="json") if usage else None,
        "raw_response_sha256": _digest("".join(raw)) if raw else None,
    }
    return DecompilerContextChainEntry(**payload, chain_sha256=_digest(payload))


def _make_result(
    packet: DecompilerHunterPacket,
    initial: DecompilerHunterAssessment,
    initial_usage: BudgetUsage,
    entries: tuple[DecompilerContextChainEntry, ...],
    terminal: DecompilerHunterAssessment,
    status: DecompilerContextTerminalStatus,
) -> DecompilerContextRunResult:
    continuation_usage = tuple(item.usage for item in entries if item.usage is not None)
    return DecompilerContextRunResult(
        work_id=packet.work_id,
        root_id=packet.root_id,
        initial_assessment_sha256=_digest(initial.model_dump(mode="json")),
        terminal_status=status,
        terminal_assessment=terminal,
        entries=entries,
        total_evidence_bytes=packet.capsule.evidence_bytes
        + sum(item.response.evidence_bytes for item in entries),
        sessions=1,
        model_calls=initial_usage.calls + sum(item.calls for item in continuation_usage),
        input_tokens=initial_usage.input_tokens
        + sum(item.input_tokens for item in continuation_usage),
        output_tokens=initial_usage.output_tokens
        + sum(item.output_tokens for item in continuation_usage),
        chain_sha256=(
            entries[-1].chain_sha256 if entries else _digest(initial.model_dump(mode="json"))
        ),
    )


def _validate_frozen_bindings(ir: NormalizedBinaryIR, packet: DecompilerHunterPacket) -> None:
    if (
        ir.ir_sha256 != packet.capsule.ir_sha256
        or ir.snapshot_sha256 != packet.capsule.snapshot_sha256
    ):
        raise ValueError("context broker IR differs from the packet-bound frozen image")
    if tuple(sorted(item.function_id for item in ir.functions)) != packet.frozen_function_ids:
        raise ValueError("context broker function census differs from the Hunter packet")


def _validate_initial_identity(
    packet: DecompilerHunterPacket,
    assessment: DecompilerHunterAssessment,
    usage: BudgetUsage,
) -> None:
    if (
        assessment.work_id != packet.work_id
        or assessment.root_id != packet.root_id
        or assessment.capsule_sha256 != packet.capsule.capsule_sha256
        or usage.work_id != packet.work_id
        or usage.sessions != 1
    ):
        raise ValueError("initial assessment/usage changed the originating Hunter session")


def _request_fingerprint(request: BinaryCodeContextRequest) -> tuple[object, ...]:
    return (
        request.kind.value,
        request.function_id,
        request.related_function_id,
        request.block_id,
        request.address,
        request.variable,
    )


def _is_circular(
    request: BinaryCodeContextRequest,
    prior_entries: Sequence[DecompilerContextChainEntry],
) -> bool:
    inverse = {
        BinaryCodeContextRequestKind.DIRECT_CALLER: BinaryCodeContextRequestKind.DIRECT_CALLEE,
        BinaryCodeContextRequestKind.DIRECT_CALLEE: BinaryCodeContextRequestKind.DIRECT_CALLER,
    }
    expected = inverse.get(request.kind)
    if expected is None or request.related_function_id is None:
        return False
    return any(
        prior.response.request.kind is expected
        and prior.response.request.function_id == request.related_function_id
        and prior.response.request.related_function_id == request.function_id
        for prior in prior_entries
    )


def _unique_functions(values: Sequence[IRFunction]) -> tuple[IRFunction, ...]:
    return tuple({item.function_id: item for item in values}.values())


def _base_has_variable(packet: DecompilerHunterPacket, variable: str) -> bool:
    return any(
        variable in (instruction.result, *instruction.operands)
        for function in packet.capsule.functions
        for block in function.blocks
        for instruction in block.instructions
    )


def _bounded_text(value: str, maximum: int) -> tuple[str, bool]:
    encoded = value.encode()
    if len(encoded) <= maximum:
        return value, False
    return encoded[:maximum].decode(errors="ignore").strip(), True


def _context_evidence_bytes(
    functions: Sequence[BinaryCodeContextFunctionSlice],
    edges: Sequence[BinaryCodeContextEdge],
    facts: Sequence[BinaryEvidenceFact],
    omissions: Sequence[str],
) -> int:
    if not functions and not edges and not facts and not omissions:
        return 0
    return len(
        _canonical_json(
            {
                "functions": [item.model_dump(mode="json") for item in functions],
                "call_edges": [item.model_dump(mode="json") for item in edges],
                "facts": [item.model_dump(mode="json") for item in facts],
                "omissions": list(omissions),
            }
        )
    )


def _context_directory(store_root: Path, work_id: str) -> Path:
    root = store_root.expanduser().resolve(strict=True)
    if not root.is_dir() or any((item / ".git").exists() for item in (root, *root.parents)):
        raise ValueError("context store must be a private directory outside Git")
    return root / "hunters" / work_id / "decompiler-analysis" / "code-context"


def _load_entries(
    directory: Path,
    packet: DecompilerHunterPacket,
    initial_sha: str,
) -> tuple[DecompilerContextChainEntry, ...]:
    if not directory.exists():
        return ()
    entries: list[DecompilerContextChainEntry] = []
    for path in sorted(directory.glob("entry-*.json")):
        entry = DecompilerContextChainEntry.model_validate_json(_read_file(path))
        if entry.work_id != packet.work_id or entry.root_id != packet.root_id:
            raise RuntimeError("persisted context entry belongs to another root session")
        expected = initial_sha if not entries else entries[-1].chain_sha256
        if entry.ordinal != len(entries) + 1 or entry.previous_chain_sha256 != expected:
            raise RuntimeError("persisted context chain is non-contiguous or stale")
        entries.append(entry)
    return tuple(entries)


def _persist_entry(
    directory: Path,
    entry: DecompilerContextChainEntry,
    raw: tuple[str, ...],
) -> None:
    _write_private_json(
        directory / f"entry-{entry.ordinal:02d}.json", entry.model_dump(mode="json")
    )
    for index, response in enumerate(raw, start=1):
        _write_private_bytes(
            directory / f"entry-{entry.ordinal:02d}-raw-{index:02d}.txt",
            response.encode()[:_MAX_RAW_RESPONSE_BYTES],
        )


def _read_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_PACKET_BYTES:
        raise RuntimeError(f"unsafe or oversized context artifact: {path}")
    return path.read_bytes()


def _write_private_json(path: Path, payload: object) -> None:
    _write_private_bytes(path, json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n")


def _write_private_bytes(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise RuntimeError("context artifact may not be a symbolic link")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    if path.exists():
        if not path.is_file() or path.read_bytes() != payload:
            raise FileExistsError("immutable context artifact already contains other data")
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


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(payload: object) -> str:
    if isinstance(payload, str):
        encoded = payload.encode()
    else:
        encoded = _canonical_json(payload)
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
