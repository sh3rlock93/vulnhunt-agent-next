"""Decompiler-native, static-only Hunter sessions for M17.

This module intentionally does not extend the M14 Binary Hunter contract.  It
accepts address-backed evidence capsules and can form a hypothesis without a
deterministic static finding.  All follow-up work is a typed request for data
already present in the frozen normalized IR; no target execution is possible.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol, cast

from pydantic import Field, model_validator

from ...agents.durable_queue import DurableHuntQueueStore
from ...core.jsonx import try_extract_object
from ...core.llm import LLMResponse
from ...domain.schemas import (
    BudgetPolicy,
    BudgetUsage,
    DomainModel,
    HunterRoutingPlan,
    HunterWorkItem,
    ProviderPreflightResult,
    SHA256_PATTERN,
)
from ...infrastructure.sqlite_repository import SqliteRepository
from ...scheduling.budget import BudgetController, BudgetedLLMClient, BudgetExceededError
from ...scheduling.metrics import with_estimated_cost
from ...scheduling.shadow import work_id_for
from .capsules import (
    BinaryEvidenceCapsule,
    BinaryEvidenceCapsuleSet,
    BinaryEvidenceFact,
    BinaryEvidenceFactKind,
    CapsuleProofStatus,
)
from .hunter import BinaryResearchScope
from .ir import NormalizedBinaryIR

DECOMPILER_HUNTER = "decompiler-imageio-analysis"
DECOMPILER_HUNTER_PLANNING_POLICY: Literal["decompiler-hunter-planning-v1"] = (
    "decompiler-hunter-planning-v1"
)
DECOMPILER_HUNTER_PROMPT_VERSION: Literal["decompiler-imageio-hunter-v2"] = (
    "decompiler-imageio-hunter-v2"
)
_MAX_PACKET_BYTES = 512 * 1024
_MAX_RAW_RESPONSE_BYTES = 128 * 1024

_PROHIBITED_OUTPUT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("code fence", re.compile(r"```")),
    ("network URL", re.compile(r"(?i)\b(?:https?|ftp)://")),
    (
        "shell command",
        re.compile(
            r"(?im)(?:^|\n)\s*(?:\$\s*)?(?:bash|zsh|sh|curl|wget|nc|ncat|"
            r"ssh|scp|socat|osascript|launchctl|python(?:3)?\s+-c)\b"
        ),
    ),
    ("executable path", re.compile(r"(?i)/(?:bin|sbin|usr/bin|usr/sbin)/[A-Za-z0-9_.-]+")),
    (
        "dynamic activity",
        re.compile(
            r"(?i)\b(?:run (?:the )?(?:image|sample|target)|execute (?:the )?"
            r"(?:image|sample|target)|start (?:a )?(?:fuzzer|vm)|fuzz(?:ing)?|"
            r"generate (?:an )?(?:image|input)|dynamic experiment)\b"
        ),
    ),
    (
        "exploit content",
        re.compile(
            r"(?i)\b(?:exploit code|weaponiz(?:e|ation)|reverse\s+shell|shellcode|"
            r"rop\s+chain|persistence\s+mechanism)\b"
        ),
    ),
)

DECOMPILER_HUNTER_SYSTEM_PROMPT = """You are the Decompiler ImageIO Hunter in an
authorized, defensive, read-only static-analysis workflow. Inspect only the
supplied digest-bound pseudocode, normalized p-code, CFG, call edges, and facts.
Decompiler output is lossy and is not Apple's original source. Do not run or
generate an input, invoke a tool, access a file or network, propose fuzzing or a
VM experiment, write exploit material, or claim that a vulnerability is
confirmed.

A code_hypothesis does not need a deterministic finding ID. It must instead
cite an input_source, an address-backed data/call path, every applicable guard,
and a security_sink from the packet. State the exact invariant, integer width
and signedness uncertainty, feasible call/CFG path, contradictions, impact
boundary, confidence, and a condition that would falsify the claim. If the
capsule is proof_incomplete, request one typed frozen-IR context slice instead
of treating omitted code as a missing guard. A not_vulnerable conclusion must
cite a guard or safe failure/return-use path.

When a hypothesis depends on whether a range-reader writes or clamps its
requested length, do not infer that callee's behavior from its name. Request
direct_callee using the caller and exact address-backed related function IDs
from the supplied call edge when that implementation is omitted.

Return only one JSON object matching the packet's response contract. Preserve
work_id, root_id, capsule_sha256, and admission_rank exactly. Use only IDs and
addresses supplied by the packet. Every evidence-ID array must be
lexicographically sorted and duplicate-free; call-path functions and CFG-path
addresses instead preserve feasible execution order. Permitted dispositions
are code_hypothesis, needs_code_context, not_vulnerable, inconclusive, and
scope_blocked."""


class DecompilerHunterDisposition(StrEnum):
    CODE_HYPOTHESIS = "code_hypothesis"
    NEEDS_CODE_CONTEXT = "needs_code_context"
    NOT_VULNERABLE = "not_vulnerable"
    INCONCLUSIVE = "inconclusive"
    SCOPE_BLOCKED = "scope_blocked"


class DecompilerVulnerabilityClass(StrEnum):
    INTEGER_OVERFLOW = "integer_overflow"
    OUT_OF_BOUNDS_READ = "out_of_bounds_read"
    OUT_OF_BOUNDS_WRITE = "out_of_bounds_write"
    BUFFER_OVERFLOW = "buffer_overflow"
    ALLOCATION_SIZE_MISMATCH = "allocation_size_mismatch"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    UNINITIALIZED_READ = "uninitialized_read"
    TYPE_CONFUSION = "type_confusion"
    STATE_CONFUSION = "state_confusion"
    INFORMATION_DISCLOSURE = "information_disclosure"
    OTHER_MEMORY_SAFETY = "other_memory_safety"


class BinaryCodeContextRequestKind(StrEnum):
    EXACT_FUNCTION = "exact_function"
    DIRECT_CALLER = "direct_caller"
    DIRECT_CALLEE = "direct_callee"
    BASIC_BLOCK_NEIGHBORHOOD = "basic_block_neighborhood"
    DEFINITION_USE_CHAIN = "definition_use_chain"
    CALLSITE_RETURN_USE = "callsite_return_use"


class BinaryCodeContextRequest(DomainModel):
    request_id: str = Field(pattern=r"^codectx-[a-z0-9][a-z0-9-]{2,80}$")
    kind: BinaryCodeContextRequestKind
    rationale: str = Field(min_length=1, max_length=2000)
    function_id: str | None = Field(default=None, pattern=r"^fn_[0-9a-f]{20}$")
    related_function_id: str | None = Field(
        default=None,
        pattern=r"^fn_[0-9a-f]{20}$",
    )
    block_id: str | None = Field(default=None, pattern=r"^bb_[0-9a-f]{16}$")
    address: int | None = Field(default=None, ge=0)
    variable: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:$@-]{1,160}$")
    supporting_addresses: tuple[int, ...] = Field(default=(), max_length=8)
    supporting_variables: tuple[str, ...] = Field(default=(), max_length=4)
    supporting_field_offsets: tuple[int, ...] = Field(default=(), max_length=8)
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=16)
    maximum_bytes: int = Field(default=32 * 1024, ge=1024, le=96 * 1024)

    @model_validator(mode="after")
    def validate_shape(self) -> "BinaryCodeContextRequest":
        _require_sorted_unique(self.evidence_ids, "context-request evidence IDs")
        if tuple(sorted(set(self.supporting_addresses))) != self.supporting_addresses:
            raise ValueError("supporting addresses must be sorted and unique")
        if any(address < 0 for address in self.supporting_addresses):
            raise ValueError("supporting addresses cannot be negative")
        if tuple(sorted(set(self.supporting_variables))) != self.supporting_variables:
            raise ValueError("supporting variables must be sorted and unique")
        if any(
            re.fullmatch(r"[A-Za-z0-9_.:$@-]{1,160}", variable) is None
            for variable in self.supporting_variables
        ):
            raise ValueError("supporting variables must be normalized IR identifiers")
        if tuple(sorted(set(self.supporting_field_offsets))) != self.supporting_field_offsets:
            raise ValueError("supporting field offsets must be sorted and unique")
        if any(offset <= 0 or offset > 0x10000 for offset in self.supporting_field_offsets):
            raise ValueError("supporting field offsets must be bounded positive object offsets")
        if self.kind is BinaryCodeContextRequestKind.EXACT_FUNCTION:
            if self.function_id is None:
                raise ValueError("exact-function request requires a function ID")
        elif self.kind in {
            BinaryCodeContextRequestKind.DIRECT_CALLER,
            BinaryCodeContextRequestKind.DIRECT_CALLEE,
        }:
            if self.function_id is None:
                raise ValueError("caller/callee request requires a base function ID")
        elif self.kind is BinaryCodeContextRequestKind.BASIC_BLOCK_NEIGHBORHOOD:
            if self.function_id is None or self.block_id is None:
                raise ValueError("block-neighborhood request requires function and block IDs")
        elif self.kind is BinaryCodeContextRequestKind.DEFINITION_USE_CHAIN:
            if self.function_id is None or self.variable is None:
                raise ValueError("definition/use request requires function ID and variable")
        elif self.kind is BinaryCodeContextRequestKind.CALLSITE_RETURN_USE:
            if self.function_id is None or self.address is None:
                raise ValueError("callsite return-use request requires function ID and address")
        if self.kind is not BinaryCodeContextRequestKind.DEFINITION_USE_CHAIN and (
            self.supporting_addresses or self.supporting_variables or self.supporting_field_offsets
        ):
            raise ValueError("supporting proof anchors require a definition/use request")
        return self


class DecompilerHunterHypothesis(DomainModel):
    hypothesis_id: str = Field(pattern=r"^codehypothesis-[a-z0-9][a-z0-9-]{2,80}$")
    title: str = Field(min_length=1, max_length=300)
    vulnerability_class: DecompilerVulnerabilityClass
    parser_reachability: str = Field(min_length=1, max_length=2000)
    attacker_control: str = Field(min_length=1, max_length=2000)
    width_signedness: str = Field(min_length=1, max_length=2000)
    call_path_function_ids: tuple[str, ...] = Field(min_length=1, max_length=16)
    cfg_path_addresses: tuple[int, ...] = Field(min_length=2, max_length=64)
    guard_analysis: str = Field(min_length=1, max_length=3000)
    no_applicable_guard: bool = False
    security_relation: str = Field(min_length=1, max_length=3000)
    impact: str = Field(min_length=1, max_length=2000)
    contradicting_evidence: str = Field(min_length=1, max_length=3000)
    decompiler_uncertainty: str = Field(min_length=1, max_length=3000)
    confidence: float = Field(ge=0.0, le=1.0)
    falsification_condition: str = Field(min_length=1, max_length=2000)
    source_evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=16)
    path_evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    guard_evidence_ids: tuple[str, ...] = Field(default=(), max_length=32)
    sink_evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=16)
    contradicting_evidence_ids: tuple[str, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def validate_citation_order(self) -> "DecompilerHunterHypothesis":
        for label, values in (
            ("source evidence IDs", self.source_evidence_ids),
            ("path evidence IDs", self.path_evidence_ids),
            ("guard evidence IDs", self.guard_evidence_ids),
            ("sink evidence IDs", self.sink_evidence_ids),
            ("contradicting evidence IDs", self.contradicting_evidence_ids),
        ):
            _require_sorted_unique(values, label)
        if self.no_applicable_guard == bool(self.guard_evidence_ids):
            raise ValueError(
                "hypothesis must either cite applicable guards or explicitly state none apply"
            )
        return self


class DecompilerHunterAssessment(DomainModel):
    schema_version: Literal["decompiler-hunter-assessment-v1"] = "decompiler-hunter-assessment-v1"
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    root_id: str = Field(pattern=r"^coderoot_[0-9a-f]{20}$")
    capsule_sha256: str = Field(pattern=SHA256_PATTERN)
    admission_rank: int = Field(ge=1, le=100000)
    disposition: DecompilerHunterDisposition
    summary: str = Field(min_length=1, max_length=4000)
    hypotheses: tuple[DecompilerHunterHypothesis, ...] = Field(default=(), max_length=4)
    context_requests: tuple[BinaryCodeContextRequest, ...] = Field(default=(), max_length=4)
    safe_path_analysis: str = Field(default="", max_length=3000)
    safe_path_evidence_ids: tuple[str, ...] = Field(default=(), max_length=32)
    evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    unresolved_questions: tuple[str, ...] = Field(default=(), max_length=12)

    @model_validator(mode="after")
    def validate_disposition(self) -> "DecompilerHunterAssessment":
        _require_sorted_unique(self.safe_path_evidence_ids, "safe-path evidence IDs")
        _require_sorted_unique(self.evidence_ids, "assessment evidence IDs")
        hypothesis_ids = tuple(item.hypothesis_id for item in self.hypotheses)
        if len(set(hypothesis_ids)) != len(hypothesis_ids):
            raise ValueError("assessment contains duplicate hypothesis IDs")
        request_ids = tuple(item.request_id for item in self.context_requests)
        if len(set(request_ids)) != len(request_ids):
            raise ValueError("assessment contains duplicate context-request IDs")
        if self.disposition is DecompilerHunterDisposition.CODE_HYPOTHESIS:
            if not self.hypotheses or self.context_requests:
                raise ValueError("code_hypothesis requires hypotheses and no context request")
        elif self.disposition is DecompilerHunterDisposition.NEEDS_CODE_CONTEXT:
            if not self.context_requests:
                raise ValueError("needs_code_context requires a typed context request")
        elif self.hypotheses or self.context_requests:
            raise ValueError("terminal disposition may not retain hypotheses or requests")
        if self.disposition is DecompilerHunterDisposition.NOT_VULNERABLE:
            if not self.safe_path_analysis or not self.safe_path_evidence_ids:
                raise ValueError("not_vulnerable requires cited safe-path analysis")
        return self


class DecompilerHunterPolicy(DomainModel):
    maximum_root_sessions: int = Field(default=16, ge=1, le=16)
    maximum_attempts_per_root: int = Field(default=2, ge=1, le=2)
    maximum_output_tokens_per_call: int = Field(default=8000, ge=512, le=32000)


class DecompilerHunterPacket(DomainModel):
    schema_version: Literal["decompiler-hunter-packet-v1"] = "decompiler-hunter-packet-v1"
    prompt_version: Literal[
        "decompiler-imageio-hunter-v1",
        "decompiler-imageio-hunter-v2",
    ] = DECOMPILER_HUNTER_PROMPT_VERSION
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    root_id: str = Field(pattern=r"^coderoot_[0-9a-f]{20}$")
    admission_rank: int = Field(ge=1, le=100000)
    capsule_set_sha256: str = Field(pattern=SHA256_PATTERN)
    scope: BinaryResearchScope
    capsule: BinaryEvidenceCapsule
    frozen_function_ids: tuple[str, ...] = Field(min_length=1, max_length=100000)
    known_function_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    known_block_ids: tuple[str, ...] = Field(min_length=1, max_length=65536)
    known_addresses: tuple[int, ...] = Field(min_length=1, max_length=100000)
    allowed_evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=10000)
    allowed_context_kinds: tuple[BinaryCodeContextRequestKind, ...]
    image_execution_allowed: Literal[False] = False
    input_generation_allowed: Literal[False] = False
    fuzzer_allowed: Literal[False] = False
    vm_allowed: Literal[False] = False
    network_allowed: Literal[False] = False
    shell_allowed: Literal[False] = False
    exploit_output_allowed: Literal[False] = False
    packet_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_packet(self) -> "DecompilerHunterPacket":
        if self.root_id != self.capsule.root_id:
            raise ValueError("Hunter packet root differs from its evidence capsule")
        if self.admission_rank != self.capsule.admission_rank:
            raise ValueError("Hunter packet changed the admission rank")
        if self.scope.snapshot_sha256 != self.capsule.snapshot_sha256:
            raise ValueError("Hunter scope and capsule snapshots differ")
        if self.known_function_ids != tuple(item.function_id for item in self.capsule.functions):
            raise ValueError("known function IDs differ from the capsule")
        expected_blocks = tuple(
            sorted(
                {block.block_id for function in self.capsule.functions for block in function.blocks}
            )
        )
        if self.known_block_ids != expected_blocks:
            raise ValueError("known block IDs differ from the capsule")
        expected_addresses = tuple(
            sorted(
                {
                    instruction.address
                    for function in self.capsule.functions
                    for block in function.blocks
                    for instruction in block.instructions
                }
            )
        )
        if self.known_addresses != expected_addresses:
            raise ValueError("known addresses differ from the capsule")
        expected_facts = tuple(sorted(item.fact_id for item in self.capsule.facts))
        if self.allowed_evidence_ids != expected_facts:
            raise ValueError("allowed evidence IDs differ from capsule facts")
        _require_sorted_unique(self.frozen_function_ids, "frozen function IDs")
        if not set(self.known_function_ids).issubset(self.frozen_function_ids):
            raise ValueError("capsule function lies outside the frozen IR")
        if self.allowed_context_kinds != tuple(BinaryCodeContextRequestKind):
            raise ValueError("packet context allow-list is incomplete or reordered")
        expected = _digest(self.model_dump(mode="json", exclude={"packet_sha256"}))
        if self.packet_sha256 != expected:
            raise ValueError("Hunter packet digest does not match its evidence")
        if len(_canonical_json(self.model_dump(mode="json"))) > _MAX_PACKET_BYTES:
            raise ValueError("Hunter packet exceeds its byte limit")
        return self


class DecompilerHunterPlan(DomainModel):
    schema_version: Literal["decompiler-hunter-plan-v1"] = "decompiler-hunter-plan-v1"
    run_id: str = Field(min_length=1, max_length=200)
    scope: BinaryResearchScope
    capsule_set_sha256: str = Field(pattern=SHA256_PATTERN)
    policy: DecompilerHunterPolicy
    provider_preflight: ProviderPreflightResult
    routing: HunterRoutingPlan
    admitted_work_ids: tuple[str, ...] = Field(max_length=16)
    deferred_work_ids: tuple[str, ...] = Field(max_length=1024)
    plan_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_plan(self) -> "DecompilerHunterPlan":
        work_ids = tuple(item.work_id for item in self.routing.work_items)
        if self.admitted_work_ids + self.deferred_work_ids != work_ids:
            raise ValueError("Decompiler Hunter plan must preserve one routing prefix")
        if len(self.admitted_work_ids) > self.policy.maximum_root_sessions:
            raise ValueError("Decompiler Hunter plan exceeds its root-session limit")
        if self.routing.scan_scope_digest != self.capsule_set_sha256:
            raise ValueError("Decompiler Hunter routing changed the capsule set")
        if not self.provider_preflight.ready:
            raise ValueError("Decompiler Hunter plan requires a ready provider preflight")
        if self.provider_preflight.billable_model_calls:
            raise ValueError("Decompiler Hunter planning preflight must be non-billable")
        expected = _plan_digest(self)
        if self.plan_sha256 != expected:
            raise ValueError("Decompiler Hunter plan digest does not match its work")
        return self

    @property
    def admitted_work_items(self) -> tuple[HunterWorkItem, ...]:
        admitted = set(self.admitted_work_ids)
        return tuple(item for item in self.routing.work_items if item.work_id in admitted)


class DecompilerHunterModelClient(Protocol):
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
class DecompilerHunterRun:
    packet: DecompilerHunterPacket
    assessment: DecompilerHunterAssessment
    usage: BudgetUsage
    raw_responses: tuple[str, ...]


class DecompilerHunterDeferred(RuntimeError):
    def __init__(
        self,
        reason: str,
        *,
        raw_responses: Sequence[str] = (),
        usage: BudgetUsage | None = None,
    ) -> None:
        self.reason = reason
        self.raw_responses = tuple(raw_responses)
        self.usage = usage
        super().__init__(f"Decompiler Hunter deferred: {reason}")


@dataclass
class DecompilerHunterAgent:
    client: DecompilerHunterModelClient
    maximum_attempts: int = 2
    maximum_output_tokens: int = 8000

    def __post_init__(self) -> None:
        if self.maximum_attempts < 1 or self.maximum_attempts > 2:
            raise ValueError("Decompiler Hunter permits at most one schema-repair call")
        if self.maximum_output_tokens < 512 or self.maximum_output_tokens > 32000:
            raise ValueError("Decompiler Hunter output-token limit is outside policy")

    async def analyze(
        self,
        work_item: HunterWorkItem,
        packet: DecompilerHunterPacket,
    ) -> tuple[DecompilerHunterAssessment, BudgetUsage, tuple[str, ...]]:
        _validate_work_item_packet(work_item, packet)
        messages: list[dict] = [
            {
                "role": "user",
                "content": [
                    {
                        "text": (
                            "# Decompiler evidence packet\n"
                            + json.dumps(packet.model_dump(mode="json"), indent=2)
                            + "\n\n# Required response JSON Schema\n"
                            + json.dumps(DecompilerHunterAssessment.model_json_schema(), indent=2)
                        )
                    }
                ],
            }
        ]
        totals = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
        }
        calls = 0
        raw_responses: list[str] = []
        for _ in range(self.maximum_attempts):
            try:
                response = await self.client.chat(
                    messages=messages,
                    system=DECOMPILER_HUNTER_SYSTEM_PROMPT,
                    max_tokens=self.maximum_output_tokens,
                    cache_system=True,
                )
            except BudgetExceededError as exc:
                usage = _budget_usage(work_item, self.client, calls, totals) if calls else None
                raise DecompilerHunterDeferred(
                    f"budget:{exc.reason}",
                    raw_responses=raw_responses,
                    usage=usage,
                ) from exc
            calls += 1
            for field in totals:
                totals[field] += int(getattr(response, field))
            raw_responses.append(response.text[:_MAX_RAW_RESPONSE_BYTES])
            parsed = try_extract_object(response.text)
            try:
                if parsed is not None:
                    assessment = DecompilerHunterAssessment.model_validate(parsed)
                    validate_decompiler_hunter_assessment(packet, assessment)
                    return (
                        assessment,
                        _budget_usage(work_item, self.client, calls, totals),
                        tuple(raw_responses),
                    )
            except ValueError:
                pass
            messages.extend(
                (
                    {"role": "assistant", "content": response.content_blocks},
                    {
                        "role": "user",
                        "content": [
                            {
                                "text": (
                                    "Return only schema-valid JSON. Preserve work_id, root_id, "
                                    "capsule_sha256, and admission_rank. Cite only packet fact IDs, "
                                    "functions, blocks, and addresses. Sort every evidence-ID array "
                                    "lexicographically and remove duplicates; preserve call-path and "
                                    "CFG-path execution order. Do not request execution, fuzzing, a VM, "
                                    "files, URLs, commands, generated inputs, or exploits."
                                )
                            }
                        ],
                    },
                )
            )
        raise DecompilerHunterDeferred(
            "invalid_model_response",
            raw_responses=raw_responses,
            usage=_budget_usage(work_item, self.client, calls, totals),
        )


def build_decompiler_hunter_plan(
    *,
    store_root: Path,
    run_id: str,
    ir: NormalizedBinaryIR,
    capsule_set: BinaryEvidenceCapsuleSet,
    scope: BinaryResearchScope,
    budget: BudgetPolicy,
    provider_preflight: ProviderPreflightResult,
    policy: DecompilerHunterPolicy | None = None,
) -> DecompilerHunterPlan:
    """Persist one immutable code packet per capsule and admit one strict prefix."""

    NormalizedBinaryIR.model_validate(ir.model_dump(mode="json"))
    BinaryEvidenceCapsuleSet.model_validate(capsule_set.model_dump(mode="json"))
    BinaryResearchScope.model_validate(scope.model_dump(mode="json"))
    active_policy = policy or DecompilerHunterPolicy()
    if ir.ir_sha256 != capsule_set.ir_sha256:
        raise ValueError("capsules are bound to a different normalized IR")
    if scope.snapshot_sha256 != capsule_set.snapshot_sha256:
        raise ValueError("research scope is bound to a different snapshot")
    if not provider_preflight.ready or provider_preflight.billable_model_calls:
        raise ValueError("planning requires a ready, non-billable provider preflight")
    store = _private_store_root(store_root)
    packet_root = (
        store
        / "decompiler-hunter-context"
        / (capsule_set.capsule_set_sha256.removeprefix("sha256:")[:24])
    )
    frozen_function_ids = tuple(sorted(item.function_id for item in ir.functions))
    work_items: list[HunterWorkItem] = []
    for capsule in capsule_set.capsules:
        relative = (packet_root / capsule.root_id / "packet.json").relative_to(store).as_posix()
        files = (relative,)
        work_id = work_id_for(
            source_snapshot=capsule_set.snapshot_sha256,
            planning_policy=DECOMPILER_HUNTER_PLANNING_POLICY,
            slice_ids=(capsule.root_id, capsule.capsule_sha256),
            files=files,
            hunter=DECOMPILER_HUNTER,
            scan_scope_digest=capsule_set.capsule_set_sha256,
        )
        packet = _make_packet(
            work_id=work_id,
            capsule_set_sha256=capsule_set.capsule_set_sha256,
            scope=scope,
            capsule=capsule,
            frozen_function_ids=frozen_function_ids,
        )
        _write_private_json(store / relative, packet.model_dump(mode="json"))
        fact_kinds = {item.kind for item in capsule.facts}
        risk = (
            4
            if {
                BinaryEvidenceFactKind.INPUT_SOURCE,
                BinaryEvidenceFactKind.SECURITY_SINK,
            }.issubset(fact_kinds)
            else 2
        )
        work_items.append(
            HunterWorkItem(
                work_id=work_id,
                run_id=run_id,
                source_snapshot=capsule_set.snapshot_sha256,
                scan_scope_digest=capsule_set.capsule_set_sha256,
                planning_policy=DECOMPILER_HUNTER_PLANNING_POLICY,
                slice_ids=(capsule.root_id, capsule.capsule_sha256),
                target_node_ids=(capsule.root_function_id,),
                target_signal_ids=tuple(sorted(item.fact_id for item in capsule.facts))[:6],
                seed_file=relative,
                files=files,
                hunter=DECOMPILER_HUNTER,
                risk=risk,
                required=risk >= 4,
                routing_reasons=(
                    "static:decompiler-evidence-capsule",
                    f"admission_rank:{capsule.admission_rank}",
                    f"proof_status:{capsule.proof_status.value}",
                ),
            )
        )
    routing = HunterRoutingPlan(
        policy_version=DECOMPILER_HUNTER_PLANNING_POLICY,
        mode="signal",
        legacy_sessions=len(work_items),
        work_items=tuple(work_items),
        scan_scope_digest=capsule_set.capsule_set_sha256,
    )
    admitted_count = min(
        len(work_items),
        active_policy.maximum_root_sessions,
        budget.max_hunter_sessions,
    )
    admitted = tuple(item.work_id for item in work_items[:admitted_count])
    deferred = tuple(item.work_id for item in work_items[admitted_count:])
    payload = {
        "schema_version": "decompiler-hunter-plan-v1",
        "run_id": run_id,
        "scope": scope.model_dump(mode="json"),
        "capsule_set_sha256": capsule_set.capsule_set_sha256,
        "policy": active_policy.model_dump(mode="json"),
        "provider_preflight": provider_preflight.model_dump(mode="json"),
        "routing": routing.model_dump(mode="json"),
        "admitted_work_ids": admitted,
        "deferred_work_ids": deferred,
    }
    plan = DecompilerHunterPlan(**payload, plan_sha256=_digest(payload))
    _write_private_json(
        store
        / "decompiler-hunter-plans"
        / f"plan-{plan.plan_sha256.removeprefix('sha256:')[:24]}.json",
        plan.model_dump(mode="json"),
    )
    return plan


def load_decompiler_hunter_packet(
    *,
    store_root: Path,
    work_item: HunterWorkItem,
) -> DecompilerHunterPacket:
    store = _private_store_root(store_root)
    path = _contained_file(store, work_item.seed_file)
    packet = DecompilerHunterPacket.model_validate_json(_read_file(path, maximum=_MAX_PACKET_BYTES))
    _validate_work_item_packet(work_item, packet)
    return packet


def validate_decompiler_hunter_assessment(
    packet: DecompilerHunterPacket,
    assessment: DecompilerHunterAssessment,
) -> None:
    if (
        assessment.work_id != packet.work_id
        or assessment.root_id != packet.root_id
        or assessment.capsule_sha256 != packet.capsule.capsule_sha256
        or assessment.admission_rank != packet.admission_rank
    ):
        raise ValueError("Decompiler Hunter assessment changed packet identity")
    facts = {item.fact_id: item for item in packet.capsule.facts}
    cited = set(assessment.evidence_ids) | set(assessment.safe_path_evidence_ids)
    for hypothesis in assessment.hypotheses:
        hypothesis_citations = (
            hypothesis.source_evidence_ids
            + hypothesis.path_evidence_ids
            + hypothesis.guard_evidence_ids
            + hypothesis.sink_evidence_ids
            + hypothesis.contradicting_evidence_ids
        )
        cited.update(hypothesis_citations)
        _validate_hypothesis(packet, facts, hypothesis)
    for request in assessment.context_requests:
        cited.update(request.evidence_ids)
        _validate_context_request(packet, request)
    if not cited.issubset(facts):
        raise ValueError("Decompiler Hunter cited evidence outside its packet")
    if assessment.disposition is DecompilerHunterDisposition.NOT_VULNERABLE:
        safe_kinds = {facts[item].kind for item in assessment.safe_path_evidence_ids}
        if not safe_kinds.intersection(
            {
                BinaryEvidenceFactKind.GUARD,
                BinaryEvidenceFactKind.RETURN_USE,
            }
        ):
            raise ValueError("not_vulnerable requires guard or failure/return-use evidence")
    _validate_safe_output(assessment)


def validate_decompiler_hunter_safe_output(
    assessment: DecompilerHunterAssessment,
) -> None:
    """Apply M17's static-only output safety policy to a later-stage assessment."""

    _validate_safe_output(assessment)


async def run_decompiler_hunter_work_item(
    *,
    store_root: Path,
    work_item: HunterWorkItem,
    client: DecompilerHunterModelClient,
    policy: DecompilerHunterPolicy,
) -> DecompilerHunterRun:
    packet = load_decompiler_hunter_packet(store_root=store_root, work_item=work_item)
    assessment, usage, raw = await DecompilerHunterAgent(
        client=client,
        maximum_attempts=policy.maximum_attempts_per_root,
        maximum_output_tokens=policy.maximum_output_tokens_per_call,
    ).analyze(work_item, packet)
    run = DecompilerHunterRun(packet=packet, assessment=assessment, usage=usage, raw_responses=raw)
    _write_run(_private_store_root(store_root), work_item, run)
    return run


async def execute_decompiler_hunter_plan(
    *,
    plan: DecompilerHunterPlan,
    store_root: Path,
    database: Path,
    client: DecompilerHunterModelClient,
    budget: BudgetPolicy,
    worker_id: str = "decompiler-imageio-hunter-worker",
) -> tuple[DecompilerHunterRun, ...]:
    """Execute the admitted prefix and stop at the first deferred work item."""

    plan = DecompilerHunterPlan.model_validate(plan.model_dump(mode="json"))
    if str(client.model_id) != plan.provider_preflight.model_id:
        raise ValueError("provider model differs from the preflight-bound plan")
    if str(getattr(client, "transport", "test_or_legacy")) != plan.provider_preflight.transport:
        raise ValueError("provider transport differs from the preflight-bound plan")
    store = _private_store_root(store_root)
    items = plan.admitted_work_items
    if not items:
        return ()
    queue = DurableHuntQueueStore(store / "hunters", database, plan.run_id)
    queue.init_from_work_items(items)
    tasks = {item.work_id: item for item in queue.load().tasks}
    with SqliteRepository(database, read_only=True) as repository:
        prior_usage = repository.list_budget_usage(plan.run_id, scope="hunter")
    controller = BudgetController(
        budget, prior_usage, soft_input_token_stop=budget.max_input_tokens
    )
    completed: set[str] = set()
    for item in items:
        if tasks[item.work_id].status == "done":
            _validate_completed_run(store, item)
            completed.add(item.work_id)
    results: list[DecompilerHunterRun] = []
    for index, item in enumerate(items):
        if not {value.work_id for value in items[:index]}.issubset(completed):
            break
        task = tasks[item.work_id]
        if task.status == "done":
            continue
        lease = queue.acquire(
            task,
            worker_id=worker_id,
            lease_seconds=max(60, budget.max_wall_clock_minutes * 60),
            max_attempts=budget.max_retries_per_work_item + 1,
        )
        if lease is None:
            break
        try:
            queue.mark_file_running(task)
            queue.mark_hunt_running(task, item.hunter)
            budgeted = BudgetedLLMClient(client, controller, work_id=item.work_id)
            result = await run_decompiler_hunter_work_item(
                store_root=store,
                work_item=item,
                client=cast(DecompilerHunterModelClient, budgeted),
                policy=plan.policy,
            )
            with SqliteRepository(database) as repository:
                repository.save_budget_usage(result.usage)
            queue.mark_hunt_done(
                task, item.hunter, findings_count=len(result.assessment.hypotheses)
            )
            queue.mark_file_done(task)
            queue.finish(lease, status="done")
            completed.add(item.work_id)
            results.append(result)
        except DecompilerHunterDeferred as exc:
            packet = load_decompiler_hunter_packet(store_root=store, work_item=item)
            _write_deferral(store, item, packet, exc)
            if exc.usage is not None:
                with SqliteRepository(database) as repository:
                    repository.save_budget_usage(exc.usage)
            queue.mark_hunt_deferred(task, item.hunter, exc.reason)
            queue.mark_file_deferred(task, exc.reason)
            queue.finish(lease, status="budget_deferred", error=exc.reason)
            break
        except Exception as exc:
            queue.mark_hunt_failed(task, item.hunter, str(exc))
            queue.mark_file_failed(task, str(exc))
            queue.finish(lease, status="failed", error=str(exc))
            raise
        finally:
            controller.finish_work(item.work_id)
    return tuple(results)


def _make_packet(
    *,
    work_id: str,
    capsule_set_sha256: str,
    scope: BinaryResearchScope,
    capsule: BinaryEvidenceCapsule,
    frozen_function_ids: tuple[str, ...],
) -> DecompilerHunterPacket:
    payload = {
        "schema_version": "decompiler-hunter-packet-v1",
        "prompt_version": DECOMPILER_HUNTER_PROMPT_VERSION,
        "work_id": work_id,
        "root_id": capsule.root_id,
        "admission_rank": capsule.admission_rank,
        "capsule_set_sha256": capsule_set_sha256,
        "scope": scope.model_dump(mode="json"),
        "capsule": capsule.model_dump(mode="json"),
        "frozen_function_ids": frozen_function_ids,
        "known_function_ids": tuple(item.function_id for item in capsule.functions),
        "known_block_ids": tuple(
            sorted({block.block_id for function in capsule.functions for block in function.blocks})
        ),
        "known_addresses": tuple(
            sorted(
                {
                    instruction.address
                    for function in capsule.functions
                    for block in function.blocks
                    for instruction in block.instructions
                }
            )
        ),
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
    return DecompilerHunterPacket(**payload, packet_sha256=_digest(payload))


def _validate_hypothesis(
    packet: DecompilerHunterPacket,
    facts: Mapping[str, BinaryEvidenceFact],
    hypothesis: DecompilerHunterHypothesis,
) -> None:
    if packet.capsule.proof_status is not CapsuleProofStatus.PROOF_CAPABLE:
        raise ValueError("proof-incomplete capsule cannot support a terminal code hypothesis")
    if any(
        identifier not in facts
        for identifier in (
            hypothesis.source_evidence_ids
            + hypothesis.path_evidence_ids
            + hypothesis.guard_evidence_ids
            + hypothesis.sink_evidence_ids
            + hypothesis.contradicting_evidence_ids
        )
    ):
        raise ValueError("hypothesis cites evidence outside the packet")
    fact_map = {item.fact_id: item for item in packet.capsule.facts}
    if {fact_map[item].kind for item in hypothesis.source_evidence_ids} != {
        BinaryEvidenceFactKind.INPUT_SOURCE
    }:
        raise ValueError("hypothesis source citations must be input-source facts")
    if not {fact_map[item].kind for item in hypothesis.path_evidence_ids}.intersection(
        {
            BinaryEvidenceFactKind.DATAFLOW,
            BinaryEvidenceFactKind.CALLSITE,
            BinaryEvidenceFactKind.RETURN_USE,
        }
    ):
        raise ValueError("hypothesis requires an address-backed data or call path")
    if {fact_map[item].kind for item in hypothesis.sink_evidence_ids} != {
        BinaryEvidenceFactKind.SECURITY_SINK
    }:
        raise ValueError("hypothesis sink citations must be security-sink facts")
    if any(
        fact_map[item].kind is not BinaryEvidenceFactKind.GUARD
        for item in hypothesis.guard_evidence_ids
    ):
        raise ValueError("guard citations must be guard facts")
    known_functions = set(packet.known_function_ids)
    if not set(hypothesis.call_path_function_ids).issubset(known_functions):
        raise ValueError("hypothesis cites an unknown function")
    if packet.capsule.root_function_id not in hypothesis.call_path_function_ids:
        raise ValueError("hypothesis call path omits the admitted root")
    if not set(hypothesis.cfg_path_addresses).issubset(packet.known_addresses):
        raise ValueError("hypothesis cites an invented address")
    capsule_guard_ids = {
        item.fact_id for item in packet.capsule.facts if item.kind is BinaryEvidenceFactKind.GUARD
    }
    if hypothesis.no_applicable_guard and capsule_guard_ids:
        raise ValueError("hypothesis ignored guard facts present in the capsule")
    if not hypothesis.no_applicable_guard and not hypothesis.guard_evidence_ids:
        raise ValueError("hypothesis omitted required guard analysis")


def _validate_context_request(
    packet: DecompilerHunterPacket,
    request: BinaryCodeContextRequest,
) -> None:
    if request.kind not in packet.allowed_context_kinds:
        raise ValueError("context request kind is outside the packet allow-list")
    if not set(request.evidence_ids).issubset(packet.allowed_evidence_ids):
        raise ValueError("context request cites evidence outside the packet")
    frozen = set(packet.frozen_function_ids)
    if request.function_id is not None and request.function_id not in frozen:
        raise ValueError("context request cites a function outside the frozen IR")
    if request.related_function_id is not None and request.related_function_id not in frozen:
        raise ValueError("context request cites a related function outside the frozen IR")
    if request.block_id is not None and request.block_id not in packet.known_block_ids:
        raise ValueError("context request cites an unknown block")
    if request.address is not None and request.address not in packet.known_addresses:
        raise ValueError("context request cites an unknown address")
    if any(address not in packet.known_addresses for address in request.supporting_addresses):
        raise ValueError("context request cites an unknown supporting address")
    variables = {
        value
        for function in packet.capsule.functions
        for block in function.blocks
        for instruction in block.instructions
        for value in ((instruction.result,) + instruction.operands)
        if value is not None
    }
    if request.variable is not None and request.variable not in variables:
        raise ValueError("context request cites an unknown IR variable")
    if any(variable not in variables for variable in request.supporting_variables):
        raise ValueError("context request cites an unknown supporting IR variable")


def _validate_work_item_packet(item: HunterWorkItem, packet: DecompilerHunterPacket) -> None:
    if item.planning_policy != DECOMPILER_HUNTER_PLANNING_POLICY:
        raise ValueError("work item was not produced by Decompiler Hunter planning")
    if item.hunter != DECOMPILER_HUNTER:
        raise ValueError("work item is assigned to another Hunter")
    if item.work_id != packet.work_id:
        raise ValueError("work item and packet IDs differ")
    if item.source_snapshot != packet.capsule.snapshot_sha256:
        raise ValueError("work item changed the frozen snapshot")
    if item.scan_scope_digest != packet.capsule_set_sha256:
        raise ValueError("work item changed the capsule set")
    if item.slice_ids != (packet.root_id, packet.capsule.capsule_sha256):
        raise ValueError("work item changed its root or capsule")
    if item.files != (item.seed_file,):
        raise ValueError("Decompiler Hunter work must contain exactly one packet")


def _validate_safe_output(assessment: DecompilerHunterAssessment) -> None:
    values = [
        assessment.summary,
        assessment.safe_path_analysis,
        *assessment.unresolved_questions,
    ]
    for hypothesis in assessment.hypotheses:
        values.extend(
            (
                hypothesis.title,
                hypothesis.parser_reachability,
                hypothesis.attacker_control,
                hypothesis.width_signedness,
                hypothesis.guard_analysis,
                hypothesis.security_relation,
                hypothesis.impact,
                hypothesis.contradicting_evidence,
                hypothesis.decompiler_uncertainty,
                hypothesis.falsification_condition,
            )
        )
    for request in assessment.context_requests:
        values.append(request.rationale)
    for value in values:
        if any(ord(character) < 32 and character not in "\n\r\t" for character in value):
            raise ValueError("Decompiler Hunter output contains unsafe control characters")
        for label, pattern in _PROHIBITED_OUTPUT_PATTERNS:
            if pattern.search(value):
                raise ValueError(f"Decompiler Hunter output contains prohibited {label}")


def _write_run(store: Path, item: HunterWorkItem, run: DecompilerHunterRun) -> None:
    directory = store / "hunters" / item.work_id / "decompiler-analysis"
    _write_private_json(directory / "packet.json", run.packet.model_dump(mode="json"))
    _write_private_json(directory / "assessment.json", run.assessment.model_dump(mode="json"))
    _write_private_json(directory / "usage.json", run.usage.model_dump(mode="json"))
    for index, response in enumerate(run.raw_responses, start=1):
        _write_private_bytes(
            directory / f"raw-response-{index:02d}.txt",
            response.encode()[:_MAX_RAW_RESPONSE_BYTES],
        )


def _write_deferral(
    store: Path,
    item: HunterWorkItem,
    packet: DecompilerHunterPacket,
    deferred: DecompilerHunterDeferred,
) -> None:
    identity = {
        "packet_sha256": packet.packet_sha256,
        "reason": deferred.reason,
        "response_digests": tuple(_digest(value) for value in deferred.raw_responses),
    }
    directory = (
        store
        / "hunters"
        / item.work_id
        / "decompiler-analysis"
        / "deferrals"
        / f"attempt-{hashlib.sha256(_canonical_json(identity)).hexdigest()[:24]}"
    )
    _write_private_json(directory / "packet.json", packet.model_dump(mode="json"))
    _write_private_json(directory / "deferral.json", identity)
    if deferred.usage is not None:
        _write_private_json(directory / "usage.json", deferred.usage.model_dump(mode="json"))
    for index, response in enumerate(deferred.raw_responses, start=1):
        _write_private_bytes(
            directory / f"raw-response-{index:02d}.txt",
            response.encode()[:_MAX_RAW_RESPONSE_BYTES],
        )


def _validate_completed_run(store: Path, item: HunterWorkItem) -> None:
    source = load_decompiler_hunter_packet(store_root=store, work_item=item)
    directory = store / "hunters" / item.work_id / "decompiler-analysis"
    persisted = DecompilerHunterPacket.model_validate_json(
        _read_file(directory / "packet.json", maximum=_MAX_PACKET_BYTES)
    )
    if persisted.packet_sha256 != source.packet_sha256:
        raise RuntimeError("completed Hunter run is bound to a different packet")
    assessment = DecompilerHunterAssessment.model_validate_json(
        _read_file(directory / "assessment.json", maximum=_MAX_RAW_RESPONSE_BYTES)
    )
    validate_decompiler_hunter_assessment(source, assessment)


def _budget_usage(
    work_item: HunterWorkItem,
    client: DecompilerHunterModelClient,
    calls: int,
    totals: dict[str, int],
) -> BudgetUsage:
    return with_estimated_cost(
        BudgetUsage(
            run_id=work_item.run_id,
            work_id=work_item.work_id,
            scope="hunter",
            model_id=str(client.model_id),
            transport=str(getattr(client, "transport", "test_or_legacy")),
            sessions=1,
            calls=calls,
            iterations=calls,
            input_tokens=totals["input_tokens"],
            output_tokens=totals["output_tokens"],
            cache_read_tokens=totals["cache_read_tokens"],
            cache_write_tokens=totals["cache_write_tokens"],
        )
    )


def _private_store_root(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError("Decompiler Hunter store may not be a symbolic link")
    resolved = expanded.resolve(strict=True)
    if not resolved.is_dir() or any(
        (candidate / ".git").exists() for candidate in (resolved, *resolved.parents)
    ):
        raise ValueError("Decompiler Hunter store must be a private directory outside Git")
    return resolved


def _contained_file(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("Decompiler Hunter artifact path escapes its private store")
    path = root / candidate
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not resolved.is_file() or root not in resolved.parents:
        raise ValueError("Decompiler Hunter artifact is not a contained regular file")
    return resolved


def _read_file(path: Path, *, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"Decompiler Hunter artifact is missing or unsafe: {path}")
    if path.stat().st_size > maximum:
        raise RuntimeError(f"Decompiler Hunter artifact exceeds its limit: {path}")
    return path.read_bytes()


def _write_private_json(path: Path, payload: object) -> None:
    _write_private_bytes(path, json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n")


def _write_private_bytes(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise RuntimeError("Decompiler Hunter output may not be a symbolic link")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path.parent, 0o700)
    if path.exists():
        if not path.is_file() or path.read_bytes() != payload:
            raise FileExistsError(
                "immutable Decompiler Hunter artifact already contains other data"
            )
        return
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _require_sorted_unique(values: tuple[str, ...], label: str) -> None:
    if tuple(sorted(set(values))) != values:
        raise ValueError(f"{label} must be sorted and unique")


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def _digest(payload: object) -> str:
    if isinstance(payload, str):
        encoded = payload.encode()
    else:
        encoded = _canonical_json(payload)
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _plan_digest(plan: DecompilerHunterPlan) -> str:
    return _digest(plan.model_dump(mode="json", exclude={"plan_sha256"}))
