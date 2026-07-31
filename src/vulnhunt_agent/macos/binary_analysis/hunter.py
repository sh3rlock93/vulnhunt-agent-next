"""Scope-bound Binary Hunter and non-executable experiment planning.

The Binary Hunter consumes only the immutable PR1-PR5 evidence chain.  It does
not extract images, invoke a decompiler, execute an input, or confirm a
vulnerability.  Model output is schema-validated and can produce only a typed,
human-review-gated experiment plan with ``auto_execute`` fixed to false.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Sequence
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
    SHA256_PATTERN,
)
from ...infrastructure.sqlite_repository import SqliteRepository
from ...scheduling.budget import BudgetController, BudgetedLLMClient, BudgetExceededError
from ...scheduling.metrics import with_estimated_cost
from ...scheduling.shadow import work_id_for
from ..imageio_inventory import ImageIOAPIRoute
from .analyzers import (
    BinaryAnalysisReport,
    BinaryFindingSeverity,
    BinaryStaticFinding,
    BinaryVulnerabilityClass,
)
from .discovery import (
    BinaryFormatFamily,
    ImageIOParserDiscovery,
    ParserCandidate,
    ParserEvidenceKind,
)
from .ir import NormalizedBinaryIR
from .ranking import BinaryContextPack, BinaryContextPlan, BinaryFunctionRanking
from .snapshot import BinarySnapshot

BINARY_HUNTER = "binary-imageio-analysis"
BINARY_HUNTER_PLANNING_POLICY: Literal["binary-hunter-planning-v1"] = "binary-hunter-planning-v1"
BINARY_HUNTER_PROMPT_VERSION: Literal["binary-imageio-hunter-v2"] = "binary-imageio-hunter-v2"
BINARY_EXPERIMENT_POLICY: Literal["binary-experiment-planning-v1"] = "binary-experiment-planning-v1"
_MAX_PACKET_BYTES = 512 * 1024
_MAX_RAW_RESPONSE_BYTES = 128 * 1024
_INPUT_EVIDENCE_KINDS = {
    "parser_api",
    "parser_format",
    "parser_input",
}
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
        "weaponization content",
        re.compile(
            r"(?i)\b(?:reverse\s+shell|shellcode|rop\s+chain|credential\s+"
            r"(?:dump|theft)|persistence\s+mechanism)\b"
        ),
    ),
)

AUTHORIZED_RESEARCH_SCOPE_PROMPT = """This task is authorized defensive research over an Apple ImageIO binary
lawfully present on an analyst-controlled macOS installation or disposable
VM. Perform bounded, read-only static analysis of the supplied evidence only.
Do not provide exploit code, arbitrary-code-execution steps, persistence,
evasion, credential access, network activity, third-party access, or public
disclosure instructions. Treat every result as a hypothesis. You may request
only a typed, non-executable experiment supported by the existing networkless
disposable-VM harness; execution requires independent human review. If the
requested conclusion cannot be supported inside this scope, return
`scope_blocked` or `inconclusive` and state the missing evidence."""

SYSTEM_PROMPT = (
    AUTHORIZED_RESEARCH_SCOPE_PROMPT
    + """

You are the Binary ImageIO static-analysis Hunter. The packet contains a
digest-bound normalized IR context pack, parser-discovery evidence, and
deterministic static candidates. Decompiler pseudocode is lossy evidence, not
original source. Separate direct evidence from inference and never upgrade a
static candidate into a confirmed or reportable vulnerability.

For each hypothesis, identify the input-controlled value, parser state,
size/allocation/index or lifetime relationship, direct supporting evidence,
contradicting evidence, and an observable falsification condition. A
static_hypothesis must cite both one static_finding evidence ID and one
parser_input, parser_api, or parser_format evidence ID from the packet.
For partial_initialization_disclosure, also cite allocation_initialization and
full_consumption_output evidence. A composite_range_gap is a range hypothesis,
not a reportable disclosure; request the missing initialization/output evidence
or a typed experiment instead of promoting it.

Return only this JSON object:
{
  "work_id": "<exact packet work_id>",
  "pack_id": "<exact packet pack_id>",
  "pack_sequence": 1,
  "disposition": "static_hypothesis|needs_context|needs_experiment|not_vulnerable|inconclusive|scope_blocked",
  "summary": "<bounded evidence-grounded summary>",
  "hypotheses": [
    {
      "hypothesis_id": "binhypothesis-<stable-label>",
      "title": "<concise>",
      "vulnerability_class": "integer_overflow|offset_length_oob|allocation_copy_mismatch|use_after_free|composite_range_gap|partial_initialization_disclosure",
      "input_control": "<controlled value and evidence limit>",
      "parser_state": "<state before the candidate sink>",
      "security_relation": "<size/allocation/index or lifetime relation>",
      "root_cause_hypothesis": "<hypothesis, not a claim>",
      "falsification_condition": "<observable evidence that rejects it>",
      "confidence": 0.0,
      "supporting_evidence_ids": ["<packet evidence ID>"],
      "contradicting_evidence_ids": []
    }
  ],
  "experiment_requests": [
    {
      "request_id": "binexperiment-<stable-label>",
      "hypothesis_id": "<one hypothesis_id>",
      "kind": "exact_replay|structured_field_boundary|api_route_differential|incremental_chunk_schedule|guard_malloc|cross_build_replay|binary_context|raw_output_differential|canary_propagation",
      "rationale": "<why the observation discriminates the hypothesis>",
      "retained_input_sha256": null,
      "target_format": null,
      "target_field": null,
      "baseline_route": null,
      "route": null,
      "boundary_values": [],
      "incremental_chunk_sizes": [],
      "context_function_ids": [],
      "target_build": null,
      "canary_value": null,
      "execution_limit": 1,
      "expected_observation": "<supporting result>",
      "falsification_condition": "<rejecting result>",
      "evidence_refs": ["<packet evidence ID>"],
      "auto_execute": false
    }
  ],
  "evidence_refs": ["<all packet evidence IDs relied on>"],
  "unresolved_questions": ["<bounded unknown>"]
}
"""
)


class BinaryResearchScope(DomainModel):
    schema_version: Literal["binary-research-scope-v1"] = "binary-research-scope-v1"
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    authorization_basis: str = Field(min_length=8, max_length=500)
    purpose: Literal["defensive_vulnerability_research"] = "defensive_vulnerability_research"
    target_origin: Literal["locally_installed_system_binary"] = "locally_installed_system_binary"
    analysis_mode: Literal["bounded_read_only_static_analysis"] = (
        "bounded_read_only_static_analysis"
    )
    host_image_execution_allowed: Literal[False] = False
    network_allowed: Literal[False] = False
    third_party_access_allowed: Literal[False] = False
    credential_access_allowed: Literal[False] = False
    persistence_allowed: Literal[False] = False
    evasion_allowed: Literal[False] = False
    weaponization_allowed: Literal[False] = False
    public_disclosure_allowed: Literal[False] = False
    external_submission_allowed: Literal[False] = False
    dynamic_experiment_mode: Literal["planning_only"] = "planning_only"
    auto_execute: Literal[False] = False
    scope_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_scope_digest(self) -> "BinaryResearchScope":
        expected = _scope_digest(self.model_dump(mode="json", exclude={"scope_sha256"}))
        if self.scope_sha256 != expected:
            raise ValueError("binary research scope digest does not match its permissions")
        return self


class BinaryHunterEvidenceKind(StrEnum):
    SCOPE = "scope"
    SNAPSHOT = "snapshot"
    IR = "ir"
    DISCOVERY = "discovery"
    STATIC_REPORT = "static_report"
    RANKING = "ranking"
    CONTEXT_PLAN = "context_plan"
    CONTEXT_PACK = "context_pack"
    STATIC_FINDING = "static_finding"
    ALLOCATION_INITIALIZATION = "allocation_initialization"
    FULL_CONSUMPTION_OUTPUT = "full_consumption_output"
    PARSER_INPUT = "parser_input"
    PARSER_API = "parser_api"
    PARSER_FORMAT = "parser_format"
    PARSER_OTHER = "parser_other"


class BinaryHunterEvidenceRef(DomainModel):
    evidence_id: str = Field(pattern=r"^binevidence_[0-9a-f]{20}$")
    kind: BinaryHunterEvidenceKind
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)
    subject_id: str = Field(min_length=1, max_length=500)


class BinaryHunterPacket(DomainModel):
    schema_version: Literal["binary-hunter-packet-v1"] = "binary-hunter-packet-v1"
    prompt_version: Literal["binary-imageio-hunter-v2"] = BINARY_HUNTER_PROMPT_VERSION
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    ir_sha256: str = Field(pattern=SHA256_PATTERN)
    discovery_sha256: str = Field(pattern=SHA256_PATTERN)
    report_sha256: str = Field(pattern=SHA256_PATTERN)
    ranking_sha256: str = Field(pattern=SHA256_PATTERN)
    context_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    scope: BinaryResearchScope
    pack: BinaryContextPack
    prior_pack_ids: tuple[str, ...] = Field(default=(), max_length=1024)
    known_function_ids: tuple[str, ...] = Field(min_length=1, max_length=10000)
    candidates: tuple[ParserCandidate, ...] = Field(min_length=1, max_length=10000)
    findings: tuple[BinaryStaticFinding, ...] = Field(default=(), max_length=10000)
    retained_input_sha256s: tuple[str, ...] = Field(default=(), max_length=32)
    evidence_refs: tuple[BinaryHunterEvidenceRef, ...] = Field(min_length=8, max_length=10000)
    allowed_experiments: tuple["BinaryExperimentKind", ...] = ()
    host_execution_allowed: Literal[False] = False
    network_allowed: Literal[False] = False
    auto_execute: Literal[False] = False
    packet_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_packet(self) -> "BinaryHunterPacket":
        if self.scope.snapshot_sha256 != self.snapshot_sha256:
            raise ValueError("binary Hunter scope is bound to a different snapshot")
        if self.pack.sequence != len(self.prior_pack_ids) + 1:
            raise ValueError("binary Hunter pack does not follow its declared prefix")
        if len(set(self.prior_pack_ids)) != len(self.prior_pack_ids):
            raise ValueError("binary Hunter prior pack IDs must be unique")
        if self.pack.pack_id in self.prior_pack_ids:
            raise ValueError("binary Hunter current pack appears in its prior prefix")
        if tuple(dict.fromkeys(self.known_function_ids)) != self.known_function_ids:
            raise ValueError("binary Hunter known functions must preserve unique ranking order")
        segment_function_ids = tuple(item.function_id for item in self.pack.segments)
        if tuple(item.function_id for item in self.candidates) != segment_function_ids:
            raise ValueError("binary Hunter candidates do not match the context segments")
        if not set(segment_function_ids).issubset(self.known_function_ids):
            raise ValueError("binary Hunter context contains an unknown ranked function")
        expected_finding_ids = tuple(
            sorted(
                {finding_id for segment in self.pack.segments for finding_id in segment.finding_ids}
            )
        )
        if tuple(item.finding_id for item in self.findings) != expected_finding_ids:
            raise ValueError("binary Hunter findings do not match the context pack")
        if any(item.ir_sha256 != self.ir_sha256 for item in self.findings):
            raise ValueError("binary Hunter finding is bound to a different IR")
        if tuple(sorted(set(self.retained_input_sha256s))) != self.retained_input_sha256s:
            raise ValueError("retained input digests must be sorted and unique")
        if tuple(self.allowed_experiments) != tuple(BinaryExperimentKind):
            raise ValueError("binary Hunter experiment allow-list is incomplete or reordered")
        expected_refs = _packet_evidence_refs(
            scope=self.scope,
            snapshot_sha256=self.snapshot_sha256,
            ir_sha256=self.ir_sha256,
            discovery_sha256=self.discovery_sha256,
            report_sha256=self.report_sha256,
            ranking_sha256=self.ranking_sha256,
            context_plan_sha256=self.context_plan_sha256,
            pack=self.pack,
            candidates=self.candidates,
            findings=self.findings,
        )
        if self.evidence_refs != expected_refs:
            raise ValueError("binary Hunter evidence references do not match packet evidence")
        expected_packet = _packet_digest(self.model_dump(mode="json", exclude={"packet_sha256"}))
        if self.packet_sha256 != expected_packet:
            raise ValueError("binary Hunter packet digest does not match its evidence")
        if len(_canonical_json(self.model_dump(mode="json"))) > _MAX_PACKET_BYTES:
            raise ValueError("binary Hunter packet exceeds its strict byte limit")
        return self


class BinaryHunterDisposition(StrEnum):
    STATIC_HYPOTHESIS = "static_hypothesis"
    NEEDS_CONTEXT = "needs_context"
    NEEDS_EXPERIMENT = "needs_experiment"
    NOT_VULNERABLE = "not_vulnerable"
    INCONCLUSIVE = "inconclusive"
    SCOPE_BLOCKED = "scope_blocked"


class BinaryExperimentKind(StrEnum):
    EXACT_REPLAY = "exact_replay"
    STRUCTURED_FIELD_BOUNDARY = "structured_field_boundary"
    API_ROUTE_DIFFERENTIAL = "api_route_differential"
    INCREMENTAL_CHUNK_SCHEDULE = "incremental_chunk_schedule"
    GUARD_MALLOC = "guard_malloc"
    CROSS_BUILD_REPLAY = "cross_build_replay"
    BINARY_CONTEXT = "binary_context"
    RAW_OUTPUT_DIFFERENTIAL = "raw_output_differential"
    CANARY_PROPAGATION = "canary_propagation"


class BinaryHunterHypothesis(DomainModel):
    hypothesis_id: str = Field(pattern=r"^binhypothesis-[a-z0-9][a-z0-9-]{2,80}$")
    title: str = Field(min_length=1, max_length=300)
    vulnerability_class: BinaryVulnerabilityClass
    input_control: str = Field(min_length=1, max_length=2000)
    parser_state: str = Field(min_length=1, max_length=2000)
    security_relation: str = Field(min_length=1, max_length=2000)
    root_cause_hypothesis: str = Field(min_length=1, max_length=3000)
    falsification_condition: str = Field(min_length=1, max_length=2000)
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_evidence_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    contradicting_evidence_ids: tuple[str, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def validate_evidence_order(self) -> "BinaryHunterHypothesis":
        if tuple(sorted(set(self.supporting_evidence_ids))) != self.supporting_evidence_ids:
            raise ValueError("supporting evidence IDs must be sorted and unique")
        if tuple(sorted(set(self.contradicting_evidence_ids))) != self.contradicting_evidence_ids:
            raise ValueError("contradicting evidence IDs must be sorted and unique")
        if set(self.supporting_evidence_ids) & set(self.contradicting_evidence_ids):
            raise ValueError("supporting and contradicting evidence may not overlap")
        return self


class BinaryExperimentRequest(DomainModel):
    request_id: str = Field(pattern=r"^binexperiment-[a-z0-9][a-z0-9-]{2,80}$")
    hypothesis_id: str = Field(pattern=r"^binhypothesis-[a-z0-9][a-z0-9-]{2,80}$")
    kind: BinaryExperimentKind
    rationale: str = Field(min_length=1, max_length=2000)
    retained_input_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    target_format: BinaryFormatFamily | None = None
    target_field: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:,\[\]-]{1,80}$")
    baseline_route: ImageIOAPIRoute | None = None
    route: ImageIOAPIRoute | None = None
    boundary_values: tuple[int, ...] = Field(default=(), max_length=8)
    incremental_chunk_sizes: tuple[int, ...] = Field(default=(), max_length=8)
    context_function_ids: tuple[str, ...] = Field(default=(), max_length=4)
    target_build: str | None = Field(
        default=None,
        pattern=r"^[0-9A-Za-z][0-9A-Za-z.() _-]{0,79}$",
    )
    canary_value: int | None = Field(default=None, ge=0, le=255)
    execution_limit: int = Field(default=1, ge=1, le=6)
    expected_observation: str = Field(min_length=1, max_length=2000)
    falsification_condition: str = Field(min_length=1, max_length=2000)
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=32)
    auto_execute: Literal[False] = False

    @model_validator(mode="after")
    def validate_parameters(self) -> "BinaryExperimentRequest":
        if tuple(sorted(set(self.context_function_ids))) != self.context_function_ids:
            raise ValueError("context function IDs must be sorted and unique")
        if tuple(sorted(set(self.evidence_refs))) != self.evidence_refs:
            raise ValueError("experiment evidence references must be sorted and unique")
        if any(value < 0 or value > 0xFFFFFFFF for value in self.boundary_values):
            raise ValueError("boundary values must fit an unsigned 32-bit field")
        if any(value < 1 or value > 1024 * 1024 for value in self.incremental_chunk_sizes):
            raise ValueError("incremental chunk size is outside the harness limit")
        if self.kind is BinaryExperimentKind.STRUCTURED_FIELD_BOUNDARY:
            if self.target_format is None or self.target_field is None or not self.boundary_values:
                raise ValueError("structured field experiment requires format, field, and values")
        if self.kind is BinaryExperimentKind.API_ROUTE_DIFFERENTIAL:
            if self.baseline_route is None or self.route is None:
                raise ValueError("route differential requires baseline and target routes")
            if self.baseline_route is self.route:
                raise ValueError("route differential requires two distinct routes")
        if self.kind is BinaryExperimentKind.INCREMENTAL_CHUNK_SCHEDULE:
            if not self.incremental_chunk_sizes:
                raise ValueError("incremental schedule requires bounded chunk sizes")
            if self.route not in {None, ImageIOAPIRoute.INCREMENTAL_DECODE}:
                raise ValueError("incremental schedule may use only the incremental route")
        if self.kind is BinaryExperimentKind.BINARY_CONTEXT and not self.context_function_ids:
            raise ValueError("binary context request requires named ranked functions")
        if self.kind is BinaryExperimentKind.CROSS_BUILD_REPLAY and self.target_build is None:
            raise ValueError("cross-build replay requires a target build label")
        if self.kind is BinaryExperimentKind.RAW_OUTPUT_DIFFERENTIAL and self.route is None:
            raise ValueError("raw-output differential requires a decode route")
        if self.kind is BinaryExperimentKind.CANARY_PROPAGATION:
            if self.route is None or self.canary_value is None:
                raise ValueError("canary propagation requires a decode route and byte value")
        return self


class BinaryHunterAssessment(DomainModel):
    schema_version: Literal["binary-hunter-assessment-v1"] = "binary-hunter-assessment-v1"
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    pack_id: str = Field(pattern=r"^binpack_[0-9a-f]{20}$")
    pack_sequence: int = Field(ge=1, le=1024)
    disposition: BinaryHunterDisposition
    summary: str = Field(min_length=1, max_length=4000)
    hypotheses: tuple[BinaryHunterHypothesis, ...] = Field(default=(), max_length=4)
    experiment_requests: tuple[BinaryExperimentRequest, ...] = Field(default=(), max_length=8)
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=64)
    unresolved_questions: tuple[str, ...] = Field(default=(), max_length=12)

    @model_validator(mode="after")
    def validate_links(self) -> "BinaryHunterAssessment":
        hypothesis_ids = tuple(item.hypothesis_id for item in self.hypotheses)
        if len(set(hypothesis_ids)) != len(hypothesis_ids):
            raise ValueError("binary Hunter returned duplicate hypothesis IDs")
        request_ids = tuple(item.request_id for item in self.experiment_requests)
        if len(set(request_ids)) != len(request_ids):
            raise ValueError("binary Hunter returned duplicate experiment request IDs")
        if any(item.hypothesis_id not in set(hypothesis_ids) for item in self.experiment_requests):
            raise ValueError("binary experiment request references an unknown hypothesis")
        if tuple(sorted(set(self.evidence_refs))) != self.evidence_refs:
            raise ValueError("assessment evidence references must be sorted and unique")
        if (
            self.disposition
            in {
                BinaryHunterDisposition.STATIC_HYPOTHESIS,
                BinaryHunterDisposition.NEEDS_EXPERIMENT,
            }
            and not self.hypotheses
        ):
            raise ValueError("binary Hunter disposition requires a hypothesis")
        if (
            self.disposition is BinaryHunterDisposition.NEEDS_EXPERIMENT
            and not self.experiment_requests
        ):
            raise ValueError("needs_experiment requires a typed experiment request")
        if self.disposition is BinaryHunterDisposition.NEEDS_CONTEXT and not any(
            item.kind is BinaryExperimentKind.BINARY_CONTEXT for item in self.experiment_requests
        ):
            raise ValueError("needs_context requires a binary context request")
        if (
            self.disposition
            in {
                BinaryHunterDisposition.NOT_VULNERABLE,
                BinaryHunterDisposition.SCOPE_BLOCKED,
            }
            and self.experiment_requests
        ):
            raise ValueError("terminal non-experimental disposition may not request execution")
        return self


class BinaryExperimentPlanStatus(StrEnum):
    REVIEW_REQUIRED = "review_required"
    REQUIRES_CONTEXT = "requires_context"
    REQUIRES_HARNESS = "requires_harness"
    REQUIRES_SNAPSHOT = "requires_snapshot"
    UNSUPPORTED = "unsupported"
    SCOPE_BLOCKED = "scope_blocked"


class BinaryExperimentPlan(DomainModel):
    schema_version: Literal["binary-experiment-plan-v1"] = "binary-experiment-plan-v1"
    policy_version: Literal["binary-experiment-planning-v1"] = BINARY_EXPERIMENT_POLICY
    plan_id: str = Field(pattern=r"^binary-plan-[0-9a-f]{32}$")
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    pack_id: str = Field(pattern=r"^binpack_[0-9a-f]{20}$")
    scope_sha256: str = Field(pattern=SHA256_PATTERN)
    request_id: str = Field(pattern=r"^binexperiment-[a-z0-9][a-z0-9-]{2,80}$")
    hypothesis_id: str = Field(pattern=r"^binhypothesis-[a-z0-9][a-z0-9-]{2,80}$")
    kind: BinaryExperimentKind
    status: BinaryExperimentPlanStatus
    execution_limit: int = Field(ge=0, le=6)
    parameters: dict
    oracle: str = Field(min_length=1, max_length=2000)
    falsification_condition: str = Field(min_length=1, max_length=2000)
    required_capabilities: tuple[str, ...]
    reviewer_question: str = Field(min_length=1, max_length=2000)
    host_execution_allowed: Literal[False] = False
    network_allowed: Literal[False] = False
    auto_execute: Literal[False] = False

    @model_validator(mode="after")
    def validate_plan(self) -> "BinaryExperimentPlan":
        if tuple(sorted(set(self.required_capabilities))) != self.required_capabilities:
            raise ValueError("experiment plan capabilities must be sorted and unique")
        runnable = self.status is BinaryExperimentPlanStatus.REVIEW_REQUIRED
        if runnable != (self.execution_limit > 0):
            raise ValueError("only review-required experiment plans retain an execution limit")
        expected = _experiment_plan_id(
            work_id=self.work_id,
            pack_id=self.pack_id,
            scope_sha256=self.scope_sha256,
            request_id=self.request_id,
            kind=self.kind,
            status=self.status,
            parameters=self.parameters,
        )
        if self.plan_id != expected:
            raise ValueError("binary experiment plan ID does not match its request")
        return self


class BinaryHunterPlan(DomainModel):
    schema_version: Literal["binary-hunter-plan-v1"] = "binary-hunter-plan-v1"
    run_id: str = Field(min_length=1, max_length=200)
    scope: BinaryResearchScope
    context_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    routing: HunterRoutingPlan
    admitted_work_ids: tuple[str, ...] = Field(default=(), max_length=1024)
    deferred_work_ids: tuple[str, ...] = Field(default=(), max_length=1024)
    plan_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_work_order(self) -> "BinaryHunterPlan":
        work_ids = tuple(item.work_id for item in self.routing.work_items)
        if self.admitted_work_ids + self.deferred_work_ids != work_ids:
            raise ValueError("binary Hunter admission must preserve one routing prefix")
        if self.routing.scan_scope_digest != self.context_plan_sha256:
            raise ValueError("binary Hunter routing is bound to a different context plan")
        expected = _hunter_plan_digest(
            run_id=self.run_id,
            scope_sha256=self.scope.scope_sha256,
            context_plan_sha256=self.context_plan_sha256,
            routing=self.routing,
            admitted_work_ids=self.admitted_work_ids,
            deferred_work_ids=self.deferred_work_ids,
        )
        if self.plan_sha256 != expected:
            raise ValueError("binary Hunter plan digest does not match its work")
        return self

    @property
    def admitted_work_items(self) -> tuple[HunterWorkItem, ...]:
        admitted = set(self.admitted_work_ids)
        return tuple(item for item in self.routing.work_items if item.work_id in admitted)


class BinaryHunterModelClient(Protocol):
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
class BinaryHunterRun:
    packet: BinaryHunterPacket
    assessment: BinaryHunterAssessment
    experiment_plans: tuple[BinaryExperimentPlan, ...]
    usage: BudgetUsage
    raw_responses: tuple[str, ...]


class BinaryHunterDeferred(RuntimeError):
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
        super().__init__(f"Binary Hunter deferred: {reason}")


@dataclass
class BinaryHunterAgent:
    client: BinaryHunterModelClient
    max_attempts: int = 2
    max_tokens: int = 5000

    async def analyze(
        self,
        work_item: HunterWorkItem,
        packet: BinaryHunterPacket,
    ) -> tuple[BinaryHunterAssessment, BudgetUsage, tuple[str, ...]]:
        _validate_work_item_packet(work_item, packet)
        messages: list[dict] = [
            {
                "role": "user",
                "content": [
                    {
                        "text": "# Binary ImageIO evidence packet\n"
                        + json.dumps(packet.model_dump(mode="json"), indent=2)
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
        raw_responses: list[str] = []
        calls = 0
        for _ in range(self.max_attempts):
            try:
                response = await self.client.chat(
                    messages=messages,
                    system=SYSTEM_PROMPT,
                    max_tokens=self.max_tokens,
                    cache_system=True,
                )
            except BudgetExceededError as exc:
                usage = _budget_usage(work_item, self.client, calls, totals) if calls else None
                raise BinaryHunterDeferred(
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
                    assessment = BinaryHunterAssessment.model_validate(parsed)
                    validate_binary_hunter_assessment(packet, assessment)
                    return (
                        assessment,
                        _budget_usage(work_item, self.client, calls, totals),
                        tuple(raw_responses),
                    )
            except ValueError:
                pass
            messages.append({"role": "assistant", "content": response.content_blocks})
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "text": (
                                "Return only schema-valid JSON. Preserve the exact work_id, "
                                "pack_id, and pack_sequence; cite only packet evidence IDs; "
                                "do not include commands, code, paths, URLs, or network activity."
                            )
                        }
                    ],
                }
            )
        usage = _budget_usage(work_item, self.client, calls, totals)
        raise BinaryHunterDeferred(
            "invalid_model_response",
            raw_responses=raw_responses,
            usage=usage,
        )


def create_binary_research_scope(
    *,
    snapshot_sha256: str,
    authorization_basis: str,
) -> BinaryResearchScope:
    payload = {
        "schema_version": "binary-research-scope-v1",
        "snapshot_sha256": snapshot_sha256,
        "authorization_basis": authorization_basis,
        "purpose": "defensive_vulnerability_research",
        "target_origin": "locally_installed_system_binary",
        "analysis_mode": "bounded_read_only_static_analysis",
        "host_image_execution_allowed": False,
        "network_allowed": False,
        "third_party_access_allowed": False,
        "credential_access_allowed": False,
        "persistence_allowed": False,
        "evasion_allowed": False,
        "weaponization_allowed": False,
        "public_disclosure_allowed": False,
        "external_submission_allowed": False,
        "dynamic_experiment_mode": "planning_only",
        "auto_execute": False,
    }
    return BinaryResearchScope(**payload, scope_sha256=_scope_digest(payload))


def build_binary_hunter_plan(
    *,
    store_root: Path,
    run_id: str,
    snapshot: BinarySnapshot,
    ir: NormalizedBinaryIR,
    discovery: ImageIOParserDiscovery,
    report: BinaryAnalysisReport,
    ranking: BinaryFunctionRanking,
    context_plan: BinaryContextPlan,
    scope: BinaryResearchScope,
    budget: BudgetPolicy,
    retained_input_sha256s: Sequence[str] = (),
) -> BinaryHunterPlan:
    """Validate PR1-PR5 and persist one immutable packet per ranked pack."""

    _validate_evidence_chain(snapshot, ir, discovery, report, ranking, context_plan, scope)
    store = _private_store_root(store_root)
    retained = tuple(sorted(set(retained_input_sha256s)))
    candidates = {item.function_id: item for item in discovery.candidates}
    findings = {item.finding_id: item for item in report.findings}
    work_items: list[HunterWorkItem] = []
    prior_pack_ids: list[str] = []
    context_root = (
        store / "binary-hunter-context" / context_plan.plan_sha256.removeprefix("sha256:")[:24]
    )
    _private_directory(store / "binary-hunter-context")
    _private_directory(context_root)
    for pack in context_plan.packs:
        relative = (context_root / pack.pack_id / "packet.json").relative_to(store).as_posix()
        files = (relative,)
        work_id = work_id_for(
            source_snapshot=snapshot.snapshot_sha256,
            planning_policy=BINARY_HUNTER_PLANNING_POLICY,
            slice_ids=(pack.pack_id,),
            files=files,
            hunter=BINARY_HUNTER,
            scan_scope_digest=context_plan.plan_sha256,
        )
        pack_candidates = tuple(candidates[item.function_id] for item in pack.segments)
        finding_ids = tuple(
            sorted({identifier for segment in pack.segments for identifier in segment.finding_ids})
        )
        pack_findings = tuple(findings[identifier] for identifier in finding_ids)
        packet = _make_packet(
            work_id=work_id,
            snapshot=snapshot,
            ir=ir,
            discovery=discovery,
            report=report,
            ranking=ranking,
            context_plan=context_plan,
            scope=scope,
            pack=pack,
            prior_pack_ids=tuple(prior_pack_ids),
            candidates=pack_candidates,
            findings=pack_findings,
            retained_input_sha256s=retained,
        )
        _write_private_json(store / relative, packet.model_dump(mode="json"))
        risk = _packet_risk(packet)
        work_items.append(
            HunterWorkItem(
                work_id=work_id,
                run_id=run_id,
                source_snapshot=snapshot.snapshot_sha256,
                scan_scope_digest=context_plan.plan_sha256,
                planning_policy=BINARY_HUNTER_PLANNING_POLICY,
                slice_ids=(pack.pack_id,),
                seed_file=relative,
                files=files,
                hunter=BINARY_HUNTER,
                risk=risk,
                required=risk >= 4,
                routing_reasons=(
                    "static:binary-imageio-context-pack",
                    f"pack_sequence:{pack.sequence}",
                    f"static_findings:{len(packet.findings)}",
                ),
            )
        )
        prior_pack_ids.append(pack.pack_id)

    routing = HunterRoutingPlan(
        policy_version=BINARY_HUNTER_PLANNING_POLICY,
        mode="signal",
        legacy_sessions=len(context_plan.packs),
        work_items=tuple(work_items),
        scan_scope_digest=context_plan.plan_sha256,
    )
    admitted_count = min(len(work_items), budget.max_hunter_sessions)
    admitted = tuple(item.work_id for item in work_items[:admitted_count])
    deferred = tuple(item.work_id for item in work_items[admitted_count:])
    plan_digest = _hunter_plan_digest(
        run_id=run_id,
        scope_sha256=scope.scope_sha256,
        context_plan_sha256=context_plan.plan_sha256,
        routing=routing,
        admitted_work_ids=admitted,
        deferred_work_ids=deferred,
    )
    plan = BinaryHunterPlan(
        run_id=run_id,
        scope=scope,
        context_plan_sha256=context_plan.plan_sha256,
        routing=routing,
        admitted_work_ids=admitted,
        deferred_work_ids=deferred,
        plan_sha256=plan_digest,
    )
    plan_directory = store / "binary-hunter-plans"
    _private_directory(plan_directory)
    _write_private_json(
        plan_directory / f"binary-hunter-plan-{plan.plan_sha256.removeprefix('sha256:')[:24]}.json",
        plan.model_dump(mode="json"),
    )
    return plan


def load_binary_hunter_packet(
    *,
    store_root: Path,
    work_item: HunterWorkItem,
) -> BinaryHunterPacket:
    store = _private_store_root(store_root)
    packet_path = _contained_file(store, work_item.seed_file)
    packet = BinaryHunterPacket.model_validate_json(
        _read_file(packet_path, maximum=_MAX_PACKET_BYTES)
    )
    _validate_work_item_packet(work_item, packet)
    return packet


def validate_binary_hunter_assessment(
    packet: BinaryHunterPacket,
    assessment: BinaryHunterAssessment,
) -> None:
    if assessment.work_id != packet.work_id:
        raise ValueError("binary Hunter assessment changed the work ID")
    if assessment.pack_id != packet.pack.pack_id:
        raise ValueError("binary Hunter assessment changed the context pack ID")
    if assessment.pack_sequence != packet.pack.sequence:
        raise ValueError("binary Hunter assessment changed the context pack sequence")
    references = {item.evidence_id: item for item in packet.evidence_refs}
    cited = set(assessment.evidence_refs)
    for hypothesis in assessment.hypotheses:
        cited.update(hypothesis.supporting_evidence_ids)
        cited.update(hypothesis.contradicting_evidence_ids)
    for request in assessment.experiment_requests:
        cited.update(request.evidence_refs)
    if not cited.issubset(references):
        raise ValueError("binary Hunter cited evidence outside its packet")
    if not set(assessment.evidence_refs):
        raise ValueError("binary Hunter assessment must cite packet evidence")
    if assessment.disposition is BinaryHunterDisposition.STATIC_HYPOTHESIS:
        for hypothesis in assessment.hypotheses:
            kinds = {
                references[identifier].kind.value
                for identifier in hypothesis.supporting_evidence_ids
            }
            if BinaryHunterEvidenceKind.STATIC_FINDING.value not in kinds:
                raise ValueError("static hypothesis requires deterministic finding evidence")
            if not kinds.intersection(_INPUT_EVIDENCE_KINDS):
                raise ValueError("static hypothesis requires parser input/reachability evidence")
    partial_findings = {
        item.finding_id
        for item in packet.findings
        if item.vulnerability_class
        is BinaryVulnerabilityClass.PARTIAL_INITIALIZATION_DISCLOSURE
    }
    for hypothesis in assessment.hypotheses:
        if (
            hypothesis.vulnerability_class
            is not BinaryVulnerabilityClass.PARTIAL_INITIALIZATION_DISCLOSURE
        ):
            continue
        supporting = {
            references[identifier].kind
            for identifier in hypothesis.supporting_evidence_ids
        }
        static_subjects = {
            references[identifier].subject_id
            for identifier in hypothesis.supporting_evidence_ids
            if references[identifier].kind is BinaryHunterEvidenceKind.STATIC_FINDING
        }
        if not static_subjects.intersection(partial_findings):
            raise ValueError("disclosure hypothesis requires a partial finding")
        if not {
            BinaryHunterEvidenceKind.ALLOCATION_INITIALIZATION,
            BinaryHunterEvidenceKind.FULL_CONSUMPTION_OUTPUT,
        }.issubset(supporting):
            raise ValueError(
                "disclosure hypothesis requires allocation and full-consumption/output evidence"
            )
        if not {item.value for item in supporting}.intersection(_INPUT_EVIDENCE_KINDS):
            raise ValueError("disclosure hypothesis requires parser input/reachability evidence")
    allowed_functions = set(packet.known_function_ids)
    allowed_inputs = set(packet.retained_input_sha256s)
    for request in assessment.experiment_requests:
        if request.kind not in packet.allowed_experiments:
            raise ValueError("binary Hunter requested an experiment outside its allow-list")
        if request.retained_input_sha256 is not None:
            if request.retained_input_sha256 not in allowed_inputs:
                raise ValueError("binary experiment cites an unbound retained input")
        if not set(request.context_function_ids).issubset(allowed_functions):
            raise ValueError("binary context request cites an unknown ranked function")
    _validate_safe_output(assessment)


def plan_binary_experiments(
    *,
    packet: BinaryHunterPacket,
    assessment: BinaryHunterAssessment,
) -> tuple[BinaryExperimentPlan, ...]:
    """Convert model requests into deterministic plans without executing them."""

    validate_binary_hunter_assessment(packet, assessment)
    plans: list[BinaryExperimentPlan] = []
    for request in assessment.experiment_requests:
        status, capabilities = _experiment_status(request)
        route = (
            ImageIOAPIRoute.INCREMENTAL_DECODE
            if request.kind is BinaryExperimentKind.INCREMENTAL_CHUNK_SCHEDULE
            else request.route
        )
        parameters = {
            "baseline_route": (
                request.baseline_route.value if request.baseline_route is not None else None
            ),
            "boundary_values": list(request.boundary_values),
            "canary_value": request.canary_value,
            "context_function_ids": list(request.context_function_ids),
            "incremental_chunk_sizes": list(request.incremental_chunk_sizes),
            "retained_input_sha256": request.retained_input_sha256,
            "route": route.value if route is not None else None,
            "target_build": request.target_build,
            "target_field": request.target_field,
            "target_format": (
                request.target_format.value if request.target_format is not None else None
            ),
        }
        plan_id = _experiment_plan_id(
            work_id=packet.work_id,
            pack_id=packet.pack.pack_id,
            scope_sha256=packet.scope.scope_sha256,
            request_id=request.request_id,
            kind=request.kind,
            status=status,
            parameters=parameters,
        )
        plans.append(
            BinaryExperimentPlan(
                plan_id=plan_id,
                work_id=packet.work_id,
                pack_id=packet.pack.pack_id,
                scope_sha256=packet.scope.scope_sha256,
                request_id=request.request_id,
                hypothesis_id=request.hypothesis_id,
                kind=request.kind,
                status=status,
                execution_limit=(
                    request.execution_limit
                    if status is BinaryExperimentPlanStatus.REVIEW_REQUIRED
                    else 0
                ),
                parameters=parameters,
                oracle=request.expected_observation,
                falsification_condition=request.falsification_condition,
                required_capabilities=tuple(sorted(capabilities)),
                reviewer_question=(
                    "Does this bounded observation discriminate the cited static hypothesis "
                    "without broadening execution beyond the networkless disposable VM?"
                ),
            )
        )
    return tuple(plans)


async def run_binary_hunter_work_item(
    *,
    store_root: Path,
    work_item: HunterWorkItem,
    client: BinaryHunterModelClient,
    max_tokens: int = 5000,
) -> BinaryHunterRun:
    packet = load_binary_hunter_packet(store_root=store_root, work_item=work_item)
    assessment, usage, raw_responses = await BinaryHunterAgent(
        client=client,
        max_tokens=max_tokens,
    ).analyze(work_item, packet)
    plans = plan_binary_experiments(packet=packet, assessment=assessment)
    run = BinaryHunterRun(
        packet=packet,
        assessment=assessment,
        experiment_plans=plans,
        usage=usage,
        raw_responses=raw_responses,
    )
    _write_hunter_run(_private_store_root(store_root), work_item, run)
    return run


async def execute_binary_hunter_plan(
    *,
    plan: BinaryHunterPlan,
    store_root: Path,
    database: Path,
    client: BinaryHunterModelClient,
    budget: BudgetPolicy,
    worker_id: str = "binary-imageio-hunter-worker",
) -> tuple[BinaryHunterRun, ...]:
    """Run an admitted prefix; stop rather than skip when one pack is deferred."""

    plan = BinaryHunterPlan.model_validate(plan.model_dump(mode="json"))
    store = _private_store_root(store_root)
    items = plan.admitted_work_items
    if not items:
        return ()
    queue_store = DurableHuntQueueStore(store / "hunters", database, plan.run_id)
    queue_store.init_from_work_items(items)
    tasks = {task.work_id: task for task in queue_store.load().tasks}
    with SqliteRepository(database, read_only=True) as repository:
        prior_usage = repository.list_budget_usage(plan.run_id, scope="hunter")
    controller = BudgetController(
        budget,
        prior_usage,
        soft_input_token_stop=budget.max_input_tokens,
    )
    completed: set[str] = set()
    for item in items:
        if tasks[item.work_id].status == "done":
            _validate_completed_run(store, item)
            completed.add(item.work_id)
    results: list[BinaryHunterRun] = []
    for index, item in enumerate(items):
        predecessors = {value.work_id for value in items[:index]}
        if not predecessors.issubset(completed):
            break
        task = tasks[item.work_id]
        if task.status == "done":
            continue
        lease = queue_store.acquire(
            task,
            worker_id=worker_id,
            lease_seconds=max(60, budget.max_wall_clock_minutes * 60),
            max_attempts=budget.max_retries_per_work_item + 1,
        )
        if lease is None:
            break
        try:
            queue_store.mark_file_running(task)
            queue_store.mark_hunt_running(task, item.hunter)
            budgeted = BudgetedLLMClient(
                client,
                controller,
                work_id=item.work_id,
            )
            result = await run_binary_hunter_work_item(
                store_root=store,
                work_item=item,
                client=cast(BinaryHunterModelClient, budgeted),
                max_tokens=min(5000, budget.max_output_tokens),
            )
            with SqliteRepository(database) as repository:
                repository.save_budget_usage(result.usage)
            queue_store.mark_hunt_done(
                task,
                item.hunter,
                findings_count=len(result.assessment.hypotheses),
            )
            queue_store.mark_file_done(task)
            queue_store.finish(lease, status="done")
            completed.add(item.work_id)
            results.append(result)
        except BinaryHunterDeferred as exc:
            packet = load_binary_hunter_packet(store_root=store, work_item=item)
            _write_hunter_deferral(store, item, packet, exc)
            if exc.usage is not None:
                with SqliteRepository(database) as repository:
                    repository.save_budget_usage(exc.usage)
            queue_store.mark_hunt_deferred(task, item.hunter, exc.reason)
            queue_store.mark_file_deferred(task, exc.reason)
            queue_store.finish(lease, status="budget_deferred", error=exc.reason)
            break
        except Exception as exc:
            queue_store.mark_hunt_failed(task, item.hunter, str(exc))
            queue_store.mark_file_failed(task, str(exc))
            queue_store.finish(lease, status="failed", error=str(exc))
            raise
        finally:
            controller.finish_work(item.work_id)
    return tuple(results)


def _make_packet(
    *,
    work_id: str,
    snapshot: BinarySnapshot,
    ir: NormalizedBinaryIR,
    discovery: ImageIOParserDiscovery,
    report: BinaryAnalysisReport,
    ranking: BinaryFunctionRanking,
    context_plan: BinaryContextPlan,
    scope: BinaryResearchScope,
    pack: BinaryContextPack,
    prior_pack_ids: tuple[str, ...],
    candidates: tuple[ParserCandidate, ...],
    findings: tuple[BinaryStaticFinding, ...],
    retained_input_sha256s: tuple[str, ...],
) -> BinaryHunterPacket:
    refs = _packet_evidence_refs(
        scope=scope,
        snapshot_sha256=snapshot.snapshot_sha256,
        ir_sha256=ir.ir_sha256,
        discovery_sha256=discovery.discovery_sha256,
        report_sha256=report.report_sha256,
        ranking_sha256=ranking.ranking_sha256,
        context_plan_sha256=context_plan.plan_sha256,
        pack=pack,
        candidates=candidates,
        findings=findings,
    )
    payload = {
        "schema_version": "binary-hunter-packet-v1",
        "prompt_version": BINARY_HUNTER_PROMPT_VERSION,
        "work_id": work_id,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "ir_sha256": ir.ir_sha256,
        "discovery_sha256": discovery.discovery_sha256,
        "report_sha256": report.report_sha256,
        "ranking_sha256": ranking.ranking_sha256,
        "context_plan_sha256": context_plan.plan_sha256,
        "scope": scope.model_dump(mode="json"),
        "pack": pack.model_dump(mode="json"),
        "prior_pack_ids": prior_pack_ids,
        "known_function_ids": tuple(item.function_id for item in ranking.entries),
        "candidates": tuple(item.model_dump(mode="json") for item in candidates),
        "findings": tuple(item.model_dump(mode="json") for item in findings),
        "retained_input_sha256s": retained_input_sha256s,
        "evidence_refs": tuple(item.model_dump(mode="json") for item in refs),
        "allowed_experiments": tuple(item.value for item in BinaryExperimentKind),
        "host_execution_allowed": False,
        "network_allowed": False,
        "auto_execute": False,
    }
    return BinaryHunterPacket(**payload, packet_sha256=_packet_digest(payload))


def _validate_evidence_chain(
    snapshot: BinarySnapshot,
    ir: NormalizedBinaryIR,
    discovery: ImageIOParserDiscovery,
    report: BinaryAnalysisReport,
    ranking: BinaryFunctionRanking,
    context_plan: BinaryContextPlan,
    scope: BinaryResearchScope,
) -> None:
    BinarySnapshot.model_validate(snapshot.model_dump(mode="json"))
    NormalizedBinaryIR.model_validate(ir.model_dump(mode="json"))
    ImageIOParserDiscovery.model_validate(discovery.model_dump(mode="json"))
    BinaryAnalysisReport.model_validate(report.model_dump(mode="json"))
    BinaryFunctionRanking.model_validate(ranking.model_dump(mode="json"))
    BinaryContextPlan.model_validate(context_plan.model_dump(mode="json"))
    BinaryResearchScope.model_validate(scope.model_dump(mode="json"))
    if ir.snapshot_sha256 != snapshot.snapshot_sha256:
        raise ValueError("normalized IR is bound to a different binary snapshot")
    if discovery.ir_sha256 != ir.ir_sha256:
        raise ValueError("parser discovery is bound to a different normalized IR")
    if report.ir_sha256 != ir.ir_sha256 or report.discovery_sha256 != discovery.discovery_sha256:
        raise ValueError("binary analysis report is not bound to discovery and IR")
    if (
        ranking.ir_sha256 != ir.ir_sha256
        or ranking.discovery_sha256 != discovery.discovery_sha256
        or ranking.report_sha256 != report.report_sha256
    ):
        raise ValueError("binary ranking is not bound to its analysis inputs")
    if context_plan.ranking_sha256 != ranking.ranking_sha256:
        raise ValueError("binary context plan is bound to a different ranking")
    if context_plan.ranked_function_ids != tuple(item.function_id for item in ranking.entries):
        raise ValueError("binary context plan changed the ranked function order")
    if scope.snapshot_sha256 != snapshot.snapshot_sha256:
        raise ValueError("binary research scope is bound to a different snapshot")


def _validate_work_item_packet(
    item: HunterWorkItem,
    packet: BinaryHunterPacket,
) -> None:
    if item.planning_policy != BINARY_HUNTER_PLANNING_POLICY:
        raise ValueError("work item was not produced by binary Hunter planning")
    if item.hunter != BINARY_HUNTER:
        raise ValueError("work item is not assigned to the Binary Hunter")
    if item.work_id != packet.work_id:
        raise ValueError("binary Hunter packet is bound to a different work item")
    if item.source_snapshot != packet.snapshot_sha256:
        raise ValueError("binary Hunter work item changed the snapshot")
    if item.scan_scope_digest != packet.context_plan_sha256:
        raise ValueError("binary Hunter work item changed the context plan")
    if item.slice_ids != (packet.pack.pack_id,):
        raise ValueError("binary Hunter work item changed the context pack")
    if item.files != (item.seed_file,):
        raise ValueError("binary Hunter work item must contain exactly its packet")


def _packet_evidence_refs(
    *,
    scope: BinaryResearchScope,
    snapshot_sha256: str,
    ir_sha256: str,
    discovery_sha256: str,
    report_sha256: str,
    ranking_sha256: str,
    context_plan_sha256: str,
    pack: BinaryContextPack,
    candidates: tuple[ParserCandidate, ...],
    findings: tuple[BinaryStaticFinding, ...],
) -> tuple[BinaryHunterEvidenceRef, ...]:
    refs = [
        _evidence_ref(BinaryHunterEvidenceKind.SCOPE, scope.scope_sha256, scope.schema_version),
        _evidence_ref(BinaryHunterEvidenceKind.SNAPSHOT, snapshot_sha256, "binary-snapshot"),
        _evidence_ref(BinaryHunterEvidenceKind.IR, ir_sha256, "normalized-binary-ir"),
        _evidence_ref(
            BinaryHunterEvidenceKind.DISCOVERY,
            discovery_sha256,
            "imageio-parser-discovery",
        ),
        _evidence_ref(
            BinaryHunterEvidenceKind.STATIC_REPORT,
            report_sha256,
            "binary-static-analysis",
        ),
        _evidence_ref(BinaryHunterEvidenceKind.RANKING, ranking_sha256, "binary-ranking"),
        _evidence_ref(
            BinaryHunterEvidenceKind.CONTEXT_PLAN,
            context_plan_sha256,
            "binary-context-plan",
        ),
        _evidence_ref(
            BinaryHunterEvidenceKind.CONTEXT_PACK,
            pack.content_sha256,
            pack.pack_id,
        ),
    ]
    for finding in findings:
        finding_digest = _model_digest(finding)
        refs.append(
            _evidence_ref(
                BinaryHunterEvidenceKind.STATIC_FINDING,
                finding_digest,
                finding.finding_id,
            )
        )
        if (
            finding.vulnerability_class
            is BinaryVulnerabilityClass.PARTIAL_INITIALIZATION_DISCLOSURE
        ):
            refs.extend(
                (
                    _evidence_ref(
                        BinaryHunterEvidenceKind.ALLOCATION_INITIALIZATION,
                        finding_digest,
                        f"{finding.finding_id}:allocation-initialization",
                    ),
                    _evidence_ref(
                        BinaryHunterEvidenceKind.FULL_CONSUMPTION_OUTPUT,
                        finding_digest,
                        f"{finding.finding_id}:full-consumption-output",
                    ),
                )
            )
    for candidate in candidates:
        for evidence in candidate.evidence:
            refs.append(
                _evidence_ref(
                    _parser_evidence_kind(evidence.kind),
                    _model_digest(evidence),
                    f"{candidate.candidate_id}:0x{(evidence.address or candidate.start_address):x}",
                )
            )
    return tuple(
        sorted(refs, key=lambda item: (item.kind.value, item.subject_id, item.evidence_id))
    )


def _parser_evidence_kind(kind: ParserEvidenceKind) -> BinaryHunterEvidenceKind:
    return {
        ParserEvidenceKind.INPUT_MARKER: BinaryHunterEvidenceKind.PARSER_INPUT,
        ParserEvidenceKind.API_CALL: BinaryHunterEvidenceKind.PARSER_API,
        ParserEvidenceKind.FORMAT_STRING: BinaryHunterEvidenceKind.PARSER_FORMAT,
    }.get(kind, BinaryHunterEvidenceKind.PARSER_OTHER)


def _evidence_ref(
    kind: BinaryHunterEvidenceKind,
    artifact_sha256: str,
    subject_id: str,
) -> BinaryHunterEvidenceRef:
    identity = f"{kind.value}\x00{artifact_sha256}\x00{subject_id}".encode()
    return BinaryHunterEvidenceRef(
        evidence_id="binevidence_" + hashlib.sha256(identity).hexdigest()[:20],
        kind=kind,
        artifact_sha256=artifact_sha256,
        subject_id=subject_id,
    )


def _experiment_status(
    request: BinaryExperimentRequest,
) -> tuple[BinaryExperimentPlanStatus, tuple[str, ...]]:
    if request.kind is BinaryExperimentKind.BINARY_CONTEXT:
        return BinaryExperimentPlanStatus.REQUIRES_CONTEXT, ("bounded_pr5_context_pack",)
    if request.kind is BinaryExperimentKind.CROSS_BUILD_REPLAY:
        return BinaryExperimentPlanStatus.REQUIRES_SNAPSHOT, ("approved_os_build_snapshot",)
    if request.kind is BinaryExperimentKind.GUARD_MALLOC:
        return BinaryExperimentPlanStatus.REQUIRES_HARNESS, ("attested_guard_malloc_harness",)
    if request.retained_input_sha256 is None:
        return BinaryExperimentPlanStatus.REQUIRES_HARNESS, ("retained_private_input",)
    if (
        request.kind is BinaryExperimentKind.STRUCTURED_FIELD_BOUNDARY
        and request.target_format is not BinaryFormatFamily.DICOM
    ):
        return BinaryExperimentPlanStatus.REQUIRES_HARNESS, (
            "format_aware_mutator",
            "retained_private_input",
        )
    if request.kind is BinaryExperimentKind.RAW_OUTPUT_DIFFERENTIAL:
        return BinaryExperimentPlanStatus.REVIEW_REQUIRED, (
            "networkless_disposable_vm",
            "raw_output_capture_oracle",
            "retained_private_input",
        )
    if request.kind is BinaryExperimentKind.CANARY_PROPAGATION:
        return BinaryExperimentPlanStatus.REVIEW_REQUIRED, (
            "canary_initialized_allocator_harness",
            "networkless_disposable_vm",
            "retained_private_input",
        )
    return BinaryExperimentPlanStatus.REVIEW_REQUIRED, (
        "exact_observation_oracle",
        "networkless_disposable_vm",
        "retained_private_input",
    )


def _validate_safe_output(assessment: BinaryHunterAssessment) -> None:
    values = [assessment.summary, *assessment.unresolved_questions]
    for hypothesis in assessment.hypotheses:
        values.extend(
            (
                hypothesis.title,
                hypothesis.input_control,
                hypothesis.parser_state,
                hypothesis.security_relation,
                hypothesis.root_cause_hypothesis,
                hypothesis.falsification_condition,
            )
        )
    for request in assessment.experiment_requests:
        values.extend(
            (request.rationale, request.expected_observation, request.falsification_condition)
        )
    for value in values:
        if any(ord(character) < 32 and character not in "\n\r\t" for character in value):
            raise ValueError("binary Hunter output contains unsafe control characters")
        for label, pattern in _PROHIBITED_OUTPUT_PATTERNS:
            if pattern.search(value):
                raise ValueError(f"binary Hunter output contains prohibited {label}")


def _packet_risk(packet: BinaryHunterPacket) -> int:
    weights = {
        BinaryFindingSeverity.CRITICAL: 5,
        BinaryFindingSeverity.HIGH: 4,
        BinaryFindingSeverity.MEDIUM: 3,
    }
    return max((weights[item.severity] for item in packet.findings), default=2)


def _write_hunter_run(
    store: Path,
    item: HunterWorkItem,
    run: BinaryHunterRun,
) -> None:
    directory = store / "hunters" / item.work_id / "binary-analysis"
    _private_directory(directory)
    payloads = {
        "packet.json": run.packet.model_dump(mode="json"),
        "assessment.json": run.assessment.model_dump(mode="json"),
        "experiment-plans.json": [item.model_dump(mode="json") for item in run.experiment_plans],
        "usage.json": run.usage.model_dump(mode="json"),
    }
    for name, payload in payloads.items():
        _write_private_json(directory / name, payload)
    for index, response in enumerate(run.raw_responses, start=1):
        _write_private_bytes(
            directory / f"raw-response-{index:02d}.txt",
            response.encode()[:_MAX_RAW_RESPONSE_BYTES],
        )


def _write_hunter_deferral(
    store: Path,
    item: HunterWorkItem,
    packet: BinaryHunterPacket,
    deferred: BinaryHunterDeferred,
) -> None:
    usage_payload = deferred.usage.model_dump(mode="json") if deferred.usage is not None else None
    response_digests = tuple(
        "sha256:" + hashlib.sha256(value.encode()).hexdigest() for value in deferred.raw_responses
    )
    attempt_identity = {
        "packet_sha256": packet.packet_sha256,
        "reason": deferred.reason,
        "response_digests": response_digests,
        "usage": usage_payload,
    }
    attempt_id = hashlib.sha256(_canonical_json(attempt_identity)).hexdigest()[:24]
    directory = (
        store / "hunters" / item.work_id / "binary-analysis" / "deferrals" / f"attempt-{attempt_id}"
    )
    _private_directory(directory)
    _write_private_json(directory / "packet.json", packet.model_dump(mode="json"))
    _write_private_json(
        directory / "deferral.json",
        {
            "schema_version": "binary-hunter-deferral-v1",
            "work_id": item.work_id,
            "pack_id": packet.pack.pack_id,
            "reason": deferred.reason,
            "model_calls": len(deferred.raw_responses),
            "response_digests": response_digests,
        },
    )
    if usage_payload is not None:
        _write_private_json(directory / "usage.json", usage_payload)
    for index, response in enumerate(deferred.raw_responses, start=1):
        _write_private_bytes(
            directory / f"raw-response-{index:02d}.txt",
            response.encode()[:_MAX_RAW_RESPONSE_BYTES],
        )


def _validate_completed_run(store: Path, item: HunterWorkItem) -> None:
    source_packet = load_binary_hunter_packet(store_root=store, work_item=item)
    directory = store / "hunters" / item.work_id / "binary-analysis"
    packet_path = _contained_file(
        store, directory.joinpath("packet.json").relative_to(store).as_posix()
    )
    assessment_path = _contained_file(
        store,
        directory.joinpath("assessment.json").relative_to(store).as_posix(),
    )
    plans_path = _contained_file(
        store,
        directory.joinpath("experiment-plans.json").relative_to(store).as_posix(),
    )
    persisted_packet = BinaryHunterPacket.model_validate_json(
        _read_file(packet_path, maximum=_MAX_PACKET_BYTES)
    )
    if persisted_packet.packet_sha256 != source_packet.packet_sha256:
        raise RuntimeError("completed Binary Hunter run is bound to a different packet")
    assessment = BinaryHunterAssessment.model_validate_json(
        _read_file(assessment_path, maximum=_MAX_RAW_RESPONSE_BYTES)
    )
    validate_binary_hunter_assessment(source_packet, assessment)
    planned_payload = json.loads(_read_file(plans_path, maximum=_MAX_RAW_RESPONSE_BYTES))
    persisted_plans = tuple(BinaryExperimentPlan.model_validate(value) for value in planned_payload)
    expected_plans = plan_binary_experiments(packet=source_packet, assessment=assessment)
    if persisted_plans != expected_plans:
        raise RuntimeError("completed Binary Hunter experiment plans changed after review")


def _budget_usage(
    work_item: HunterWorkItem,
    client: BinaryHunterModelClient,
    calls: int,
    totals: dict[str, int],
) -> BudgetUsage:
    return with_estimated_cost(
        BudgetUsage(
            run_id=work_item.run_id,
            work_id=work_item.work_id,
            scope="hunter",
            model_id=str(client.model_id),
            transport=str(getattr(client, "transport", "bedrock_converse")),
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
        raise ValueError("Binary Hunter store may not be a symbolic link")
    resolved = expanded.resolve(strict=True)
    if not resolved.is_dir() or any(
        (candidate / ".git").exists() for candidate in (resolved, *resolved.parents)
    ):
        raise ValueError("Binary Hunter store must be a private directory outside Git")
    return resolved


def _contained_file(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("Binary Hunter artifact path escapes its private store")
    path = root / candidate
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not resolved.is_file() or root not in resolved.parents:
        raise ValueError("Binary Hunter artifact is not a contained regular file")
    return resolved


def _read_file(path: Path, *, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"Binary Hunter artifact is missing or unsafe: {path}")
    if path.stat().st_size > maximum:
        raise RuntimeError(f"Binary Hunter artifact exceeds its limit: {path}")
    return path.read_bytes()


def _private_directory(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError("Binary Hunter output directory may not be a symbolic link")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _write_private_json(path: Path, payload: object) -> None:
    encoded = json.dumps(payload, indent=2, sort_keys=True).encode() + b"\n"
    _write_private_bytes(path, encoded)


def _write_private_bytes(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise RuntimeError("Binary Hunter output may not be a symbolic link")
    _private_directory(path.parent)
    if path.exists():
        if not path.is_file() or path.read_bytes() != payload:
            raise FileExistsError("immutable Binary Hunter artifact already contains other data")
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


def _scope_digest(payload: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload)).hexdigest()


def _packet_digest(payload: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload)).hexdigest()


def _model_digest(model: DomainModel) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(model.model_dump(mode="json"))).hexdigest()


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _hunter_plan_digest(
    *,
    run_id: str,
    scope_sha256: str,
    context_plan_sha256: str,
    routing: HunterRoutingPlan,
    admitted_work_ids: tuple[str, ...],
    deferred_work_ids: tuple[str, ...],
) -> str:
    payload = {
        "admitted_work_ids": admitted_work_ids,
        "context_plan_sha256": context_plan_sha256,
        "deferred_work_ids": deferred_work_ids,
        "routing": routing.model_dump(mode="json"),
        "run_id": run_id,
        "schema_version": "binary-hunter-plan-v1",
        "scope_sha256": scope_sha256,
    }
    return "sha256:" + hashlib.sha256(_canonical_json(payload)).hexdigest()


def _experiment_plan_id(
    *,
    work_id: str,
    pack_id: str,
    scope_sha256: str,
    request_id: str,
    kind: BinaryExperimentKind,
    status: BinaryExperimentPlanStatus,
    parameters: dict,
) -> str:
    payload = {
        "kind": kind.value,
        "pack_id": pack_id,
        "parameters": parameters,
        "policy_version": BINARY_EXPERIMENT_POLICY,
        "request_id": request_id,
        "scope_sha256": scope_sha256,
        "status": status.value,
        "work_id": work_id,
    }
    return "binary-plan-" + hashlib.sha256(_canonical_json(payload)).hexdigest()[:32]
