"""ImageIO-specific Hunter and reviewer-gated experiment planning.

This module consumes the same ``HunterWorkItem`` and durable queue used by the
source-guided pipeline, but uses a closed-source evidence packet rather than C
source ranges. The Hunter can propose discriminating experiments; it cannot
execute them or advance a finding without an independent review decision.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol, cast

from pydantic import Field, model_validator

from ..agents.durable_queue import DurableHuntQueueStore
from ..core.jsonx import try_extract_object
from ..core.llm import LLMResponse
from ..domain.schemas import BudgetPolicy, BudgetUsage, DomainModel, HunterWorkItem
from ..infrastructure.sqlite_repository import SqliteRepository
from ..reporting.apple_cve import AppleCrashClass
from ..scheduling.metrics import with_estimated_cost
from ..scheduling.budget import BudgetController, BudgetedLLMClient, BudgetExceededError
from .imageio_crashes import (
    IMAGEIO_CRASH_HUNTER,
    IMAGEIO_CRASH_RANKING_POLICY,
    ImageIOCrashCluster,
    ImageIOCrashHunterPlan,
    ImageIOCrashTriageClass,
)
from .imageio_fuzzer import ImageIOFuzzCaseResult
from .imageio_inventory import ImageIOAPIRoute

IMAGEIO_HUNTER_PROMPT_VERSION: Literal["imageio-crash-hunter-v1"] = "imageio-crash-hunter-v1"
IMAGEIO_EXPERIMENT_POLICY: Literal["imageio-experiment-planning-v1"] = (
    "imageio-experiment-planning-v1"
)
_MAX_CLUSTER_BYTES = 8 * 1024 * 1024
_MAX_CASE_BYTES = 8 * 1024 * 1024
_MAX_CRASH_EXCERPT_BYTES = 32 * 1024
_MAX_BINARY_CONTEXT_BYTES = 96 * 1024
_MAX_DICOM_ELEMENTS = 64
_DICOM_LONG_VRS = {b"OB", b"OD", b"OF", b"OL", b"OW", b"SQ", b"UC", b"UR", b"UT", b"UN"}

SYSTEM_PROMPT = """You are the ImageIO crash-analysis Hunter.

You receive one already-deduplicated crash cluster from a networkless macOS VM.
The packet may include DICOM mutation provenance, normalized stack frames, raw
crash-log excerpts, and bounded decompiler context. Treat a crash as evidence,
not as proof of a vulnerability.

For each hypothesis:
- identify the attacker-controlled field or byte relationship;
- state the parser state and the size/allocation/use relation that may fail;
- distinguish direct evidence from inference;
- state exactly what would falsify the hypothesis;
- cite only evidence_ref IDs present in the packet.
- cite both retained input and crash-log evidence before naming a memory-safety class.

Propose the smallest discriminating experiment. Do not provide shell commands,
exploit steps, persistence, network activity, host execution, or public
disclosure instructions. Experiments run only through the existing disposable
networkless VM harness after independent review. If bounded binary context is
required, request it rather than inventing implementation details.

Output only this JSON object:
{
  "work_id": "<exact packet work_id>",
  "cluster_id": "<exact packet cluster_id>",
  "disposition": "memory_safety_hypothesis|needs_binary_context|low_value_crash|inconclusive",
  "summary": "<evidence-grounded summary>",
  "hypotheses": [
    {
      "hypothesis_id": "hypothesis-<stable short label>",
      "title": "<concise>",
      "proposed_crash_class": null | "out_of_bounds_read|out_of_bounds_write|use_after_free|heap_corruption|integer_overflow|type_confusion|other_memory_corruption",
      "attacker_control": "<controlled bytes/fields and limits>",
      "parser_state": "<state before failure>",
      "size_allocation_relation": "<allocation/length/index relationship or unknown>",
      "root_cause_hypothesis": "<mechanism, clearly marked as hypothesis>",
      "falsification_condition": "<observable result that disproves it>",
      "confidence": 0.0,
      "evidence_refs": ["<packet evidence_ref ID>"]
    }
  ],
  "experiment_proposals": [
    {
      "proposal_id": "experiment-<stable short label>",
      "hypothesis_id": "<one hypothesis_id>",
      "kind": "exact_replay|route_differential|field_boundary|incremental_chunk_schedule|guard_malloc|binary_context|cross_build_replay",
      "rationale": "<why this distinguishes the hypothesis>",
      "route": null | "data_properties|image_properties|thumbnail_decode|full_decode|incremental_decode",
      "target_tag": null | "GGGG,EEEE",
      "boundary_values": [],
      "incremental_chunk_sizes": [],
      "execution_limit": 1,
      "expected_observation": "<supporting result>",
      "falsification_condition": "<rejecting result>"
    }
  ],
  "evidence_refs": ["<all packet evidence IDs relied on>"],
  "unresolved_questions": ["<bounded unknown>"]
}
"""


class ImageIOHunterDisposition(StrEnum):
    MEMORY_SAFETY_HYPOTHESIS = "memory_safety_hypothesis"
    NEEDS_BINARY_CONTEXT = "needs_binary_context"
    LOW_VALUE_CRASH = "low_value_crash"
    INCONCLUSIVE = "inconclusive"


class ImageIOExperimentKind(StrEnum):
    EXACT_REPLAY = "exact_replay"
    ROUTE_DIFFERENTIAL = "route_differential"
    FIELD_BOUNDARY = "field_boundary"
    INCREMENTAL_CHUNK_SCHEDULE = "incremental_chunk_schedule"
    GUARD_MALLOC = "guard_malloc"
    BINARY_CONTEXT = "binary_context"
    CROSS_BUILD_REPLAY = "cross_build_replay"


class ImageIOExperimentPlanStatus(StrEnum):
    REVIEW_REQUIRED = "review_required"
    REQUIRES_HARNESS = "requires_harness"
    REQUIRES_BINARY_CONTEXT = "requires_binary_context"
    REQUIRES_SNAPSHOT = "requires_snapshot"
    UNSUPPORTED = "unsupported"


class ImageIOBinaryContext(DomainModel):
    context_id: str = Field(pattern=r"^binary-context-[0-9a-f]{16,64}$")
    image_name: str = Field(min_length=1, max_length=200)
    symbol: str = Field(min_length=1, max_length=500)
    producer: str = Field(min_length=1, max_length=100)
    artifact_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    pseudocode: str = Field(min_length=1, max_length=_MAX_BINARY_CONTEXT_BYTES)

    @model_validator(mode="after")
    def verify_context_digest(self) -> "ImageIOBinaryContext":
        if _sha256_bytes(self.pseudocode.encode()) != self.artifact_sha256:
            raise ValueError("binary context digest does not match its pseudocode")
        return self


class ImageIOHunterEvidenceRef(DomainModel):
    evidence_id: str = Field(pattern=r"^imageio-evidence-[0-9a-f]{20}$")
    kind: Literal["cluster", "case", "input", "crash_log", "binary_context"]
    artifact_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    path: str | None = None


class ImageIODICOMElementSlice(DomainModel):
    tag: str = Field(pattern=r"^[0-9A-F]{4},[0-9A-F]{4}$")
    offset: int = Field(ge=132)
    vr: str = Field(pattern=r"^[A-Z]{2}$")
    declared_length: int = Field(ge=0, le=0xFFFFFFFF)
    value_preview_hex: str = Field(pattern=r"^(?:[0-9a-f]{2}){0,16}$")


class ImageIODICOMGrammarSlice(DomainModel):
    schema_version: Literal["imageio-dicom-grammar-slice-v1"] = "imageio-dicom-grammar-slice-v1"
    input_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    input_size_bytes: int = Field(ge=0)
    transfer_syntax: Literal["explicit_vr_little_endian"] = "explicit_vr_little_endian"
    elements: tuple[ImageIODICOMElementSlice, ...] = Field(max_length=_MAX_DICOM_ELEMENTS)
    parse_complete: bool
    parse_stop_reason: str = Field(max_length=300)


class ImageIOHunterPacket(DomainModel):
    schema_version: Literal["imageio-hunter-packet-v1"] = "imageio-hunter-packet-v1"
    prompt_version: Literal["imageio-crash-hunter-v1"] = IMAGEIO_HUNTER_PROMPT_VERSION
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    cluster: ImageIOCrashCluster
    representative_case: dict
    representative_execution: dict
    format_grammar: ImageIODICOMGrammarSlice
    crash_log_excerpt: str = Field(max_length=_MAX_CRASH_EXCERPT_BYTES)
    binary_contexts: tuple[ImageIOBinaryContext, ...] = Field(max_length=8)
    evidence_refs: tuple[ImageIOHunterEvidenceRef, ...] = Field(min_length=3, max_length=12)
    allowed_experiments: tuple[ImageIOExperimentKind, ...] = tuple(ImageIOExperimentKind)
    host_execution_allowed: Literal[False] = False
    network_allowed: Literal[False] = False

    @model_validator(mode="after")
    def validate_packet_refs(self) -> "ImageIOHunterPacket":
        identifiers = [item.evidence_id for item in self.evidence_refs]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("ImageIO Hunter packet contains duplicate evidence IDs")
        return self


class ImageIOHunterHypothesis(DomainModel):
    hypothesis_id: str = Field(pattern=r"^hypothesis-[a-z0-9][a-z0-9-]{2,80}$")
    title: str = Field(min_length=1, max_length=300)
    proposed_crash_class: AppleCrashClass | None = None
    attacker_control: str = Field(min_length=1, max_length=2000)
    parser_state: str = Field(min_length=1, max_length=2000)
    size_allocation_relation: str = Field(min_length=1, max_length=2000)
    root_cause_hypothesis: str = Field(min_length=1, max_length=3000)
    falsification_condition: str = Field(min_length=1, max_length=2000)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=12)

    @model_validator(mode="after")
    def require_memory_safety_class(self) -> "ImageIOHunterHypothesis":
        allowed = {
            AppleCrashClass.OUT_OF_BOUNDS_READ,
            AppleCrashClass.OUT_OF_BOUNDS_WRITE,
            AppleCrashClass.USE_AFTER_FREE,
            AppleCrashClass.HEAP_CORRUPTION,
            AppleCrashClass.INTEGER_OVERFLOW,
            AppleCrashClass.TYPE_CONFUSION,
            AppleCrashClass.OTHER_MEMORY_CORRUPTION,
        }
        if self.proposed_crash_class is not None and self.proposed_crash_class not in allowed:
            raise ValueError("ImageIO Hunter may classify only memory-safety hypotheses")
        return self


class ImageIOExperimentProposal(DomainModel):
    proposal_id: str = Field(pattern=r"^experiment-[a-z0-9][a-z0-9-]{2,80}$")
    hypothesis_id: str = Field(pattern=r"^hypothesis-[a-z0-9][a-z0-9-]{2,80}$")
    kind: ImageIOExperimentKind
    rationale: str = Field(min_length=1, max_length=2000)
    route: ImageIOAPIRoute | None = None
    target_tag: str | None = Field(default=None, pattern=r"^[0-9A-F]{4},[0-9A-F]{4}$")
    boundary_values: tuple[int, ...] = Field(default=(), max_length=8)
    incremental_chunk_sizes: tuple[int, ...] = Field(default=(), max_length=8)
    execution_limit: int = Field(ge=1, le=6)
    expected_observation: str = Field(min_length=1, max_length=2000)
    falsification_condition: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def validate_kind_parameters(self) -> "ImageIOExperimentProposal":
        if any(value < 0 or value > 0xFFFFFFFF for value in self.boundary_values):
            raise ValueError("field-boundary values must fit an unsigned 32-bit field")
        if any(value < 1 or value > 1024 * 1024 for value in self.incremental_chunk_sizes):
            raise ValueError("incremental chunk size is outside the harness limit")
        if self.kind is ImageIOExperimentKind.FIELD_BOUNDARY and self.target_tag is None:
            raise ValueError("field-boundary experiment requires a target tag")
        if self.kind is ImageIOExperimentKind.FIELD_BOUNDARY and not self.boundary_values:
            raise ValueError("field-boundary experiment requires boundary values")
        if (
            self.kind is ImageIOExperimentKind.INCREMENTAL_CHUNK_SCHEDULE
            and not self.incremental_chunk_sizes
        ):
            raise ValueError("incremental schedule experiment requires chunk sizes")
        return self


class ImageIOHunterAssessment(DomainModel):
    schema_version: Literal["imageio-hunter-assessment-v1"] = "imageio-hunter-assessment-v1"
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    cluster_id: str = Field(pattern=r"^imageio-cluster-[0-9a-f]{32}$")
    disposition: ImageIOHunterDisposition
    summary: str = Field(min_length=1, max_length=4000)
    hypotheses: tuple[ImageIOHunterHypothesis, ...] = Field(max_length=4)
    experiment_proposals: tuple[ImageIOExperimentProposal, ...] = Field(max_length=8)
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=12)
    unresolved_questions: tuple[str, ...] = Field(max_length=12)

    @model_validator(mode="after")
    def validate_hypothesis_links(self) -> "ImageIOHunterAssessment":
        hypothesis_ids = [item.hypothesis_id for item in self.hypotheses]
        if len(set(hypothesis_ids)) != len(hypothesis_ids):
            raise ValueError("ImageIO Hunter returned duplicate hypothesis IDs")
        proposal_ids = [item.proposal_id for item in self.experiment_proposals]
        if len(set(proposal_ids)) != len(proposal_ids):
            raise ValueError("ImageIO Hunter returned duplicate proposal IDs")
        if any(
            proposal.hypothesis_id not in set(hypothesis_ids)
            for proposal in self.experiment_proposals
        ):
            raise ValueError("experiment proposal references an unknown hypothesis")
        if (
            self.disposition is ImageIOHunterDisposition.MEMORY_SAFETY_HYPOTHESIS
            and not self.hypotheses
        ):
            raise ValueError("memory-safety disposition requires a hypothesis")
        return self


class ImageIOExperimentPlan(DomainModel):
    schema_version: Literal["imageio-experiment-plan-v1"] = "imageio-experiment-plan-v1"
    policy_version: Literal["imageio-experiment-planning-v1"] = IMAGEIO_EXPERIMENT_POLICY
    plan_id: str = Field(pattern=r"^imageio-plan-[0-9a-f]{32}$")
    work_id: str = Field(pattern=r"^work_[0-9a-f]{64}$")
    cluster_id: str = Field(pattern=r"^imageio-cluster-[0-9a-f]{32}$")
    proposal_id: str
    hypothesis_id: str
    kind: ImageIOExperimentKind
    status: ImageIOExperimentPlanStatus
    route: ImageIOAPIRoute | None = None
    target_signature_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    execution_limit: int = Field(ge=0, le=6)
    parameters: dict
    oracle: str = Field(min_length=1, max_length=2000)
    falsification_condition: str = Field(min_length=1, max_length=2000)
    required_capabilities: tuple[str, ...]
    reviewer_question: str = Field(min_length=1, max_length=2000)
    auto_execute: Literal[False] = False


class ImageIOExperimentReview(DomainModel):
    schema_version: Literal["imageio-experiment-review-v1"] = "imageio-experiment-review-v1"
    plan_id: str
    reviewer: str = Field(min_length=1, max_length=200)
    approved: bool
    rationale: str = Field(min_length=1, max_length=2000)
    reviewed_at: datetime

    @model_validator(mode="after")
    def require_aware_review_time(self) -> "ImageIOExperimentReview":
        if self.reviewed_at.tzinfo is None:
            raise ValueError("experiment review timestamp must include a timezone")
        return self


class ImageIOHunterModelClient(Protocol):
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
class ImageIOHunterRun:
    packet: ImageIOHunterPacket
    assessment: ImageIOHunterAssessment
    experiment_plans: tuple[ImageIOExperimentPlan, ...]
    usage: BudgetUsage


class ImageIOHunterBudgetDeferred(RuntimeError):
    def __init__(self, reason: str, usage: BudgetUsage | None = None) -> None:
        self.reason = reason
        self.usage = usage
        super().__init__(f"ImageIO Hunter budget deferred: {reason}")


def build_imageio_hunter_packet(
    *,
    store_root: Path,
    work_item: HunterWorkItem,
    binary_contexts: Sequence[ImageIOBinaryContext] = (),
) -> ImageIOHunterPacket:
    """Build a bounded packet and verify every private artifact against PR5."""

    store = _private_store_root(store_root)
    if work_item.planning_policy != IMAGEIO_CRASH_RANKING_POLICY:
        raise ValueError("work item was not produced by ImageIO crash ranking")
    if work_item.hunter != IMAGEIO_CRASH_HUNTER:
        raise ValueError("work item is not assigned to the ImageIO Hunter")
    cluster_path = _contained_file(store, work_item.seed_file)
    cluster_payload = _read_file(cluster_path, maximum=_MAX_CLUSTER_BYTES)
    cluster = ImageIOCrashCluster.model_validate_json(cluster_payload)
    if work_item.slice_ids != (cluster.cluster_id,):
        raise ValueError("work item is bound to a different crash cluster")
    if work_item.scan_scope_digest != cluster.signature_sha256:
        raise ValueError("work item scope digest does not match the crash signature")
    if work_item.risk != cluster.risk or work_item.required != (
        cluster.triage_class is ImageIOCrashTriageClass.STRONG_MEMORY_SAFETY
    ):
        raise ValueError("work item priority changed after crash ranking")
    representative = cluster.representative
    case_path = _contained_file(store, representative.case_result_path)
    case_payload = _read_file(case_path, maximum=_MAX_CASE_BYTES)
    case = ImageIOFuzzCaseResult.model_validate_json(case_payload)
    execution = next(
        (
            item
            for item in case.executions
            if item.route is representative.route
            and item.evidence.input_sha256 == representative.input_sha256
        ),
        None,
    )
    if execution is None:
        raise RuntimeError("representative crash execution is missing from its case")
    context_inputs = tuple(
        _contained_file(store, path) for path in work_item.files if Path(path).name == "input.dcm"
    )
    if len(context_inputs) != 1:
        raise RuntimeError("ImageIO Hunter work item must have one retained input")
    context_input_path = context_inputs[0]
    input_payload = _read_file(
        context_input_path,
        maximum=execution.evidence.limits.max_input_bytes,
    )
    if _sha256_bytes(input_payload) != representative.input_sha256:
        raise RuntimeError("retained Hunter input changed after crash ranking")
    crash_paths = tuple(
        _contained_file(store, path) for path in work_item.files if Path(path).name == "crash.log"
    )
    crash_path = crash_paths[0] if len(crash_paths) == 1 else None
    crash_payload = b""
    if representative.crash_log_sha256 is not None:
        if crash_path is None:
            raise RuntimeError("representative crash log path is missing")
        full_crash = _read_file(
            crash_path,
            maximum=execution.evidence.limits.max_output_bytes,
        )
        if _sha256_bytes(full_crash) != representative.crash_log_sha256:
            raise RuntimeError("representative crash log changed after clustering")
        crash_payload = full_crash[:_MAX_CRASH_EXCERPT_BYTES]
    contexts = tuple(binary_contexts)
    if sum(len(item.pseudocode.encode()) for item in contexts) > _MAX_BINARY_CONTEXT_BYTES:
        raise ValueError("binary contexts exceed the ImageIO Hunter packet limit")
    refs = [
        _evidence_ref("cluster", _sha256_bytes(cluster_payload), work_item.seed_file),
        _evidence_ref(
            "case",
            _sha256_bytes(case_payload),
            representative.case_result_path,
        ),
        _evidence_ref(
            "input",
            representative.input_sha256,
            context_input_path.relative_to(store).as_posix(),
        ),
        _evidence_ref(
            "crash_log",
            representative.crash_log_sha256 or _sha256_bytes(b""),
            crash_path.relative_to(store).as_posix() if crash_path is not None else None,
        ),
    ]
    refs.extend(_evidence_ref("binary_context", item.artifact_sha256, None) for item in contexts)
    return ImageIOHunterPacket(
        work_id=work_item.work_id,
        cluster=cluster,
        representative_case=case.case.model_dump(mode="json"),
        representative_execution=execution.model_dump(mode="json"),
        format_grammar=_dicom_grammar_slice(input_payload),
        crash_log_excerpt=crash_payload.decode("utf-8", errors="replace"),
        binary_contexts=contexts,
        evidence_refs=tuple(refs),
    )


@dataclass
class ImageIOHunterAgent:
    client: ImageIOHunterModelClient
    max_attempts: int = 2
    max_tokens: int = 5000

    async def analyze(
        self,
        work_item: HunterWorkItem,
        packet: ImageIOHunterPacket,
    ) -> tuple[ImageIOHunterAssessment, BudgetUsage]:
        messages: list[dict] = [
            {
                "role": "user",
                "content": [
                    {
                        "text": "# ImageIO crash evidence packet\n"
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
        assessment: ImageIOHunterAssessment | None = None
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
                usage = (
                    _budget_usage(
                        work_item=work_item,
                        client=self.client,
                        calls=calls,
                        totals=totals,
                    )
                    if calls
                    else None
                )
                raise ImageIOHunterBudgetDeferred(exc.reason, usage) from exc
            calls += 1
            for field in totals:
                totals[field] += int(getattr(response, field))
            parsed = try_extract_object(response.text)
            try:
                if parsed is not None:
                    candidate = ImageIOHunterAssessment.model_validate(parsed)
                    _validate_assessment(packet, candidate)
                    assessment = candidate
                    break
            except ValueError:
                pass
            messages.append({"role": "assistant", "content": response.content_blocks})
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "text": (
                                "Return only a schema-valid JSON object. Preserve the exact "
                                "work_id and cluster_id and cite only packet evidence IDs."
                            )
                        }
                    ],
                }
            )
        if assessment is None:
            raise RuntimeError("ImageIO Hunter did not return a valid evidence-bound assessment")
        usage = _budget_usage(
            work_item=work_item,
            client=self.client,
            calls=calls,
            totals=totals,
        )
        return assessment, usage


async def run_imageio_hunter_work_item(
    *,
    store_root: Path,
    work_item: HunterWorkItem,
    client: ImageIOHunterModelClient,
    binary_contexts: Sequence[ImageIOBinaryContext] = (),
    max_tokens: int = 5000,
) -> ImageIOHunterRun:
    packet = build_imageio_hunter_packet(
        store_root=store_root,
        work_item=work_item,
        binary_contexts=binary_contexts,
    )
    assessment, usage = await ImageIOHunterAgent(
        client,
        max_tokens=max_tokens,
    ).analyze(work_item, packet)
    plans = plan_imageio_experiments(packet=packet, assessment=assessment)
    run = ImageIOHunterRun(
        packet=packet,
        assessment=assessment,
        experiment_plans=plans,
        usage=usage,
    )
    _write_hunter_run(_private_store_root(store_root), work_item, run)
    return run


async def execute_imageio_hunter_plan(
    *,
    plan: ImageIOCrashHunterPlan,
    store_root: Path,
    database: Path,
    client: ImageIOHunterModelClient,
    budget: BudgetPolicy,
    binary_contexts: Sequence[ImageIOBinaryContext] = (),
    worker_id: str = "imageio-hunter-worker",
) -> tuple[ImageIOHunterRun, ...]:
    """Execute admitted PR5 work through the existing durable Hunter queue."""

    store = _private_store_root(store_root)
    if not plan.admitted_work_items:
        return ()
    run_id = plan.admitted_work_items[0].run_id
    queue_store = DurableHuntQueueStore(store / "hunters", database, run_id)
    queue_store.init_from_work_items(plan.admitted_work_items)
    tasks = {task.work_id: task for task in queue_store.load().tasks}
    with SqliteRepository(database, read_only=True) as repository:
        prior_usage = repository.list_budget_usage(run_id, scope="hunter")
    budget_controller = BudgetController(
        budget,
        prior_usage,
        soft_input_token_stop=budget.max_input_tokens,
    )
    results: list[ImageIOHunterRun] = []
    for item in plan.admitted_work_items:
        task = tasks[item.work_id]
        lease = queue_store.acquire(
            task,
            worker_id=worker_id,
            lease_seconds=max(60, budget.max_wall_clock_minutes * 60),
            max_attempts=budget.max_retries_per_work_item + 1,
        )
        if lease is None:
            continue
        try:
            queue_store.mark_file_running(task)
            queue_store.mark_hunt_running(task, item.hunter)
            budgeted_client = BudgetedLLMClient(
                client,
                budget_controller,
                work_id=item.work_id,
            )
            result = await run_imageio_hunter_work_item(
                store_root=store,
                work_item=item,
                client=cast(ImageIOHunterModelClient, budgeted_client),
                binary_contexts=binary_contexts,
                max_tokens=min(5000, budget.max_output_tokens),
            )
            queue_store.mark_hunt_done(
                task,
                item.hunter,
                findings_count=len(result.assessment.hypotheses),
            )
            queue_store.mark_file_done(task)
            with SqliteRepository(database) as repository:
                repository.save_budget_usage(result.usage)
            queue_store.finish(lease, status="done")
            results.append(result)
        except ImageIOHunterBudgetDeferred as exc:
            if exc.usage is not None:
                with SqliteRepository(database) as repository:
                    repository.save_budget_usage(exc.usage)
            queue_store.mark_hunt_deferred(task, item.hunter, exc.reason)
            queue_store.mark_file_deferred(task, exc.reason)
            queue_store.finish(lease, status="budget_deferred", error=exc.reason)
        except Exception as exc:
            queue_store.mark_hunt_failed(task, item.hunter, str(exc))
            queue_store.mark_file_failed(task, str(exc))
            queue_store.finish(lease, status="failed", error=str(exc))
            raise
        finally:
            budget_controller.finish_work(item.work_id)
    return tuple(results)


def plan_imageio_experiments(
    *,
    packet: ImageIOHunterPacket,
    assessment: ImageIOHunterAssessment,
) -> tuple[ImageIOExperimentPlan, ...]:
    """Turn model proposals into non-executable, reviewer-gated plans."""

    _validate_assessment(packet, assessment)
    plans: list[ImageIOExperimentPlan] = []
    for proposal in assessment.experiment_proposals:
        route = _planned_route(packet, proposal)
        status, capabilities = _experiment_status(packet, proposal, route)
        parameters = {
            "input_sha256": packet.format_grammar.input_sha256,
            "source_route": packet.representative_execution["route"],
            "mutation_operator": packet.representative_case["operator"],
            "target_tag": proposal.target_tag,
            "boundary_values": list(proposal.boundary_values),
            "incremental_chunk_sizes": list(proposal.incremental_chunk_sizes),
        }
        identity = {
            "policy": IMAGEIO_EXPERIMENT_POLICY,
            "work_id": assessment.work_id,
            "cluster_id": assessment.cluster_id,
            "proposal": proposal.model_dump(mode="json"),
            "planned_route": route.value if route is not None else None,
            "status": status.value,
        }
        plan_id = (
            "imageio-plan-"
            + hashlib.sha256(
                json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()[:32]
        )
        plans.append(
            ImageIOExperimentPlan(
                plan_id=plan_id,
                work_id=assessment.work_id,
                cluster_id=assessment.cluster_id,
                proposal_id=proposal.proposal_id,
                hypothesis_id=proposal.hypothesis_id,
                kind=proposal.kind,
                status=status,
                route=route,
                target_signature_sha256=packet.cluster.signature_sha256,
                execution_limit=(
                    proposal.execution_limit
                    if status is ImageIOExperimentPlanStatus.REVIEW_REQUIRED
                    else 0
                ),
                parameters=parameters,
                oracle=proposal.expected_observation,
                falsification_condition=proposal.falsification_condition,
                required_capabilities=capabilities,
                reviewer_question=(
                    "Does this bounded experiment discriminate the cited hypothesis "
                    "without broadening execution beyond the networkless disposable VM?"
                ),
            )
        )
    return tuple(plans)


def review_imageio_experiment(
    plan: ImageIOExperimentPlan,
    *,
    reviewer: str,
    approved: bool,
    rationale: str,
    reviewed_at: datetime | None = None,
) -> ImageIOExperimentReview:
    """Record independent authorization; planning never implies execution approval."""

    if approved and plan.status is not ImageIOExperimentPlanStatus.REVIEW_REQUIRED:
        raise ValueError("only a review-ready experiment can be approved")
    return ImageIOExperimentReview(
        plan_id=plan.plan_id,
        reviewer=reviewer,
        approved=approved,
        rationale=rationale,
        reviewed_at=reviewed_at or datetime.now(UTC),
    )


def _planned_route(
    packet: ImageIOHunterPacket,
    proposal: ImageIOExperimentProposal,
) -> ImageIOAPIRoute | None:
    representative = ImageIOAPIRoute(packet.representative_execution["route"])
    if proposal.kind is ImageIOExperimentKind.EXACT_REPLAY:
        return representative
    if proposal.kind is ImageIOExperimentKind.FIELD_BOUNDARY:
        return proposal.route or representative
    if proposal.kind is ImageIOExperimentKind.INCREMENTAL_CHUNK_SCHEDULE:
        return ImageIOAPIRoute.INCREMENTAL_DECODE
    return proposal.route


def _experiment_status(
    packet: ImageIOHunterPacket,
    proposal: ImageIOExperimentProposal,
    route: ImageIOAPIRoute | None,
) -> tuple[ImageIOExperimentPlanStatus, tuple[str, ...]]:
    if proposal.kind is ImageIOExperimentKind.BINARY_CONTEXT:
        return (
            ImageIOExperimentPlanStatus.REQUIRES_BINARY_CONTEXT,
            ("bounded_dyld_shared_cache_context",),
        )
    if proposal.kind is ImageIOExperimentKind.CROSS_BUILD_REPLAY:
        return (
            ImageIOExperimentPlanStatus.REQUIRES_SNAPSHOT,
            ("approved_latest_stable_or_beta_snapshot",),
        )
    if proposal.kind is ImageIOExperimentKind.GUARD_MALLOC:
        return (
            ImageIOExperimentPlanStatus.REQUIRES_HARNESS,
            ("attested_guard_malloc_environment",),
        )
    if proposal.kind is ImageIOExperimentKind.ROUTE_DIFFERENTIAL:
        representative = ImageIOAPIRoute(packet.representative_execution["route"])
        if route is None or route is representative:
            return ImageIOExperimentPlanStatus.UNSUPPORTED, ("distinct_api_route",)
    return (
        ImageIOExperimentPlanStatus.REVIEW_REQUIRED,
        ("networkless_disposable_vm", "exact_crash_signature_oracle"),
    )


def _validate_assessment(
    packet: ImageIOHunterPacket,
    assessment: ImageIOHunterAssessment,
) -> None:
    if assessment.work_id != packet.work_id:
        raise ValueError("ImageIO Hunter assessment changed the work ID")
    if assessment.cluster_id != packet.cluster.cluster_id:
        raise ValueError("ImageIO Hunter assessment changed the cluster ID")
    allowed = {item.evidence_id for item in packet.evidence_refs}
    evidence_kinds = {item.evidence_id: item.kind for item in packet.evidence_refs}
    cited = set(assessment.evidence_refs)
    cited.update(
        evidence_id
        for hypothesis in assessment.hypotheses
        for evidence_id in hypothesis.evidence_refs
    )
    if not cited <= allowed:
        raise ValueError("ImageIO Hunter cited evidence outside its packet")
    if not set(assessment.evidence_refs):
        raise ValueError("ImageIO Hunter assessment must cite packet evidence")
    if any(
        proposal.kind not in packet.allowed_experiments
        for proposal in assessment.experiment_proposals
    ):
        raise ValueError("ImageIO Hunter proposed an experiment outside its packet")
    for hypothesis in assessment.hypotheses:
        if hypothesis.proposed_crash_class is None:
            continue
        cited_kinds = {evidence_kinds[item] for item in hypothesis.evidence_refs}
        if not {"input", "crash_log"} <= cited_kinds:
            raise ValueError(
                "memory-safety classification requires retained input and crash evidence"
            )


def _write_hunter_run(
    store: Path,
    item: HunterWorkItem,
    run: ImageIOHunterRun,
) -> None:
    directory = store / "hunters" / item.work_id / "imageio-analysis"
    _private_directory(directory)
    payloads = {
        "packet.json": run.packet.model_dump(mode="json"),
        "assessment.json": run.assessment.model_dump(mode="json"),
        "experiment-plans.json": [plan.model_dump(mode="json") for plan in run.experiment_plans],
        "usage.json": run.usage.model_dump(mode="json"),
    }
    for name, payload in payloads.items():
        _write_private_json(directory / name, payload)


def _budget_usage(
    *,
    work_item: HunterWorkItem,
    client: ImageIOHunterModelClient,
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


def _evidence_ref(
    kind: Literal["cluster", "case", "input", "crash_log", "binary_context"],
    digest: str,
    path: str | None,
) -> ImageIOHunterEvidenceRef:
    identity = f"{kind}\x00{digest}\x00{path or ''}".encode()
    return ImageIOHunterEvidenceRef(
        evidence_id="imageio-evidence-" + hashlib.sha256(identity).hexdigest()[:20],
        kind=kind,
        artifact_sha256=digest,
        path=path,
    )


def _dicom_grammar_slice(payload: bytes) -> ImageIODICOMGrammarSlice:
    if len(payload) < 132 or payload[128:132] != b"DICM":
        raise ValueError("ImageIO Hunter input is not a DICOM Part 10 payload")
    elements: list[ImageIODICOMElementSlice] = []
    offset = 132
    stop_reason = "end_of_input"
    complete = True
    while offset < len(payload) and len(elements) < _MAX_DICOM_ELEMENTS:
        if len(payload) - offset < 8:
            stop_reason = "truncated_element_header"
            complete = False
            break
        group = int.from_bytes(payload[offset : offset + 2], "little")
        element = int.from_bytes(payload[offset + 2 : offset + 4], "little")
        vr_bytes = payload[offset + 4 : offset + 6]
        try:
            vr = vr_bytes.decode("ascii")
        except UnicodeDecodeError:
            stop_reason = "invalid_vr"
            complete = False
            break
        if len(vr) != 2 or not vr.isupper():
            stop_reason = "invalid_vr"
            complete = False
            break
        if vr_bytes in _DICOM_LONG_VRS:
            if len(payload) - offset < 12:
                stop_reason = "truncated_long_vr_header"
                complete = False
                break
            header_size = 12
            declared_length = int.from_bytes(payload[offset + 8 : offset + 12], "little")
        else:
            header_size = 8
            declared_length = int.from_bytes(payload[offset + 6 : offset + 8], "little")
        value_start = offset + header_size
        if declared_length == 0xFFFFFFFF:
            stop_reason = "undefined_length_deferred"
            complete = False
            break
        value_end = value_start + declared_length
        preview_end = min(value_end, value_start + 16, len(payload))
        elements.append(
            ImageIODICOMElementSlice(
                tag=f"{group:04X},{element:04X}",
                offset=offset,
                vr=vr,
                declared_length=declared_length,
                value_preview_hex=payload[value_start:preview_end].hex(),
            )
        )
        if value_end > len(payload):
            stop_reason = "declared_value_exceeds_input"
            complete = False
            break
        offset = value_end
    if len(elements) == _MAX_DICOM_ELEMENTS and offset < len(payload):
        stop_reason = "element_limit_reached"
        complete = False
    return ImageIODICOMGrammarSlice(
        input_sha256=_sha256_bytes(payload),
        input_size_bytes=len(payload),
        elements=tuple(elements),
        parse_complete=complete,
        parse_stop_reason=stop_reason,
    )


def _contained_file(root: Path, relative: str | None) -> Path:
    if relative is None:
        raise RuntimeError("required private ImageIO artifact path is missing")
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("ImageIO Hunter artifact path escapes its private store")
    path = root / candidate
    resolved = path.resolve(strict=True)
    if path.is_symlink() or root not in resolved.parents:
        raise ValueError("ImageIO Hunter artifact is not a contained regular file")
    return resolved


def _read_file(path: Path, *, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"ImageIO Hunter artifact is missing or unsafe: {path}")
    if path.stat().st_size > maximum:
        raise RuntimeError(f"ImageIO Hunter artifact exceeds its packet limit: {path}")
    return path.read_bytes()


def _private_store_root(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError("ImageIO Hunter store may not be a symbolic link")
    resolved = expanded.resolve(strict=True)
    if not resolved.is_dir() or any(
        (candidate / ".git").exists() for candidate in (resolved, *resolved.parents)
    ):
        raise ValueError("ImageIO Hunter store must be a private directory outside Git")
    return resolved


def _private_directory(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError("ImageIO Hunter output directory may not be a symbolic link")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    current = path
    while current.name and current != current.parent:
        if current.exists():
            os.chmod(current, 0o700)
        if current.name == "hunters":
            break
        current = current.parent


def _write_private_json(path: Path, payload: object) -> None:
    if path.is_symlink():
        raise RuntimeError("ImageIO Hunter output may not be a symbolic link")
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o600)


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()
