"""Evidence-aware ranking and budgeted context packing for binary Hunters."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from ...domain.schemas import DomainModel, SHA256_PATTERN
from .analyzers import (
    BinaryAnalysisReport,
    BinaryFindingSeverity,
    BinaryStaticFinding,
)
from .discovery import (
    ImageIOParserDiscovery,
    ParserCandidate,
    ParserEvidenceKind,
)
from .ir import IRFunction, IRInstruction, IROperation, NormalizedBinaryIR


class BinaryScoreComponentKind(StrEnum):
    STATIC_FINDINGS = "static_findings"
    FINDING_CONFIDENCE = "finding_confidence"
    DISCOVERY_EVIDENCE = "discovery_evidence"
    INPUT_REACHABILITY = "input_reachability"
    CALLGRAPH_POSITION = "callgraph_position"
    FUNCTION_COMPLEXITY = "function_complexity"
    UNKNOWN_IR_PENALTY = "unknown_ir_penalty"


class BinaryScoreComponent(DomainModel):
    kind: BinaryScoreComponentKind
    score: int = Field(ge=-1000, le=5000)
    reason: str = Field(min_length=1, max_length=500)


class RankedBinaryFunction(DomainModel):
    rank: int = Field(ge=1, le=100000)
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    candidate_id: str = Field(pattern=r"^parser_[0-9a-f]{20}$")
    function_name: str = Field(min_length=1, max_length=500)
    start_address: int = Field(ge=0)
    priority_score: int = Field(ge=-1000, le=10000)
    components: tuple[BinaryScoreComponent, ...] = Field(min_length=7, max_length=7)
    finding_ids: tuple[str, ...] = Field(default=(), max_length=256)
    estimated_context_bytes: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_ranked_function(self) -> "RankedBinaryFunction":
        if tuple(sorted(self.components, key=lambda item: item.kind.value)) != self.components:
            raise ValueError("binary score components must use canonical order")
        if len({item.kind for item in self.components}) != len(self.components):
            raise ValueError("binary score component kinds must be unique")
        if sum(item.score for item in self.components) != self.priority_score:
            raise ValueError("binary priority score does not match its components")
        if tuple(sorted(set(self.finding_ids))) != self.finding_ids:
            raise ValueError("binary ranking finding ids must be sorted and unique")
        return self


class BinaryRankingPolicy(DomainModel):
    maximum_ranked_functions: int = Field(default=200, ge=1, le=10000)
    context_budget_bytes: int = Field(default=24 * 1024, ge=512, le=1024 * 1024)
    maximum_segment_bytes: int = Field(default=20 * 1024, ge=256, le=1024 * 1024)
    maximum_packs: int = Field(default=64, ge=1, le=1024)
    maximum_instructions_per_function: int = Field(default=240, ge=1, le=10000)
    maximum_pseudocode_bytes: int = Field(default=12 * 1024, ge=0, le=512 * 1024)


class BinaryFunctionRanking(DomainModel):
    schema_version: Literal["binary-function-ranking-v1"] = "binary-function-ranking-v1"
    ir_sha256: str = Field(pattern=SHA256_PATTERN)
    discovery_sha256: str = Field(pattern=SHA256_PATTERN)
    report_sha256: str = Field(pattern=SHA256_PATTERN)
    entries: tuple[RankedBinaryFunction, ...] = Field(max_length=10000)
    ranking_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_ranking(self) -> "BinaryFunctionRanking":
        if tuple(item.rank for item in self.entries) != tuple(range(1, len(self.entries) + 1)):
            raise ValueError("binary ranking ranks must be contiguous")
        if len({item.function_id for item in self.entries}) != len(self.entries):
            raise ValueError("binary ranking functions must be unique")
        ordering = tuple(
            sorted(
                self.entries,
                key=lambda item: (-item.priority_score, item.start_address, item.function_id),
            )
        )
        if ordering != self.entries:
            raise ValueError("binary ranking entries do not match priority order")
        expected = _ranking_digest(
            ir_sha256=self.ir_sha256,
            discovery_sha256=self.discovery_sha256,
            report_sha256=self.report_sha256,
            entries=self.entries,
        )
        if self.ranking_sha256 != expected:
            raise ValueError("binary ranking digest does not match its entries")
        return self


class BinaryContextSegment(DomainModel):
    rank: int = Field(ge=1)
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    function_name: str = Field(min_length=1, max_length=500)
    finding_ids: tuple[str, ...] = Field(default=(), max_length=256)
    evidence_addresses: tuple[int, ...] = Field(default=(), max_length=1024)
    truncated: bool
    content: str = Field(min_length=1, max_length=1024 * 1024)
    content_bytes: int = Field(ge=1)
    content_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_segment(self) -> "BinaryContextSegment":
        if tuple(sorted(set(self.finding_ids))) != self.finding_ids:
            raise ValueError("context segment finding ids must be sorted and unique")
        if tuple(sorted(set(self.evidence_addresses))) != self.evidence_addresses:
            raise ValueError("context evidence addresses must be sorted and unique")
        encoded = self.content.encode()
        if len(encoded) != self.content_bytes:
            raise ValueError("context segment byte count does not match its content")
        if _text_digest(self.content) != self.content_sha256:
            raise ValueError("context segment digest does not match its content")
        return self


class BinaryContextPack(DomainModel):
    pack_id: str = Field(pattern=r"^binpack_[0-9a-f]{20}$")
    sequence: int = Field(ge=1)
    budget_bytes: int = Field(ge=512)
    segments: tuple[BinaryContextSegment, ...] = Field(min_length=1, max_length=10000)
    content: str = Field(min_length=1, max_length=1024 * 1024)
    content_bytes: int = Field(ge=1)
    content_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_pack(self) -> "BinaryContextPack":
        ranks = tuple(item.rank for item in self.segments)
        if tuple(sorted(ranks)) != ranks or len(set(ranks)) != len(ranks):
            raise ValueError("context pack segments must preserve ranking order")
        expected_content = "\n\n".join(item.content for item in self.segments)
        if expected_content != self.content:
            raise ValueError("context pack content does not match its segments")
        encoded = self.content.encode()
        if len(encoded) != self.content_bytes or self.content_bytes > self.budget_bytes:
            raise ValueError("context pack violates its byte budget")
        if _text_digest(self.content) != self.content_sha256:
            raise ValueError("context pack digest does not match its content")
        expected_id = _pack_id(self.sequence, self.content_sha256)
        if self.pack_id != expected_id:
            raise ValueError("context pack id does not match its content")
        return self


class BinaryContextPlan(DomainModel):
    schema_version: Literal["binary-context-plan-v1"] = "binary-context-plan-v1"
    ranking_sha256: str = Field(pattern=SHA256_PATTERN)
    context_budget_bytes: int = Field(ge=512)
    packs: tuple[BinaryContextPack, ...] = Field(max_length=1024)
    ranked_function_ids: tuple[str, ...] = Field(default=(), max_length=10000)
    packed_function_ids: tuple[str, ...] = Field(default=(), max_length=10000)
    omitted_function_ids: tuple[str, ...] = Field(default=(), max_length=10000)
    total_context_bytes: int = Field(ge=0)
    plan_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_plan(self) -> "BinaryContextPlan":
        if tuple(item.sequence for item in self.packs) != tuple(range(1, len(self.packs) + 1)):
            raise ValueError("binary context pack sequences must be contiguous")
        segments = tuple(segment for pack in self.packs for segment in pack.segments)
        if tuple(item.rank for item in segments) != tuple(range(1, len(segments) + 1)):
            raise ValueError("binary context plan must preserve a contiguous ranking prefix")
        if tuple(item.function_id for item in segments) != self.packed_function_ids:
            raise ValueError("packed function ids do not match context segment order")
        if self.packed_function_ids + self.omitted_function_ids != self.ranked_function_ids:
            raise ValueError("context plan must partition the ranking into a prefix and suffix")
        if set(self.packed_function_ids) & set(self.omitted_function_ids):
            raise ValueError("packed and omitted functions may not overlap")
        if sum(item.content_bytes for item in self.packs) != self.total_context_bytes:
            raise ValueError("binary context total does not match its packs")
        if any(item.budget_bytes != self.context_budget_bytes for item in self.packs):
            raise ValueError("binary context packs must share the plan byte budget")
        expected = _plan_digest(
            ranking_sha256=self.ranking_sha256,
            context_budget_bytes=self.context_budget_bytes,
            packs=self.packs,
            ranked_function_ids=self.ranked_function_ids,
            packed_function_ids=self.packed_function_ids,
            omitted_function_ids=self.omitted_function_ids,
            total_context_bytes=self.total_context_bytes,
        )
        if self.plan_sha256 != expected:
            raise ValueError("binary context plan digest does not match its packs")
        return self


def rank_binary_functions(
    ir: NormalizedBinaryIR,
    discovery: ImageIOParserDiscovery,
    report: BinaryAnalysisReport,
    *,
    policy: BinaryRankingPolicy | None = None,
) -> BinaryFunctionRanking:
    active_policy = policy or BinaryRankingPolicy()
    _validate_inputs(ir, discovery, report)
    functions = {item.function_id: item for item in ir.functions}
    findings_by_function: dict[str, list[BinaryStaticFinding]] = {}
    for finding in report.findings:
        findings_by_function.setdefault(finding.function_id, []).append(finding)

    scored: list[
        tuple[
            int,
            int,
            str,
            ParserCandidate,
            IRFunction,
            tuple[BinaryScoreComponent, ...],
            tuple[str, ...],
            int,
        ]
    ] = []
    for candidate in discovery.candidates:
        function = functions[candidate.function_id]
        findings = findings_by_function.get(candidate.function_id, [])
        components = _score_components(candidate, function, findings)
        score = sum(item.score for item in components)
        finding_ids = tuple(sorted(item.finding_id for item in findings))
        estimated = len(_render_full_context(function, candidate, findings).encode())
        scored.append(
            (
                -score,
                function.start_address,
                function.function_id,
                candidate,
                function,
                components,
                finding_ids,
                estimated,
            )
        )
    scored.sort(key=lambda item: item[:3])
    entries = tuple(
        RankedBinaryFunction(
            rank=rank,
            function_id=function.function_id,
            candidate_id=candidate.candidate_id,
            function_name=function.name,
            start_address=function.start_address,
            priority_score=-sort_score,
            components=components,
            finding_ids=finding_ids,
            estimated_context_bytes=estimated,
        )
        for rank, (
            sort_score,
            _,
            _,
            candidate,
            function,
            components,
            finding_ids,
            estimated,
        ) in enumerate(scored[: active_policy.maximum_ranked_functions], start=1)
    )
    digest = _ranking_digest(
        ir_sha256=ir.ir_sha256,
        discovery_sha256=discovery.discovery_sha256,
        report_sha256=report.report_sha256,
        entries=entries,
    )
    return BinaryFunctionRanking(
        ir_sha256=ir.ir_sha256,
        discovery_sha256=discovery.discovery_sha256,
        report_sha256=report.report_sha256,
        entries=entries,
        ranking_sha256=digest,
    )


def pack_ranked_binary_contexts(
    ir: NormalizedBinaryIR,
    discovery: ImageIOParserDiscovery,
    report: BinaryAnalysisReport,
    ranking: BinaryFunctionRanking,
    *,
    policy: BinaryRankingPolicy | None = None,
) -> BinaryContextPlan:
    active_policy = policy or BinaryRankingPolicy()
    _validate_inputs(ir, discovery, report)
    if (
        ranking.ir_sha256 != ir.ir_sha256
        or ranking.discovery_sha256 != discovery.discovery_sha256
        or ranking.report_sha256 != report.report_sha256
    ):
        raise ValueError("binary ranking is not bound to its IR, discovery, and report")
    functions = {item.function_id: item for item in ir.functions}
    candidates = {item.function_id: item for item in discovery.candidates}
    findings_by_function: dict[str, list[BinaryStaticFinding]] = {}
    for finding in report.findings:
        findings_by_function.setdefault(finding.function_id, []).append(finding)

    packs: list[BinaryContextPack] = []
    pending: list[BinaryContextSegment] = []
    pending_bytes = 0
    packed_ids: list[str] = []
    omitted_ids: list[str] = []
    for entry_index, entry in enumerate(ranking.entries):
        if len(packs) >= active_policy.maximum_packs:
            omitted_ids.extend(item.function_id for item in ranking.entries[entry_index:])
            break
        function = functions[entry.function_id]
        candidate = candidates[entry.function_id]
        findings = findings_by_function.get(entry.function_id, [])
        segment = _make_segment(entry, function, candidate, findings, active_policy)
        separator_bytes = 2 if pending else 0
        if (
            pending
            and pending_bytes + separator_bytes + segment.content_bytes
            > active_policy.context_budget_bytes
        ):
            packs.append(_make_pack(len(packs) + 1, pending, active_policy.context_budget_bytes))
            pending = []
            pending_bytes = 0
            if len(packs) >= active_policy.maximum_packs:
                omitted_ids.extend(item.function_id for item in ranking.entries[entry_index:])
                break
        pending.append(segment)
        pending_bytes += (2 if len(pending) > 1 else 0) + segment.content_bytes
        packed_ids.append(entry.function_id)
    if pending and len(packs) < active_policy.maximum_packs:
        packs.append(_make_pack(len(packs) + 1, pending, active_policy.context_budget_bytes))

    packed = tuple(packs)
    ranked_function_ids = tuple(item.function_id for item in ranking.entries)
    packed_function_ids = tuple(packed_ids)
    omitted_function_ids = tuple(omitted_ids)
    total_bytes = sum(item.content_bytes for item in packed)
    digest = _plan_digest(
        ranking_sha256=ranking.ranking_sha256,
        context_budget_bytes=active_policy.context_budget_bytes,
        packs=packed,
        ranked_function_ids=ranked_function_ids,
        packed_function_ids=packed_function_ids,
        omitted_function_ids=omitted_function_ids,
        total_context_bytes=total_bytes,
    )
    return BinaryContextPlan(
        ranking_sha256=ranking.ranking_sha256,
        context_budget_bytes=active_policy.context_budget_bytes,
        packs=packed,
        ranked_function_ids=ranked_function_ids,
        packed_function_ids=packed_function_ids,
        omitted_function_ids=omitted_function_ids,
        total_context_bytes=total_bytes,
        plan_sha256=digest,
    )


def _score_components(
    candidate: ParserCandidate,
    function: IRFunction,
    findings: list[BinaryStaticFinding],
) -> tuple[BinaryScoreComponent, ...]:
    severity_weights = {
        BinaryFindingSeverity.CRITICAL: 55,
        BinaryFindingSeverity.HIGH: 40,
        BinaryFindingSeverity.MEDIUM: 20,
    }
    finding_score = min(140, sum(severity_weights[item.severity] for item in findings))
    confidence_score = round(max((item.confidence for item in findings), default=0.0) * 20)
    input_evidence_count = sum(
        item.kind
        in {
            ParserEvidenceKind.INPUT_MARKER,
            ParserEvidenceKind.API_CALL,
            ParserEvidenceKind.FORMAT_STRING,
        }
        for item in candidate.evidence
    )
    instructions = tuple(
        instruction for block in function.blocks for instruction in block.instructions
    )
    unknown_count = sum(item.operation is IROperation.UNKNOWN for item in instructions)
    unknown_penalty = -round((unknown_count / max(1, len(instructions))) * 20)
    distance = candidate.callgraph_distance
    values = {
        BinaryScoreComponentKind.STATIC_FINDINGS: (
            finding_score,
            f"{len(findings)} deterministic static finding(s)",
        ),
        BinaryScoreComponentKind.FINDING_CONFIDENCE: (
            confidence_score,
            "maximum deterministic finding confidence",
        ),
        BinaryScoreComponentKind.DISCOVERY_EVIDENCE: (
            min(60, candidate.discovery_score),
            "bounded parser discovery evidence",
        ),
        BinaryScoreComponentKind.INPUT_REACHABILITY: (
            min(24, input_evidence_count * 6),
            f"{input_evidence_count} input/format reachability marker(s)",
        ),
        BinaryScoreComponentKind.CALLGRAPH_POSITION: (
            max(0, 12 - (3 * distance)) if distance is not None else 0,
            "proximity to a direct parser seed",
        ),
        BinaryScoreComponentKind.FUNCTION_COMPLEXITY: (
            min(10, max(1, len(instructions) // 20 + 1)),
            f"{len(instructions)} normalized instruction(s)",
        ),
        BinaryScoreComponentKind.UNKNOWN_IR_PENALTY: (
            unknown_penalty,
            f"{unknown_count} unknown normalized operation(s)",
        ),
    }
    return tuple(
        BinaryScoreComponent(kind=kind, score=score, reason=reason)
        for kind, (score, reason) in sorted(values.items(), key=lambda item: item[0].value)
    )


def _make_segment(
    entry: RankedBinaryFunction,
    function: IRFunction,
    candidate: ParserCandidate,
    findings: list[BinaryStaticFinding],
    policy: BinaryRankingPolicy,
) -> BinaryContextSegment:
    evidence_addresses = tuple(
        sorted({step.address for finding in findings for step in finding.evidence})
    )
    maximum = min(policy.context_budget_bytes, policy.maximum_segment_bytes)
    content, truncated = _render_budgeted_context(
        entry,
        function,
        candidate,
        findings,
        evidence_addresses=evidence_addresses,
        maximum_bytes=maximum,
        maximum_instructions=policy.maximum_instructions_per_function,
        maximum_pseudocode_bytes=policy.maximum_pseudocode_bytes,
    )
    return BinaryContextSegment(
        rank=entry.rank,
        function_id=entry.function_id,
        function_name=entry.function_name,
        finding_ids=entry.finding_ids,
        evidence_addresses=evidence_addresses,
        truncated=truncated,
        content=content,
        content_bytes=len(content.encode()),
        content_sha256=_text_digest(content),
    )


def _render_full_context(
    function: IRFunction,
    candidate: ParserCandidate,
    findings: list[BinaryStaticFinding],
) -> str:
    instructions = tuple(
        instruction for block in function.blocks for instruction in block.instructions
    )
    return _render_context(
        rank=None,
        function=function,
        candidate=candidate,
        findings=findings,
        instructions=instructions,
        pseudocode=function.pseudocode,
        truncated=False,
    )


def _render_budgeted_context(
    entry: RankedBinaryFunction,
    function: IRFunction,
    candidate: ParserCandidate,
    findings: list[BinaryStaticFinding],
    *,
    evidence_addresses: tuple[int, ...],
    maximum_bytes: int,
    maximum_instructions: int,
    maximum_pseudocode_bytes: int,
) -> tuple[str, bool]:
    all_instructions = tuple(
        instruction for block in function.blocks for instruction in block.instructions
    )
    selected = _select_instructions(
        all_instructions,
        evidence_addresses=evidence_addresses,
        maximum=maximum_instructions,
    )
    pseudocode = _truncate_utf8(function.pseudocode, maximum_pseudocode_bytes)
    structurally_reduced = selected != all_instructions or pseudocode != function.pseudocode
    rendered = _render_context(
        rank=entry.rank,
        function=function,
        candidate=candidate,
        findings=findings,
        instructions=selected,
        pseudocode=pseudocode,
        truncated=structurally_reduced,
    )
    content = _truncate_utf8(rendered, maximum_bytes, marker="\n[CONTEXT TRUNCATED]")
    return content, structurally_reduced or content != rendered


def _render_context(
    *,
    rank: int | None,
    function: IRFunction,
    candidate: ParserCandidate,
    findings: list[BinaryStaticFinding],
    instructions: tuple[IRInstruction, ...],
    pseudocode: str,
    truncated: bool,
) -> str:
    rank_text = "unranked" if rank is None else str(rank)
    lines = [
        f"## rank={rank_text} function={function.name} id={function.function_id}",
        f"address=0x{function.start_address:x} discovery_score={candidate.discovery_score}",
    ]
    for finding in sorted(findings, key=lambda item: item.finding_id):
        addresses = ",".join(f"0x{step.address:x}" for step in finding.evidence)
        lines.append(
            f"FINDING {finding.finding_id} {finding.vulnerability_class.value} "
            f"severity={finding.severity.value} evidence={addresses}: {finding.summary}"
        )
    lines.append("IR:")
    lines.extend(_instruction_line(item) for item in instructions)
    if pseudocode:
        lines.extend(("PSEUDOCODE:", pseudocode))
    if truncated:
        lines.append("[FUNCTION CONTENT REDUCED]")
    return "\n".join(lines)


def _select_instructions(
    instructions: tuple[IRInstruction, ...],
    *,
    evidence_addresses: tuple[int, ...],
    maximum: int,
) -> tuple[IRInstruction, ...]:
    if len(instructions) <= maximum:
        return instructions
    selected_indices: set[int] = set()
    evidence_set = set(evidence_addresses)
    for index, instruction in enumerate(instructions):
        if instruction.address in evidence_set:
            selected_indices.update(range(max(0, index - 2), min(len(instructions), index + 3)))
    if not selected_indices:
        selected_indices.update(range(min(maximum, len(instructions))))
    for index in range(len(instructions)):
        if len(selected_indices) >= maximum:
            break
        selected_indices.add(index)
    selected = sorted(selected_indices)[:maximum]
    return tuple(instructions[index] for index in selected)


def _instruction_line(instruction: IRInstruction) -> str:
    result = f"{instruction.result} = " if instruction.result else ""
    operands = ", ".join(instruction.operands)
    constants = ", ".join(str(item) for item in instruction.constants)
    suffix = ", ".join(item for item in (operands, constants) if item)
    callee = f" callee={instruction.callee}" if instruction.callee else ""
    return f"0x{instruction.address:x} {result}{instruction.operation.value}({suffix}){callee}"


def _make_pack(
    sequence: int,
    segments: list[BinaryContextSegment],
    budget_bytes: int,
) -> BinaryContextPack:
    content = "\n\n".join(item.content for item in segments)
    digest = _text_digest(content)
    return BinaryContextPack(
        pack_id=_pack_id(sequence, digest),
        sequence=sequence,
        budget_bytes=budget_bytes,
        segments=tuple(segments),
        content=content,
        content_bytes=len(content.encode()),
        content_sha256=digest,
    )


def _validate_inputs(
    ir: NormalizedBinaryIR,
    discovery: ImageIOParserDiscovery,
    report: BinaryAnalysisReport,
) -> None:
    if discovery.ir_sha256 != ir.ir_sha256:
        raise ValueError("parser discovery is not bound to the supplied IR")
    if report.ir_sha256 != ir.ir_sha256 or report.discovery_sha256 != discovery.discovery_sha256:
        raise ValueError("binary analysis report is not bound to its IR and discovery")


def _truncate_utf8(value: str, maximum_bytes: int, *, marker: str = "") -> str:
    encoded = value.encode()
    if len(encoded) <= maximum_bytes:
        return value
    marker_bytes = marker.encode()
    if len(marker_bytes) >= maximum_bytes:
        return marker_bytes[:maximum_bytes].decode("utf-8", errors="ignore")
    prefix = encoded[: maximum_bytes - len(marker_bytes)].decode("utf-8", errors="ignore")
    return prefix + marker


def _text_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _pack_id(sequence: int, content_sha256: str) -> str:
    return "binpack_" + hashlib.sha256(f"{sequence}:{content_sha256}".encode()).hexdigest()[:20]


def _ranking_digest(
    *,
    ir_sha256: str,
    discovery_sha256: str,
    report_sha256: str,
    entries: tuple[RankedBinaryFunction, ...],
) -> str:
    payload = {
        "discovery_sha256": discovery_sha256,
        "entries": [item.model_dump(mode="json") for item in entries],
        "ir_sha256": ir_sha256,
        "report_sha256": report_sha256,
        "schema_version": "binary-function-ranking-v1",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _plan_digest(
    *,
    ranking_sha256: str,
    context_budget_bytes: int,
    packs: tuple[BinaryContextPack, ...],
    ranked_function_ids: tuple[str, ...],
    packed_function_ids: tuple[str, ...],
    omitted_function_ids: tuple[str, ...],
    total_context_bytes: int,
) -> str:
    payload = {
        "context_budget_bytes": context_budget_bytes,
        "omitted_function_ids": omitted_function_ids,
        "packed_function_ids": packed_function_ids,
        "ranked_function_ids": ranked_function_ids,
        "packs": [item.model_dump(mode="json") for item in packs],
        "ranking_sha256": ranking_sha256,
        "schema_version": "binary-context-plan-v1",
        "total_context_bytes": total_context_bytes,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
