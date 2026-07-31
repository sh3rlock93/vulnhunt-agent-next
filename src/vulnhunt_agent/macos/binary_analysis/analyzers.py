"""Bounded deterministic vulnerability analyzers for normalized binary IR."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from ...domain.schemas import DomainModel, SHA256_PATTERN
from .discovery import ImageIOParserDiscovery, ParserCandidate
from .ir import IRBasicBlock, IRFunction, IRInstruction, IROperation, NormalizedBinaryIR


class BinaryVulnerabilityClass(StrEnum):
    INTEGER_OVERFLOW = "integer_overflow"
    OFFSET_LENGTH_OOB = "offset_length_oob"
    ALLOCATION_COPY_MISMATCH = "allocation_copy_mismatch"
    USE_AFTER_FREE = "use_after_free"
    COMPOSITE_RANGE_GAP = "composite_range_gap"


class BinaryFindingSeverity(StrEnum):
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BinaryEvidenceStep(DomainModel):
    address: int = Field(ge=0)
    operation: IROperation
    variables: tuple[str, ...] = Field(default=(), max_length=16)
    description: str = Field(min_length=1, max_length=1000)


class BinaryStaticFinding(DomainModel):
    finding_id: str = Field(pattern=r"^binfinding_[0-9a-f]{20}$")
    status: Literal["static_candidate"] = "static_candidate"
    ir_sha256: str = Field(pattern=SHA256_PATTERN)
    candidate_id: str = Field(pattern=r"^parser_[0-9a-f]{20}$")
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    function_name: str = Field(min_length=1, max_length=500)
    vulnerability_class: BinaryVulnerabilityClass
    severity: BinaryFindingSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    sink_address: int = Field(ge=0)
    summary: str = Field(min_length=1, max_length=1000)
    evidence: tuple[BinaryEvidenceStep, ...] = Field(min_length=2, max_length=16)

    @model_validator(mode="after")
    def validate_finding(self) -> "BinaryStaticFinding":
        addresses = tuple(item.address for item in self.evidence)
        if tuple(sorted(addresses)) != addresses:
            raise ValueError("binary finding evidence must be ordered by address")
        if self.sink_address != self.evidence[-1].address:
            raise ValueError("binary finding sink must be its final evidence step")
        expected = _finding_id(
            self.ir_sha256,
            self.function_id,
            self.vulnerability_class,
            self.sink_address,
            self.evidence[0].address,
        )
        if self.finding_id != expected:
            raise ValueError("binary finding id does not match its evidence")
        return self


class BinaryAnalyzerLimits(DomainModel):
    maximum_findings: int = Field(default=1000, ge=1, le=10000)
    maximum_findings_per_function: int = Field(default=32, ge=1, le=256)


class BinaryAnalysisReport(DomainModel):
    schema_version: Literal["binary-static-analysis-v1"] = "binary-static-analysis-v1"
    ir_sha256: str = Field(pattern=SHA256_PATTERN)
    discovery_sha256: str = Field(pattern=SHA256_PATTERN)
    analyzed_function_count: int = Field(ge=0)
    findings: tuple[BinaryStaticFinding, ...] = Field(max_length=10000)
    report_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_report(self) -> "BinaryAnalysisReport":
        if tuple(sorted(self.findings, key=_finding_sort_key)) != self.findings:
            raise ValueError("binary findings must use canonical order")
        if len({item.finding_id for item in self.findings}) != len(self.findings):
            raise ValueError("binary finding ids must be unique")
        expected = _report_digest(
            ir_sha256=self.ir_sha256,
            discovery_sha256=self.discovery_sha256,
            analyzed_function_count=self.analyzed_function_count,
            findings=self.findings,
        )
        if self.report_sha256 != expected:
            raise ValueError("binary analysis report digest does not match its findings")
        return self


class BinaryScalarUseKind(StrEnum):
    COMPARISON = "comparison"
    INDEX = "index"
    RANGE_OFFSET = "range_offset"
    REQUESTED_LENGTH = "requested_length"
    CAPACITY = "capacity"
    COUNT = "count"
    TRANSFORM = "transform"


class BinaryScalarUseEvidence(DomainModel):
    address: int = Field(ge=0)
    operation: IROperation
    operand_index: int = Field(ge=0, le=31)
    kind: BinaryScalarUseKind
    callee: str | None = Field(default=None, min_length=1, max_length=500)


class BinaryInputScalarFlow(DomainModel):
    flow_id: str = Field(pattern=r"^scalarflow_[0-9a-f]{20}$")
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    function_name: str = Field(min_length=1, max_length=500)
    variable: str = Field(min_length=1, max_length=160)
    definition_address: int = Field(ge=0)
    source_identities: tuple[str, ...] = Field(min_length=1, max_length=64)
    uses: tuple[BinaryScalarUseEvidence, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def validate_flow(self) -> "BinaryInputScalarFlow":
        if tuple(sorted(set(self.source_identities))) != self.source_identities:
            raise ValueError("input scalar sources must be sorted and unique")
        order = tuple((item.address, item.operand_index, item.kind.value) for item in self.uses)
        if tuple(sorted(set(order))) != order:
            raise ValueError("input scalar uses must be canonically ordered and unique")
        expected = _scalar_flow_id(
            self.function_id,
            self.variable,
            self.definition_address,
            self.source_identities,
            self.uses,
        )
        if self.flow_id != expected:
            raise ValueError("input scalar flow id does not match its evidence")
        return self


class BinaryProvenanceReport(DomainModel):
    schema_version: Literal["binary-input-provenance-v1"] = "binary-input-provenance-v1"
    ir_sha256: str = Field(pattern=SHA256_PATTERN)
    discovery_sha256: str = Field(pattern=SHA256_PATTERN)
    analyzed_function_count: int = Field(ge=0)
    flows: tuple[BinaryInputScalarFlow, ...] = Field(max_length=100000)
    report_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_report(self) -> "BinaryProvenanceReport":
        order = tuple(
            (item.function_id, item.definition_address, item.variable) for item in self.flows
        )
        if tuple(sorted(set(order))) != order:
            raise ValueError("input scalar flows must be canonically ordered and unique")
        expected = _provenance_report_digest(
            self.ir_sha256,
            self.discovery_sha256,
            self.analyzed_function_count,
            self.flows,
        )
        if self.report_sha256 != expected:
            raise ValueError("input provenance report digest does not match its flows")
        return self


class BinaryRangeGuardStatus(StrEnum):
    SAFE_COMBINED = "safe_combined"
    INDIVIDUAL_ONLY = "individual_only"
    LENGTH_CLAMPED = "length_clamped"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class BinaryRangeCallSummary(DomainModel):
    summary_id: str = Field(pattern=r"^rangecall_[0-9a-f]{20}$")
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    function_name: str = Field(min_length=1, max_length=500)
    address: int = Field(ge=0)
    instruction_index: int = Field(ge=0)
    method_identity: str = Field(min_length=1, max_length=120)
    destination: str = Field(min_length=1, max_length=160)
    offset: str = Field(min_length=1, max_length=160)
    requested_length: str = Field(min_length=1, max_length=160)
    available_capacity: str | None = Field(default=None, min_length=1, max_length=160)
    actual_length: str | None = Field(default=None, min_length=1, max_length=160)
    offset_source_identities: tuple[str, ...] = Field(default=(), max_length=64)
    length_source_identities: tuple[str, ...] = Field(default=(), max_length=64)
    individual_check_addresses: tuple[int, ...] = Field(default=(), max_length=16)
    combined_check_address: int | None = Field(default=None, ge=0)
    guard_status: BinaryRangeGuardStatus

    @model_validator(mode="after")
    def validate_summary(self) -> "BinaryRangeCallSummary":
        if tuple(sorted(set(self.offset_source_identities))) != self.offset_source_identities:
            raise ValueError("range offset sources must be sorted and unique")
        if tuple(sorted(set(self.length_source_identities))) != self.length_source_identities:
            raise ValueError("range length sources must be sorted and unique")
        if tuple(sorted(set(self.individual_check_addresses))) != (
            self.individual_check_addresses
        ):
            raise ValueError("range individual checks must be sorted and unique")
        expected = _range_call_id(
            self.function_id,
            self.address,
            self.instruction_index,
            self.method_identity,
            self.destination,
            self.offset,
            self.requested_length,
            self.available_capacity,
            self.actual_length,
            self.offset_source_identities,
            self.length_source_identities,
            self.individual_check_addresses,
            self.combined_check_address,
            self.guard_status,
        )
        if self.summary_id != expected:
            raise ValueError("range call id does not match its typed evidence")
        return self


class BinaryRangeAnalysisReport(DomainModel):
    schema_version: Literal["binary-range-analysis-v1"] = "binary-range-analysis-v1"
    ir_sha256: str = Field(pattern=SHA256_PATTERN)
    discovery_sha256: str = Field(pattern=SHA256_PATTERN)
    analyzed_function_count: int = Field(ge=0)
    calls: tuple[BinaryRangeCallSummary, ...] = Field(max_length=100000)
    findings: tuple[BinaryStaticFinding, ...] = Field(max_length=10000)
    report_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_report(self) -> "BinaryRangeAnalysisReport":
        call_order = tuple(
            (item.function_id, item.address, item.instruction_index) for item in self.calls
        )
        if tuple(sorted(set(call_order))) != call_order:
            raise ValueError("range calls must be canonically ordered and unique")
        if tuple(sorted(self.findings, key=_finding_sort_key)) != self.findings:
            raise ValueError("range findings must use canonical order")
        if any(
            item.vulnerability_class is not BinaryVulnerabilityClass.COMPOSITE_RANGE_GAP
            for item in self.findings
        ):
            raise ValueError("range analysis report contains an unrelated finding class")
        expected = _range_report_digest(
            self.ir_sha256,
            self.discovery_sha256,
            self.analyzed_function_count,
            self.calls,
            self.findings,
        )
        if self.report_sha256 != expected:
            raise ValueError("range analysis digest does not match its evidence")
        return self


@dataclass(frozen=True)
class _ArithmeticOrigin:
    instruction: IRInstruction
    position: int
    taint: frozenset[str]


@dataclass(frozen=True)
class _CopyRoles:
    destination: str
    source: str
    length: str


@dataclass(frozen=True)
class _DataflowState:
    taint: dict[str, frozenset[str]]
    origins: dict[str, _ArithmeticOrigin]


@dataclass(frozen=True)
class _ConditionalGuard:
    compare: IRInstruction
    block_id: str
    true_successor: str
    false_successor: str


@dataclass(frozen=True)
class _ControlFlowFacts:
    entry_block_id: str
    reachable: frozenset[str]
    predecessors: dict[str, frozenset[str]]
    dominators: dict[str, frozenset[str]]
    guards: tuple[_ConditionalGuard, ...]


@dataclass(frozen=True)
class _RangeRoles:
    destination: str
    offset: str
    requested_length: str


@dataclass(frozen=True)
class _RangeGuardAssessment:
    capacity: str | None
    offset_check: IRInstruction | None
    length_check: IRInstruction | None
    combined_check: IRInstruction | None
    status: BinaryRangeGuardStatus


@dataclass(frozen=True)
class _EntailedComparison:
    compare: IRInstruction
    truth: bool


_EXPLICIT_INPUT_CLASSES = frozenset(
    {
        "input_data",
        "input_length",
        "input_offset",
        "input_scalar",
        "input_state",
    }
)
_EXACT_RANGE_READER_IDENTITIES = frozenset(
    {"getbytesatoffset", "iioimagereadsessiongetbytesatoffset"}
)


def analyze_binary_candidates(
    ir: NormalizedBinaryIR,
    discovery: ImageIOParserDiscovery,
    *,
    limits: BinaryAnalyzerLimits | None = None,
) -> BinaryAnalysisReport:
    """Analyze parser candidates; results remain unconfirmed static candidates."""

    if discovery.ir_sha256 != ir.ir_sha256:
        raise ValueError("parser discovery is not bound to the supplied IR")
    active_limits = limits or BinaryAnalyzerLimits()
    functions = {item.function_id: item for item in ir.functions}
    range_report = analyze_composite_ranges(ir, discovery)
    range_findings: dict[str, list[BinaryStaticFinding]] = {}
    for finding in range_report.findings:
        range_findings.setdefault(finding.function_id, []).append(finding)
    findings: list[BinaryStaticFinding] = []
    analyzed = 0
    for candidate in discovery.candidates:
        function = functions.get(candidate.function_id)
        if function is None:
            raise ValueError("parser discovery cites a function absent from the IR")
        analyzed += 1
        function_findings = _analyze_function(ir, candidate, function)
        function_findings.extend(range_findings.get(function.function_id, ()))
        function_findings = sorted(_deduplicate(function_findings), key=_finding_sort_key)
        findings.extend(function_findings[: active_limits.maximum_findings_per_function])
        if len(findings) >= active_limits.maximum_findings:
            findings = findings[: active_limits.maximum_findings]
            break

    ordered = tuple(sorted(_deduplicate(findings), key=_finding_sort_key))
    digest = _report_digest(
        ir_sha256=ir.ir_sha256,
        discovery_sha256=discovery.discovery_sha256,
        analyzed_function_count=analyzed,
        findings=ordered,
    )
    return BinaryAnalysisReport(
        ir_sha256=ir.ir_sha256,
        discovery_sha256=discovery.discovery_sha256,
        analyzed_function_count=analyzed,
        findings=ordered,
        report_sha256=digest,
    )


def analyze_input_scalar_provenance(
    ir: NormalizedBinaryIR,
    discovery: ImageIOParserDiscovery,
) -> BinaryProvenanceReport:
    """Trace input-backed scalar loads without treating unrelated memory as input."""

    if discovery.ir_sha256 != ir.ir_sha256:
        raise ValueError("parser discovery is not bound to the supplied IR")
    functions = {item.function_id: item for item in ir.functions}
    flows: list[BinaryInputScalarFlow] = []
    analyzed = 0
    for candidate in discovery.candidates:
        function = functions.get(candidate.function_id)
        if function is None:
            raise ValueError("parser discovery cites a function absent from the IR")
        analyzed += 1
        flows.extend(_function_scalar_flows(function))
    ordered = tuple(
        sorted(
            flows,
            key=lambda item: (item.function_id, item.definition_address, item.variable),
        )
    )
    digest = _provenance_report_digest(
        ir.ir_sha256,
        discovery.discovery_sha256,
        analyzed,
        ordered,
    )
    return BinaryProvenanceReport(
        ir_sha256=ir.ir_sha256,
        discovery_sha256=discovery.discovery_sha256,
        analyzed_function_count=analyzed,
        flows=ordered,
        report_sha256=digest,
    )


def analyze_composite_ranges(
    ir: NormalizedBinaryIR,
    discovery: ImageIOParserDiscovery,
) -> BinaryRangeAnalysisReport:
    """Summarize exact range reads and report missing combined bounds proofs."""

    if discovery.ir_sha256 != ir.ir_sha256:
        raise ValueError("parser discovery is not bound to the supplied IR")
    functions = {item.function_id: item for item in ir.functions}
    calls: list[BinaryRangeCallSummary] = []
    findings: list[BinaryStaticFinding] = []
    analyzed = 0
    for candidate in discovery.candidates:
        function = functions.get(candidate.function_id)
        if function is None:
            raise ValueError("parser discovery cites a function absent from the IR")
        analyzed += 1
        function_calls, function_findings = _function_range_analysis(
            ir,
            candidate,
            function,
        )
        calls.extend(function_calls)
        findings.extend(function_findings)
    ordered_calls = tuple(
        sorted(
            calls,
            key=lambda item: (item.function_id, item.address, item.instruction_index),
        )
    )
    ordered_findings = tuple(sorted(_deduplicate(findings), key=_finding_sort_key))
    digest = _range_report_digest(
        ir.ir_sha256,
        discovery.discovery_sha256,
        analyzed,
        ordered_calls,
        ordered_findings,
    )
    return BinaryRangeAnalysisReport(
        ir_sha256=ir.ir_sha256,
        discovery_sha256=discovery.discovery_sha256,
        analyzed_function_count=analyzed,
        calls=ordered_calls,
        findings=ordered_findings,
        report_sha256=digest,
    )


def _analyze_function(
    ir: NormalizedBinaryIR,
    candidate: ParserCandidate,
    function: IRFunction,
) -> list[BinaryStaticFinding]:
    findings: list[BinaryStaticFinding] = []
    control_flow = _control_flow_facts(function)
    block_inputs = _block_input_states(function, control_flow)
    for block in function.blocks:
        input_state = block_inputs.get(block.block_id, _DataflowState({}, {}))
        taint = dict(input_state.taint)
        origins = dict(input_state.origins)
        allocations: dict[str, tuple[str, IRInstruction]] = {}
        freed: dict[str, IRInstruction] = {}
        for instruction in block.instructions:
            _update_dataflow(instruction, instruction.index, taint, origins, freed)

            if instruction.operation is IROperation.ALLOCATE:
                allocation_size = _allocation_size_variable(instruction)
                if instruction.result and allocation_size:
                    allocations[instruction.result] = (
                        allocation_size,
                        instruction,
                    )
                    freed.pop(instruction.result, None)
                findings.extend(
                    _arithmetic_sink_findings(
                        ir,
                        candidate,
                        function,
                        instruction,
                        instruction.index,
                        block.block_id,
                        _sink_variables(instruction),
                        origins,
                        control_flow,
                    )
                )
            elif instruction.operation is IROperation.COPY:
                findings.extend(
                    _arithmetic_sink_findings(
                        ir,
                        candidate,
                        function,
                        instruction,
                        instruction.index,
                        block.block_id,
                        _sink_variables(instruction),
                        origins,
                        control_flow,
                    )
                )
                mismatch = _allocation_copy_finding(
                    ir,
                    candidate,
                    function,
                    instruction,
                    block.block_id,
                    allocations,
                    taint,
                    control_flow,
                )
                if mismatch:
                    findings.append(mismatch)
            elif instruction.operation in {IROperation.LOAD, IROperation.STORE}:
                findings.extend(
                    _arithmetic_sink_findings(
                        ir,
                        candidate,
                        function,
                        instruction,
                        instruction.index,
                        block.block_id,
                        _sink_variables(instruction),
                        origins,
                        control_flow,
                    )
                )

            if instruction.operation is IROperation.FREE and instruction.operands:
                freed[instruction.operands[0]] = instruction
            elif instruction.operation in {
                IROperation.LOAD,
                IROperation.STORE,
                IROperation.COPY,
                IROperation.CALL,
            }:
                for variable in instruction.operands:
                    free_instruction = freed.get(variable)
                    if free_instruction:
                        findings.append(
                            _use_after_free_finding(
                                ir,
                                candidate,
                                function,
                                variable,
                                free_instruction,
                                instruction,
                            )
                        )
    return sorted(_deduplicate(findings), key=_finding_sort_key)


def _function_scalar_flows(function: IRFunction) -> list[BinaryInputScalarFlow]:
    control_flow = _control_flow_facts(function)
    block_inputs = _block_input_states(function, control_flow)
    definitions: dict[str, tuple[int, tuple[str, ...]]] = {}
    uses: dict[str, dict[tuple[int, int, str], BinaryScalarUseEvidence]] = {}

    for block in function.blocks:
        if block.block_id not in control_flow.reachable:
            continue
        input_state = block_inputs.get(block.block_id, _DataflowState({}, {}))
        taint = dict(input_state.taint)
        origins = dict(input_state.origins)
        freed: dict[str, IRInstruction] = {}
        for instruction in block.instructions:
            for operand_index, operand in enumerate(instruction.operands):
                if "input_scalar" not in taint.get(operand, frozenset()):
                    continue
                kind = _scalar_use_kind(instruction, operand_index)
                if kind is None:
                    continue
                evidence = BinaryScalarUseEvidence(
                    address=instruction.address,
                    operation=instruction.operation,
                    operand_index=operand_index,
                    kind=kind,
                    callee=instruction.callee,
                )
                key = (evidence.address, evidence.operand_index, evidence.kind.value)
                uses.setdefault(operand, {})[key] = evidence

            _update_dataflow(instruction, instruction.index, taint, origins, freed)
            if instruction.result and "input_scalar" in taint.get(
                instruction.result, frozenset()
            ):
                source_identities = tuple(
                    sorted(
                        tag
                        for tag in taint[instruction.result]
                        if tag.startswith("input_source:")
                    )
                )
                if source_identities:
                    definitions[instruction.result] = (
                        instruction.address,
                        source_identities,
                    )

    flows: list[BinaryInputScalarFlow] = []
    for variable, (definition_address, source_identities) in definitions.items():
        ordered_uses = tuple(
            sorted(
                uses.get(variable, {}).values(),
                key=lambda item: (item.address, item.operand_index, item.kind.value),
            )
        )
        flows.append(
            BinaryInputScalarFlow(
                flow_id=_scalar_flow_id(
                    function.function_id,
                    variable,
                    definition_address,
                    source_identities,
                    ordered_uses,
                ),
                function_id=function.function_id,
                function_name=function.name,
                variable=variable,
                definition_address=definition_address,
                source_identities=source_identities,
                uses=ordered_uses,
            )
        )
    return sorted(flows, key=lambda item: (item.definition_address, item.variable))


def _function_range_analysis(
    ir: NormalizedBinaryIR,
    candidate: ParserCandidate,
    function: IRFunction,
) -> tuple[list[BinaryRangeCallSummary], list[BinaryStaticFinding]]:
    scalar_flows = _function_scalar_flows(function)
    sources = {
        item.variable: frozenset(item.source_identities) for item in scalar_flows
    }
    definitions = {
        instruction.result: instruction
        for block in function.blocks
        for instruction in block.instructions
        if instruction.result is not None
    }
    control_flow = _control_flow_facts(function)
    summaries: list[BinaryRangeCallSummary] = []
    findings: list[BinaryStaticFinding] = []
    for block in function.blocks:
        if block.block_id not in control_flow.reachable:
            continue
        for instruction in block.instructions:
            roles = _range_call_roles(instruction)
            if roles is None:
                continue
            offset_sources = sources.get(roles.offset, frozenset())
            length_sources = sources.get(roles.requested_length, frozenset())
            assessment = _assess_range_guard(
                function,
                block.block_id,
                roles,
                offset_sources,
                length_sources,
                definitions,
                sources,
                control_flow,
            )
            identity = _canonical_callee(instruction.callee)
            check_addresses = tuple(
                sorted(
                    {
                        item.address
                        for item in (assessment.offset_check, assessment.length_check)
                        if item is not None
                    }
                )
            )
            summary = BinaryRangeCallSummary(
                summary_id=_range_call_id(
                    function.function_id,
                    instruction.address,
                    instruction.index,
                    identity,
                    roles.destination,
                    roles.offset,
                    roles.requested_length,
                    assessment.capacity,
                    instruction.result,
                    tuple(sorted(offset_sources)),
                    tuple(sorted(length_sources)),
                    check_addresses,
                    (
                        assessment.combined_check.address
                        if assessment.combined_check is not None
                        else None
                    ),
                    assessment.status,
                ),
                function_id=function.function_id,
                function_name=function.name,
                address=instruction.address,
                instruction_index=instruction.index,
                method_identity=identity,
                destination=roles.destination,
                offset=roles.offset,
                requested_length=roles.requested_length,
                available_capacity=assessment.capacity,
                actual_length=instruction.result,
                offset_source_identities=tuple(sorted(offset_sources)),
                length_source_identities=tuple(sorted(length_sources)),
                individual_check_addresses=check_addresses,
                combined_check_address=(
                    assessment.combined_check.address
                    if assessment.combined_check is not None
                    else None
                ),
                guard_status=assessment.status,
            )
            summaries.append(summary)
            if assessment.status is BinaryRangeGuardStatus.INDIVIDUAL_ONLY:
                finding = _composite_range_finding(
                    ir,
                    candidate,
                    function,
                    instruction,
                    roles,
                    assessment,
                    definitions,
                )
                if finding is not None:
                    findings.append(finding)
    return summaries, findings


def _range_call_roles(instruction: IRInstruction) -> _RangeRoles | None:
    if instruction.operation is not IROperation.CALL:
        return None
    if _canonical_callee(instruction.callee) not in _EXACT_RANGE_READER_IDENTITIES:
        return None
    indexes: dict[str, int] = {}
    tag_roles = {
        "input_buffer_operand": "destination",
        "scalar_role:offset": "offset",
        "scalar_role:requested_length": "requested_length",
    }
    for tag in instruction.tags:
        for prefix, role in tag_roles.items():
            match = re.fullmatch(re.escape(prefix) + r":(\d+)", tag)
            if match:
                if role in indexes:
                    return None
                indexes[role] = int(match.group(1))
    if set(indexes) != set(tag_roles.values()):
        return None
    values = tuple(indexes.values())
    if len(set(values)) != len(values) or any(
        index >= len(instruction.operands) for index in values
    ):
        return None
    return _RangeRoles(
        destination=instruction.operands[indexes["destination"]],
        offset=instruction.operands[indexes["offset"]],
        requested_length=instruction.operands[indexes["requested_length"]],
    )


def _assess_range_guard(
    function: IRFunction,
    call_block_id: str,
    roles: _RangeRoles,
    offset_sources: frozenset[str],
    length_sources: frozenset[str],
    definitions: dict[str, IRInstruction],
    sources: dict[str, frozenset[str]],
    control_flow: _ControlFlowFacts,
) -> _RangeGuardAssessment:
    if (
        roles.offset == roles.requested_length
        or not offset_sources
        or not length_sources
    ):
        return _RangeGuardAssessment(
            None,
            None,
            None,
            None,
            BinaryRangeGuardStatus.INSUFFICIENT_EVIDENCE,
        )
    if _requested_length_is_clamped(
        roles.requested_length,
        offset_sources,
        definitions,
        sources,
    ):
        return _RangeGuardAssessment(
            None,
            None,
            None,
            None,
            BinaryRangeGuardStatus.LENGTH_CLAMPED,
        )

    entailed = _dominating_entailed_comparisons(
        function,
        call_block_id,
        definitions,
        control_flow,
    )
    offset_bounds: list[tuple[str, IRInstruction]] = []
    length_bounds: list[tuple[str, IRInstruction]] = []
    subtraction_bounds: list[tuple[str, IRInstruction]] = []
    combined_bounds: list[tuple[str, IRInstruction]] = []
    for item in entailed:
        offset_capacity = _upper_bound_capacity(
            item.compare,
            item.truth,
            offset_sources,
            length_sources,
            sources,
            target="offset",
        )
        if offset_capacity is not None:
            offset_bounds.append((offset_capacity, item.compare))
        subtraction_capacity = _subtraction_bound_capacity(
            item.compare,
            item.truth,
            offset_sources,
            length_sources,
            definitions,
            sources,
        )
        if subtraction_capacity is not None:
            subtraction_bounds.append((subtraction_capacity, item.compare))
        else:
            length_capacity = _upper_bound_capacity(
                item.compare,
                item.truth,
                offset_sources,
                length_sources,
                sources,
                target="length",
            )
            if length_capacity is not None:
                length_bounds.append((length_capacity, item.compare))
        combined_capacity = _upper_bound_capacity(
            item.compare,
            item.truth,
            offset_sources,
            length_sources,
            sources,
            target="combined",
        )
        if combined_capacity is not None and not _explicitly_wrapping_sum(
            item.compare,
            offset_sources,
            length_sources,
            definitions,
            sources,
        ):
            combined_bounds.append((combined_capacity, item.compare))

    offset_by_capacity = _checks_by_capacity(offset_bounds, definitions)
    length_by_capacity = _checks_by_capacity(length_bounds, definitions)
    subtraction_by_capacity = _checks_by_capacity(subtraction_bounds, definitions)
    combined_by_capacity = _checks_by_capacity(combined_bounds, definitions)
    common = set(offset_by_capacity) & (
        set(length_by_capacity) | set(subtraction_by_capacity)
    )
    if not common:
        return _RangeGuardAssessment(
            None,
            None,
            None,
            None,
            BinaryRangeGuardStatus.INSUFFICIENT_EVIDENCE,
        )
    capacity = sorted(common)[0]
    offset_check = offset_by_capacity[capacity]
    length_check = (
        length_by_capacity.get(capacity) or subtraction_by_capacity[capacity]
    )
    combined_check = (
        combined_by_capacity.get(capacity) or subtraction_by_capacity.get(capacity)
    )
    status = (
        BinaryRangeGuardStatus.SAFE_COMBINED
        if combined_check is not None
        else BinaryRangeGuardStatus.INDIVIDUAL_ONLY
    )
    return _RangeGuardAssessment(
        capacity,
        offset_check,
        length_check,
        combined_check,
        status,
    )


def _dominating_entailed_comparisons(
    function: IRFunction,
    call_block_id: str,
    definitions: dict[str, IRInstruction],
    control_flow: _ControlFlowFacts,
) -> tuple[_EntailedComparison, ...]:
    blocks_by_start = {block.start_address: block for block in function.blocks}
    collected: dict[tuple[int, int, bool], _EntailedComparison] = {}
    for block in function.blocks:
        if len(block.successors) != 2:
            continue
        for branch in block.instructions:
            if (
                branch.operation is not IROperation.BRANCH
                or not branch.operands
                or "conditional_branch" not in branch.tags
            ):
                continue
            target_address = _branch_target_address(branch)
            target = blocks_by_start.get(target_address) if target_address is not None else None
            if target is None or target.block_id not in block.successors:
                continue
            false_successors = [item for item in block.successors if item != target.block_id]
            if len(false_successors) != 1:
                continue
            condition = branch.operands[-1]
            for truth, successor in (
                (True, target.block_id),
                (False, false_successors[0]),
            ):
                if not _range_edge_controls_call(
                    function,
                    block.block_id,
                    successor,
                    call_block_id,
                    control_flow,
                ):
                    continue
                for entailed in _entailed_compare_truths(
                    condition,
                    truth,
                    definitions,
                    frozenset(),
                ):
                    key = (entailed.compare.address, entailed.compare.index, entailed.truth)
                    collected[key] = entailed
    return tuple(
        sorted(
            collected.values(),
            key=lambda item: (item.compare.address, item.compare.index, item.truth),
        )
    )


def _range_edge_controls_call(
    function: IRFunction,
    branch_block_id: str,
    successor: str,
    call_block_id: str,
    control_flow: _ControlFlowFacts,
) -> bool:
    if call_block_id == branch_block_id:
        return False
    if (
        successor in control_flow.dominators.get(call_block_id, frozenset())
        and control_flow.predecessors.get(successor, frozenset())
        == frozenset({branch_block_id})
    ):
        return True
    blocks = {block.block_id: block for block in function.blocks}
    branch = blocks[branch_block_id]
    if not _path_exists(blocks, branch_block_id, branch_block_id, require_edge=True):
        return False
    if not _path_exists(blocks, successor, call_block_id):
        return False
    return all(
        other == successor or not _path_exists(blocks, other, call_block_id)
        for other in branch.successors
    )


def _path_exists(
    blocks: dict[str, IRBasicBlock],
    start: str,
    target: str,
    *,
    require_edge: bool = False,
) -> bool:
    pending = list(blocks[start].successors) if require_edge else [start]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current == target:
            return True
        if current in visited:
            continue
        visited.add(current)
        pending.extend(blocks[current].successors)
    return False


def _entailed_compare_truths(
    variable: str,
    truth: bool,
    definitions: dict[str, IRInstruction],
    visited: frozenset[str],
) -> tuple[_EntailedComparison, ...]:
    if variable in visited:
        return ()
    instruction = definitions.get(variable)
    if instruction is None:
        return ()
    if instruction.operation is IROperation.COMPARE:
        return (_EntailedComparison(instruction, truth),)
    next_visited = visited | {variable}
    if instruction.operation is IROperation.BOOLEAN_NOT and instruction.operands:
        return _entailed_compare_truths(
            instruction.operands[0],
            not truth,
            definitions,
            next_visited,
        )
    if (
        instruction.operation is IROperation.BOOLEAN_OR
        and not truth
        or instruction.operation is IROperation.BOOLEAN_AND
        and truth
    ):
        return tuple(
            item
            for operand in instruction.operands
            for item in _entailed_compare_truths(
                operand,
                truth,
                definitions,
                next_visited,
            )
        )
    if instruction.operation in {IROperation.ASSIGN, IROperation.CAST} and len(
        instruction.operands
    ) == 1:
        return _entailed_compare_truths(
            instruction.operands[0],
            truth,
            definitions,
            next_visited,
        )
    return ()


def _upper_bound_capacity(
    compare: IRInstruction,
    truth: bool,
    offset_sources: frozenset[str],
    length_sources: frozenset[str],
    sources: dict[str, frozenset[str]],
    *,
    target: Literal["offset", "length", "combined"],
) -> str | None:
    if len(compare.operands) < 2:
        return None
    kind = _comparison_kind(compare)
    if kind not in {"unsigned_less", "unsigned_less_equal"}:
        return None
    left, right = compare.operands[:2]
    left_role = _range_source_role(
        sources.get(left, frozenset()),
        offset_sources,
        length_sources,
    )
    right_role = _range_source_role(
        sources.get(right, frozenset()),
        offset_sources,
        length_sources,
    )
    if left_role == target and right_role is None and truth:
        return right
    if right_role == target and left_role is None and not truth:
        return left
    return None


def _range_source_role(
    value_sources: frozenset[str],
    offset_sources: frozenset[str],
    length_sources: frozenset[str],
) -> Literal["offset", "length", "combined"] | None:
    if not value_sources:
        return None
    has_offset = bool(value_sources & offset_sources)
    has_length = bool(value_sources & length_sources)
    if has_offset and has_length:
        return "combined"
    if has_offset:
        return "offset"
    if has_length:
        return "length"
    return None


def _remaining_capacity(
    variable: str,
    offset_sources: frozenset[str],
    definitions: dict[str, IRInstruction],
    sources: dict[str, frozenset[str]],
) -> str | None:
    instruction = _strip_value_definition(variable, definitions)
    if instruction is None or instruction.operation is not IROperation.SUBTRACT:
        return None
    if len(instruction.operands) < 2:
        return None
    capacity, offset = instruction.operands[:2]
    if not (sources.get(offset, frozenset()) & offset_sources):
        return None
    if sources.get(capacity, frozenset()) & offset_sources:
        return None
    return capacity


def _subtraction_bound_capacity(
    compare: IRInstruction,
    truth: bool,
    offset_sources: frozenset[str],
    length_sources: frozenset[str],
    definitions: dict[str, IRInstruction],
    sources: dict[str, frozenset[str]],
) -> str | None:
    if len(compare.operands) < 2:
        return None
    kind = _comparison_kind(compare)
    if kind not in {"unsigned_less", "unsigned_less_equal"}:
        return None
    left, right = compare.operands[:2]
    left_role = _range_source_role(
        sources.get(left, frozenset()), offset_sources, length_sources
    )
    right_role = _range_source_role(
        sources.get(right, frozenset()), offset_sources, length_sources
    )
    remaining: str | None = None
    if left_role == "length" and truth:
        remaining = right
    elif right_role == "length" and not truth:
        remaining = left
    if remaining is None:
        return None
    return _remaining_capacity(remaining, offset_sources, definitions, sources)


def _strip_value_definition(
    variable: str,
    definitions: dict[str, IRInstruction],
) -> IRInstruction | None:
    visited: set[str] = set()
    current = variable
    while current not in visited:
        visited.add(current)
        instruction = definitions.get(current)
        if instruction is None:
            return None
        if instruction.operation not in {IROperation.ASSIGN, IROperation.CAST} or len(
            instruction.operands
        ) != 1:
            return instruction
        current = instruction.operands[0]
    return None


def _explicitly_wrapping_sum(
    compare: IRInstruction,
    offset_sources: frozenset[str],
    length_sources: frozenset[str],
    definitions: dict[str, IRInstruction],
    sources: dict[str, frozenset[str]],
) -> bool:
    combined = next(
        (
            operand
            for operand in compare.operands[:2]
            if _range_source_role(
                sources.get(operand, frozenset()),
                offset_sources,
                length_sources,
            )
            == "combined"
        ),
        None,
    )
    if combined is None:
        return False
    addition = _strip_value_definition(combined, definitions)
    if addition is None or addition.operation is not IROperation.ADD:
        return False
    if "arithmetic_may_wrap" in addition.tags:
        return True
    operand_widths = tuple(
        definition.width_bits
        for operand in addition.operands
        if (definition := definitions.get(operand)) is not None
        and definition.width_bits is not None
    )
    return bool(
        addition.width_bits is not None
        and operand_widths
        and addition.width_bits < max(operand_widths)
    )


def _checks_by_capacity(
    checks: list[tuple[str, IRInstruction]],
    definitions: dict[str, IRInstruction],
) -> dict[str, IRInstruction]:
    result: dict[str, IRInstruction] = {}
    for capacity, instruction in checks:
        canonical = _canonical_value(capacity, definitions)
        current = result.get(canonical)
        if current is None or (instruction.address, instruction.index) < (
            current.address,
            current.index,
        ):
            result[canonical] = instruction
    return result


def _canonical_value(
    variable: str,
    definitions: dict[str, IRInstruction],
    visited_from_parent: frozenset[str] = frozenset(),
) -> str:
    visited = set(visited_from_parent)
    current = variable
    while current not in visited:
        visited.add(current)
        instruction = definitions.get(current)
        if instruction is None:
            break
        if instruction.operation in {IROperation.ASSIGN, IROperation.CAST} and len(
            instruction.operands
        ) == 1:
            current = instruction.operands[0]
            continue
        if instruction.operation is IROperation.PHI and instruction.operands:
            roots = {
                _canonical_value(operand, definitions, frozenset(visited))
                for operand in instruction.operands
                if operand not in visited
            }
            if len(roots) == 1:
                current = roots.pop()
            break
        break
    return current


def _requested_length_is_clamped(
    variable: str,
    offset_sources: frozenset[str],
    definitions: dict[str, IRInstruction],
    sources: dict[str, frozenset[str]],
) -> bool:
    pending = [variable]
    visited: set[str] = set()
    saw_phi = False
    saw_remaining = False
    while pending and len(visited) < 64:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        instruction = definitions.get(current)
        if instruction is None:
            continue
        if "range_length_clamped" in instruction.tags:
            return True
        if instruction.operation is IROperation.PHI:
            saw_phi = True
        if (
            instruction.operation is IROperation.SUBTRACT
            and len(instruction.operands) >= 2
            and sources.get(instruction.operands[1], frozenset()) & offset_sources
        ):
            saw_remaining = True
        if instruction.operation in {
            IROperation.ASSIGN,
            IROperation.CAST,
            IROperation.PHI,
            IROperation.SUBTRACT,
        }:
            pending.extend(instruction.operands)
    return saw_phi and saw_remaining


def _composite_range_finding(
    ir: NormalizedBinaryIR,
    candidate: ParserCandidate,
    function: IRFunction,
    call: IRInstruction,
    roles: _RangeRoles,
    assessment: _RangeGuardAssessment,
    definitions: dict[str, IRInstruction],
) -> BinaryStaticFinding | None:
    if assessment.offset_check is None or assessment.length_check is None:
        return None
    evidence: list[BinaryEvidenceStep] = []
    for variable, label in (
        (roles.offset, "Input-backed range offset is produced here."),
        (roles.requested_length, "Input-backed requested length is produced here."),
    ):
        definition = definitions.get(variable)
        if definition is not None:
            evidence.append(
                _step(definition, variables=(variable,), description=label)
            )
    evidence.extend(
        [
            _step(
                assessment.offset_check,
                variables=assessment.offset_check.operands[:2],
                description="A dominating guard validates the offset individually.",
            ),
            _step(
                assessment.length_check,
                variables=assessment.length_check.operands[:2],
                description="A dominating guard validates the length individually.",
            ),
            _step(
                call,
                variables=(roles.offset, roles.requested_length),
                description=(
                    "The exact range reader receives both values without a dominating "
                    "combined offset/length proof against their shared capacity."
                ),
            ),
        ]
    )
    return _make_finding(
        ir,
        candidate,
        function,
        vulnerability_class=BinaryVulnerabilityClass.COMPOSITE_RANGE_GAP,
        severity=BinaryFindingSeverity.HIGH,
        confidence=0.88,
        summary=(
            "Individually bounded input offset and length reach the same range read "
            "without a dominating combined-range invariant."
        ),
        evidence=tuple(evidence),
    )


def _scalar_use_kind(
    instruction: IRInstruction,
    operand_index: int,
) -> BinaryScalarUseKind | None:
    role_kinds = {
        "capacity": BinaryScalarUseKind.CAPACITY,
        "count": BinaryScalarUseKind.COUNT,
        "index": BinaryScalarUseKind.INDEX,
        "offset": BinaryScalarUseKind.RANGE_OFFSET,
        "requested_length": BinaryScalarUseKind.REQUESTED_LENGTH,
    }
    for tag in instruction.tags:
        match = re.fullmatch(r"scalar_role:([a-z_]+):(\d+)", tag)
        if match and int(match.group(2)) == operand_index:
            return role_kinds.get(match.group(1))
    if instruction.operation is IROperation.COMPARE:
        return BinaryScalarUseKind.COMPARISON
    if "pointer_arithmetic" in instruction.tags:
        return BinaryScalarUseKind.INDEX
    if instruction.operation in {
        IROperation.ASSIGN,
        IROperation.BITWISE_AND,
        IROperation.BITWISE_OR,
        IROperation.BOOLEAN_AND,
        IROperation.BOOLEAN_NOT,
        IROperation.BOOLEAN_OR,
        IROperation.BOOLEAN_XOR,
        IROperation.BYTE_SWAP,
        IROperation.CAST,
        IROperation.PHI,
        IROperation.SHIFT_RIGHT,
    }:
        return BinaryScalarUseKind.TRANSFORM
    return None


def _update_dataflow(
    instruction: IRInstruction,
    position: int,
    taint: dict[str, frozenset[str]],
    origins: dict[str, _ArithmeticOrigin],
    freed: dict[str, IRInstruction],
) -> None:
    if instruction.operation is IROperation.PARAMETER and instruction.result:
        source_tags = _input_source_taint(instruction)
        if source_tags:
            taint[instruction.result] = source_tags
        else:
            taint.pop(instruction.result, None)
        origins.pop(instruction.result, None)
        freed.pop(instruction.result, None)
    elif instruction.operation is IROperation.CALL:
        _mark_read_session_buffer(instruction, taint)
        if instruction.result:
            source_tags = _input_source_taint(instruction)
            if source_tags:
                taint[instruction.result] = source_tags
            else:
                taint.pop(instruction.result, None)
            origins.pop(instruction.result, None)
            freed.pop(instruction.result, None)
    elif (
        instruction.operation
        in {
            IROperation.ASSIGN,
            IROperation.BYTE_SWAP,
            IROperation.BOOLEAN_AND,
            IROperation.BOOLEAN_OR,
            IROperation.BOOLEAN_XOR,
            IROperation.BOOLEAN_NOT,
            IROperation.CAST,
            IROperation.COMPARE,
            IROperation.PHI,
        }
        and instruction.result
    ):
        taint[instruction.result] = _operand_taint(instruction, taint)
        origin = _first_origin(instruction.operands, origins)
        if origin:
            origins[instruction.result] = origin
        else:
            origins.pop(instruction.result, None)
        freed.pop(instruction.result, None)
    elif (
        instruction.operation
        in {
            IROperation.ADD,
            IROperation.SUBTRACT,
            IROperation.MULTIPLY,
            IROperation.SHIFT_LEFT,
        }
        and instruction.result
    ):
        combined = _operand_taint(instruction, taint)
        taint[instruction.result] = combined
        if combined:
            origins[instruction.result] = _ArithmeticOrigin(instruction, position, combined)
        else:
            origins.pop(instruction.result, None)
        freed.pop(instruction.result, None)
    elif instruction.operation in {
        IROperation.BITWISE_AND,
        IROperation.BITWISE_OR,
        IROperation.SHIFT_RIGHT,
    } and instruction.result:
        taint[instruction.result] = _operand_taint(instruction, taint)
        origins.pop(instruction.result, None)
        freed.pop(instruction.result, None)
    elif instruction.operation is IROperation.LOAD and instruction.result:
        address = instruction.operands[-1] if instruction.operands else None
        address_taint = taint.get(address, frozenset()) if address else frozenset()
        if {"input_data", "input_buffer"} & address_taint:
            identities = {tag for tag in address_taint if tag.startswith("input_source:")}
            taint[instruction.result] = frozenset({"input_scalar", *identities})
        else:
            taint.pop(instruction.result, None)
        origins.pop(instruction.result, None)
        freed.pop(instruction.result, None)


def _block_input_states(
    function: IRFunction,
    control_flow: _ControlFlowFacts,
) -> dict[str, _DataflowState]:
    outputs: dict[str, _DataflowState] = {}
    inputs: dict[str, _DataflowState] = {}
    maximum_passes = max(1, len(control_flow.reachable) * 2)
    for _ in range(maximum_passes):
        changed = False
        for block in function.blocks:
            if block.block_id not in control_flow.reachable:
                continue
            if block.block_id == control_flow.entry_block_id:
                incoming = _DataflowState({}, {})
            else:
                incoming = _merge_dataflow_states(
                    tuple(
                        outputs[predecessor]
                        for predecessor in control_flow.predecessors[block.block_id]
                        if predecessor in outputs
                    )
                )
            taint = dict(incoming.taint)
            origins = dict(incoming.origins)
            freed: dict[str, IRInstruction] = {}
            for instruction in block.instructions:
                _update_dataflow(instruction, instruction.index, taint, origins, freed)
            output = _DataflowState(taint, origins)
            if inputs.get(block.block_id) != incoming or outputs.get(block.block_id) != output:
                inputs[block.block_id] = incoming
                outputs[block.block_id] = output
                changed = True
        if not changed:
            break
    return inputs


def _merge_dataflow_states(states: tuple[_DataflowState, ...]) -> _DataflowState:
    taint: dict[str, frozenset[str]] = {}
    origins: dict[str, _ArithmeticOrigin] = {}
    for state in states:
        for variable, tags in state.taint.items():
            taint[variable] = taint.get(variable, frozenset()) | tags
        for variable, origin in state.origins.items():
            current = origins.get(variable)
            if current is None or origin.position < current.position:
                origins[variable] = origin
    return _DataflowState(taint, origins)


def _control_flow_facts(function: IRFunction) -> _ControlFlowFacts:
    blocks = {block.block_id: block for block in function.blocks}
    entry = function.blocks[0].block_id
    reachable: set[str] = set()
    pending = [entry]
    while pending:
        block_id = pending.pop()
        if block_id in reachable:
            continue
        reachable.add(block_id)
        pending.extend(blocks[block_id].successors)

    predecessors: dict[str, set[str]] = {block_id: set() for block_id in blocks}
    for block in function.blocks:
        for successor in block.successors:
            predecessors[successor].add(block.block_id)

    dominators: dict[str, set[str]] = {
        block_id: ({entry} if block_id == entry else set(reachable))
        for block_id in reachable
    }
    for _ in range(max(1, len(reachable))):
        changed = False
        for block_id in reachable:
            if block_id == entry:
                continue
            reachable_predecessors = [
                predecessor
                for predecessor in predecessors[block_id]
                if predecessor in reachable
            ]
            if not reachable_predecessors:
                updated = {block_id}
            else:
                shared = set(dominators[reachable_predecessors[0]])
                for predecessor in reachable_predecessors[1:]:
                    shared.intersection_update(dominators[predecessor])
                updated = {block_id, *shared}
            if updated != dominators[block_id]:
                dominators[block_id] = updated
                changed = True
        if not changed:
            break

    return _ControlFlowFacts(
        entry_block_id=entry,
        reachable=frozenset(reachable),
        predecessors={key: frozenset(value) for key, value in predecessors.items()},
        dominators={key: frozenset(value) for key, value in dominators.items()},
        guards=_conditional_guards(function),
    )


def _conditional_guards(function: IRFunction) -> tuple[_ConditionalGuard, ...]:
    blocks_by_start = {block.start_address: block for block in function.blocks}
    guards: list[_ConditionalGuard] = []
    for block in function.blocks:
        if len(block.successors) != 2:
            continue
        comparisons = {
            instruction.result: instruction
            for instruction in block.instructions
            if instruction.operation is IROperation.COMPARE
            and instruction.result
            and len(instruction.operands) >= 2
        }
        for branch in block.instructions:
            if branch.operation is not IROperation.BRANCH or not branch.operands:
                continue
            if "conditional_branch" not in branch.tags and not branch.text.lstrip().upper().startswith(
                "CBRANCH"
            ):
                continue
            compare = comparisons.get(branch.operands[-1])
            if compare is None or compare.index >= branch.index:
                continue
            target_address = _branch_target_address(branch)
            target = blocks_by_start.get(target_address) if target_address is not None else None
            if target is None or target.block_id not in block.successors:
                continue
            false_successors = [item for item in block.successors if item != target.block_id]
            if len(false_successors) != 1:
                continue
            guards.append(
                _ConditionalGuard(
                    compare=compare,
                    block_id=block.block_id,
                    true_successor=target.block_id,
                    false_successor=false_successors[0],
                )
            )
    return tuple(sorted(guards, key=lambda item: item.compare.index))


def _branch_target_address(branch: IRInstruction) -> int | None:
    for tag in branch.tags:
        if tag.startswith("branch_target:"):
            try:
                return int(tag.removeprefix("branch_target:"), 16)
            except ValueError:
                return None
    if branch.operands:
        match = re.search(r"(?:^|_)ram_([0-9a-f]+)(?:_|$)", branch.operands[0].casefold())
        if match:
            return int(match.group(1), 16)
    match = re.search(r"\(ram,\s*0x([0-9a-f]+)", branch.text.casefold())
    return int(match.group(1), 16) if match else None


def _arithmetic_sink_findings(
    ir: NormalizedBinaryIR,
    candidate: ParserCandidate,
    function: IRFunction,
    sink: IRInstruction,
    sink_position: int,
    sink_block_id: str,
    variables: tuple[str, ...],
    origins: dict[str, _ArithmeticOrigin],
    control_flow: _ControlFlowFacts,
) -> list[BinaryStaticFinding]:
    findings: list[BinaryStaticFinding] = []
    for variable in variables:
        origin = origins.get(variable)
        if origin is None or origin.position >= sink_position:
            continue
        if _arithmetic_guarded(variable, origin, sink_block_id, control_flow):
            continue
        pointer_arithmetic = "pointer_arithmetic" in origin.instruction.tags
        is_offset_length = (
            origin.instruction.operation in {IROperation.ADD, IROperation.SUBTRACT}
            and any("offset" in tag for tag in origin.taint)
            and any("length" in tag for tag in origin.taint)
        )
        # Ghidra PTRADD/PTRSUB expresses address formation, including ordinary
        # structure-field access. It is not integer size arithmetic by itself.
        # Preserve the origin for the narrower offset+length OOB rule, but do
        # not promote generic pointer math into an integer-overflow candidate.
        if pointer_arithmetic and not is_offset_length:
            continue
        vulnerability_class = (
            BinaryVulnerabilityClass.OFFSET_LENGTH_OOB
            if is_offset_length
            else BinaryVulnerabilityClass.INTEGER_OVERFLOW
        )
        summary = (
            "Input-derived offset/length arithmetic reaches a memory access without a "
            "visible dominating bound check."
            if is_offset_length
            else "Input-derived arithmetic reaches a memory size sink without a visible "
            "dominating overflow check."
        )
        findings.append(
            _make_finding(
                ir,
                candidate,
                function,
                vulnerability_class=vulnerability_class,
                severity=BinaryFindingSeverity.HIGH,
                confidence=0.76 if is_offset_length else 0.72,
                summary=summary,
                evidence=(
                    _step(
                        origin.instruction,
                        variables=origin.instruction.operands,
                        description="Input-derived arithmetic value is produced here.",
                    ),
                    _step(
                        sink,
                        variables=(variable,),
                        description="The unchecked value reaches a memory size or access sink.",
                    ),
                ),
            )
        )
    return findings


def _allocation_copy_finding(
    ir: NormalizedBinaryIR,
    candidate: ParserCandidate,
    function: IRFunction,
    copy: IRInstruction,
    copy_block_id: str,
    allocations: dict[str, tuple[str, IRInstruction]],
    taint: dict[str, frozenset[str]],
    control_flow: _ControlFlowFacts,
) -> BinaryStaticFinding | None:
    roles = _copy_roles(copy)
    if roles is None:
        return None
    allocation = allocations.get(roles.destination)
    if allocation is None:
        return None
    allocation_size, allocation_instruction = allocation
    if allocation_size == roles.length or not taint.get(roles.length):
        return None
    if _copy_length_guarded(
        allocation_size,
        roles.length,
        copy_block_id,
        control_flow,
    ):
        return None
    return _make_finding(
        ir,
        candidate,
        function,
        vulnerability_class=BinaryVulnerabilityClass.ALLOCATION_COPY_MISMATCH,
        severity=BinaryFindingSeverity.HIGH,
        confidence=0.78,
        summary="An input-derived copy length is not visibly bounded by the destination "
        "allocation size.",
        evidence=(
            _step(
                allocation_instruction,
                variables=(roles.destination, allocation_size),
                description="Destination allocation size is established here.",
            ),
            _step(
                copy,
                variables=(roles.destination, roles.length),
                description="A distinct input-derived length controls the copy.",
            ),
        ),
    )


def _use_after_free_finding(
    ir: NormalizedBinaryIR,
    candidate: ParserCandidate,
    function: IRFunction,
    variable: str,
    free_instruction: IRInstruction,
    use_instruction: IRInstruction,
) -> BinaryStaticFinding:
    return _make_finding(
        ir,
        candidate,
        function,
        vulnerability_class=BinaryVulnerabilityClass.USE_AFTER_FREE,
        severity=BinaryFindingSeverity.CRITICAL,
        confidence=0.86,
        summary="A freed value is reused in the same basic block without reassignment.",
        evidence=(
            _step(
                free_instruction,
                variables=(variable,),
                description="The value is released here.",
            ),
            _step(
                use_instruction,
                variables=(variable,),
                description="The released value is subsequently used here.",
            ),
        ),
    )


def _make_finding(
    ir: NormalizedBinaryIR,
    candidate: ParserCandidate,
    function: IRFunction,
    *,
    vulnerability_class: BinaryVulnerabilityClass,
    severity: BinaryFindingSeverity,
    confidence: float,
    summary: str,
    evidence: tuple[BinaryEvidenceStep, ...],
) -> BinaryStaticFinding:
    ordered_evidence = tuple(sorted(evidence, key=lambda item: item.address))
    sink_address = ordered_evidence[-1].address
    return BinaryStaticFinding(
        finding_id=_finding_id(
            ir.ir_sha256,
            function.function_id,
            vulnerability_class,
            sink_address,
            ordered_evidence[0].address,
        ),
        ir_sha256=ir.ir_sha256,
        candidate_id=candidate.candidate_id,
        function_id=function.function_id,
        function_name=function.name,
        vulnerability_class=vulnerability_class,
        severity=severity,
        confidence=confidence,
        sink_address=sink_address,
        summary=summary,
        evidence=ordered_evidence,
    )


def _step(
    instruction: IRInstruction,
    *,
    variables: tuple[str, ...],
    description: str,
) -> BinaryEvidenceStep:
    return BinaryEvidenceStep(
        address=instruction.address,
        operation=instruction.operation,
        variables=tuple(dict.fromkeys(variables)),
        description=description,
    )


def _operand_taint(
    instruction: IRInstruction,
    taint: dict[str, frozenset[str]],
) -> frozenset[str]:
    return frozenset(
        tag for operand in instruction.operands for tag in taint.get(operand, frozenset())
    )


def _input_source_taint(instruction: IRInstruction) -> frozenset[str]:
    input_classes = _EXPLICIT_INPUT_CLASSES.intersection(instruction.tags)
    if not input_classes or instruction.result is None:
        return frozenset()
    identity = f"input_source:{instruction.address:x}:{instruction.result}"
    return frozenset({*input_classes, identity})


def _mark_read_session_buffer(
    instruction: IRInstruction,
    taint: dict[str, frozenset[str]],
) -> None:
    if "read_session_input" not in instruction.tags:
        return
    indexes: set[int] = set()
    for tag in instruction.tags:
        match = re.fullmatch(r"input_buffer_operand:(\d+)", tag)
        if match:
            indexes.add(int(match.group(1)))
    for operand_index in indexes:
        if operand_index >= len(instruction.operands):
            continue
        variable = instruction.operands[operand_index]
        identity = f"input_source:read_session:{instruction.address:x}"
        taint[variable] = taint.get(variable, frozenset()) | frozenset(
            {"input_buffer", "input_data", identity}
        )


def _first_origin(
    operands: tuple[str, ...],
    origins: dict[str, _ArithmeticOrigin],
) -> _ArithmeticOrigin | None:
    return next((origins[item] for item in operands if item in origins), None)


def _sink_variables(instruction: IRInstruction) -> tuple[str, ...]:
    if instruction.operation is IROperation.COPY:
        roles = _copy_roles(instruction)
        return (roles.destination, roles.length) if roles else ()
    if instruction.operation is IROperation.ALLOCATE:
        size = _allocation_size_variable(instruction)
        return (size,) if size else ()
    if instruction.operation is IROperation.LOAD:
        # Ghidra LOAD is [address_space, address]. Keep the one-operand form
        # accepted by the normalized-IR fixtures and other adapters.
        return instruction.operands[-1:] if instruction.operands else ()
    if instruction.operation is IROperation.STORE:
        # Ghidra STORE is [address_space, address, stored_value]. A simplified
        # adapter may omit the address-space operand and emit [address, value].
        if len(instruction.operands) >= 3:
            return (instruction.operands[1],)
        return instruction.operands[:1]
    return ()


def _copy_roles(instruction: IRInstruction) -> _CopyRoles | None:
    if len(instruction.operands) < 3:
        return None
    callee = _canonical_callee(instruction.callee)
    if callee == "bcopy":
        return _CopyRoles(
            source=instruction.operands[0],
            destination=instruction.operands[1],
            length=instruction.operands[2],
        )
    if callee in {
        "memcpy",
        "memcpychk",
        "memmove",
        "memmovechk",
        "builtinememcpy",
        "builtinememmove",
    }:
        return _CopyRoles(
            destination=instruction.operands[0],
            source=instruction.operands[1],
            length=instruction.operands[2],
        )
    return None


def _allocation_size_variable(instruction: IRInstruction) -> str | None:
    operands = instruction.operands
    if not operands:
        return None
    callee = _canonical_callee(instruction.callee)

    # calloc capacity is count * element_size. Treating either operand as the
    # allocation size would invent a relationship and hide the multiplication
    # that a future composite-capacity rule must model explicitly.
    if callee in {"calloc", "malloctypecalloc", "malloczonecalloc"}:
        return None
    if callee == "cfallocatorallocate" and len(operands) >= 2:
        return operands[1]
    if callee in {"realloc", "reallocf", "malloctyperealloc"} and len(operands) >= 2:
        return operands[1]
    if callee == "malloczonerealloc" and len(operands) >= 3:
        return operands[2]
    if callee == "malloczonemalloc" and len(operands) >= 2:
        return operands[1]
    if callee in {"malloc", "malloctypemalloc", "imageiomalloc"}:
        return operands[0]
    return None


def _canonical_callee(callee: str | None) -> str:
    return "".join(character for character in (callee or "").casefold() if character.isalnum())


def _arithmetic_guarded(
    variable: str,
    origin: _ArithmeticOrigin,
    sink_block_id: str,
    control_flow: _ControlFlowFacts,
) -> bool:
    for guard in control_flow.guards:
        safe_truth = _arithmetic_guard_truth(guard.compare, variable, origin)
        if safe_truth is not None and _safe_edge_dominates_sink(
            guard,
            safe_truth=safe_truth,
            sink_block_id=sink_block_id,
            control_flow=control_flow,
        ):
            return True
    return False


def _copy_length_guarded(
    allocation_size: str,
    copy_length: str,
    sink_block_id: str,
    control_flow: _ControlFlowFacts,
) -> bool:
    for guard in control_flow.guards:
        safe_truth = _copy_guard_truth(guard.compare, allocation_size, copy_length)
        if safe_truth is not None and _safe_edge_dominates_sink(
            guard,
            safe_truth=safe_truth,
            sink_block_id=sink_block_id,
            control_flow=control_flow,
        ):
            return True
    return False


def _safe_edge_dominates_sink(
    guard: _ConditionalGuard,
    *,
    safe_truth: bool,
    sink_block_id: str,
    control_flow: _ControlFlowFacts,
) -> bool:
    if sink_block_id == guard.block_id:
        return False
    safe_successor = guard.true_successor if safe_truth else guard.false_successor
    return (
        safe_successor in control_flow.dominators.get(sink_block_id, frozenset())
        and control_flow.predecessors.get(safe_successor, frozenset())
        == frozenset({guard.block_id})
    )


def _arithmetic_guard_truth(
    compare: IRInstruction,
    variable: str,
    origin: _ArithmeticOrigin,
) -> bool | None:
    kind = _comparison_kind(compare)
    if kind not in {"unsigned_less", "unsigned_less_equal"}:
        return None
    precondition = _arithmetic_input_limit(origin.instruction)
    if precondition is not None:
        input_variables, maximum = precondition
        for input_variable in input_variables:
            truth = _upper_bound_truth(compare, input_variable, maximum, kind)
            if truth is not None:
                return truth

    left, right = compare.operands[:2]
    result_variables = {variable}
    if origin.instruction.result:
        result_variables.add(origin.instruction.result)
    pointer_oob = (
        origin.instruction.operation in {IROperation.ADD, IROperation.SUBTRACT}
        and any("offset" in tag for tag in origin.taint)
        and any("length" in tag for tag in origin.taint)
    )
    if pointer_oob:
        if left in result_variables and right not in result_variables:
            return True
        if right in result_variables and left not in result_variables:
            return False

    if origin.instruction.operation is IROperation.ADD:
        if left in result_variables and right in origin.instruction.operands:
            # Unsigned result < an addend is the canonical wrap predicate; the
            # non-taken edge is the checked path. <= is also a sufficient,
            # deliberately stricter check when the safe path requires result > addend.
            return False
    return None


def _copy_guard_truth(
    compare: IRInstruction,
    allocation_size: str,
    copy_length: str,
) -> bool | None:
    kind = _comparison_kind(compare)
    if kind not in {"unsigned_less", "unsigned_less_equal"}:
        return None
    left, right = compare.operands[:2]
    if left == copy_length and right == allocation_size:
        return True
    if left == allocation_size and right == copy_length:
        return False
    return None


def _arithmetic_input_limit(
    instruction: IRInstruction,
) -> tuple[tuple[str, ...], int] | None:
    if instruction.width_bits is None or instruction.signed is True:
        return None
    constants = tuple(value for value in instruction.constants if value >= 0)
    if len(constants) != 1:
        return None
    constant = constants[0]
    maximum = (1 << instruction.width_bits) - 1
    variables = tuple(
        operand for operand in instruction.operands if _constant_value(operand) is None
    )
    if not variables:
        return None
    if instruction.operation is IROperation.MULTIPLY:
        if constant <= 1:
            return None
        return variables, maximum // constant
    if instruction.operation is IROperation.SHIFT_LEFT:
        if constant >= instruction.width_bits:
            return None
        return variables, maximum >> constant
    if instruction.operation is IROperation.ADD:
        if constant > maximum:
            return None
        return variables, maximum - constant
    return None


def _upper_bound_truth(
    compare: IRInstruction,
    variable: str,
    maximum: int,
    kind: str,
) -> bool | None:
    left, right = compare.operands[:2]
    if left == variable:
        bound = _constant_value(right)
        if bound is None:
            return None
        effective_maximum = bound - 1 if kind == "unsigned_less" else bound
        return True if effective_maximum <= maximum else None
    if right == variable:
        bound = _constant_value(left)
        if bound is None:
            return None
        effective_maximum = bound if kind == "unsigned_less" else bound - 1
        return False if effective_maximum <= maximum else None
    return None


def _constant_value(variable: str) -> int | None:
    match = re.fullmatch(r"const_([0-9a-f]+)", variable.casefold())
    return int(match.group(1), 16) if match else None


def _comparison_kind(compare: IRInstruction) -> str | None:
    for tag in compare.tags:
        if tag.startswith("comparison:"):
            return tag.removeprefix("comparison:")
    mnemonic = compare.text.lstrip().split(maxsplit=1)[0].upper() if compare.text.strip() else ""
    return {
        "INT_LESS": "unsigned_less",
        "INT_LESSEQUAL": "unsigned_less_equal",
        "INT_SLESS": "signed_less",
        "INT_SLESSEQUAL": "signed_less_equal",
        "INT_EQUAL": "equal",
        "INT_NOTEQUAL": "not_equal",
    }.get(mnemonic)


def _deduplicate(findings: list[BinaryStaticFinding]) -> list[BinaryStaticFinding]:
    return list({item.finding_id: item for item in findings}.values())


def _finding_id(
    ir_sha256: str,
    function_identifier: str,
    vulnerability_class: BinaryVulnerabilityClass,
    sink_address: int,
    origin_address: int,
) -> str:
    payload = (
        f"{ir_sha256}:{function_identifier}:{vulnerability_class.value}:"
        f"{origin_address:x}:{sink_address:x}"
    ).encode()
    return "binfinding_" + hashlib.sha256(payload).hexdigest()[:20]


def _finding_sort_key(item: BinaryStaticFinding) -> tuple[int, int, str, str]:
    severity_order = {
        BinaryFindingSeverity.CRITICAL: 0,
        BinaryFindingSeverity.HIGH: 1,
        BinaryFindingSeverity.MEDIUM: 2,
    }
    return (
        severity_order[item.severity],
        item.sink_address,
        item.vulnerability_class.value,
        item.finding_id,
    )


def _scalar_flow_id(
    function_identifier: str,
    variable: str,
    definition_address: int,
    source_identities: tuple[str, ...],
    uses: tuple[BinaryScalarUseEvidence, ...],
) -> str:
    payload = {
        "definition_address": definition_address,
        "function_id": function_identifier,
        "source_identities": source_identities,
        "uses": [item.model_dump(mode="json") for item in uses],
        "variable": variable,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "scalarflow_" + hashlib.sha256(canonical).hexdigest()[:20]


def _range_call_id(
    function_identifier: str,
    address: int,
    instruction_index: int,
    method_identity: str,
    destination: str,
    offset: str,
    requested_length: str,
    available_capacity: str | None,
    actual_length: str | None,
    offset_source_identities: tuple[str, ...],
    length_source_identities: tuple[str, ...],
    individual_check_addresses: tuple[int, ...],
    combined_check_address: int | None,
    guard_status: BinaryRangeGuardStatus,
) -> str:
    payload = {
        "actual_length": actual_length,
        "address": address,
        "available_capacity": available_capacity,
        "combined_check_address": combined_check_address,
        "destination": destination,
        "function_id": function_identifier,
        "instruction_index": instruction_index,
        "guard_status": guard_status.value,
        "individual_check_addresses": individual_check_addresses,
        "length_source_identities": length_source_identities,
        "method_identity": method_identity,
        "offset": offset,
        "offset_source_identities": offset_source_identities,
        "requested_length": requested_length,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "rangecall_" + hashlib.sha256(canonical).hexdigest()[:20]


def _range_report_digest(
    ir_sha256: str,
    discovery_sha256: str,
    analyzed_function_count: int,
    calls: tuple[BinaryRangeCallSummary, ...],
    findings: tuple[BinaryStaticFinding, ...],
) -> str:
    payload = {
        "analyzed_function_count": analyzed_function_count,
        "calls": [item.model_dump(mode="json") for item in calls],
        "discovery_sha256": discovery_sha256,
        "findings": [item.model_dump(mode="json") for item in findings],
        "ir_sha256": ir_sha256,
        "schema_version": "binary-range-analysis-v1",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _provenance_report_digest(
    ir_sha256: str,
    discovery_sha256: str,
    analyzed_function_count: int,
    flows: tuple[BinaryInputScalarFlow, ...],
) -> str:
    payload = {
        "analyzed_function_count": analyzed_function_count,
        "discovery_sha256": discovery_sha256,
        "flows": [item.model_dump(mode="json") for item in flows],
        "ir_sha256": ir_sha256,
        "schema_version": "binary-input-provenance-v1",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _report_digest(
    *,
    ir_sha256: str,
    discovery_sha256: str,
    analyzed_function_count: int,
    findings: tuple[BinaryStaticFinding, ...],
) -> str:
    payload = {
        "analyzed_function_count": analyzed_function_count,
        "discovery_sha256": discovery_sha256,
        "findings": [item.model_dump(mode="json") for item in findings],
        "ir_sha256": ir_sha256,
        "schema_version": "binary-static-analysis-v1",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
