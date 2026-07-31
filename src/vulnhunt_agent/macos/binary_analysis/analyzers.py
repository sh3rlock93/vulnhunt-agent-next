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
from .ir import IRFunction, IRInstruction, IROperation, NormalizedBinaryIR


class BinaryVulnerabilityClass(StrEnum):
    INTEGER_OVERFLOW = "integer_overflow"
    OFFSET_LENGTH_OOB = "offset_length_oob"
    ALLOCATION_COPY_MISMATCH = "allocation_copy_mismatch"
    USE_AFTER_FREE = "use_after_free"


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
    findings: list[BinaryStaticFinding] = []
    analyzed = 0
    for candidate in discovery.candidates:
        function = functions.get(candidate.function_id)
        if function is None:
            raise ValueError("parser discovery cites a function absent from the IR")
        analyzed += 1
        function_findings = _analyze_function(ir, candidate, function)
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


def _update_dataflow(
    instruction: IRInstruction,
    position: int,
    taint: dict[str, frozenset[str]],
    origins: dict[str, _ArithmeticOrigin],
    freed: dict[str, IRInstruction],
) -> None:
    if instruction.operation is IROperation.PARAMETER and instruction.result:
        source_tags = _input_source_tags(instruction)
        if source_tags:
            taint[instruction.result] = source_tags
        else:
            taint.pop(instruction.result, None)
        origins.pop(instruction.result, None)
        freed.pop(instruction.result, None)
    elif instruction.operation is IROperation.CALL and instruction.result:
        source_tags = _input_source_tags(instruction)
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
            IROperation.CAST,
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
    elif instruction.operation is IROperation.BITWISE_AND and instruction.result:
        taint[instruction.result] = _operand_taint(instruction, taint)
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


def _input_source_tags(instruction: IRInstruction) -> frozenset[str]:
    return frozenset(tag for tag in instruction.tags if tag.startswith("input_"))


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
