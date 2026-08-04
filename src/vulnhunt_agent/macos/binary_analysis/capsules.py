"""Bounded interprocedural evidence capsules for decompiler-native Hunters."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from ...domain.schemas import DomainModel, SHA256_PATTERN
from .admission import (
    CodeHuntAdmission,
    CodeHuntRoot,
    materialize_code_hunt_admission,
)
from .analyzers import BinaryAnalysisReport
from .decompiler_hunt import (
    DecompilerArtifactDigest,
    DecompilerHuntStatus,
    load_decompiler_hunt_manifest,
)
from .ir import (
    IRBasicBlock,
    IRFunction,
    IRFunctionCoverage,
    IRInstruction,
    IROperation,
    NormalizedBinaryIR,
)

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


class CapsuleProofStatus(StrEnum):
    PROOF_CAPABLE = "proof_capable"
    PROOF_INCOMPLETE = "proof_incomplete"


class EvidenceFunctionRole(StrEnum):
    ROOT = "root"
    CALLER = "caller"
    CALLEE = "callee"


class BinaryEvidenceFactKind(StrEnum):
    INPUT_SOURCE = "input_source"
    DATAFLOW = "dataflow"
    GUARD = "guard"
    SECURITY_SINK = "security_sink"
    CALLSITE = "callsite"
    RETURN_USE = "return_use"
    UNKNOWN = "unknown"


class CapsuleOmissionKind(StrEnum):
    BYTE_BUDGET = "byte_budget"
    CALL_DEPTH = "call_depth"
    FUNCTION_CAP = "function_cap"
    INSTRUCTION_CAP = "instruction_cap"
    BLOCK_CAP = "block_cap"
    PSEUDOCODE_TRUNCATED = "pseudocode_truncated"
    UNAVAILABLE_FUNCTION = "unavailable_function"
    UNRESOLVED_CALL = "unresolved_call"


class CapsuleIncompleteReason(StrEnum):
    BYTE_BUDGET = "byte_budget"
    CALL_DEPTH = "call_depth"
    FUNCTION_CAP = "function_cap"
    MISSING_INPUT_SOURCE = "missing_input_source"
    MISSING_SECURITY_SINK = "missing_security_sink"
    REQUIRED_BLOCKS_OMITTED = "required_blocks_omitted"
    REQUIRED_INSTRUCTIONS_OMITTED = "required_instructions_omitted"
    UNRESOLVED_CALL_BOUNDARY = "unresolved_call_boundary"


class BinaryEvidenceCapsulePolicy(DomainModel):
    maximum_call_depth: int = Field(default=2, ge=0, le=8)
    maximum_functions: int = Field(default=8, ge=1, le=64)
    maximum_evidence_bytes: int = Field(default=96 * 1024, ge=16 * 1024, le=1024 * 1024)
    maximum_blocks_per_function: int = Field(default=32, ge=1, le=1024)
    maximum_instructions_per_function: int = Field(default=192, ge=8, le=10000)
    maximum_pseudocode_bytes_per_function: int = Field(
        default=12 * 1024,
        ge=0,
        le=256 * 1024,
    )


class BinaryEvidenceBlock(DomainModel):
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    block_id: str = Field(pattern=r"^bb_[0-9a-f]{16}$")
    start_address: int = Field(ge=0)
    end_address: int = Field(ge=0)
    successors: tuple[str, ...] = Field(default=(), max_length=64)
    instructions: tuple[IRInstruction, ...] = Field(min_length=1, max_length=10000)
    full_instruction_count: int = Field(ge=1)
    omitted_instruction_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_block(self) -> "BinaryEvidenceBlock":
        order = tuple((item.address, item.index) for item in self.instructions)
        if tuple(sorted(set(order))) != order:
            raise ValueError("capsule instructions must be canonically ordered and unique")
        if self.full_instruction_count != len(self.instructions) + self.omitted_instruction_count:
            raise ValueError("capsule block instruction accounting does not balance")
        if tuple(sorted(set(self.successors))) != self.successors:
            raise ValueError("capsule block successors must be sorted and unique")
        return self


class BinaryEvidenceFunction(DomainModel):
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    function_name: str = Field(min_length=1, max_length=500)
    start_address: int = Field(ge=0)
    end_address: int = Field(ge=0)
    roles: tuple[EvidenceFunctionRole, ...] = Field(min_length=1, max_length=3)
    call_depth: int = Field(ge=0, le=8)
    pseudocode_excerpt: str = Field(default="", max_length=256000)
    pseudocode_sha256: str = Field(pattern=SHA256_PATTERN)
    pseudocode_truncated: bool
    blocks: tuple[BinaryEvidenceBlock, ...] = Field(min_length=1, max_length=1024)
    omitted_block_ids: tuple[str, ...] = Field(default=(), max_length=10000)
    function_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_function(self) -> "BinaryEvidenceFunction":
        if tuple(sorted(set(self.roles), key=str)) != self.roles:
            raise ValueError("capsule function roles must be sorted and unique")
        if tuple(sorted(self.blocks, key=lambda item: item.start_address)) != self.blocks:
            raise ValueError("capsule blocks must preserve address order")
        if tuple(sorted(set(self.omitted_block_ids))) != self.omitted_block_ids:
            raise ValueError("omitted capsule blocks must be sorted and unique")
        overlap = {item.block_id for item in self.blocks}.intersection(
            self.omitted_block_ids
        )
        if overlap:
            raise ValueError(
                "included and omitted capsule blocks overlap: "
                + ", ".join(sorted(overlap))
            )
        expected = _function_digest(
            function_id=self.function_id,
            function_name=self.function_name,
            start_address=self.start_address,
            end_address=self.end_address,
            roles=self.roles,
            call_depth=self.call_depth,
            pseudocode_excerpt=self.pseudocode_excerpt,
            pseudocode_sha256=self.pseudocode_sha256,
            pseudocode_truncated=self.pseudocode_truncated,
            blocks=self.blocks,
            omitted_block_ids=self.omitted_block_ids,
        )
        if self.function_sha256 != expected:
            raise ValueError(
                "capsule function digest does not match its code evidence: "
                f"expected {expected}, observed {self.function_sha256}"
            )
        return self


class BinaryInterproceduralEdge(DomainModel):
    edge_id: str = Field(pattern=r"^calledge_[0-9a-f]{20}$")
    caller_function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    callee_function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    callsite_address: int = Field(ge=0)
    arguments: tuple[str, ...] = Field(default=(), max_length=32)
    return_result: str | None = Field(default=None, min_length=1, max_length=160)

    @model_validator(mode="after")
    def validate_edge(self) -> "BinaryInterproceduralEdge":
        expected = _edge_id(
            self.caller_function_id,
            self.callee_function_id,
            self.callsite_address,
        )
        if self.edge_id != expected:
            raise ValueError("capsule call edge id does not match its callsite")
        return self


class BinaryEvidenceFact(DomainModel):
    fact_id: str = Field(pattern=r"^codefact_[0-9a-f]{20}$")
    kind: BinaryEvidenceFactKind
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    block_id: str = Field(pattern=r"^bb_[0-9a-f]{16}$")
    address: int = Field(ge=0)
    instruction_index: int = Field(ge=0)
    operation: IROperation
    result: str | None = Field(default=None, min_length=1, max_length=160)
    operands: tuple[str, ...] = Field(default=(), max_length=32)
    callee: str | None = Field(default=None, min_length=1, max_length=500)
    detail: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def validate_fact(self) -> "BinaryEvidenceFact":
        expected = _fact_id(
            self.function_id,
            self.address,
            self.instruction_index,
            self.kind,
        )
        if self.fact_id != expected:
            raise ValueError("binary evidence fact id does not match its address")
        return self


class BinaryCapsuleOmission(DomainModel):
    kind: CapsuleOmissionKind
    function_id: str | None = Field(default=None, pattern=r"^fn_[0-9a-f]{20}$")
    block_id: str | None = Field(default=None, pattern=r"^bb_[0-9a-f]{16}$")
    address: int | None = Field(default=None, ge=0)
    detail: str = Field(min_length=1, max_length=500)


class BinaryEvidenceCapsule(DomainModel):
    schema_version: Literal["binary-evidence-capsule-v1"] = "binary-evidence-capsule-v1"
    root_id: str = Field(pattern=r"^coderoot_[0-9a-f]{20}$")
    admission_rank: int = Field(ge=1, le=100000)
    root_function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    ir_sha256: str = Field(pattern=SHA256_PATTERN)
    discovery_sha256: str = Field(pattern=SHA256_PATTERN)
    report_sha256: str = Field(pattern=SHA256_PATTERN)
    coverage_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    admission_sha256: str = Field(pattern=SHA256_PATTERN)
    policy: BinaryEvidenceCapsulePolicy
    proof_status: CapsuleProofStatus
    proof_incomplete_reasons: tuple[CapsuleIncompleteReason, ...] = Field(
        default=(),
        max_length=16,
    )
    functions: tuple[BinaryEvidenceFunction, ...] = Field(min_length=1, max_length=64)
    call_edges: tuple[BinaryInterproceduralEdge, ...] = Field(default=(), max_length=10000)
    facts: tuple[BinaryEvidenceFact, ...] = Field(min_length=1, max_length=10000)
    omissions: tuple[BinaryCapsuleOmission, ...] = Field(default=(), max_length=10000)
    evidence_bytes: int = Field(ge=1, le=1024 * 1024)
    capsule_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_capsule(self) -> "BinaryEvidenceCapsule":
        if len(self.functions) > self.policy.maximum_functions:
            raise ValueError("capsule function count exceeds its policy")
        if self.functions[0].function_id != self.root_function_id:
            raise ValueError("capsule root function must be first")
        function_ids = {item.function_id for item in self.functions}
        if len(function_ids) != len(self.functions):
            raise ValueError("capsule functions must be deduplicated")
        if EvidenceFunctionRole.ROOT not in self.functions[0].roles:
            raise ValueError("capsule first function lacks the root role")
        edge_order = tuple(
            sorted(
                self.call_edges,
                key=lambda item: (
                    item.callsite_address,
                    item.caller_function_id,
                    item.callee_function_id,
                ),
            )
        )
        if edge_order != self.call_edges or len({item.edge_id for item in self.call_edges}) != len(
            self.call_edges
        ):
            raise ValueError("capsule call edges must be canonically ordered and unique")
        if any(
            edge.caller_function_id not in function_ids
            or edge.callee_function_id not in function_ids
            for edge in self.call_edges
        ):
            raise ValueError("capsule call edge cites a function outside the capsule")
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
        if fact_order != self.facts or len({item.fact_id for item in self.facts}) != len(self.facts):
            raise ValueError("capsule facts must be canonically ordered and unique")
        addresses = {
            (function.function_id, instruction.address, instruction.index)
            for function in self.functions
            for block in function.blocks
            for instruction in block.instructions
        }
        callsite_addresses = {
            (function_id, address)
            for function_id, address, _ in addresses
        }
        if any(
            (item.caller_function_id, item.callsite_address) not in callsite_addresses
            for item in self.call_edges
        ):
            raise ValueError("capsule call edge lacks address-backed callsite IR")
        if any(
            (item.function_id, item.address, item.instruction_index) not in addresses
            for item in self.facts
        ):
            raise ValueError("capsule fact lacks address-backed normalized IR")
        if tuple(sorted(set(self.proof_incomplete_reasons), key=str)) != (
            self.proof_incomplete_reasons
        ):
            raise ValueError("proof-incomplete reasons must be sorted and unique")
        if self.proof_status is CapsuleProofStatus.PROOF_CAPABLE:
            if self.proof_incomplete_reasons:
                raise ValueError("proof-capable capsule cannot have incomplete reasons")
        elif not self.proof_incomplete_reasons:
            raise ValueError("proof-incomplete capsule requires an explicit reason")
        expected_bytes = _evidence_size(
            self.functions,
            self.call_edges,
            self.facts,
            self.omissions,
        )
        if self.evidence_bytes != expected_bytes:
            raise ValueError("capsule evidence byte count does not match its content")
        if self.evidence_bytes > self.policy.maximum_evidence_bytes:
            raise ValueError("capsule exceeds its evidence byte budget")
        expected_digest = _capsule_digest(self)
        if self.capsule_sha256 != expected_digest:
            raise ValueError("capsule digest does not match its evidence")
        return self


class BinaryEvidenceCapsuleSet(DomainModel):
    schema_version: Literal["binary-evidence-capsule-set-v1"] = (
        "binary-evidence-capsule-set-v1"
    )
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    ir_sha256: str = Field(pattern=SHA256_PATTERN)
    admission_sha256: str = Field(pattern=SHA256_PATTERN)
    policy: BinaryEvidenceCapsulePolicy
    admitted_root_ids: tuple[str, ...] = Field(max_length=1024)
    capsules: tuple[BinaryEvidenceCapsule, ...] = Field(max_length=1024)
    capsule_set_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_capsule_set(self) -> "BinaryEvidenceCapsuleSet":
        if tuple(item.admission_rank for item in self.capsules) != tuple(
            range(1, len(self.capsules) + 1)
        ):
            raise ValueError("capsules must preserve exact admission execution order")
        if tuple(item.root_id for item in self.capsules) != self.admitted_root_ids:
            raise ValueError("capsule roots do not match admitted root order")
        if any(
            item.snapshot_sha256 != self.snapshot_sha256
            or item.ir_sha256 != self.ir_sha256
            or item.admission_sha256 != self.admission_sha256
            or item.policy != self.policy
            for item in self.capsules
        ):
            raise ValueError("capsule set contains evidence from a different run or policy")
        expected = _capsule_set_digest(
            snapshot_sha256=self.snapshot_sha256,
            ir_sha256=self.ir_sha256,
            admission_sha256=self.admission_sha256,
            policy=self.policy,
            admitted_root_ids=self.admitted_root_ids,
            capsules=self.capsules,
        )
        if self.capsule_set_sha256 != expected:
            raise ValueError("capsule set digest does not match its capsules")
        return self


@dataclass(frozen=True)
class _RawCallEdge:
    caller_function_id: str
    callee_function_id: str
    instruction: IRInstruction


@dataclass(frozen=True)
class _FunctionSelection:
    function: IRFunction
    roles: tuple[EvidenceFunctionRole, ...]
    depth: int


@dataclass(frozen=True)
class _FunctionBuild:
    evidence: BinaryEvidenceFunction
    facts: tuple[BinaryEvidenceFact, ...]
    omissions: tuple[BinaryCapsuleOmission, ...]
    incomplete: tuple[CapsuleIncompleteReason, ...]


def build_binary_evidence_capsules(
    ir: NormalizedBinaryIR,
    report: BinaryAnalysisReport,
    admission: CodeHuntAdmission,
    *,
    policy: BinaryEvidenceCapsulePolicy | None = None,
) -> BinaryEvidenceCapsuleSet:
    """Build one deterministic, address-backed code capsule per admitted root."""

    active_policy = policy or BinaryEvidenceCapsulePolicy()
    _validate_inputs(ir, report, admission)
    raw_edges, unresolved = _recover_call_edges(ir)
    functions = {item.function_id: item for item in ir.functions}
    coverage_by_id = (
        {item.function_id: item for item in ir.function_coverage.functions}
        if ir.function_coverage is not None
        else {}
    )
    address_to_id = {item.start_address: item.function_id for item in ir.functions}
    finding_addresses: dict[str, set[int]] = defaultdict(set)
    for finding in report.findings:
        finding_addresses[finding.function_id].update(item.address for item in finding.evidence)

    capsules = tuple(
        _build_capsule(
            root,
            ir=ir,
            admission=admission,
            functions=functions,
            coverage_by_id=coverage_by_id,
            address_to_id=address_to_id,
            raw_edges=raw_edges,
            unresolved=unresolved,
            finding_addresses=finding_addresses,
            policy=active_policy,
        )
        for root in admission.roots
    )
    root_ids = tuple(item.root_id for item in admission.roots)
    digest = _capsule_set_digest(
        snapshot_sha256=ir.snapshot_sha256,
        ir_sha256=ir.ir_sha256,
        admission_sha256=admission.admission_sha256,
        policy=active_policy,
        admitted_root_ids=root_ids,
        capsules=capsules,
    )
    return BinaryEvidenceCapsuleSet(
        snapshot_sha256=ir.snapshot_sha256,
        ir_sha256=ir.ir_sha256,
        admission_sha256=admission.admission_sha256,
        policy=active_policy,
        admitted_root_ids=root_ids,
        capsules=capsules,
        capsule_set_sha256=digest,
    )


def materialize_binary_evidence_capsules(
    output_directory: Path,
    *,
    policy: BinaryEvidenceCapsulePolicy | None = None,
) -> BinaryEvidenceCapsuleSet:
    """Materialize M17-3 capsules beneath a completed private M17 run."""

    output = output_directory.expanduser()
    manifest = load_decompiler_hunt_manifest(output)
    if manifest.status is not DecompilerHuntStatus.COMPLETED:
        raise ValueError("evidence capsules require a completed M17 run")
    admission = materialize_code_hunt_admission(output)
    artifacts = {item.name: item for item in manifest.artifacts}
    ir_payload = _read_frozen_artifact(output, "normalized-ir.json", artifacts)
    report_payload = _read_frozen_artifact(output, "static-analysis.json", artifacts)
    ir = NormalizedBinaryIR.model_validate_json(ir_payload)
    report = BinaryAnalysisReport.model_validate_json(report_payload)
    capsule_set = build_binary_evidence_capsules(
        ir,
        report,
        admission,
        policy=policy,
    )
    m17 = _private_directory(output / "m17")
    path = m17 / "evidence-capsules.json"
    encoded = _encoded_json(capsule_set.model_dump(mode="json"))
    if path.exists():
        existing = _regular_file(path).read_bytes()
        if existing != encoded:
            raise ValueError("existing evidence capsules do not match requested policy")
        return BinaryEvidenceCapsuleSet.model_validate_json(existing)
    _write_private_bytes(path, encoded)
    return capsule_set


def _build_capsule(
    root: CodeHuntRoot,
    *,
    ir: NormalizedBinaryIR,
    admission: CodeHuntAdmission,
    functions: dict[str, IRFunction],
    coverage_by_id: Mapping[str, IRFunctionCoverage],
    address_to_id: dict[int, str],
    raw_edges: tuple[_RawCallEdge, ...],
    unresolved: dict[str, tuple[IRInstruction, ...]],
    finding_addresses: dict[str, set[int]],
    policy: BinaryEvidenceCapsulePolicy,
) -> BinaryEvidenceCapsule:
    selections, graph_omissions, graph_incomplete = _select_functions(
        root.function_id,
        functions=functions,
        coverage_by_id=coverage_by_id,
        address_to_id=address_to_id,
        raw_edges=raw_edges,
        policy=policy,
    )
    builds = [
        _build_function_evidence(
            item,
            finding_addresses=finding_addresses.get(item.function.function_id, set()),
            policy=policy,
            instruction_limit=policy.maximum_instructions_per_function,
        )
        for item in selections
    ]
    omissions = list(graph_omissions)
    incomplete = set(graph_incomplete)
    for build in builds:
        omissions.extend(build.omissions)
        incomplete.update(build.incomplete)
    for selection in selections:
        for instruction in unresolved.get(selection.function.function_id, ()):
            omissions.append(
                BinaryCapsuleOmission(
                    kind=CapsuleOmissionKind.UNRESOLVED_CALL,
                    function_id=selection.function.function_id,
                    address=instruction.address,
                    detail=f"unresolved internal call target: {instruction.callee}",
                )
            )
            incomplete.add(CapsuleIncompleteReason.UNRESOLVED_CALL_BOUNDARY)

    evidence_functions = [item.evidence for item in builds]
    included_ids = {item.function_id for item in evidence_functions}
    edges = _materialized_edges(raw_edges, included_ids)
    facts = [fact for build in builds for fact in build.facts]
    available_addresses = {
        (function.function_id, instruction.address)
        for function in evidence_functions
        for block in function.blocks
        for instruction in block.instructions
    }
    retained_edges: list[BinaryInterproceduralEdge] = []
    for edge in edges:
        if (edge.caller_function_id, edge.callsite_address) in available_addresses:
            retained_edges.append(edge)
            continue
        omissions.append(
            BinaryCapsuleOmission(
                kind=CapsuleOmissionKind.UNRESOLVED_CALL,
                function_id=edge.caller_function_id,
                address=edge.callsite_address,
                detail="internal callsite fell outside the bounded IR slice",
            )
        )
        incomplete.add(CapsuleIncompleteReason.UNRESOLVED_CALL_BOUNDARY)
    edges = retained_edges
    _add_missing_fact_reasons(facts, incomplete)

    for index in range(len(evidence_functions) - 1, -1, -1):
        if _evidence_size_tuple(evidence_functions, edges, facts, omissions) <= (
            policy.maximum_evidence_bytes
        ):
            break
        function = evidence_functions[index]
        if not function.pseudocode_excerpt:
            continue
        evidence_functions[index] = _without_pseudocode(function)
        omissions.append(
            BinaryCapsuleOmission(
                kind=CapsuleOmissionKind.BYTE_BUDGET,
                function_id=function.function_id,
                detail="pseudocode excerpt omitted after preserving normalized IR evidence",
            )
        )
        incomplete.add(CapsuleIncompleteReason.BYTE_BUDGET)

    while _evidence_size_tuple(evidence_functions, edges, facts, omissions) > (
        policy.maximum_evidence_bytes
    ) and len(evidence_functions) > 1:
        removed = evidence_functions.pop()
        included_ids.remove(removed.function_id)
        facts = [item for item in facts if item.function_id != removed.function_id]
        edges = [
            item
            for item in edges
            if item.caller_function_id in included_ids and item.callee_function_id in included_ids
        ]
        omissions.append(
            BinaryCapsuleOmission(
                kind=CapsuleOmissionKind.BYTE_BUDGET,
                function_id=removed.function_id,
                detail="lower-priority interprocedural neighbor omitted to preserve required evidence",
            )
        )
        incomplete.add(CapsuleIncompleteReason.BYTE_BUDGET)

    instruction_limit = policy.maximum_instructions_per_function
    while _evidence_size_tuple(evidence_functions, edges, facts, omissions) > (
        policy.maximum_evidence_bytes
    ) and instruction_limit > 8:
        instruction_limit = max(8, instruction_limit // 2)
        root_selection = selections[0]
        rebuilt = _build_function_evidence(
            root_selection,
            finding_addresses=finding_addresses.get(root.function_id, set()),
            policy=policy,
            instruction_limit=instruction_limit,
        )
        evidence_functions = [rebuilt.evidence]
        facts = list(rebuilt.facts)
        edges = []
        omissions.extend(rebuilt.omissions)
        incomplete.update(rebuilt.incomplete)
        incomplete.add(CapsuleIncompleteReason.BYTE_BUDGET)

    if _evidence_size_tuple(evidence_functions, edges, facts, omissions) > (
        policy.maximum_evidence_bytes
    ):
        raise ValueError("minimum address-backed root evidence exceeds capsule budget")

    _add_missing_fact_reasons(facts, incomplete)

    ordered_functions = tuple(evidence_functions)
    ordered_edges = tuple(
        sorted(
            edges,
            key=lambda item: (
                item.callsite_address,
                item.caller_function_id,
                item.callee_function_id,
            ),
        )
    )
    ordered_facts = tuple(
        sorted(
            facts,
            key=lambda item: (
                item.address,
                item.instruction_index,
                item.function_id,
                item.kind.value,
            ),
        )
    )
    ordered_omissions = tuple(sorted(omissions, key=_omission_key))
    reasons = tuple(sorted(incomplete, key=str))
    status = (
        CapsuleProofStatus.PROOF_INCOMPLETE
        if reasons
        else CapsuleProofStatus.PROOF_CAPABLE
    )
    evidence_bytes = _evidence_size(
        ordered_functions,
        ordered_edges,
        ordered_facts,
        ordered_omissions,
    )
    payload = {
        "root_id": root.root_id,
        "admission_rank": root.admission_rank,
        "root_function_id": root.function_id,
        "snapshot_sha256": ir.snapshot_sha256,
        "ir_sha256": ir.ir_sha256,
        "discovery_sha256": admission.discovery_sha256,
        "report_sha256": admission.report_sha256,
        "coverage_sha256": admission.coverage_sha256,
        "admission_sha256": admission.admission_sha256,
        "policy": policy,
        "proof_status": status,
        "proof_incomplete_reasons": reasons,
        "functions": ordered_functions,
        "call_edges": ordered_edges,
        "facts": ordered_facts,
        "omissions": ordered_omissions,
        "evidence_bytes": evidence_bytes,
    }
    capsule = BinaryEvidenceCapsule(
        **payload,
        capsule_sha256=_capsule_digest_payload(payload),
    )
    return capsule


def _select_functions(
    root_id: str,
    *,
    functions: dict[str, IRFunction],
    coverage_by_id: Mapping[str, IRFunctionCoverage],
    address_to_id: dict[int, str],
    raw_edges: tuple[_RawCallEdge, ...],
    policy: BinaryEvidenceCapsulePolicy,
) -> tuple[
    tuple[_FunctionSelection, ...],
    tuple[BinaryCapsuleOmission, ...],
    tuple[CapsuleIncompleteReason, ...],
]:
    adjacency: dict[str, list[tuple[str, EvidenceFunctionRole]]] = defaultdict(list)
    for edge in raw_edges:
        adjacency[edge.caller_function_id].append(
            (edge.callee_function_id, EvidenceFunctionRole.CALLEE)
        )
        adjacency[edge.callee_function_id].append(
            (edge.caller_function_id, EvidenceFunctionRole.CALLER)
        )
    unavailable_by_id: dict[str, set[int]] = defaultdict(set)
    for identifier, coverage in coverage_by_id.items():
        for address in coverage.callees:
            neighbor = address_to_id.get(address)
            if neighbor is None:
                unavailable_by_id[identifier].add(address)
            else:
                adjacency[identifier].append((neighbor, EvidenceFunctionRole.CALLEE))
        for address in coverage.callers:
            neighbor = address_to_id.get(address)
            if neighbor is None:
                unavailable_by_id[identifier].add(address)
            else:
                adjacency[identifier].append((neighbor, EvidenceFunctionRole.CALLER))
    for identifier in adjacency:
        adjacency[identifier] = sorted(set(adjacency[identifier]), key=lambda item: (item[0], str(item[1])))

    depths = {root_id: 0}
    roles: dict[str, set[EvidenceFunctionRole]] = defaultdict(set)
    roles[root_id].add(EvidenceFunctionRole.ROOT)
    queue: deque[str] = deque([root_id])
    depth_limited: set[str] = set()
    while queue:
        current = queue.popleft()
        depth = depths[current]
        for neighbor, role in adjacency.get(current, []):
            if neighbor not in functions:
                continue
            if depth >= policy.maximum_call_depth:
                if neighbor not in depths:
                    depth_limited.add(neighbor)
                continue
            roles[neighbor].add(role)
            proposed = depth + 1
            if neighbor not in depths or proposed < depths[neighbor]:
                depths[neighbor] = proposed
                queue.append(neighbor)

    candidates = sorted(
        (identifier for identifier in depths if identifier != root_id),
        key=lambda identifier: (
            depths[identifier],
            0 if EvidenceFunctionRole.CALLER in roles[identifier] else 1,
            functions[identifier].start_address,
            identifier,
        ),
    )
    selected_ids = [root_id, *candidates[: policy.maximum_functions - 1]]
    selections = tuple(
        _FunctionSelection(
            function=functions[identifier],
            roles=tuple(sorted(roles[identifier], key=str)),
            depth=depths[identifier],
        )
        for identifier in selected_ids
    )
    omissions: list[BinaryCapsuleOmission] = []
    incomplete: set[CapsuleIncompleteReason] = set()
    for identifier in candidates[policy.maximum_functions - 1 :]:
        omissions.append(
            BinaryCapsuleOmission(
                kind=CapsuleOmissionKind.FUNCTION_CAP,
                function_id=identifier,
                detail=f"reachable function omitted at maximum_functions={policy.maximum_functions}",
            )
        )
        incomplete.add(CapsuleIncompleteReason.FUNCTION_CAP)
    for identifier in sorted(depth_limited, key=lambda item: functions[item].start_address):
        omissions.append(
            BinaryCapsuleOmission(
                kind=CapsuleOmissionKind.CALL_DEPTH,
                function_id=identifier,
                detail=f"reachable function exceeds maximum_call_depth={policy.maximum_call_depth}",
            )
        )
        incomplete.add(CapsuleIncompleteReason.CALL_DEPTH)
    unavailable = {
        address
        for identifier in depths
        for address in unavailable_by_id.get(identifier, set())
    }
    for address in sorted(unavailable)[:32]:
        omissions.append(
            BinaryCapsuleOmission(
                kind=CapsuleOmissionKind.UNAVAILABLE_FUNCTION,
                address=address,
                detail="coverage references a function absent from the frozen normalized IR",
            )
        )
    return selections, tuple(omissions), tuple(sorted(incomplete, key=str))


def _build_function_evidence(
    selection: _FunctionSelection,
    *,
    finding_addresses: set[int],
    policy: BinaryEvidenceCapsulePolicy,
    instruction_limit: int,
) -> _FunctionBuild:
    function = selection.function
    records = [
        (block, instruction)
        for block in function.blocks
        for instruction in block.instructions
    ]
    definitions = {
        instruction.result: (block, instruction)
        for block, instruction in records
        if instruction.result is not None
    }
    priorities: dict[tuple[int, int], int] = {}
    pending: deque[tuple[IRBasicBlock, IRInstruction]] = deque()
    for block, instruction in records:
        priority = _instruction_priority(instruction, finding_addresses)
        if priority is not None:
            key = (instruction.address, instruction.index)
            priorities[key] = min(priority, priorities.get(key, priority))
            pending.append((block, instruction))
    while pending:
        _, instruction = pending.popleft()
        current_priority = priorities[(instruction.address, instruction.index)]
        for operand in instruction.operands:
            definition = definitions.get(operand)
            if definition is None:
                continue
            _, dependency = definition
            key = (dependency.address, dependency.index)
            priority = min(6, max(4, current_priority + 1))
            if key not in priorities or priority < priorities[key]:
                priorities[key] = priority
                pending.append(definition)

    ordered = sorted(
        (
            (priorities[(instruction.address, instruction.index)], block, instruction)
            for block, instruction in records
            if (instruction.address, instruction.index) in priorities
        ),
        key=lambda item: (item[0], item[2].address, item[2].index),
    )
    omitted_required = len(ordered) > instruction_limit
    chosen = ordered[:instruction_limit]
    chosen_keys = {(item.address, item.index) for _, _, item in chosen}
    block_priority: dict[str, tuple[int, int]] = {}
    for priority, block, instruction in chosen:
        block_priority[block.block_id] = min(
            block_priority.get(block.block_id, (priority, instruction.address)),
            (priority, instruction.address),
        )
    chosen_blocks = {
        block_id
        for block_id, _ in sorted(block_priority.items(), key=lambda item: (*item[1], item[0]))[
            : policy.maximum_blocks_per_function
        ]
    }
    block_limited = len(block_priority) > policy.maximum_blocks_per_function
    evidence_blocks: list[BinaryEvidenceBlock] = []
    included_keys: set[tuple[int, int]] = set()
    omitted_block_ids: list[str] = []
    for block in function.blocks:
        if block.block_id not in chosen_blocks:
            omitted_block_ids.append(block.block_id)
            continue
        instructions = tuple(
            item
            for item in block.instructions
            if (item.address, item.index) in chosen_keys
        )
        if not instructions:
            continue
        included_keys.update((item.address, item.index) for item in instructions)
        evidence_blocks.append(
            BinaryEvidenceBlock(
                function_id=function.function_id,
                block_id=block.block_id,
                start_address=block.start_address,
                end_address=block.end_address,
                successors=block.successors,
                instructions=instructions,
                full_instruction_count=len(block.instructions),
                omitted_instruction_count=len(block.instructions) - len(instructions),
            )
        )

    if not evidence_blocks:
        block = function.blocks[0]
        instruction = block.instructions[0]
        if block.block_id in omitted_block_ids:
            omitted_block_ids.remove(block.block_id)
        included_keys.add((instruction.address, instruction.index))
        evidence_blocks.append(
            BinaryEvidenceBlock(
                function_id=function.function_id,
                block_id=block.block_id,
                start_address=block.start_address,
                end_address=block.end_address,
                successors=block.successors,
                instructions=(instruction,),
                full_instruction_count=len(block.instructions),
                omitted_instruction_count=len(block.instructions) - 1,
            )
        )
        omitted_required = True

    pseudocode_excerpt, pseudocode_truncated = _bounded_text(
        function.pseudocode,
        policy.maximum_pseudocode_bytes_per_function,
    )
    blocks = tuple(evidence_blocks)
    roles = selection.roles
    omitted_ids = tuple(sorted(set(omitted_block_ids)))
    function_digest = _function_digest(
        function_id=function.function_id,
        function_name=function.name,
        start_address=function.start_address,
        end_address=function.end_address,
        roles=roles,
        call_depth=selection.depth,
        pseudocode_excerpt=pseudocode_excerpt,
        pseudocode_sha256=function.pseudocode_sha256,
        pseudocode_truncated=pseudocode_truncated,
        blocks=blocks,
        omitted_block_ids=omitted_ids,
    )
    evidence = BinaryEvidenceFunction(
        function_id=function.function_id,
        function_name=function.name,
        start_address=function.start_address,
        end_address=function.end_address,
        roles=roles,
        call_depth=selection.depth,
        pseudocode_excerpt=pseudocode_excerpt,
        pseudocode_sha256=function.pseudocode_sha256,
        pseudocode_truncated=pseudocode_truncated,
        blocks=blocks,
        omitted_block_ids=omitted_ids,
        function_sha256=function_digest,
    )
    facts = tuple(
        sorted(
            (
                _fact(function.function_id, block.block_id, instruction)
                for block, instruction in records
                if (instruction.address, instruction.index) in included_keys
            ),
            key=lambda item: (
                item.address,
                item.instruction_index,
                item.function_id,
                item.kind.value,
            ),
        )
    )
    omissions: list[BinaryCapsuleOmission] = []
    incomplete: set[CapsuleIncompleteReason] = set()
    if omitted_required:
        omissions.append(
            BinaryCapsuleOmission(
                kind=CapsuleOmissionKind.INSTRUCTION_CAP,
                function_id=function.function_id,
                detail=f"required IR slice exceeds instruction limit {instruction_limit}",
            )
        )
        incomplete.add(CapsuleIncompleteReason.REQUIRED_INSTRUCTIONS_OMITTED)
    if block_limited:
        omissions.append(
            BinaryCapsuleOmission(
                kind=CapsuleOmissionKind.BLOCK_CAP,
                function_id=function.function_id,
                detail=(
                    "required IR neighborhoods exceed maximum_blocks_per_function="
                    f"{policy.maximum_blocks_per_function}"
                ),
            )
        )
        incomplete.add(CapsuleIncompleteReason.REQUIRED_BLOCKS_OMITTED)
    if pseudocode_truncated:
        omissions.append(
            BinaryCapsuleOmission(
                kind=CapsuleOmissionKind.PSEUDOCODE_TRUNCATED,
                function_id=function.function_id,
                detail=(
                    "pseudocode exceeds maximum_pseudocode_bytes_per_function="
                    f"{policy.maximum_pseudocode_bytes_per_function}; normalized IR retained"
                ),
            )
        )
    return _FunctionBuild(
        evidence=evidence,
        facts=facts,
        omissions=tuple(omissions),
        incomplete=tuple(sorted(incomplete, key=str)),
    )


def _recover_call_edges(
    ir: NormalizedBinaryIR,
) -> tuple[tuple[_RawCallEdge, ...], dict[str, tuple[IRInstruction, ...]]]:
    by_name: dict[str, list[IRFunction]] = defaultdict(list)
    by_address = {item.start_address: item for item in ir.functions}
    for function in ir.functions:
        for name in {function.name, function.name.lstrip("_")}:
            by_name[name].append(function)
    edges: list[_RawCallEdge] = []
    unresolved: dict[str, list[IRInstruction]] = defaultdict(list)
    for function in ir.functions:
        for block in function.blocks:
            for instruction in block.instructions:
                if instruction.operation is not IROperation.CALL or not instruction.callee:
                    continue
                target = _resolve_callee(instruction.callee, by_name, by_address)
                if target is None:
                    if not instruction.callee.startswith("_"):
                        unresolved[function.function_id].append(instruction)
                    continue
                edges.append(
                    _RawCallEdge(
                        caller_function_id=function.function_id,
                        callee_function_id=target.function_id,
                        instruction=instruction,
                    )
                )
    ordered = tuple(
        sorted(
            edges,
            key=lambda item: (
                item.instruction.address,
                item.caller_function_id,
                item.callee_function_id,
            ),
        )
    )
    return ordered, {
        identifier: tuple(sorted(items, key=lambda item: (item.address, item.index)))
        for identifier, items in unresolved.items()
    }


def _resolve_callee(
    callee: str,
    by_name: dict[str, list[IRFunction]],
    by_address: dict[int, IRFunction],
) -> IRFunction | None:
    candidates = {
        item.function_id: item
        for name in {callee, callee.lstrip("_")}
        for item in by_name.get(name, [])
    }
    if len(candidates) == 1:
        return next(iter(candidates.values()))
    lowered = callee.lower()
    for prefix in ("fun_", "sub_"):
        if lowered.startswith(prefix):
            try:
                return by_address.get(int(lowered.removeprefix(prefix), 16))
            except ValueError:
                return None
    return None


def _materialized_edges(
    raw_edges: tuple[_RawCallEdge, ...],
    included_ids: set[str],
) -> list[BinaryInterproceduralEdge]:
    return [
        BinaryInterproceduralEdge(
            edge_id=_edge_id(
                edge.caller_function_id,
                edge.callee_function_id,
                edge.instruction.address,
            ),
            caller_function_id=edge.caller_function_id,
            callee_function_id=edge.callee_function_id,
            callsite_address=edge.instruction.address,
            arguments=edge.instruction.operands,
            return_result=edge.instruction.result,
        )
        for edge in raw_edges
        if edge.caller_function_id in included_ids and edge.callee_function_id in included_ids
    ]


def _instruction_priority(
    instruction: IRInstruction,
    finding_addresses: set[int],
) -> int | None:
    if _is_input_source(instruction) or instruction.operation in (
        _MEMORY_SINKS - {IROperation.LOAD}
    ):
        return 0
    if instruction.operation in {IROperation.COMPARE, IROperation.BRANCH}:
        return 1
    if instruction.address in finding_addresses or instruction.operation in {
        IROperation.CALL,
        IROperation.LOAD,
    }:
        return 2
    if instruction.operation is IROperation.RETURN:
        return 2
    return None


def _fact(
    function_id: str,
    block_id: str,
    instruction: IRInstruction,
) -> BinaryEvidenceFact:
    kind = _fact_kind(instruction)
    detail = (
        f"{kind.value} {instruction.operation.value} evidence at "
        f"0x{instruction.address:x}:{instruction.index}"
    )
    return BinaryEvidenceFact(
        fact_id=_fact_id(
            function_id,
            instruction.address,
            instruction.index,
            kind,
        ),
        kind=kind,
        function_id=function_id,
        block_id=block_id,
        address=instruction.address,
        instruction_index=instruction.index,
        operation=instruction.operation,
        result=instruction.result,
        operands=instruction.operands,
        callee=instruction.callee,
        detail=detail[:1000],
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
        tag.startswith("input")
        or (tag.startswith("source") and not tag.startswith("source_op:"))
        for tag in instruction.tags
    ):
        return True
    if instruction.callee:
        lowered = instruction.callee.lower()
        return any(marker in lowered for marker in _INPUT_CALLEE_MARKERS)
    return False


def _add_missing_fact_reasons(
    facts: list[BinaryEvidenceFact],
    incomplete: set[CapsuleIncompleteReason],
) -> None:
    kinds = {item.kind for item in facts}
    if BinaryEvidenceFactKind.INPUT_SOURCE not in kinds:
        incomplete.add(CapsuleIncompleteReason.MISSING_INPUT_SOURCE)
    if BinaryEvidenceFactKind.SECURITY_SINK not in kinds:
        incomplete.add(CapsuleIncompleteReason.MISSING_SECURITY_SINK)


def _without_pseudocode(function: BinaryEvidenceFunction) -> BinaryEvidenceFunction:
    digest = _function_digest(
        function_id=function.function_id,
        function_name=function.function_name,
        start_address=function.start_address,
        end_address=function.end_address,
        roles=function.roles,
        call_depth=function.call_depth,
        pseudocode_excerpt="",
        pseudocode_sha256=function.pseudocode_sha256,
        pseudocode_truncated=True,
        blocks=function.blocks,
        omitted_block_ids=function.omitted_block_ids,
    )
    return BinaryEvidenceFunction(
        **function.model_dump(
            exclude={"pseudocode_excerpt", "pseudocode_truncated", "function_sha256"}
        ),
        pseudocode_excerpt="",
        pseudocode_truncated=True,
        function_sha256=digest,
    )


def _bounded_text(value: str, maximum_bytes: int) -> tuple[str, bool]:
    encoded = value.encode()
    if len(encoded) <= maximum_bytes:
        return value, False
    if maximum_bytes == 0:
        return "", True
    excerpt = encoded[:maximum_bytes].decode(errors="ignore").strip()
    return excerpt, True


def _validate_inputs(
    ir: NormalizedBinaryIR,
    report: BinaryAnalysisReport,
    admission: CodeHuntAdmission,
) -> None:
    if report.ir_sha256 != ir.ir_sha256:
        raise ValueError("binary report is bound to a different IR")
    if (
        admission.ir_sha256 != ir.ir_sha256
        or admission.discovery_sha256 != report.discovery_sha256
        or admission.report_sha256 != report.report_sha256
    ):
        raise ValueError("code admission is bound to different static evidence")
    if admission.coverage_sha256 != (
        ir.function_coverage.coverage_sha256 if ir.function_coverage is not None else None
    ):
        raise ValueError("code admission is bound to different function coverage")
    functions = {item.function_id for item in ir.functions}
    if not set(admission.execution_function_ids).issubset(functions):
        raise ValueError("code admission cites a function absent from normalized IR")


def _function_digest(
    *,
    function_id: str,
    function_name: str,
    start_address: int,
    end_address: int,
    roles: tuple[EvidenceFunctionRole, ...],
    call_depth: int,
    pseudocode_excerpt: str,
    pseudocode_sha256: str,
    pseudocode_truncated: bool,
    blocks: tuple[BinaryEvidenceBlock, ...],
    omitted_block_ids: tuple[str, ...],
) -> str:
    return _digest(
        {
            "function_id": function_id,
            "function_name": function_name,
            "start_address": start_address,
            "end_address": end_address,
            "roles": [item.value for item in roles],
            "call_depth": call_depth,
            "pseudocode_excerpt": pseudocode_excerpt,
            "pseudocode_sha256": pseudocode_sha256,
            "pseudocode_truncated": pseudocode_truncated,
            "blocks": [item.model_dump(mode="json") for item in blocks],
            "omitted_block_ids": omitted_block_ids,
        }
    )


def _capsule_digest(capsule: BinaryEvidenceCapsule) -> str:
    return _digest(capsule.model_dump(mode="json", exclude={"capsule_sha256"}))


def _capsule_digest_payload(payload: dict[str, object]) -> str:
    normalized = {key: _jsonable(value) for key, value in payload.items()}
    normalized["schema_version"] = "binary-evidence-capsule-v1"
    return _digest(normalized)


def _capsule_set_digest(
    *,
    snapshot_sha256: str,
    ir_sha256: str,
    admission_sha256: str,
    policy: BinaryEvidenceCapsulePolicy,
    admitted_root_ids: tuple[str, ...],
    capsules: tuple[BinaryEvidenceCapsule, ...],
) -> str:
    return _digest(
        {
            "schema_version": "binary-evidence-capsule-set-v1",
            "snapshot_sha256": snapshot_sha256,
            "ir_sha256": ir_sha256,
            "admission_sha256": admission_sha256,
            "policy": policy.model_dump(mode="json"),
            "admitted_root_ids": admitted_root_ids,
            "capsules": [item.model_dump(mode="json") for item in capsules],
        }
    )


def _evidence_size(
    functions: tuple[BinaryEvidenceFunction, ...],
    edges: tuple[BinaryInterproceduralEdge, ...],
    facts: tuple[BinaryEvidenceFact, ...],
    omissions: tuple[BinaryCapsuleOmission, ...],
) -> int:
    payload = {
        "functions": [item.model_dump(mode="json") for item in functions],
        "call_edges": [item.model_dump(mode="json") for item in edges],
        "facts": [item.model_dump(mode="json") for item in facts],
        "omissions": [item.model_dump(mode="json") for item in omissions],
    }
    return len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def _evidence_size_tuple(
    functions: list[BinaryEvidenceFunction],
    edges: list[BinaryInterproceduralEdge],
    facts: list[BinaryEvidenceFact],
    omissions: list[BinaryCapsuleOmission],
) -> int:
    return _evidence_size(tuple(functions), tuple(edges), tuple(facts), tuple(omissions))


def _fact_id(
    function_id: str,
    address: int,
    instruction_index: int,
    kind: BinaryEvidenceFactKind,
) -> str:
    return "codefact_" + hashlib.sha256(
        f"{function_id}:{address:x}:{instruction_index}:{kind.value}".encode()
    ).hexdigest()[:20]


def _edge_id(caller: str, callee: str, address: int) -> str:
    return "calledge_" + hashlib.sha256(f"{caller}:{callee}:{address:x}".encode()).hexdigest()[:20]


def _omission_key(item: BinaryCapsuleOmission) -> tuple[str, str, str, int, str]:
    return (
        item.kind.value,
        item.function_id or "",
        item.block_id or "",
        item.address if item.address is not None else -1,
        item.detail,
    )


def _digest(payload: object) -> str:
    canonical = json.dumps(
        _jsonable(payload),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _jsonable(value: object) -> object:
    if isinstance(value, DomainModel):
        return value.model_dump(mode="json")
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, tuple | list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


def _read_frozen_artifact(
    output: Path,
    name: str,
    artifacts: Mapping[str, DecompilerArtifactDigest],
) -> bytes:
    path = _regular_file(output / name)
    payload = path.read_bytes()
    expected = artifacts[name].sha256
    if _bytes_digest(payload) != expected:
        raise ValueError(f"M17 artifact changed after manifest freeze: {name}")
    return payload


def _regular_file(path: Path) -> Path:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("M17 capsule input must be a regular non-symlink file")
    return path


def _private_directory(path: Path) -> Path:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("M17 capsule path must be a regular non-symlink directory")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("M17 capsule directory must not grant group or other access")
    return path


def _bytes_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _encoded_json(payload: object) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n").encode()


def _write_private_bytes(path: Path, payload: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
