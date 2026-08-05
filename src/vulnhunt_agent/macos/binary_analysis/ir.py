"""Decompiler-independent intermediate representation for binary evidence."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from ...domain.schemas import DomainModel, SHA256_PATTERN
from .snapshot import DyldArchitecture

_UUID_PATTERN = r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"


class DecompilerEngine(StrEnum):
    GHIDRA = "ghidra"
    BINARY_NINJA = "binary_ninja"


class IROperation(StrEnum):
    PARAMETER = "parameter"
    ASSIGN = "assign"
    PHI = "phi"
    ADD = "add"
    SUBTRACT = "subtract"
    MULTIPLY = "multiply"
    SHIFT_LEFT = "shift_left"
    SHIFT_RIGHT = "shift_right"
    BITWISE_AND = "bitwise_and"
    BITWISE_OR = "bitwise_or"
    BYTE_SWAP = "byte_swap"
    BOOLEAN_AND = "boolean_and"
    BOOLEAN_OR = "boolean_or"
    BOOLEAN_XOR = "boolean_xor"
    BOOLEAN_NOT = "boolean_not"
    CAST = "cast"
    COMPARE = "compare"
    BRANCH = "branch"
    ALLOCATE = "allocate"
    COPY = "copy"
    LOAD = "load"
    STORE = "store"
    INDIRECT = "indirect"
    CALL = "call"
    FREE = "free"
    RETURN = "return"
    UNKNOWN = "unknown"


class IRInstruction(DomainModel):
    index: int = Field(ge=0)
    address: int = Field(ge=0)
    operation: IROperation
    result: str | None = Field(default=None, min_length=1, max_length=160)
    operands: tuple[str, ...] = Field(default=(), max_length=32)
    constants: tuple[int, ...] = Field(default=(), max_length=16)
    callee: str | None = Field(default=None, min_length=1, max_length=500)
    width_bits: int | None = Field(default=None, ge=1, le=1024)
    signed: bool | None = None
    tags: tuple[str, ...] = Field(default=(), max_length=32)
    text: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def validate_instruction(self) -> "IRInstruction":
        if tuple(sorted(set(self.tags))) != self.tags:
            raise ValueError("IR instruction tags must be sorted and unique")
        if self.operation is IROperation.CALL and not self.callee:
            raise ValueError("call instructions require a callee")
        if self.operation in {IROperation.ALLOCATE, IROperation.COPY, IROperation.FREE}:
            if not self.callee:
                raise ValueError(f"{self.operation.value} instructions require a callee")
        return self


class IRBasicBlock(DomainModel):
    block_id: str = Field(pattern=r"^bb_[0-9a-f]{16}$")
    start_address: int = Field(ge=0)
    end_address: int = Field(ge=0)
    instructions: tuple[IRInstruction, ...] = Field(min_length=1, max_length=10000)
    successors: tuple[str, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def validate_block(self) -> "IRBasicBlock":
        if self.end_address <= self.start_address:
            raise ValueError("IR block end must follow its start")
        order = tuple((item.address, item.index) for item in self.instructions)
        if tuple(sorted(set(order))) != order:
            raise ValueError("IR instructions must be canonically ordered and unique")
        if any(
            item.address < self.start_address or item.address >= self.end_address
            for item in self.instructions
        ):
            raise ValueError("IR instruction falls outside its block")
        if tuple(sorted(set(self.successors))) != self.successors:
            raise ValueError("IR block successors must be sorted and unique")
        return self


class IRStringReference(DomainModel):
    address: int = Field(ge=0)
    value: str = Field(min_length=1, max_length=4000)
    referenced_at: tuple[int, ...] = Field(default=(), max_length=1024)

    @model_validator(mode="after")
    def validate_references(self) -> "IRStringReference":
        if tuple(sorted(set(self.referenced_at))) != self.referenced_at:
            raise ValueError("string references must be sorted and unique")
        return self


class IRVirtualMethodReference(DomainModel):
    """Address-backed Itanium C++ vtable entry for one exported function."""

    owner: str = Field(min_length=1, max_length=500)
    vtable_symbol: str = Field(min_length=1, max_length=1000)
    vtable_address: int = Field(ge=0)
    address_point: int = Field(ge=0)
    slot_offset: int = Field(ge=0, le=64 * 1024)
    reference_address: int = Field(ge=0)
    target_function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    target_address: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_reference(self) -> "IRVirtualMethodReference":
        if self.address_point <= self.vtable_address:
            raise ValueError("vtable address point must follow the table symbol")
        if self.slot_offset % 8:
            raise ValueError("vtable slot offset must be pointer aligned")
        if self.reference_address != self.address_point + self.slot_offset:
            raise ValueError("vtable reference address does not match its slot")
        return self


class IRFunction(DomainModel):
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    name: str = Field(min_length=1, max_length=500)
    start_address: int = Field(ge=0)
    end_address: int = Field(ge=0)
    parameters: tuple[str, ...] = Field(default=(), max_length=128)
    blocks: tuple[IRBasicBlock, ...] = Field(min_length=1, max_length=10000)
    pseudocode: str = Field(default="", max_length=256000)
    pseudocode_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_function(self) -> "IRFunction":
        if self.end_address <= self.start_address:
            raise ValueError("IR function end must follow its start")
        if tuple(sorted(set(self.parameters))) != self.parameters:
            raise ValueError("IR parameters must be sorted and unique")
        if tuple(sorted(self.blocks, key=lambda block: block.start_address)) != self.blocks:
            raise ValueError("IR basic blocks must be sorted by address")
        block_ids = {block.block_id for block in self.blocks}
        if len(block_ids) != len(self.blocks):
            raise ValueError("IR basic block ids must be unique")
        for block in self.blocks:
            if block.start_address < self.start_address or block.end_address > self.end_address:
                raise ValueError("IR basic block falls outside its function")
            if not set(block.successors).issubset(block_ids):
                raise ValueError("IR basic block cites an unknown successor")
        expected = "sha256:" + hashlib.sha256(self.pseudocode.encode()).hexdigest()
        if self.pseudocode_sha256 != expected:
            raise ValueError("IR pseudocode digest does not match its text")
        return self


class FunctionCoverageTier(StrEnum):
    MANDATORY = "mandatory"
    NEIGHBORHOOD = "neighborhood"
    FALLBACK = "fallback"


class IRFunctionCoverage(DomainModel):
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    name: str = Field(min_length=1, max_length=500)
    start_address: int = Field(ge=0)
    end_address: int = Field(ge=0)
    direct_strings: tuple[str, ...] = Field(default=(), max_length=256)
    callers: tuple[int, ...] = Field(default=(), max_length=256)
    callees: tuple[int, ...] = Field(default=(), max_length=256)
    selected: bool
    selection_tier: FunctionCoverageTier | None = None
    selection_reasons: tuple[str, ...] = Field(default=(), max_length=256)
    omission_reason: str | None = Field(default=None, min_length=1, max_length=200)

    @model_validator(mode="after")
    def validate_coverage(self) -> "IRFunctionCoverage":
        if self.end_address <= self.start_address:
            raise ValueError("coverage function end must follow its start")
        if tuple(sorted(set(self.direct_strings))) != self.direct_strings:
            raise ValueError("coverage direct strings must be sorted and unique")
        if tuple(sorted(set(self.callers))) != self.callers:
            raise ValueError("coverage callers must be sorted and unique")
        if tuple(sorted(set(self.callees))) != self.callees:
            raise ValueError("coverage callees must be sorted and unique")
        if tuple(sorted(set(self.selection_reasons))) != self.selection_reasons:
            raise ValueError("coverage selection reasons must be sorted and unique")
        if self.selected:
            if self.selection_tier is None or not self.selection_reasons:
                raise ValueError("selected coverage functions require a tier and reason")
            if self.omission_reason is not None:
                raise ValueError("selected coverage functions cannot have an omission reason")
        elif self.selection_tier is not None or self.selection_reasons:
            raise ValueError("omitted coverage functions cannot have selection metadata")
        elif self.omission_reason is None:
            raise ValueError("omitted coverage functions require an omission reason")
        return self


class IRFunctionCoverageManifest(DomainModel):
    schema_version: Literal["binary-function-coverage-v1"] = (
        "binary-function-coverage-v1"
    )
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    maximum_functions: int = Field(ge=1, le=10000)
    maximum_evidence_functions: int = Field(ge=1, le=10000)
    callgraph_depth: int = Field(ge=0, le=8)
    total_function_count: int = Field(ge=1, le=100000)
    selected_function_count: int = Field(ge=1, le=100000)
    cap_saturated: bool
    warnings: tuple[str, ...] = Field(default=(), max_length=32)
    functions: tuple[IRFunctionCoverage, ...] = Field(min_length=1, max_length=100000)
    coverage_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_manifest(self) -> "IRFunctionCoverageManifest":
        if tuple(sorted(set(self.warnings))) != self.warnings:
            raise ValueError("coverage warnings must be sorted and unique")
        starts = tuple(item.start_address for item in self.functions)
        if tuple(sorted(set(starts))) != starts:
            raise ValueError("coverage functions must be ordered at unique start addresses")
        if self.total_function_count != len(self.functions):
            raise ValueError("coverage total does not match its function census")
        selected = sum(item.selected for item in self.functions)
        if self.selected_function_count != selected:
            raise ValueError("coverage selected count does not match its census")
        if self.cap_saturated != any(not item.selected for item in self.functions):
            raise ValueError("coverage cap saturation does not match its omissions")
        if self.cap_saturated and "function_export_cap_saturated" not in self.warnings:
            raise ValueError("saturated function coverage requires a visible warning")
        expected = function_coverage_digest(
            snapshot_sha256=self.snapshot_sha256,
            maximum_functions=self.maximum_functions,
            maximum_evidence_functions=self.maximum_evidence_functions,
            callgraph_depth=self.callgraph_depth,
            total_function_count=self.total_function_count,
            selected_function_count=self.selected_function_count,
            cap_saturated=self.cap_saturated,
            warnings=self.warnings,
            functions=self.functions,
        )
        if self.coverage_sha256 != expected:
            raise ValueError("function coverage digest does not match its evidence")
        return self


class NormalizedBinaryIR(DomainModel):
    schema_version: Literal["binary-ir-v1"] = "binary-ir-v1"
    created_at: datetime
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    image_name: str = Field(min_length=1, max_length=1000)
    image_uuid: str = Field(pattern=_UUID_PATTERN)
    architecture: DyldArchitecture
    base_address: int = Field(ge=0)
    decompiler_engine: DecompilerEngine
    decompiler_version: str = Field(min_length=1, max_length=120)
    imports: tuple[str, ...] = Field(default=(), max_length=50000)
    strings: tuple[IRStringReference, ...] = Field(default=(), max_length=100000)
    virtual_methods: tuple[IRVirtualMethodReference, ...] = Field(
        default=(), max_length=100000
    )
    functions: tuple[IRFunction, ...] = Field(min_length=1, max_length=100000)
    function_coverage: IRFunctionCoverageManifest | None = None
    ir_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_ir(self) -> "NormalizedBinaryIR":
        if self.created_at.tzinfo is None:
            raise ValueError("IR creation time must include a timezone")
        if tuple(sorted(set(self.imports))) != self.imports:
            raise ValueError("IR imports must be sorted and unique")
        string_order = tuple((item.address, item.value) for item in self.strings)
        if tuple(sorted(set(string_order))) != string_order:
            raise ValueError("IR strings must be canonically ordered and unique")
        virtual_order = tuple(
            (
                item.target_address,
                item.slot_offset,
                item.vtable_address,
                item.reference_address,
                item.owner,
            )
            for item in self.virtual_methods
        )
        if tuple(sorted(set(virtual_order))) != virtual_order:
            raise ValueError("IR virtual methods must be canonically ordered and unique")
        function_order = tuple(item.start_address for item in self.functions)
        if tuple(sorted(set(function_order))) != function_order:
            raise ValueError("IR functions must be ordered at unique start addresses")
        if self.function_coverage is not None:
            if self.function_coverage.snapshot_sha256 != self.snapshot_sha256:
                raise ValueError("function coverage is bound to a different snapshot")
            selected_ids = {
                item.function_id
                for item in self.function_coverage.functions
                if item.selected
            }
            if selected_ids != {item.function_id for item in self.functions}:
                raise ValueError("IR functions do not match the function coverage selection")
        functions_by_id = {item.function_id: item for item in self.functions}
        if any(
            item.target_function_id not in functions_by_id
            or functions_by_id[item.target_function_id].start_address != item.target_address
            for item in self.virtual_methods
        ):
            raise ValueError("IR virtual method targets an absent or mismatched function")
        expected = normalized_ir_digest(
            snapshot_sha256=self.snapshot_sha256,
            image_name=self.image_name,
            image_uuid=self.image_uuid,
            architecture=self.architecture,
            base_address=self.base_address,
            decompiler_engine=self.decompiler_engine,
            decompiler_version=self.decompiler_version,
            imports=self.imports,
            strings=self.strings,
            virtual_methods=self.virtual_methods,
            functions=self.functions,
            function_coverage=self.function_coverage,
        )
        if self.ir_sha256 != expected:
            raise ValueError("normalized IR digest does not match its evidence")
        return self


def function_id(image_uuid: str, start_address: int) -> str:
    payload = f"{image_uuid.upper()}:{start_address:x}".encode()
    return "fn_" + hashlib.sha256(payload).hexdigest()[:20]


def block_id(function_identifier: str, ordinal: int, start_address: int) -> str:
    payload = f"{function_identifier}:{ordinal}:{start_address:x}".encode()
    return "bb_" + hashlib.sha256(payload).hexdigest()[:16]


def pseudocode_digest(pseudocode: str) -> str:
    return "sha256:" + hashlib.sha256(pseudocode.encode()).hexdigest()


def normalized_ir_digest(
    *,
    snapshot_sha256: str,
    image_name: str,
    image_uuid: str,
    architecture: DyldArchitecture,
    base_address: int,
    decompiler_engine: DecompilerEngine,
    decompiler_version: str,
    imports: tuple[str, ...],
    strings: tuple[IRStringReference, ...],
    functions: tuple[IRFunction, ...],
    virtual_methods: tuple[IRVirtualMethodReference, ...] = (),
    function_coverage: IRFunctionCoverageManifest | None = None,
) -> str:
    payload = {
        "architecture": architecture.value,
        "base_address": base_address,
        "decompiler_engine": decompiler_engine.value,
        "decompiler_version": decompiler_version,
        "functions": [item.model_dump(mode="json") for item in functions],
        "image_name": image_name,
        "image_uuid": image_uuid,
        "imports": imports,
        "schema_version": "binary-ir-v1",
        "snapshot_sha256": snapshot_sha256,
        "strings": [item.model_dump(mode="json") for item in strings],
    }
    if function_coverage is not None:
        payload["function_coverage"] = function_coverage.model_dump(mode="json")
    if virtual_methods:
        payload["virtual_methods"] = [
            item.model_dump(mode="json") for item in virtual_methods
        ]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def function_coverage_digest(
    *,
    snapshot_sha256: str,
    maximum_functions: int,
    maximum_evidence_functions: int,
    callgraph_depth: int,
    total_function_count: int,
    selected_function_count: int,
    cap_saturated: bool,
    warnings: tuple[str, ...],
    functions: tuple[IRFunctionCoverage, ...],
) -> str:
    payload = {
        "callgraph_depth": callgraph_depth,
        "cap_saturated": cap_saturated,
        "functions": [item.model_dump(mode="json") for item in functions],
        "maximum_evidence_functions": maximum_evidence_functions,
        "maximum_functions": maximum_functions,
        "schema_version": "binary-function-coverage-v1",
        "selected_function_count": selected_function_count,
        "snapshot_sha256": snapshot_sha256,
        "total_function_count": total_function_count,
        "warnings": warnings,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
