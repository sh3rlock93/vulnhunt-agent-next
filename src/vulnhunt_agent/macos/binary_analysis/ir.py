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
    BITWISE_AND = "bitwise_and"
    CAST = "cast"
    COMPARE = "compare"
    BRANCH = "branch"
    ALLOCATE = "allocate"
    COPY = "copy"
    LOAD = "load"
    STORE = "store"
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
    functions: tuple[IRFunction, ...] = Field(min_length=1, max_length=100000)
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
        function_order = tuple(item.start_address for item in self.functions)
        if tuple(sorted(set(function_order))) != function_order:
            raise ValueError("IR functions must be ordered at unique start addresses")
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
            functions=self.functions,
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
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
