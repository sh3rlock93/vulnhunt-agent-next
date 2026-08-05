"""Adapters from bounded decompiler JSON exports to normalized binary IR."""

from __future__ import annotations

import json
import re
import stat
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .ir import (
    DecompilerEngine,
    IRBasicBlock,
    IRFunction,
    IRFunctionCoverage,
    IRFunctionCoverageManifest,
    IRInstruction,
    IROperation,
    IRStringReference,
    IRVirtualMethodReference,
    NormalizedBinaryIR,
    block_id,
    function_id,
    function_coverage_digest,
    normalized_ir_digest,
    pseudocode_digest,
)
from .snapshot import DyldArchitecture

_MAX_EXPORT_BYTES = 256 * 1024 * 1024

_STACK_STORAGE_PATTERN = re.compile(
    r"(?:^|_)stack_([0-9a-f]+)_[0-9]+(?:_|$)", re.IGNORECASE
)
_CONSTANT_OPERAND_PATTERN = re.compile(r"^const_([0-9a-f]+)$", re.IGNORECASE)

_OPERATION_ALIASES = {
    "param": IROperation.PARAMETER,
    "parameter": IROperation.PARAMETER,
    "copy": IROperation.COPY,
    "memcpy": IROperation.COPY,
    "alloc": IROperation.ALLOCATE,
    "allocate": IROperation.ALLOCATE,
    "malloc": IROperation.ALLOCATE,
    "free": IROperation.FREE,
    "int_add": IROperation.ADD,
    "add": IROperation.ADD,
    "int_sub": IROperation.SUBTRACT,
    "sub": IROperation.SUBTRACT,
    "subtract": IROperation.SUBTRACT,
    "int_mult": IROperation.MULTIPLY,
    "mul": IROperation.MULTIPLY,
    "multiply": IROperation.MULTIPLY,
    "int_left": IROperation.SHIFT_LEFT,
    "lsl": IROperation.SHIFT_LEFT,
    "shift_left": IROperation.SHIFT_LEFT,
    "int_right": IROperation.SHIFT_RIGHT,
    "lsr": IROperation.SHIFT_RIGHT,
    "shift_right": IROperation.SHIFT_RIGHT,
    "and": IROperation.BITWISE_AND,
    "bitwise_and": IROperation.BITWISE_AND,
    "int_or": IROperation.BITWISE_OR,
    "or": IROperation.BITWISE_OR,
    "bitwise_or": IROperation.BITWISE_OR,
    "byte_swap": IROperation.BYTE_SWAP,
    "bswap": IROperation.BYTE_SWAP,
    "bool_and": IROperation.BOOLEAN_AND,
    "boolean_and": IROperation.BOOLEAN_AND,
    "bool_or": IROperation.BOOLEAN_OR,
    "boolean_or": IROperation.BOOLEAN_OR,
    "bool_xor": IROperation.BOOLEAN_XOR,
    "boolean_xor": IROperation.BOOLEAN_XOR,
    "bool_not": IROperation.BOOLEAN_NOT,
    "boolean_not": IROperation.BOOLEAN_NOT,
    "cast": IROperation.CAST,
    "cmp": IROperation.COMPARE,
    "compare": IROperation.COMPARE,
    "if": IROperation.BRANCH,
    "branch": IROperation.BRANCH,
    "load": IROperation.LOAD,
    "store": IROperation.STORE,
    "indirect": IROperation.INDIRECT,
    "call": IROperation.CALL,
    "phi": IROperation.PHI,
    "ret": IROperation.RETURN,
    "return": IROperation.RETURN,
    "assign": IROperation.ASSIGN,
    "set": IROperation.ASSIGN,
}


class DecompilerExportAdapter(Protocol):
    engine: DecompilerEngine

    def normalize(
        self,
        payload: Mapping[str, Any],
        *,
        expected_snapshot_sha256: str,
        created_at: datetime | None = None,
    ) -> NormalizedBinaryIR: ...


class GhidraJSONAdapter:
    engine = DecompilerEngine.GHIDRA

    def normalize(
        self,
        payload: Mapping[str, Any],
        *,
        expected_snapshot_sha256: str,
        created_at: datetime | None = None,
    ) -> NormalizedBinaryIR:
        schema_version = payload.get("schema_version")
        if schema_version not in {
            "ghidra-imageio-export-v1",
            "ghidra-imageio-export-v2",
            "ghidra-imageio-export-v3",
        }:
            raise ValueError("unsupported Ghidra export schema")
        if payload.get("snapshot_sha256") != expected_snapshot_sha256:
            raise ValueError("Ghidra export is not bound to the expected binary snapshot")
        image = _mapping(payload.get("image"), label="Ghidra image")
        image_uuid = _canonical_uuid(image.get("uuid"))
        coverage = None
        if schema_version in {"ghidra-imageio-export-v2", "ghidra-imageio-export-v3"}:
            coverage = _normalize_ghidra_coverage(
                payload.get("function_coverage"),
                image_uuid=image_uuid,
                expected_snapshot_sha256=expected_snapshot_sha256,
            )
        return _normalize_export(
            engine=self.engine,
            decompiler_version=_text(payload.get("decompiler_version"), label="version"),
            snapshot_sha256=expected_snapshot_sha256,
            image_name=_text(image.get("name"), label="image name"),
            image_uuid=image_uuid,
            architecture=DyldArchitecture(_text(image.get("architecture"), label="architecture")),
            base_address=_address(image.get("base_address")),
            imports=_string_sequence(payload.get("imports", ()), label="imports"),
            strings=_normalize_strings(
                payload.get("strings", ()),
                address_key="address",
                value_key="value",
                references_key="references",
            ),
            virtual_methods=(
                _normalize_ghidra_virtual_methods(
                    payload.get("virtual_methods", ()),
                    image_uuid=image_uuid,
                )
                if schema_version == "ghidra-imageio-export-v3"
                else ()
            ),
            functions=_normalize_functions(
                payload.get("functions"),
                image_uuid=image_uuid,
                function_start_key="entry",
                function_size_key="size",
                function_name_key="name",
                parameters_key="parameters",
                blocks_key="blocks",
                block_label_key="name",
                block_start_key="start",
                block_size_key="size",
                successors_key="successors",
                instructions_key="instructions",
                instruction_operation_key="op",
                instruction_operands_key="inputs",
                instruction_callee_key="target",
            ),
            function_coverage=coverage,
            created_at=created_at,
        )


class BinaryNinjaJSONAdapter:
    engine = DecompilerEngine.BINARY_NINJA

    def normalize(
        self,
        payload: Mapping[str, Any],
        *,
        expected_snapshot_sha256: str,
        created_at: datetime | None = None,
    ) -> NormalizedBinaryIR:
        if payload.get("format") != "binary-ninja-imageio-export-v1":
            raise ValueError("unsupported Binary Ninja export schema")
        if payload.get("source_snapshot") != expected_snapshot_sha256:
            raise ValueError("Binary Ninja export is not bound to the expected binary snapshot")
        image = _mapping(payload.get("binary"), label="Binary Ninja image")
        image_uuid = _canonical_uuid(image.get("uuid"))
        return _normalize_export(
            engine=self.engine,
            decompiler_version=_text(payload.get("version"), label="version"),
            snapshot_sha256=expected_snapshot_sha256,
            image_name=_text(image.get("filename"), label="image name"),
            image_uuid=image_uuid,
            architecture=DyldArchitecture(_text(image.get("arch"), label="architecture")),
            base_address=_address(image.get("start")),
            imports=_string_sequence(payload.get("externals", ()), label="externals"),
            strings=_normalize_strings(
                payload.get("data_strings", ()),
                address_key="start",
                value_key="text",
                references_key="code_refs",
            ),
            virtual_methods=(),
            functions=_normalize_functions(
                payload.get("routines"),
                image_uuid=image_uuid,
                function_start_key="start",
                function_size_key="length",
                function_name_key="display_name",
                parameters_key="arguments",
                blocks_key="basic_blocks",
                block_label_key="index",
                block_start_key="start",
                block_size_key="length",
                successors_key="outgoing",
                instructions_key="high_level_il",
                instruction_operation_key="operation",
                instruction_operands_key="sources",
                instruction_callee_key="target",
            ),
            function_coverage=None,
            created_at=created_at,
        )


def load_decompiler_export(
    path: Path,
    *,
    adapter: DecompilerExportAdapter,
    expected_snapshot_sha256: str,
    created_at: datetime | None = None,
) -> NormalizedBinaryIR:
    """Read a bounded, regular JSON export and normalize it without tool execution."""

    source = path.expanduser()
    metadata = source.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("decompiler export must be a regular non-symlink file")
    if metadata.st_size > _MAX_EXPORT_BYTES:
        raise ValueError("decompiler export exceeds the configured size limit")
    payload = json.loads(source.read_text(encoding="utf-8"))
    return adapter.normalize(
        _mapping(payload, label="decompiler export"),
        expected_snapshot_sha256=expected_snapshot_sha256,
        created_at=created_at,
    )


def _normalize_export(
    *,
    engine: DecompilerEngine,
    decompiler_version: str,
    snapshot_sha256: str,
    image_name: str,
    image_uuid: str,
    architecture: DyldArchitecture,
    base_address: int,
    imports: tuple[str, ...],
    strings: tuple[IRStringReference, ...],
    virtual_methods: tuple[IRVirtualMethodReference, ...],
    functions: tuple[IRFunction, ...],
    function_coverage: IRFunctionCoverageManifest | None,
    created_at: datetime | None,
) -> NormalizedBinaryIR:
    ordered_imports = tuple(sorted(set(imports)))
    ordered_strings = tuple(sorted(strings, key=lambda item: (item.address, item.value)))
    ordered_virtual_methods = tuple(
        sorted(
            virtual_methods,
            key=lambda item: (
                item.target_address,
                item.slot_offset,
                item.vtable_address,
                item.reference_address,
                item.owner,
            ),
        )
    )
    ordered_functions = tuple(sorted(functions, key=lambda item: item.start_address))
    if function_coverage is not None:
        selected = {
            item.function_id: item
            for item in function_coverage.functions
            if item.selected
        }
        exported = {item.function_id: item for item in ordered_functions}
        if set(selected) != set(exported):
            raise ValueError("exported functions do not match the coverage selection")
        for identifier, function in exported.items():
            census = selected[identifier]
            if (
                census.name != function.name
                or census.start_address != function.start_address
                or census.end_address != function.end_address
            ):
                raise ValueError("exported function metadata does not match its census")
    digest = normalized_ir_digest(
        snapshot_sha256=snapshot_sha256,
        image_name=image_name,
        image_uuid=image_uuid,
        architecture=architecture,
        base_address=base_address,
        decompiler_engine=engine,
        decompiler_version=decompiler_version,
        imports=ordered_imports,
        strings=ordered_strings,
        virtual_methods=ordered_virtual_methods,
        functions=ordered_functions,
        function_coverage=function_coverage,
    )
    return NormalizedBinaryIR(
        created_at=created_at or datetime.now(UTC),
        snapshot_sha256=snapshot_sha256,
        image_name=image_name,
        image_uuid=image_uuid,
        architecture=architecture,
        base_address=base_address,
        decompiler_engine=engine,
        decompiler_version=decompiler_version,
        imports=ordered_imports,
        strings=ordered_strings,
        virtual_methods=ordered_virtual_methods,
        functions=ordered_functions,
        function_coverage=function_coverage,
        ir_sha256=digest,
    )


def _normalize_ghidra_coverage(
    raw: object,
    *,
    image_uuid: str,
    expected_snapshot_sha256: str,
) -> IRFunctionCoverageManifest:
    manifest = _mapping(raw, label="Ghidra function coverage")
    if manifest.get("schema_version") != "ghidra-function-coverage-v1":
        raise ValueError("unsupported Ghidra function coverage schema")
    if manifest.get("snapshot_sha256") != expected_snapshot_sha256:
        raise ValueError("Ghidra function coverage is not bound to the expected snapshot")
    functions: list[IRFunctionCoverage] = []
    for raw_function in _sequence(manifest.get("functions"), label="coverage functions"):
        item = _mapping(raw_function, label="coverage function")
        start = _address(item.get("entry"))
        size = _positive_int(item.get("size"), label="coverage function size")
        tier_value = item.get("selection_tier")
        functions.append(
            IRFunctionCoverage(
                function_id=function_id(image_uuid, start),
                name=_text(item.get("name"), label="coverage function name"),
                start_address=start,
                end_address=start + size,
                direct_strings=tuple(
                    sorted(set(_string_sequence(item.get("direct_strings", ()), label="direct strings")))
                ),
                callers=tuple(
                    sorted({_address(value) for value in _sequence(item.get("callers", ()), label="callers")})
                ),
                callees=tuple(
                    sorted({_address(value) for value in _sequence(item.get("callees", ()), label="callees")})
                ),
                selected=_boolean(item.get("selected"), label="coverage selection"),
                selection_tier=(
                    None if tier_value is None else str(tier_value)
                ),
                selection_reasons=tuple(
                    sorted(set(_string_sequence(item.get("selection_reasons", ()), label="selection reasons")))
                ),
                omission_reason=_optional_text(item.get("omission_reason")),
            )
        )
    ordered = tuple(sorted(functions, key=lambda item: item.start_address))
    maximum_functions = _positive_int(
        manifest.get("maximum_functions"), label="maximum functions"
    )
    maximum_evidence = _positive_int(
        manifest.get("maximum_evidence_functions"),
        label="maximum evidence functions",
    )
    callgraph_depth = _non_negative_int(
        manifest.get("callgraph_depth"), label="callgraph depth"
    )
    warnings = tuple(
        sorted(set(_string_sequence(manifest.get("warnings", ()), label="coverage warnings")))
    )
    selected_count = sum(item.selected for item in ordered)
    cap_saturated = any(not item.selected for item in ordered)
    digest = function_coverage_digest(
        snapshot_sha256=expected_snapshot_sha256,
        maximum_functions=maximum_functions,
        maximum_evidence_functions=maximum_evidence,
        callgraph_depth=callgraph_depth,
        total_function_count=len(ordered),
        selected_function_count=selected_count,
        cap_saturated=cap_saturated,
        warnings=warnings,
        functions=ordered,
    )
    return IRFunctionCoverageManifest(
        snapshot_sha256=expected_snapshot_sha256,
        maximum_functions=maximum_functions,
        maximum_evidence_functions=maximum_evidence,
        callgraph_depth=callgraph_depth,
        total_function_count=len(ordered),
        selected_function_count=selected_count,
        cap_saturated=cap_saturated,
        warnings=warnings,
        functions=ordered,
        coverage_sha256=digest,
    )


def _normalize_strings(
    raw: object,
    *,
    address_key: str,
    value_key: str,
    references_key: str,
) -> tuple[IRStringReference, ...]:
    strings: list[IRStringReference] = []
    for item in _sequence(raw, label="strings"):
        entry = _mapping(item, label="string entry")
        references = tuple(
            sorted(
                {
                    _address(value)
                    for value in _sequence(entry.get(references_key, ()), label="refs")
                }
            )
        )
        strings.append(
            IRStringReference(
                address=_address(entry.get(address_key)),
                value=_text(entry.get(value_key), label="string value"),
                referenced_at=references,
            )
        )
    return tuple(strings)


def _normalize_ghidra_virtual_methods(
    raw: object,
    *,
    image_uuid: str,
) -> tuple[IRVirtualMethodReference, ...]:
    references: list[IRVirtualMethodReference] = []
    for raw_reference in _sequence(raw, label="virtual methods"):
        item = _mapping(raw_reference, label="virtual method")
        target_address = _address(item.get("target_entry"))
        references.append(
            IRVirtualMethodReference(
                owner=_text(item.get("owner"), label="vtable owner"),
                vtable_symbol=_text(
                    item.get("vtable_symbol"), label="vtable symbol"
                ),
                vtable_address=_address(item.get("vtable_address")),
                address_point=_address(item.get("address_point")),
                slot_offset=_non_negative_int(
                    item.get("slot_offset"), label="vtable slot offset"
                ),
                reference_address=_address(item.get("reference_address")),
                target_function_id=function_id(image_uuid, target_address),
                target_address=target_address,
            )
        )
    return tuple(references)


def _address_taken_out_parameter_aliases(
    raw_blocks: Sequence[object],
    *,
    instructions_key: str,
    instruction_operation_key: str,
    instruction_operands_key: str,
) -> dict[tuple[int, str], tuple[int, str, str | None]]:
    """Bind Ghidra INDIRECT outputs to an address-taken call argument.

    Ghidra models a value potentially changed through a pointer argument as an
    ``INDIRECT`` SSA output at the call's address.  The second INDIRECT input is
    an internal op token, not a value definition.  Preserve an address-backed
    dependency only when the call operand is defined by pointer arithmetic for
    the exact stack storage named by the INDIRECT result.
    """

    instructions = tuple(
        _mapping(instruction, label="instruction")
        for raw_block in raw_blocks
        for instruction in _sequence(
            _mapping(raw_block, label="basic block").get(instructions_key),
            label="instructions",
        )
    )
    definitions = {
        result: instruction
        for instruction in instructions
        if (result := _optional_text(instruction.get("result"))) is not None
    }
    calls_by_address: dict[int, list[Mapping[str, Any]]] = {}
    indirects_by_address: dict[int, list[Mapping[str, Any]]] = {}
    for instruction in instructions:
        address = _address(instruction.get("address"))
        raw_operation = _text(
            instruction.get(instruction_operation_key), label="operation"
        )
        operation = _operation(raw_operation)
        if operation in {
            IROperation.ALLOCATE,
            IROperation.CALL,
            IROperation.COPY,
            IROperation.FREE,
        }:
            calls_by_address.setdefault(address, []).append(instruction)
        elif operation is IROperation.INDIRECT:
            indirects_by_address.setdefault(address, []).append(instruction)

    aliases: dict[tuple[int, str], tuple[int, str, str | None]] = {}
    ambiguous: set[tuple[int, str]] = set()
    for address, calls in calls_by_address.items():
        effects = indirects_by_address.get(address, ())
        if not effects:
            continue
        for call in calls:
            call_result = _optional_text(call.get("result"))
            call_operands = _string_sequence(
                call.get(instruction_operands_key, ()), label="instruction operands"
            )
            for argument_index, pointer_operand in enumerate(call_operands):
                pointer_definition = definitions.get(pointer_operand)
                if pointer_definition is None:
                    continue
                pointer_tags = _string_sequence(
                    pointer_definition.get("tags", ()), label="tags"
                )
                if "pointer_arithmetic" not in pointer_tags:
                    continue
                pointer_inputs = _string_sequence(
                    pointer_definition.get(instruction_operands_key, ()),
                    label="instruction operands",
                )
                offsets = {
                    match.group(1).lower()
                    for operand in pointer_inputs
                    if (match := _CONSTANT_OPERAND_PATTERN.fullmatch(operand))
                }
                if not offsets:
                    continue
                for effect in effects:
                    result = _optional_text(effect.get("result"))
                    if result is None:
                        continue
                    storage = _STACK_STORAGE_PATTERN.search(result)
                    if storage is None or storage.group(1).lower() not in offsets:
                        continue
                    key = (address, result)
                    relation = (argument_index, pointer_operand, call_result)
                    if key in ambiguous:
                        continue
                    if key in aliases and aliases[key] != relation:
                        aliases.pop(key)
                        ambiguous.add(key)
                        continue
                    aliases[key] = relation
    return aliases


def _normalize_functions(
    raw: object,
    *,
    image_uuid: str,
    function_start_key: str,
    function_size_key: str,
    function_name_key: str,
    parameters_key: str,
    blocks_key: str,
    block_label_key: str,
    block_start_key: str,
    block_size_key: str,
    successors_key: str,
    instructions_key: str,
    instruction_operation_key: str,
    instruction_operands_key: str,
    instruction_callee_key: str,
) -> tuple[IRFunction, ...]:
    functions: list[IRFunction] = []
    for raw_function in _sequence(raw, label="functions"):
        item = _mapping(raw_function, label="function")
        start = _address(item.get(function_start_key))
        size = _positive_int(item.get(function_size_key), label="function size")
        identifier = function_id(image_uuid, start)
        raw_blocks = _sequence(item.get(blocks_key), label="basic blocks")
        raw_parameters = _string_sequence(item.get(parameters_key, ()), label="parameters")
        address_taken_out_parameters = _address_taken_out_parameter_aliases(
            raw_blocks,
            instructions_key=instructions_key,
            instruction_operation_key=instruction_operation_key,
            instruction_operands_key=instruction_operands_key,
        )
        preserved_argument_aliases = _argument_preserving_stack_probe_aliases(
            raw_blocks,
            parameters=raw_parameters,
            instructions_key=instructions_key,
            instruction_operation_key=instruction_operation_key,
            instruction_operands_key=instruction_operands_key,
        )
        label_to_id: dict[str, str] = {}
        for ordinal, raw_block in enumerate(raw_blocks):
            block = _mapping(raw_block, label="basic block")
            label = str(block.get(block_label_key))
            block_start = _address(block.get(block_start_key))
            label_to_id[label] = block_id(identifier, ordinal, block_start)

        blocks: list[IRBasicBlock] = []
        instruction_index = 0
        for ordinal, raw_block in enumerate(raw_blocks):
            block = _mapping(raw_block, label="basic block")
            block_start = _address(block.get(block_start_key))
            block_size = _positive_int(block.get(block_size_key), label="block size")
            instructions: list[IRInstruction] = []
            for raw_instruction in _sequence(block.get(instructions_key), label="instructions"):
                instruction = _mapping(raw_instruction, label="instruction")
                raw_operation = _text(instruction.get(instruction_operation_key), label="operation")
                operation = _operation(raw_operation)
                tags = _string_sequence(instruction.get("tags", ()), label="tags")
                if operation in {IROperation.INDIRECT, IROperation.UNKNOWN}:
                    tags = (*tags, f"source_op:{raw_operation.lower()}")
                address = _address(instruction.get("address"))
                result = _optional_text(instruction.get("result"))
                operands = _string_sequence(
                    instruction.get(instruction_operands_key, ()),
                    label="instruction operands",
                )
                out_parameter = address_taken_out_parameters.get((address, result or ""))
                text = str(instruction.get("text", ""))
                if out_parameter is not None:
                    argument_index, pointer_operand, call_result = out_parameter
                    dependencies = tuple(
                        dependency
                        for dependency in (pointer_operand, call_result)
                        if dependency is not None and dependency not in operands
                    )
                    operands = (*operands, *dependencies)[:32]
                    tags = (
                        *tags,
                        "side_effect:address_taken_out_parameter",
                        f"out_parameter_index:{argument_index}",
                    )
                    text = (
                        f"{text} [address-taken call output argument "
                        f"{argument_index}: {pointer_operand}]"
                    )[:2000]
                preserved_parameter = preserved_argument_aliases.get((address, result))
                if preserved_parameter is not None:
                    operands = (preserved_parameter, *operands[1:])
                    tags = (*tags, "abi:preserved_argument")
                    text = (
                        f"{text} [stack-probe preserved argument: {preserved_parameter}]"
                    )[:2000]
                callee_value = instruction.get(instruction_callee_key)
                callee = None if callee_value is None else str(callee_value)
                instructions.append(
                    IRInstruction(
                        index=instruction_index,
                        address=address,
                        operation=operation,
                        result=result,
                        operands=operands,
                        constants=tuple(
                            _integer(value, label="instruction constant")
                            for value in _sequence(
                                instruction.get("constants", ()), label="constants"
                            )
                        ),
                        callee=callee,
                        width_bits=_optional_positive_int(instruction.get("width")),
                        signed=_optional_bool(instruction.get("signed")),
                        tags=tuple(sorted(set(tags))),
                        text=text,
                    )
                )
                instruction_index += 1
            raw_successors = _sequence(block.get(successors_key, ()), label="successors")
            try:
                successors = tuple(
                    sorted({label_to_id[str(successor)] for successor in raw_successors})
                )
            except KeyError as exc:
                raise ValueError("basic block cites an unknown successor label") from exc
            blocks.append(
                IRBasicBlock(
                    block_id=label_to_id[str(block.get(block_label_key))],
                    start_address=block_start,
                    end_address=block_start + block_size,
                    instructions=tuple(instructions),
                    successors=successors,
                )
            )
        pseudocode = str(item.get("pseudocode", ""))
        parameters = tuple(sorted(set(raw_parameters)))
        functions.append(
            IRFunction(
                function_id=identifier,
                name=_text(item.get(function_name_key), label="function name"),
                start_address=start,
                end_address=start + size,
                parameters=parameters,
                blocks=tuple(sorted(blocks, key=lambda block: block.start_address)),
                pseudocode=pseudocode,
                pseudocode_sha256=pseudocode_digest(pseudocode),
            )
        )
    return tuple(functions)


def _argument_preserving_stack_probe_aliases(
    raw_blocks: Sequence[object],
    *,
    parameters: tuple[str, ...],
    instructions_key: str,
    instruction_operation_key: str,
    instruction_operands_key: str,
) -> dict[tuple[int, str | None], str]:
    marker = "abi:argument_preserving_stack_probe"
    instructions = tuple(
        _mapping(raw_instruction, label="instruction")
        for raw_block in raw_blocks
        for raw_instruction in _sequence(
            _mapping(raw_block, label="basic block").get(instructions_key),
            label="instructions",
        )
    )
    probes: dict[int, set[str]] = {}
    for instruction in instructions:
        if marker not in _string_sequence(instruction.get("tags", ()), label="tags"):
            continue
        if _operation(
            _text(instruction.get(instruction_operation_key), label="operation")
        ) is not IROperation.CALL:
            continue
        result = _optional_text(instruction.get("result"))
        if result is None:
            continue
        probes.setdefault(_address(instruction.get("address")), set()).add(result)

    aliases: dict[tuple[int, str | None], str] = {}
    for instruction in instructions:
        address = _address(instruction.get("address"))
        if address not in probes:
            continue
        if _operation(
            _text(instruction.get(instruction_operation_key), label="operation")
        ) is not IROperation.CAST:
            continue
        operands = _string_sequence(
            instruction.get(instruction_operands_key, ()),
            label="instruction operands",
        )
        if not operands or operands[0] not in probes[address]:
            continue
        constants = tuple(
            _integer(value, label="instruction constant")
            for value in _sequence(instruction.get("constants", ()), label="constants")
        )
        if not constants or constants[0] < 0 or constants[0] % 8 != 0:
            continue
        if _optional_positive_int(instruction.get("width")) != 64:
            continue
        parameter_index = constants[0] // 8
        if parameter_index >= len(parameters):
            continue
        key = (
            address,
            _optional_text(instruction.get("result")),
        )
        parameter = parameters[parameter_index]
        if key in aliases and aliases[key] != parameter:
            raise ValueError("conflicting stack-probe preserved argument aliases")
        aliases[key] = parameter
    return aliases


def _operation(value: str) -> IROperation:
    return _OPERATION_ALIASES.get(value.strip().lower(), IROperation.UNKNOWN)


def _canonical_uuid(value: object) -> str:
    return str(uuid.UUID(_text(value, label="image UUID"))).upper()


def _address(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("address must be an integer or hexadecimal string")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("address may not be negative")
        return value
    if isinstance(value, str):
        base = 16 if value.lower().startswith("0x") else 10
        parsed = int(value, base)
        if parsed < 0:
            raise ValueError("address may not be negative")
        return parsed
    raise ValueError("address must be an integer or hexadecimal string")


def _integer(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def _positive_int(value: object, *, label: str) -> int:
    parsed = _integer(value, label=label)
    if parsed <= 0:
        raise ValueError(f"{label} must be positive")
    return parsed


def _non_negative_int(value: object, *, label: str) -> int:
    parsed = _integer(value, label=label)
    if parsed < 0:
        raise ValueError(f"{label} may not be negative")
    return parsed


def _boolean(value: object, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def _optional_positive_int(value: object) -> int | None:
    if value is None:
        return None
    return _positive_int(value, label="instruction width")


def _optional_bool(value: object) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError("instruction signedness must be boolean")
    return value


def _text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty text")
    return value.strip()


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    return _text(value, label="optional text")


def _mapping(value: object, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _sequence(value: object, *, label: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{label} must be an array")
    return value


def _string_sequence(value: object, *, label: str) -> tuple[str, ...]:
    return tuple(_text(item, label=label) for item in _sequence(value, label=label))
