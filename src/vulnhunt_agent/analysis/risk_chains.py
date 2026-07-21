"""Bounded intraprocedural integer and allocation risk-chain analysis."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from tree_sitter import Node

from .models import (
    GuardState,
    RiskChain,
    RiskTransform,
    SecuritySignal,
)

RISK_CHAIN_POLICY = "c-risk-chain-v1"

_SOURCE_CALLS = frozenset({
    "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull",
    "read", "recv", "recvfrom", "fread", "fgets", "getline", "getdelim",
    "scanf", "fscanf", "sscanf", "getenv", "getopt", "getopt_long",
})
_COPY_CALLS = frozenset({
    "memcpy", "memmove", "strcpy", "strcat", "stpcpy", "sprintf", "vsprintf",
})
_ARITHMETIC = re.compile(r"<<|>>|[+*/%-]")
_IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_FIXED_WIDTH_TYPE = re.compile(
    r"(?:u?int(?:8|16|32)_t|unsigned(?:\s+int)?|signed(?:\s+int)?|\bint\b)",
    re.IGNORECASE,
)
_OVERFLOW_LIMIT = re.compile(
    r"(?:UINT|INT|SIZE|SSIZE|TMSIZE|PTRDIFF|LONG|ULONG)_MAX|"
    r"__builtin_(?:add|mul|sub)_overflow",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _ValueState:
    source_signal_ids: tuple[str, ...]
    source_lines: tuple[int, ...]
    variables: tuple[str, ...]
    transforms: tuple[RiskTransform, ...]


@dataclass(frozen=True)
class _Allocation:
    variable: str
    line: int
    signal_id: str
    state: _ValueState


def is_allocator_name(name: str) -> bool:
    """Recognize ordinary allocators and prefixed allocator wrappers."""
    folded = name.casefold()
    return folded.endswith(("malloc", "calloc", "realloc", "alloca")) or name == "ALLOC"


def build_function_risk_chains(
    *,
    path: str,
    node_id: str,
    function: str,
    source: bytes,
    function_node: Node,
    declarator: Node,
    body_nodes: tuple[Node, ...],
    signals: tuple[SecuritySignal, ...],
) -> tuple[RiskChain, ...]:
    """Link local input, arithmetic, allocation, and copy operations.

    The pass is deliberately intraprocedural and bounded. It follows only
    simple identifiers and assignments and records uncertainty instead of
    claiming whole-program taint or control-flow proof.
    """
    nodes = _ordered_nodes(body_nodes)
    type_by_variable = _declared_types(
        _text_range(source, function_node.start_byte, function_node.end_byte)
    )
    states = _parameter_states(declarator, source, function_node.start_point[0] + 1)
    source_signals = {
        (signal.line, signal.operation): signal.signal_id
        for signal in signals
        if signal.role.value == "source"
    }
    sink_signals = {
        (signal.line, signal.operation): signal.signal_id
        for signal in signals
        if signal.role.value == "sink"
    }
    allocations: list[_Allocation] = []

    assignments = [
        node for node in nodes
        if node.type in {"assignment_expression", "init_declarator"}
    ]
    for assignment in assignments:
        target_node, value_node = _assignment_parts(assignment)
        target = _simple_variable(target_node, source)
        if not target or value_node is None:
            continue
        expression = _text(value_node, source)
        identifiers = tuple(sorted(set(_IDENTIFIER.findall(expression))))
        upstream = [states[name] for name in identifiers if name in states]
        call_pairs = tuple(
            (call, name)
            for call in _self_and_descendants(value_node)
            if call.type == "call_expression"
            if (name := _call_name(call, source))
        )
        line = assignment.start_point[0] + 1
        direct_sources = tuple(sorted({
            source_signals.get((call.start_point[0] + 1, name), "")
            for call, name in call_pairs
            if name in _SOURCE_CALLS
        } - {""}))
        if not upstream and not direct_sources:
            continue

        arithmetic_nodes = [
            child for child in _self_and_descendants(value_node)
            if child.type == "binary_expression"
        ]
        operations = tuple(sorted({
            operation
            for child in arithmetic_nodes
            for operation in _ARITHMETIC.findall(_text(child, source))
        }))
        transforms = tuple(
            transform for state in upstream for transform in state.transforms
        )
        if operations:
            operand_types = tuple(sorted({
                type_by_variable[name]
                for name in identifiers
                if name in type_by_variable
            }))
            transforms = (*transforms, RiskTransform(
                line=line,
                target=target,
                expression=" ".join(expression.split())[:240],
                operations=operations,
                operand_types=operand_types,
                narrowing_or_wrap=bool(
                    _FIXED_WIDTH_TYPE.search(type_by_variable.get(target, ""))
                ),
            ))
        state = _ValueState(
            source_signal_ids=tuple(sorted({
                *direct_sources,
                *(item for upstream_state in upstream
                  for item in upstream_state.source_signal_ids),
            })),
            source_lines=tuple(sorted({
                *(call.start_point[0] + 1 for call, name in call_pairs
                  if name in _SOURCE_CALLS),
                *(item for upstream_state in upstream
                  for item in upstream_state.source_lines),
            })),
            variables=tuple(sorted({
                target,
                *(item for upstream_state in upstream
                  for item in upstream_state.variables),
            })),
            transforms=_dedupe_transforms(transforms),
        )
        states[target] = state

        for call, callee in call_pairs:
            if not is_allocator_name(callee) or not state.transforms:
                continue
            signal_id = sink_signals.get((call.start_point[0] + 1, callee), "")
            if signal_id:
                allocations.append(_Allocation(
                    variable=target,
                    line=call.start_point[0] + 1,
                    signal_id=signal_id,
                    state=state,
                ))

    allocated_signal_ids = {item.signal_id for item in allocations}
    for call in (node for node in nodes if node.type == "call_expression"):
        callee = _call_name(call, source)
        if not is_allocator_name(callee):
            continue
        signal_id = sink_signals.get((call.start_point[0] + 1, callee), "")
        if not signal_id or signal_id in allocated_signal_ids:
            continue
        arguments = call.child_by_field_name("arguments")
        expression = _text(arguments, source) if arguments is not None else ""
        upstream = [
            states[name]
            for name in sorted(set(_IDENTIFIER.findall(expression)))
            if name in states
        ]
        transforms = _dedupe_transforms(tuple(
            transform for state in upstream for transform in state.transforms
        ))
        if not upstream or not transforms:
            continue
        allocations.append(_Allocation(
            variable="",
            line=call.start_point[0] + 1,
            signal_id=signal_id,
            state=_ValueState(
                source_signal_ids=tuple(sorted({
                    item for state in upstream for item in state.source_signal_ids
                })),
                source_lines=tuple(sorted({
                    item for state in upstream for item in state.source_lines
                })),
                variables=tuple(sorted({
                    item for state in upstream for item in state.variables
                })),
                transforms=transforms,
            ),
        ))

    chains = [
        _chain_for_allocation(
            allocation=allocation,
            path=path,
            node_id=node_id,
            function=function,
            source=source,
            nodes=nodes,
            signals=sink_signals,
        )
        for allocation in allocations
    ]
    return tuple(sorted(chains, key=lambda item: item.chain_id))


def _chain_for_allocation(
    *,
    allocation: _Allocation,
    path: str,
    node_id: str,
    function: str,
    source: bytes,
    nodes: tuple[Node, ...],
    signals: dict[tuple[int, str], str],
) -> RiskChain:
    copies: list[tuple[int, str, bool]] = []
    for call in (
        node for node in nodes
        if node.type == "call_expression" and node.start_point[0] + 1 >= allocation.line
    ):
        callee = _call_name(call, source)
        if callee not in _COPY_CALLS:
            continue
        arguments = call.child_by_field_name("arguments")
        values = tuple(arguments.named_children) if arguments is not None else ()
        if not values:
            continue
        destination = _text(values[0], source)
        if allocation.variable not in set(_IDENTIFIER.findall(destination)):
            continue
        loop_bound = _loop_uses_source(call, allocation.state.variables, source)
        signal_id = signals.get((call.start_point[0] + 1, callee), "")
        if signal_id:
            copies.append((call.start_point[0] + 1, signal_id, loop_bound))

    guard_state, guard_lines = _guard_state(
        allocation=allocation,
        nodes=nodes,
        source=source,
    )
    wrap = any(step.narrowing_or_wrap for step in allocation.state.transforms)
    score = 55 + (20 if wrap else 5)
    if copies:
        score += 15
    if any(loop_bound for _, _, loop_bound in copies):
        score += 5
    if guard_state is GuardState.PARTIAL:
        score -= 5
    elif guard_state is GuardState.DOMINATES:
        score -= 50
    score = max(0, min(100, score))
    confidence = (
        "high" if wrap and copies and guard_state is not GuardState.DOMINATES
        else "medium" if wrap or copies else "low"
    )
    sink_signal_ids = tuple(sorted({signal_id for _, signal_id, _ in copies}))
    sink_lines = tuple(sorted({allocation.line, *(line for line, _, _ in copies)}))
    identity = json.dumps({
        "policy": RISK_CHAIN_POLICY,
        "node_id": node_id,
        "sources": allocation.state.source_signal_ids,
        "transforms": [step.model_dump(mode="json") for step in allocation.state.transforms],
        "allocation": allocation.signal_id,
        "sinks": sink_signal_ids,
    }, sort_keys=True, separators=(",", ":"))
    chain_id = "risk_" + hashlib.sha256(identity.encode()).hexdigest()[:20]
    copy_text = "copy/index loop" if copies else "allocation"
    return RiskChain(
        chain_id=chain_id,
        policy_version=RISK_CHAIN_POLICY,
        node_id=node_id,
        path=path,
        function=function,
        source_signal_ids=allocation.state.source_signal_ids,
        source_variables=allocation.state.variables,
        source_lines=allocation.state.source_lines,
        transform_steps=allocation.state.transforms,
        guard_state=guard_state,
        guard_lines=guard_lines,
        allocation_signal_ids=(allocation.signal_id,),
        sink_signal_ids=sink_signal_ids,
        sink_lines=sink_lines,
        score=score,
        confidence=confidence,
        rationale=(
            f"External or parameter-derived values reach a fixed-width arithmetic "
            f"allocation and subsequent {copy_text}; overflow guard={guard_state.value}."
        ),
    )


def _guard_state(
    *,
    allocation: _Allocation,
    nodes: tuple[Node, ...],
    source: bytes,
) -> tuple[GuardState, tuple[int, ...]]:
    relevant = set(allocation.state.variables)
    partial: list[int] = []
    strong: list[int] = []
    for node in nodes:
        if node.type != "if_statement" or node.start_point[0] + 1 >= allocation.line:
            continue
        condition = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        if condition is None or consequence is None:
            continue
        condition_text = _text(condition, source)
        if not relevant.intersection(_IDENTIFIER.findall(condition_text)):
            continue
        consequence_text = _text(consequence, source)
        if not re.search(r"\b(?:return|goto|break)\b", consequence_text):
            continue
        line = node.start_point[0] + 1
        partial.append(line)
        if _OVERFLOW_LIMIT.search(condition_text) or (
            "/" in condition_text
            and re.search(r"(?:>|>=|<|<=)", condition_text)
        ):
            strong.append(line)
    if strong:
        return GuardState.DOMINATES, tuple(sorted(set(strong)))
    if partial:
        return GuardState.PARTIAL, tuple(sorted(set(partial)))
    return GuardState.ABSENT, ()


def _loop_uses_source(call: Node, variables: tuple[str, ...], source: bytes) -> bool:
    current = call.parent
    relevant = set(variables)
    while current is not None:
        if current.type == "for_statement":
            condition = current.child_by_field_name("condition")
            condition_text = _text(condition, source) if condition is not None else ""
            return bool(relevant.intersection(_IDENTIFIER.findall(condition_text)))
        if current.type == "function_definition":
            break
        current = current.parent
    return False


def _parameter_states(
    declarator: Node,
    source: bytes,
    line: int,
) -> dict[str, _ValueState]:
    states: dict[str, _ValueState] = {}
    for node in _self_and_descendants(declarator):
        if node.type != "parameter_declaration":
            continue
        identifiers = [
            child for child in _self_and_descendants(node)
            if child.type == "identifier"
        ]
        if not identifiers:
            continue
        name = _text(identifiers[-1], source)
        states[name] = _ValueState((), (line,), (name,), ())
    return states


def _declared_types(function_text: str) -> dict[str, str]:
    types: dict[str, str] = {}
    declaration = re.compile(
        r"(?m)^\s*(?P<type>(?:(?:const|volatile|signed|unsigned|short|long)\s+)*"
        r"(?:[A-Za-z_][A-Za-z0-9_]*_t|int|char|float|double|size_t|ssize_t))"
        r"\s+(?P<values>[^;(){}]+);"
    )
    for match in declaration.finditer(function_text):
        declared_type = " ".join(match.group("type").split())
        for value in match.group("values").split(","):
            name_match = re.search(r"[*\s]([A-Za-z_][A-Za-z0-9_]*)", " " + value)
            if name_match:
                types[name_match.group(1)] = declared_type
    return types


def _assignment_parts(node: Node) -> tuple[Node | None, Node | None]:
    if node.type == "assignment_expression":
        return node.child_by_field_name("left"), node.child_by_field_name("right")
    return node.child_by_field_name("declarator"), node.child_by_field_name("value")


def _simple_variable(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    if node.type == "identifier":
        return _text(node, source)
    identifiers = [
        child for child in _self_and_descendants(node)
        if child.type == "identifier"
    ]
    return _text(identifiers[-1], source) if identifiers else ""


def _call_name(node: Node, source: bytes) -> str:
    function = node.child_by_field_name("function")
    if function is None:
        return ""
    if function.type == "identifier":
        return _text(function, source)
    field = function.child_by_field_name("field")
    return _text(field, source) if field is not None else ""


def _ordered_nodes(body_nodes: tuple[Node, ...]) -> tuple[Node, ...]:
    unique = {
        (node.start_byte, node.end_byte, node.type): node
        for root in body_nodes
        for node in _self_and_descendants(root)
    }
    return tuple(sorted(
        unique.values(),
        key=lambda node: (node.start_byte, node.end_byte, node.type),
    ))


def _self_and_descendants(root: Node):
    yield root
    for child in root.children:
        yield from _self_and_descendants(child)


def _dedupe_transforms(transforms: tuple[RiskTransform, ...]) -> tuple[RiskTransform, ...]:
    unique = {
        (item.line, item.target, item.expression): item for item in transforms
    }
    return tuple(sorted(unique.values(), key=lambda item: (
        item.line, item.target, item.expression
    )))


def _text(node: Node, source: bytes) -> str:
    return _text_range(source, node.start_byte, node.end_byte)


def _text_range(source: bytes, start: int, end: int) -> str:
    return source[start:end].decode(errors="replace")
