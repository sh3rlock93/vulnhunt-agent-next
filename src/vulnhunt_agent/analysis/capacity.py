"""Bounded, intraprocedural capacity fact extraction for C code."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re

from tree_sitter import Node

from .models import (
    CapacityFact,
    CapacityFactKind,
    CapacityReturnKind,
    FunctionCapacitySummary,
)
from .risk_chains import is_allocator_name

CAPACITY_FACT_POLICY = "c-capacity-fact-v1"
MAX_ALIAS_HOPS = 8
MAX_CAPACITY_TRANSFORMS = 12

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CAPACITY_TERM = re.compile(
    r"\b(?:capacity|cap|remaining|remain|limit|allocated|alloc_size|"
    r"table_size|buffer_size|buf_size|end)\w*\b",
    re.IGNORECASE,
)
_COMPARISON = re.compile(r"(.+?)\s*(<=|<|>=|>|==|!=)\s*(.+)")
_MEMORY_WRITES = frozenset({"memcpy", "memmove", "memset"})
_NON_POINTER_IDENTIFIERS = frozenset({"NULL", "true", "false"})
_FAILURE_RETURN = re.compile(r"^(?:0|-1|NULL|false)$")
_REJECT_ACTION = re.compile(r"\b(?:return|goto|break|continue)\b")
_GROWTH_CALL = re.compile(r"(?:realloc|grow|reserve|resize)", re.IGNORECASE)
_CALL_TOKEN = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_OVERFLOW_GUARD = re.compile(
    r"__builtin_(?:add|sub|mul)_overflow|(?:safe|checked)\w*(?:add|mul|size|capacity)",
    re.IGNORECASE,
)
_NULL_GUARD = re.compile(
    r"if\s*\(\s*!\s*(?P<subject>[A-Za-z_]\w*)\s*\)|"
    r"if\s*\(\s*(?P<subject2>[A-Za-z_]\w*)\s*(?:==|!=)\s*NULL\s*\)",
)


@dataclass(frozen=True)
class _PointerState:
    base: str
    offset: str
    element_count: str
    element_size: str
    alias_depth: int
    transform_depth: int


def extract_capacity_facts(
    *,
    path: str,
    node_id: str,
    function: str,
    source: bytes,
    function_node: Node,
    body_nodes: tuple[Node, ...],
) -> tuple[CapacityFact, ...]:
    """Extract local capacity relationships without whole-program inference."""
    pointers: dict[str, _PointerState] = {}
    blocked_pointers: set[str] = set()
    facts: list[CapacityFact] = []
    pointer_variables = set(re.findall(
        r"\*+\s*(?:(?:const|restrict|volatile)\s+)*([A-Za-z_]\w*)",
        _text(function_node, source),
    ))
    nodes = sorted(
        {
            (node.start_byte, node.end_byte, node.type): node
            for body in body_nodes
            for node in (body, *_walk(body))
        }.values(),
        key=lambda item: (item.start_byte, item.end_byte, item.type),
    )

    for node in nodes:
        if node.type not in {"assignment_expression", "init_declarator"}:
            continue
        left, right = _assignment_parts(node)
        if left is None or right is None:
            continue
        subject = _declared_or_simple_identifier(left, source)
        if not subject:
            continue
        line = node.start_point[0] + 1
        expression = _compact(_text(right, source))
        call = _first_node(right, "call_expression")
        callee = _call_name(call, source) if call is not None else ""
        if call is not None and (
            is_allocator_name(callee) or _GROWTH_CALL.search(callee)
        ):
            if _GROWTH_CALL.search(callee):
                arguments = _arguments(call, source)
                base = _argument_root(arguments[0]) if arguments else subject
                count = arguments[1] if len(arguments) > 1 else "unknown"
                element_size = arguments[2] if len(arguments) > 2 else "1"
                previous = pointers.get(base)
                state = _PointerState(
                    base=(previous.base if previous is not None else base),
                    offset="0",
                    element_count=count,
                    element_size=element_size,
                    alias_depth=min(
                        MAX_ALIAS_HOPS,
                        previous.alias_depth + 1 if previous is not None else 1,
                    ),
                    transform_depth=(
                        min(
                            MAX_CAPACITY_TRANSFORMS,
                            previous.transform_depth + 1 if previous is not None else 1,
                        )
                    ),
                )
                pointers[subject] = state
                facts.append(_fact(
                    kind=CapacityFactKind.GROWTH,
                    node_id=node_id,
                    path=path,
                    function=function,
                    line=line,
                    subject=subject,
                    state=state,
                    evidence=(
                        f"{subject} receives grown storage from {callee}"
                        f"({', '.join(arguments)})"
                    ),
                    confidence="high",
                ))
                continue
            count, element_size = _allocation_shape(call, callee, source)
            state = _PointerState(
                base=subject,
                offset="0",
                element_count=count,
                element_size=element_size,
                alias_depth=0,
                transform_depth=0,
            )
            pointers[subject] = state
            facts.append(_fact(
                kind=CapacityFactKind.ALLOCATION,
                node_id=node_id,
                path=path,
                function=function,
                line=line,
                subject=subject,
                state=state,
                evidence=f"{subject} allocated by {callee}({', '.join(_arguments(call, source))})",
                confidence="high",
            ))
            continue

        operator = _assignment_operator(node, source)
        if operator == "+=" and subject in pointers:
            previous = pointers[subject]
            if previous.transform_depth >= MAX_CAPACITY_TRANSFORMS:
                continue
            state = _PointerState(
                base=previous.base,
                offset=_add(previous.offset, expression),
                element_count=previous.element_count,
                element_size=previous.element_size,
                alias_depth=previous.alias_depth,
                transform_depth=previous.transform_depth + 1,
            )
            pointers[subject] = state
            facts.append(_fact(
                kind=CapacityFactKind.ADVANCE,
                node_id=node_id,
                path=path,
                function=function,
                line=line,
                subject=subject,
                state=state,
                evidence=f"{subject} advances by {expression}",
                confidence="high",
            ))
            continue

        if subject not in pointer_variables and subject not in pointers:
            continue
        alias_root = _alias_root(expression)
        if alias_root in blocked_pointers:
            blocked_pointers.add(subject)
            continue
        alias = _alias_expression(expression, pointers)
        if alias is None:
            continue
        if alias.alias_depth > MAX_ALIAS_HOPS:
            blocked_pointers.add(subject)
            continue
        pointers[subject] = alias
        facts.append(_fact(
            kind=CapacityFactKind.ALIAS,
            node_id=node_id,
            path=path,
            function=function,
            line=line,
            subject=subject,
            state=alias,
            evidence=f"{subject} aliases {expression}",
            confidence="high" if alias.base in pointers else "medium",
        ))

    transforms_by_base: dict[str, int] = {}
    for node in nodes:
        write = _write_shape(node, source)
        if write is None:
            continue
        subject, extent, evidence = write
        state = pointers.get(subject, _PointerState(subject, "0", "", "", 0, 0))
        transforms = transforms_by_base.get(state.base, 0)
        if transforms >= MAX_CAPACITY_TRANSFORMS:
            continue
        transforms_by_base[state.base] = transforms + 1
        state = _PointerState(
            base=state.base,
            offset=state.offset,
            element_count=state.element_count,
            element_size=state.element_size,
            alias_depth=state.alias_depth,
            transform_depth=max(state.transform_depth, transforms + 1),
        )
        facts.append(_fact(
            kind=CapacityFactKind.WRITE,
            node_id=node_id,
            path=path,
            function=function,
            line=node.start_point[0] + 1,
            subject=subject,
            state=state,
            write_extent=extent,
            evidence=evidence,
            confidence="high" if subject in pointers else "medium",
        ))

    function_text = _text(function_node, source)
    start_line = function_node.start_point[0] + 1
    function_lines = function_text.splitlines()
    allocation_terms = {
        identifier
        for state in pointers.values()
        for identifier in re.findall(r"\b[A-Za-z_]\w*\b", state.element_count)
        if identifier not in {"sizeof"}
    }
    growth_subjects = {
        fact.subject for fact in facts if fact.kind is CapacityFactKind.GROWTH
    }
    for offset, raw_line in enumerate(function_lines):
        line = _compact(raw_line)
        if "if" not in line:
            continue
        line_terms = set(re.findall(r"\b[A-Za-z_]\w*\b", line))
        null_guard = _NULL_GUARD.search(line)
        overflow_guard = _OVERFLOW_GUARD.search(line)
        if (
            not _CAPACITY_TERM.search(line)
            and not allocation_terms.intersection(line_terms)
            and not growth_subjects.intersection(line_terms)
            and null_guard is None
            and overflow_guard is None
        ):
            continue
        action_window = " ".join(function_lines[offset:offset + 4])
        effect = "reject" if _REJECT_ACTION.search(action_window) else "unknown"
        if any(
            _GROWTH_CALL.search(name) for name in _CALL_TOKEN.findall(action_window)
        ):
            effect = "grow"
        condition_match = re.search(r"\bif\s*\((.*?)\)", line)
        condition = (
            condition_match.group(1)
            if condition_match is not None else line[line.find("if") + 2:].strip(" (){")
        )
        comparison = _COMPARISON.search(condition)
        if comparison is not None:
            relation = _compact(comparison.group(0))
            subject = _compact(comparison.group(1))
        elif null_guard is not None:
            subject = null_guard.group("subject") or null_guard.group("subject2") or "unknown"
            relation = f"{subject} != NULL on continuing path"
        elif overflow_guard is not None:
            subject = _compact(overflow_guard.group(0))
            relation = line
        else:
            continue
        facts.append(_fact(
            kind=CapacityFactKind.GUARD,
            node_id=node_id,
            path=path,
            function=function,
            line=start_line + offset,
            subject=subject,
            state=_PointerState("", "", "", "", 0, 0),
            relation=relation,
            evidence=f"explicit capacity comparison: {relation}",
            confidence="medium",
            guard_effect=effect,
            dominates=effect == "reject",
        ))

    return tuple(sorted(
        {fact.fact_id: fact for fact in facts}.values(),
        key=lambda item: item.fact_id,
    ))


def build_local_capacity_summary(
    *,
    path: str,
    node_id: str,
    function: str,
    source: bytes,
    declarator: Node,
    body_nodes: tuple[Node, ...],
    facts: tuple[CapacityFact, ...],
) -> FunctionCapacitySummary:
    """Summarize only locally established parameter and return behavior."""
    parameters, pointer_parameters = _function_parameters(declarator, source)
    pointer_set = set(pointer_parameters)
    writes: dict[str, set[str]] = {}
    for fact in facts:
        if fact.kind is not CapacityFactKind.WRITE:
            continue
        parameter = fact.subject if fact.subject in pointer_set else fact.base
        if parameter not in pointer_set:
            continue
        writes.setdefault(parameter, set()).add(fact.write_extent or "1")

    returns = tuple(sorted({
        expression
        for body in body_nodes
        for node in (body, *_walk(body))
        if node.type == "return_statement"
        if (expression := _return_expression(node, source))
    }))
    pass_through = tuple(sorted(pointer_set.intersection(returns)))
    failures = tuple(sorted(expression for expression in returns if _FAILURE_RETURN.fullmatch(
        expression
    )))
    if not returns:
        return_kind = CapacityReturnKind.NONE
    elif pass_through:
        return_kind = CapacityReturnKind.PASS_THROUGH
    elif writes and any(not _FAILURE_RETURN.fullmatch(item) for item in returns):
        return_kind = CapacityReturnKind.CONSUMED_OR_REQUIRED
    elif len(failures) == len(returns):
        return_kind = CapacityReturnKind.STATUS
    else:
        return_kind = CapacityReturnKind.UNKNOWN

    identity = "\0".join(("c-capacity-summary-v1", node_id))
    return FunctionCapacitySummary(
        summary_id="capacity_summary_" + hashlib.sha256(identity.encode()).hexdigest()[:20],
        node_id=node_id,
        path=path,
        function=function,
        parameters=parameters,
        pointer_parameters=pointer_parameters,
        written_parameters=tuple(sorted(writes)),
        write_extents={
            parameter: tuple(sorted(extents))
            for parameter, extents in sorted(writes.items())
        },
        return_expressions=returns,
        return_kind=return_kind,
        pass_through_parameters=pass_through,
        guard_fact_ids=tuple(sorted(
            fact.fact_id for fact in facts if fact.kind is CapacityFactKind.GUARD
        )),
        failure_returns=failures,
    )


def _assignment_parts(node: Node) -> tuple[Node | None, Node | None]:
    if node.type == "assignment_expression":
        return node.child_by_field_name("left"), node.child_by_field_name("right")
    return node.child_by_field_name("declarator"), node.child_by_field_name("value")


def _function_parameters(
    declarator: Node,
    source: bytes,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    parameter_list = _first_node(declarator, "parameter_list")
    if parameter_list is None:
        return (), ()
    parameters = []
    pointers = []
    for declaration in parameter_list.named_children:
        if declaration.type not in {"parameter_declaration", "variadic_parameter"}:
            continue
        identifiers = [
            _text(item, source) for item in (declaration, *_walk(declaration))
            if item.type == "identifier"
        ]
        if not identifiers:
            continue
        name = identifiers[-1]
        parameters.append(name)
        declaration_text = _text(declaration, source)
        if "*" in declaration_text or "[" in declaration_text:
            pointers.append(name)
    return tuple(parameters), tuple(pointers)


def _return_expression(node: Node, source: bytes) -> str:
    named = tuple(node.named_children)
    if not named:
        return ""
    return _compact(_text(named[0], source)).rstrip(";")


def _assignment_operator(node: Node, source: bytes) -> str:
    if node.type != "assignment_expression":
        return "="
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return ""
    return _text_range(source, left.end_byte, right.start_byte).strip()


def _allocation_shape(call: Node, callee: str, source: bytes) -> tuple[str, str]:
    arguments = _arguments(call, source)
    if len(arguments) >= 2 and (
        callee.casefold().endswith("calloc") or "safe" in callee.casefold()
    ):
        return arguments[0], arguments[1]
    expression = arguments[0] if arguments else "unknown"
    sizeof = re.search(r"(.+?)\s*\*\s*(sizeof\s*\(.+\))$", expression)
    if sizeof is not None:
        return _compact(sizeof.group(1)), _compact(sizeof.group(2))
    return expression, "1"


def _alias_expression(
    expression: str,
    pointers: dict[str, _PointerState],
) -> _PointerState | None:
    expression = _strip_casts(expression)
    address = re.fullmatch(r"&\s*([A-Za-z_]\w*)\s*\[(.+)]", expression)
    if address is not None:
        name, delta = address.groups()
    else:
        addition = re.fullmatch(r"([A-Za-z_]\w*)\s*\+\s*(.+)", expression)
        if addition is not None:
            name, delta = addition.groups()
        elif _IDENTIFIER.fullmatch(expression):
            name, delta = expression, "0"
        else:
            return None
    if name in _NON_POINTER_IDENTIFIERS:
        return None
    previous = pointers.get(name)
    if previous is None:
        return _PointerState(name, _compact(delta), "", "", 1, 0)
    return _PointerState(
        previous.base,
        _add(previous.offset, _compact(delta)),
        previous.element_count,
        previous.element_size,
        previous.alias_depth + 1,
        previous.transform_depth,
    )


def _alias_root(expression: str) -> str:
    expression = _strip_casts(expression)
    match = re.match(r"(?:&\s*)?([A-Za-z_]\w*)", expression)
    return match.group(1) if match is not None else ""


def _write_shape(node: Node, source: bytes) -> tuple[str, str, str] | None:
    if node.type == "assignment_expression":
        left = node.child_by_field_name("left")
        if left is None:
            return None
        subscript = left if left.type == "subscript_expression" else _first_node(
            left, "subscript_expression"
        )
        if subscript is not None:
            argument = subscript.child_by_field_name("argument")
            index = subscript.child_by_field_name("index")
            if argument is not None and index is not None:
                subject = _strip_casts(_compact(_text(argument, source)))
                if _IDENTIFIER.fullmatch(subject):
                    index_text = _compact(_text(index, source))
                    return subject, _add(index_text, "1"), _compact(_text(node, source))
        pointer = left if left.type == "pointer_expression" else None
        if pointer is not None:
            subject = next(
                (_text(item, source) for item in _walk(pointer) if item.type == "identifier"),
                "",
            )
            if subject:
                return subject, "1", _compact(_text(node, source))
    if node.type != "call_expression":
        return None
    callee = _call_name(node, source)
    if callee not in _MEMORY_WRITES:
        return None
    arguments = _arguments(node, source)
    if len(arguments) < 3:
        return None
    destination = _strip_casts(arguments[0])
    alias = re.match(r"(?:&\s*)?([A-Za-z_]\w*)", destination)
    if alias is None:
        return None
    return alias.group(1), arguments[2], f"{callee} writes {arguments[2]} bytes"


def _fact(
    *,
    kind: CapacityFactKind,
    node_id: str,
    path: str,
    function: str,
    line: int,
    subject: str,
    state: _PointerState,
    evidence: str,
    confidence: str,
    write_extent: str = "",
    relation: str = "",
    guard_effect: str = "unknown",
    dominates: bool = False,
) -> CapacityFact:
    remaining = (
        _subtract(state.element_count, state.offset)
        if state.element_count and state.offset else ""
    )
    identity = "\0".join((
        CAPACITY_FACT_POLICY, kind.value, node_id, str(line), subject,
        state.base, state.offset, write_extent, relation, evidence,
    ))
    return CapacityFact(
        fact_id="capacity_" + hashlib.sha256(identity.encode()).hexdigest()[:20],
        policy_version=CAPACITY_FACT_POLICY,
        kind=kind,
        node_id=node_id,
        path=path,
        function=function,
        line=line,
        subject=subject,
        base=state.base,
        element_count=state.element_count,
        element_size=state.element_size,
        offset=state.offset,
        remaining_capacity=remaining,
        write_extent=write_extent,
        relation=relation,
        guard_effect=guard_effect,
        dominates=dominates,
        evidence=evidence[:500],
        confidence=confidence,
        alias_depth=state.alias_depth,
        transform_depth=state.transform_depth,
    )


def _declared_or_simple_identifier(node: Node, source: bytes) -> str:
    text = _compact(_text(node, source))
    if _IDENTIFIER.fullmatch(text):
        return text
    identifiers = [
        _text(item, source) for item in (node, *_walk(node))
        if item.type == "identifier"
    ]
    return identifiers[-1] if identifiers else ""


def _call_name(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    function = node.child_by_field_name("function")
    if function is None:
        return ""
    if function.type == "identifier":
        return _text(function, source)
    field = function.child_by_field_name("field")
    return _text(field, source) if field is not None else ""


def _arguments(call: Node, source: bytes) -> tuple[str, ...]:
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return ()
    return tuple(_compact(_text(item, source)) for item in arguments.named_children)


def _first_node(root: Node, kind: str) -> Node | None:
    if root.type == kind:
        return root
    return next((item for item in _walk(root) if item.type == kind), None)


def _walk(root: Node):
    for child in root.children:
        yield child
        yield from _walk(child)


def _strip_casts(expression: str) -> str:
    return re.sub(r"^(?:\([^()]*(?:\*|_t)\)\s*)+", "", expression).strip()


def _argument_root(argument: str) -> str:
    value = _strip_casts(argument)
    match = re.match(r"(?:&\s*)?([A-Za-z_]\w*)", value)
    return match.group(1) if match is not None else ""


def _add(left: str, right: str) -> str:
    if left in {"", "0"}:
        return right or "0"
    if right in {"", "0"}:
        return left
    return f"({left}) + ({right})"


def _subtract(left: str, right: str) -> str:
    if right in {"", "0"}:
        return left
    return f"({left}) - ({right})"


def _text(node: Node, source: bytes) -> str:
    return _text_range(source, node.start_byte, node.end_byte)


def _text_range(source: bytes, start: int, end: int) -> str:
    return source[start:end].decode(errors="replace")


def _compact(value: str) -> str:
    return " ".join(value.strip().split())[:500]
