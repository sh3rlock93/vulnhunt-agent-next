"""Bounded macro-aware cursor reads and caller-to-callee transitions."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from tree_sitter import Node

from .models import (
    CapacityCallSite,
    CursorFact,
    CursorFactKind,
    CursorTransitionChain,
    FunctionCapacitySummary,
    GuardState,
)

CURSOR_ACCESS_POLICY = "c-cursor-access-v1"
CURSOR_TRANSITION_POLICY = "c-cursor-transition-v1"
_DEFINE = re.compile(
    r"^[ \t]*#define[ \t]+([A-Za-z_]\w*)\(([^\n)]*)\)[ \t]+([^\n]+)$",
    re.MULTILINE,
)
_MEMBER = re.compile(
    r"\(?\s*([A-Za-z_]\w*)\s*\)?\s*->\s*([A-Za-z_]\w*)"
)
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(([^()]*)\)")
_INTEGER = re.compile(r"^\s*(\d+)\s*$")


@dataclass(frozen=True)
class CursorMacro:
    name: str
    parameters: tuple[str, ...]
    body: str
    buffer_parameter: str = ""
    index_parameter: str = ""
    cursor_field: str = ""
    bound_field: str = ""
    data_field: str = ""
    guard: bool = False
    negated: bool = False


def extract_cursor_macros(source: bytes) -> dict[str, CursorMacro]:
    """Resolve one-line local macros that expose a cursor/bound relationship."""
    text = source.decode(errors="replace")
    raw: dict[str, tuple[tuple[str, ...], str]] = {}
    direct_guards: dict[str, CursorMacro] = {}
    cursor_bounds: dict[str, str] = {}
    for match in _DEFINE.finditer(text):
        name = match.group(1)
        parameters = tuple(
            item.strip() for item in match.group(2).split(",") if item.strip()
        )
        body = match.group(3).strip()
        raw[name] = (parameters, body)
        relation = re.search(r"(.+?)(?:<=|<)(.+)", body)
        if relation is None:
            continue
        left = _MEMBER.findall(relation.group(1))
        right = _MEMBER.findall(relation.group(2))
        if not left or not right:
            continue
        buffer_parameter, cursor_field = left[-1]
        right_parameter, bound_field = right[0]
        if buffer_parameter != right_parameter or buffer_parameter not in parameters:
            continue
        index_parameter = next(
            (
                parameter
                for parameter in parameters
                if parameter != buffer_parameter
                and re.search(rf"\b{re.escape(parameter)}\b", relation.group(1))
            ),
            "",
        )
        macro = CursorMacro(
            name=name,
            parameters=parameters,
            body=body,
            buffer_parameter=buffer_parameter,
            index_parameter=index_parameter,
            cursor_field=cursor_field,
            bound_field=bound_field,
            guard=True,
        )
        direct_guards[name] = macro
        cursor_bounds[cursor_field] = bound_field

    macros = dict(direct_guards)
    for name, (parameters, body) in raw.items():
        if name in macros:
            continue
        nested = _CALL.search(body)
        if nested and nested.group(1) in direct_guards:
            target = direct_guards[nested.group(1)]
            arguments = tuple(
                item.strip() for item in nested.group(2).split(",")
            )
            mapping = dict(zip(target.parameters, arguments))
            buffer_parameter = mapping.get(target.buffer_parameter, "")
            index_parameter = mapping.get(target.index_parameter, "")
            if buffer_parameter in parameters:
                macros[name] = CursorMacro(
                    name=name,
                    parameters=parameters,
                    body=body,
                    buffer_parameter=buffer_parameter,
                    index_parameter=(
                        index_parameter if index_parameter in parameters else ""
                    ),
                    cursor_field=target.cursor_field,
                    bound_field=target.bound_field,
                    guard=True,
                    negated=(target.negated != _nested_call_negated(body, nested)),
                )
                continue
        members = _MEMBER.findall(body)
        for parameter, field in members:
            bound = cursor_bounds.get(field)
            if not bound or parameter not in parameters:
                continue
            data_field = next(
                (
                    candidate_field
                    for candidate_parameter, candidate_field in members
                    if candidate_parameter == parameter and candidate_field != field
                ),
                "",
            )
            if not data_field or "+" not in body:
                continue
            macros[name] = CursorMacro(
                name=name,
                parameters=parameters,
                body=body,
                buffer_parameter=parameter,
                cursor_field=field,
                bound_field=bound,
                data_field=data_field,
            )
            break
    return macros


def extract_cursor_facts(
    *,
    path: str,
    node_id: str,
    function: str,
    source: bytes,
    function_node: Node,
    body_nodes: tuple[Node, ...],
    macros: dict[str, CursorMacro],
) -> tuple[CursorFact, ...]:
    facts: list[CursorFact] = []
    cursor_bounds = {
        macro.cursor_field: macro.bound_field
        for macro in macros.values()
        if macro.cursor_field and macro.bound_field
    }
    for body in body_nodes:
        for node in (body, *_walk(body)):
            if node.type == "subscript_expression" and not _is_write(node):
                fact = _read_fact(
                    node, path, node_id, function, source, macros
                )
                if fact is not None:
                    facts.append(fact)
            elif node.type == "update_expression":
                fact = _advance_fact(
                    node, path, node_id, function, source, cursor_bounds
                )
                if fact is not None:
                    facts.append(fact)
            elif node.type == "assignment_expression":
                fact = _assignment_advance_fact(
                    node, path, node_id, function, source, cursor_bounds
                )
                if fact is not None:
                    facts.append(fact)
            elif node.type == "call_expression":
                fact = _guard_fact(
                    node,
                    path,
                    node_id,
                    function,
                    source,
                    function_node,
                    macros,
                )
                if fact is not None:
                    facts.append(fact)
    return tuple(sorted(
        {fact.fact_id: fact for fact in facts}.values(),
        key=lambda fact: fact.fact_id,
    ))


def build_cursor_transition_chains(
    *,
    facts: tuple[CursorFact, ...],
    calls: tuple[CapacityCallSite, ...],
    summaries: tuple[FunctionCapacitySummary, ...],
) -> tuple[CursorTransitionChain, ...]:
    by_node: dict[str, list[CursorFact]] = {}
    for fact in facts:
        by_node.setdefault(fact.node_id, []).append(fact)
    parameters = {summary.node_id: summary.parameters for summary in summaries}
    chains: list[CursorTransitionChain] = []
    for call in calls:
        if not call.target_node_id:
            continue
        reads = [
            fact for fact in by_node.get(call.target_node_id, ())
            if fact.kind is CursorFactKind.READ
        ]
        target_parameters = parameters.get(call.target_node_id, ())
        caller_facts = by_node.get(call.caller_id, ())
        for read in reads:
            read_base, separator, cursor_field = read.subject.partition("->")
            if not separator or read_base not in target_parameters:
                continue
            parameter_index = target_parameters.index(read_base)
            if parameter_index >= len(call.arguments):
                continue
            actual_base = _simple_identifier(call.arguments[parameter_index])
            if not actual_base:
                continue
            caller_subject = f"{actual_base}->{cursor_field}"
            caller_bound = f"{actual_base}->{read.bound.partition('->')[2]}"
            advances = [
                fact for fact in caller_facts
                if fact.kind is CursorFactKind.ADVANCE
                and fact.subject == caller_subject
                and 0 <= call.line - fact.line <= 4
            ]
            if not advances:
                continue
            advance = max(advances, key=lambda fact: (fact.line, fact.fact_id))
            read_index = _integer(read.access_index)
            if read_index is None or advance.delta <= 0:
                continue
            required = read_index + advance.delta
            guards = [
                fact for fact in caller_facts
                if fact.kind is CursorFactKind.GUARD
                and fact.subject == caller_subject
                and _controls(fact, advance.line)
                and _integer(fact.access_index) is not None
            ]
            local_guards = [
                fact for fact in by_node.get(call.target_node_id, ())
                if fact.kind is CursorFactKind.GUARD
                and fact.subject == read.subject
                and _controls(fact, read.line)
                and _integer(fact.access_index) is not None
            ]
            guard_indexes = [
                value
                for fact in guards
                if (value := _integer(fact.access_index)) is not None
            ]
            guard_indexes.extend(
                advance.delta + value
                for fact in local_guards
                if (value := _integer(fact.access_index)) is not None
            )
            observed = max(guard_indexes) if guard_indexes else None
            if observed is None:
                guard_state = GuardState.ABSENT
            elif observed >= required:
                guard_state = GuardState.DOMINATES
            else:
                guard_state = GuardState.PARTIAL
            fact_ids = tuple(sorted({
                read.fact_id,
                advance.fact_id,
                *(fact.fact_id for fact in guards),
                *(fact.fact_id for fact in local_guards),
            }))
            identity = "\0".join((
                call.caller_id,
                call.target_node_id,
                str(call.line),
                *fact_ids,
            ))
            chain_id = "cursor_transition_" + hashlib.sha256(
                identity.encode()
            ).hexdigest()[:20]
            paths = tuple(sorted({read.path, advance.path}))
            unsafe = guard_state is not GuardState.DOMINATES
            chains.append(CursorTransitionChain(
                chain_id=chain_id,
                caller_node_id=call.caller_id,
                reader_node_id=call.target_node_id,
                paths=paths,
                fact_ids=fact_ids,
                guard_fact_ids=tuple(sorted(
                    fact.fact_id for fact in (*guards, *local_guards)
                )),
                advance_fact_id=advance.fact_id,
                read_fact_id=read.fact_id,
                call_line=call.line,
                subject=caller_subject,
                bound=caller_bound,
                required_access_index=required,
                observed_guard_index=observed,
                guard_state=guard_state,
                evidence_lines=_evidence_lines(
                    read, advance, [*guards, *local_guards], call.line
                ),
                score=95 if guard_state is GuardState.PARTIAL else (90 if unsafe else 15),
                confidence="high",
                rationale=(
                    f"cursor advances by {advance.delta} before a read at index "
                    f"{read_index}; required pre-advance guard index={required}, "
                    f"observed={observed if observed is not None else 'none'}"
                ),
            ))
    return tuple(sorted(
        {chain.chain_id: chain for chain in chains}.values(),
        key=lambda chain: chain.chain_id,
    ))


def _read_fact(
    node: Node,
    path: str,
    node_id: str,
    function: str,
    source: bytes,
    macros: dict[str, CursorMacro],
) -> CursorFact | None:
    base = node.child_by_field_name("argument")
    index = node.child_by_field_name("index")
    if base is None or index is None or base.type != "call_expression":
        return None
    name = _call_name(base, source)
    macro = macros.get(name)
    if macro is None or macro.guard or not macro.cursor_field:
        return None
    arguments = _arguments(base, source)
    try:
        position = macro.parameters.index(macro.buffer_parameter)
    except ValueError:
        return None
    if position >= len(arguments):
        return None
    actual = _simple_identifier(arguments[position])
    if not actual:
        return None
    return _fact(
        kind=CursorFactKind.READ,
        node_id=node_id,
        path=path,
        function=function,
        line=node.start_point[0] + 1,
        subject=f"{actual}->{macro.cursor_field}",
        bound=f"{actual}->{macro.bound_field}",
        access_index=_text(index, source),
        macro=name,
        evidence=_text(node, source),
        confidence="high",
    )


def _advance_fact(
    node: Node,
    path: str,
    node_id: str,
    function: str,
    source: bytes,
    cursor_bounds: dict[str, str],
) -> CursorFact | None:
    argument = node.child_by_field_name("argument")
    subject = _field_subject(argument, source)
    if subject is None:
        return None
    base, field = subject
    bound_field = cursor_bounds.get(field)
    if not bound_field:
        return None
    expression = _text(node, source)
    delta = 1 if "++" in expression else (-1 if "--" in expression else 0)
    if delta == 0:
        return None
    return _fact(
        kind=CursorFactKind.ADVANCE,
        node_id=node_id,
        path=path,
        function=function,
        line=node.start_point[0] + 1,
        subject=f"{base}->{field}",
        bound=f"{base}->{bound_field}",
        delta=delta,
        evidence=expression,
        confidence="high",
    )


def _assignment_advance_fact(
    node: Node,
    path: str,
    node_id: str,
    function: str,
    source: bytes,
    cursor_bounds: dict[str, str],
) -> CursorFact | None:
    left = node.child_by_field_name("left")
    subject = _field_subject(left, source)
    if subject is None:
        return None
    base, field = subject
    bound_field = cursor_bounds.get(field)
    expression = _text(node, source)
    match = re.search(r"(?:\+=|-=)\s*(\d+)", expression)
    if not bound_field or match is None:
        return None
    delta = int(match.group(1)) * (-1 if "-=" in expression else 1)
    return _fact(
        kind=CursorFactKind.ADVANCE,
        node_id=node_id,
        path=path,
        function=function,
        line=node.start_point[0] + 1,
        subject=f"{base}->{field}",
        bound=f"{base}->{bound_field}",
        delta=delta,
        evidence=expression,
        confidence="high",
    )


def _guard_fact(
    node: Node,
    path: str,
    node_id: str,
    function: str,
    source: bytes,
    function_node: Node,
    macros: dict[str, CursorMacro],
) -> CursorFact | None:
    name = _call_name(node, source)
    macro = macros.get(name)
    if macro is None or not macro.guard:
        return None
    arguments = _arguments(node, source)
    try:
        buffer_position = macro.parameters.index(macro.buffer_parameter)
    except ValueError:
        return None
    if buffer_position >= len(arguments):
        return None
    actual = _simple_identifier(arguments[buffer_position])
    if not actual:
        return None
    access_index = "0"
    if macro.index_parameter:
        try:
            index_position = macro.parameters.index(macro.index_parameter)
        except ValueError:
            return None
        if index_position >= len(arguments):
            return None
        access_index = arguments[index_position]
    accessible_when_true = not macro.negated
    if _call_is_negated(node, source):
        accessible_when_true = not accessible_when_true
    control, start_line, end_line = _guard_control(
        node, function_node, source, accessible_when_true=accessible_when_true
    )
    if control == "none":
        return None
    return _fact(
        kind=CursorFactKind.GUARD,
        node_id=node_id,
        path=path,
        function=function,
        line=node.start_point[0] + 1,
        subject=f"{actual}->{macro.cursor_field}",
        bound=f"{actual}->{macro.bound_field}",
        access_index=access_index,
        macro=name,
        control=control,
        controlled_start_line=start_line,
        controlled_end_line=end_line,
        evidence=_text(node, source),
        confidence="high",
    )


def _guard_control(
    node: Node,
    function_node: Node,
    source: bytes,
    *,
    accessible_when_true: bool,
) -> tuple[str, int, int]:
    current = node.parent
    while current is not None and current != function_node:
        if current.type in {"do_statement", "while_statement", "for_statement"}:
            condition = current.child_by_field_name("condition")
            body = current.child_by_field_name("body")
            if (
                accessible_when_true
                and condition is not None
                and body is not None
                and _inside(node, condition)
            ):
                return (
                    "loop_entry",
                    body.start_point[0] + 1,
                    body.end_point[0] + 1,
                )
        current = current.parent

    current = node.parent
    while current is not None and current != function_node:
        if current.type == "binary_expression":
            left = current.child_by_field_name("left")
            right = current.child_by_field_name("right")
            if (
                left is not None
                and right is not None
                and accessible_when_true
                and any(child.type == "&&" for child in current.children)
                and _inside(node, left)
            ):
                return (
                    "positive_branch",
                    right.start_point[0] + 1,
                    right.end_point[0] + 1,
                )
        if current.type == "if_statement":
            condition = current.child_by_field_name("condition")
            consequence = current.child_by_field_name("consequence")
            if condition is not None and consequence is not None and _inside(node, condition):
                if _terminates(consequence) and not accessible_when_true:
                    compound = current.parent
                    while compound is not None and compound.type != "compound_statement":
                        compound = compound.parent
                    return (
                        "reject_fallthrough",
                        consequence.end_point[0] + 1,
                        (
                            compound.end_point[0] + 1
                            if compound is not None
                            else function_node.end_point[0] + 1
                        ),
                    )
                if accessible_when_true:
                    return (
                        "positive_branch",
                        consequence.start_point[0] + 1,
                        consequence.end_point[0] + 1,
                    )
                return ("none", 0, 0)
        current = current.parent
    return ("none", 0, 0)


def _terminates(node: Node) -> bool:
    if node.type in {"return_statement", "goto_statement"}:
        return True
    statements = [
        child for child in node.named_children if child.type != "comment"
    ]
    return bool(
        statements
        and statements[-1].type in {"return_statement", "goto_statement"}
    )


def _controls(fact: CursorFact, line: int) -> bool:
    return (
        fact.control != "none"
        and fact.controlled_start_line <= line <= fact.controlled_end_line
    )


def _evidence_lines(
    read: CursorFact,
    advance: CursorFact,
    guards: list[CursorFact],
    call_line: int,
) -> dict[str, tuple[int, ...]]:
    lines: dict[str, set[int]] = {
        advance.path: {advance.line, call_line, *(fact.line for fact in guards)},
    }
    lines.setdefault(read.path, set()).add(read.line)
    return {
        path: tuple(sorted(values)) for path, values in sorted(lines.items())
    }


def _fact(**values) -> CursorFact:
    identity = "\0".join(str(values.get(key, "")) for key in (
        "kind", "node_id", "path", "line", "subject", "bound",
        "access_index", "delta", "macro", "control",
    ))
    return CursorFact(
        fact_id="cursor_" + hashlib.sha256(identity.encode()).hexdigest()[:20],
        **values,
    )


def _call_name(node: Node, source: bytes) -> str:
    function = node.child_by_field_name("function")
    return _text(function, source) if function is not None else ""


def _arguments(node: Node, source: bytes) -> tuple[str, ...]:
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return ()
    return tuple(
        _text(child, source)
        for child in arguments.named_children
    )


def _field_subject(node: Node | None, source: bytes) -> tuple[str, str] | None:
    if node is None or node.type != "field_expression":
        return None
    argument = node.child_by_field_name("argument")
    field = node.child_by_field_name("field")
    if argument is None or field is None:
        return None
    base = _simple_identifier(_text(argument, source))
    if not base:
        return None
    return base, _text(field, source)


def _is_write(node: Node) -> bool:
    current = node
    parent = current.parent
    while parent is not None and parent.type in {
        "parenthesized_expression", "pointer_expression"
    }:
        current, parent = parent, parent.parent
    if parent is None:
        return False
    if parent.type == "assignment_expression":
        return parent.child_by_field_name("left") == current
    return parent.type == "update_expression"


def _inside(node: Node, container: Node) -> bool:
    return (
        container.start_byte <= node.start_byte
        and node.end_byte <= container.end_byte
    )


def _nested_call_negated(body: str, match: re.Match[str]) -> bool:
    prefix = body[:match.start()].rstrip()
    return prefix.endswith("!")


def _call_is_negated(node: Node, source: bytes) -> bool:
    current = node
    parent = current.parent
    while parent is not None and parent.type == "parenthesized_expression":
        current, parent = parent, parent.parent
    return bool(
        parent is not None
        and parent.type == "unary_expression"
        and _text(parent, source).lstrip().startswith("!")
    )


def _simple_identifier(value: str) -> str:
    stripped = value.strip()
    return stripped if re.fullmatch(r"[A-Za-z_]\w*", stripped) else ""


def _integer(value: str) -> int | None:
    match = _INTEGER.fullmatch(value)
    return int(match.group(1)) if match else None


def _text(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    return source[node.start_byte:node.end_byte].decode(errors="replace")


def _walk(root: Node):
    for child in root.children:
        yield child
        yield from _walk(child)
