"""Loop-state capacity facts for C output builders."""
from __future__ import annotations

import hashlib
import re

from tree_sitter import Node

from .models import GuardState, OutputComponentKind, StatefulOutputFact

STATEFUL_OUTPUT_POLICY = "c-stateful-output-v1"

_INITIAL_ZERO = re.compile(
    r"\b[A-Za-z_]\w*(?:\s*\*+)?\s+([A-Za-z_]\w*)\s*=\s*0\s*;"
)
_INITIAL_TRUE = re.compile(
    r"\b[A-Za-z_]\w*\s+([A-Za-z_]\w*)\s*=\s*"
    r"(?:1|true|[A-Za-z_]\w*TRUE)\s*;",
    re.IGNORECASE,
)
_CAPACITY_NAME = re.compile(
    r"(?:cap|capacity|remaining|remain|max|limit|available|space|end)",
    re.IGNORECASE,
)
_ESCAPE_CALL = re.compile(
    r"\b[A-Za-z_0-9]*(?:escape|encode|quote)[A-Za-z_0-9]*\s*(?:\)\s*)?\(",
    re.I,
)


def extract_stateful_output_facts(
    *,
    path: str,
    node_id: str,
    function: str,
    source: bytes,
    function_node: Node,
    body_nodes: tuple[Node, ...],
) -> tuple[StatefulOutputFact, ...]:
    """Find guards whose per-iteration overhead depends on a loop transition."""
    function_text = _text(function_node, source)
    zero_terms = set(_INITIAL_ZERO.findall(function_text))
    true_states = set(_INITIAL_TRUE.findall(function_text))
    candidates: list[tuple[Node, Node, Node, str, str, Node]] = []

    for body in body_nodes:
        for branch in (body, *_walk(body)):
            if branch.type != "if_statement":
                continue
            condition = branch.child_by_field_name("condition")
            consequence = branch.child_by_field_name("consequence")
            alternative = branch.child_by_field_name("alternative")
            if condition is None or consequence is None or alternative is None:
                continue
            condition_text = _text(condition, source)
            state = next(
                (name for name in sorted(true_states) if _has_identifier(condition_text, name)),
                "",
            )
            if not state or not _sets_false(_text(consequence, source), state):
                continue
            loop = _enclosing_loop(branch)
            if loop is None:
                continue
            separator_bytes = _separator_writes(_text(alternative, source))
            if separator_bytes == 0:
                continue
            guard_match = _capacity_guard_before(
                loop=loop,
                branch=branch,
                source=source,
                zero_terms=zero_terms,
            )
            if guard_match is None:
                continue
            guard, overhead, capacity = guard_match
            candidates.append((branch, consequence, alternative, overhead, capacity, guard))

    facts = []
    for ordinal, candidate in enumerate(
        sorted(candidates, key=lambda item: item[0].start_byte),
        start=1,
    ):
        branch, consequence, alternative, overhead, capacity, guard = candidate
        consequence_text = _text(consequence, source)
        alternative_text = _text(alternative, source)
        separator_bytes = _separator_writes(alternative_text)
        guarded_overhead = _assigned_nonnegative(consequence_text, overhead)
        updates = guarded_overhead is not None and guarded_overhead >= separator_bytes
        guarded_subsequent = guarded_overhead if guarded_overhead is not None else 0
        loop = _enclosing_loop(branch)
        assert loop is not None
        loop_text = _text(loop, source)
        prefix = function_text[: max(0, loop.start_byte - function_node.start_byte)]
        terminator_reserve = int(bool(re.search(
            rf"\b{re.escape(capacity)}\b\s*(?:--|-=\s*1)",
            prefix,
        )))
        guard_text = _text(guard.child_by_field_name("condition") or guard, source)
        components = {
            OutputComponentKind.DATA,
            OutputComponentKind.SEPARATOR,
        }
        if _ESCAPE_CALL.search(loop_text):
            components.add(OutputComponentKind.ESCAPE)
        if _separator_writes(loop_text) > separator_bytes:
            components.add(OutputComponentKind.PREFIX)
        if terminator_reserve:
            components.add(OutputComponentKind.TERMINATOR)
        if _pointer_advances(loop_text):
            components.add(OutputComponentKind.POINTER_ADVANCE)
        exact_fit_allowed = ">" in guard_text and ">=" not in guard_text
        suffix = function_text[max(0, loop.end_byte - function_node.start_byte):]
        empty_list_safe = bool(
            terminator_reserve
            and re.search(
                r"\[\s*0\s*\]\s*=\s*[^;]*(?:\\0|\b0\b)[^;]*;",
                suffix,
            )
        )
        guard_state = GuardState.DOMINATES if updates else GuardState.ABSENT
        line = branch.start_point[0] + 1
        guard_line = guard.start_point[0] + 1
        identity = "\0".join((
            STATEFUL_OUTPUT_POLICY,
            path,
            node_id,
            str(line),
            str(ordinal),
            str(separator_bytes),
            str(guarded_subsequent),
            str(terminator_reserve),
            str(exact_fit_allowed),
            str(empty_list_safe),
        ))
        evidence = (
            f"loop transition at line {line}: first_overhead=0; "
            f"subsequent_overhead={separator_bytes}; guard line {guard_line} "
            f"accounts_for={guarded_subsequent}; terminator_reserve={terminator_reserve}; "
            f"transition_updates_guard_term={str(updates).lower()}"
        )
        facts.append(StatefulOutputFact(
            fact_id="output_state_" + hashlib.sha256(identity.encode()).hexdigest()[:20],
            node_id=node_id,
            path=path,
            function=function,
            line=line,
            guard_line=guard_line,
            transition_ordinal=ordinal,
            first_iteration_overhead=0,
            subsequent_iteration_overhead=separator_bytes,
            guarded_subsequent_overhead=guarded_subsequent,
            terminator_reserve=terminator_reserve,
            component_kinds=tuple(sorted(components, key=lambda item: item.value)),
            transition_updates_guard_term=updates,
            exact_fit_allowed=exact_fit_allowed,
            empty_list_terminator_safe=empty_list_safe,
            guard_state=guard_state,
            evidence=evidence,
            confidence="high",
        ))
    return tuple(sorted(facts, key=lambda item: item.fact_id))


def _capacity_guard_before(
    *,
    loop: Node,
    branch: Node,
    source: bytes,
    zero_terms: set[str],
) -> tuple[Node, str, str] | None:
    guards = []
    for node in (loop, *_walk(loop)):
        if node.type != "if_statement" or node.start_byte >= branch.start_byte:
            continue
        condition = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        if condition is None or consequence is None:
            continue
        condition_text = _text(condition, source)
        if not re.search(r"(?:>|>=|<|<=)", condition_text):
            continue
        if "return" not in _text(consequence, source):
            continue
        overhead = next(
            (name for name in sorted(zero_terms) if _has_identifier(condition_text, name)),
            "",
        )
        capacity = next(
            (
                token for token in re.findall(r"\b[A-Za-z_]\w*\b", condition_text)
                if token != overhead and _CAPACITY_NAME.search(token)
            ),
            "",
        )
        if overhead and capacity:
            guards.append((node, overhead, capacity))
    return max(guards, key=lambda item: item[0].start_byte) if guards else None


def _sets_false(text: str, state: str) -> bool:
    return bool(re.search(
        rf"\b{re.escape(state)}\b\s*=\s*(?:0|false|[A-Za-z_]\w*FALSE)\b",
        text,
        re.IGNORECASE,
    ))


def _assigned_nonnegative(text: str, subject: str) -> int | None:
    match = re.search(rf"\b{re.escape(subject)}\b\s*=\s*([0-9]+)\b", text)
    return int(match.group(1)) if match else None


def _separator_writes(text: str) -> int:
    return len(re.findall(r"\[\s*0\s*\]\s*=\s*[^;]+;", text))


def _pointer_advances(text: str) -> bool:
    return bool(re.search(r"\b[A-Za-z_]\w*\s*(?:\+\+|\+=)", text))


def _enclosing_loop(node: Node) -> Node | None:
    current = node.parent
    while current is not None:
        if current.type in {"while_statement", "for_statement", "do_statement"}:
            return current
        current = current.parent
    return None


def _has_identifier(text: str, identifier: str) -> bool:
    return re.search(rf"\b{re.escape(identifier)}\b", text) is not None


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode(errors="replace")


def _walk(node: Node):
    for child in node.children:
        yield child
        yield from _walk(child)
