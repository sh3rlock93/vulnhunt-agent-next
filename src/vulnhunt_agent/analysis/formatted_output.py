"""Structural formatted-output capacity facts for C code."""
from __future__ import annotations

import hashlib
import re

from tree_sitter import Node

from .models import (
    FormattedDestinationKind,
    FormattedExpansionClass,
    FormattedOutputFact,
    GuardState,
)

FORMATTED_OUTPUT_POLICY = "c-formatted-output-v1"

_FORMATTERS = {
    "sprintf": (False, 0, None, 1),
    "vsprintf": (False, 0, None, 1),
    "snprintf": (True, 0, 1, 2),
    "vsnprintf": (True, 0, 1, 2),
}
_ARRAY_DECLARATION = re.compile(
    r"\b(?:char|signed\s+char|unsigned\s+char)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*([1-9][0-9]*)\s*\]"
)
_DIRECTIVE = re.compile(
    r"%(?:[1-9][0-9]*\$)?[-+ #0']*(?:\*|[0-9]+)?"
    r"(?:\.(?:\*|[0-9]+))?(?:hh|h|ll|l|j|z|t|L)?([diouxXfFeEgGaAcspn%])"
)


def extract_formatted_output_facts(
    *,
    path: str,
    node_id: str,
    function: str,
    source: bytes,
    function_node: Node,
    body_nodes: tuple[Node, ...],
) -> tuple[FormattedOutputFact, ...]:
    function_text = _text(function_node, source)
    function_start_line = function_node.start_point[0] + 1
    arrays = _fixed_arrays(function_text, function_start_line)
    facts = []
    seen: set[tuple[int, int]] = set()
    for root in body_nodes:
        for node in (root, *_walk(root)):
            if node.type != "call_expression":
                continue
            key = (node.start_byte, node.end_byte)
            if key in seen:
                continue
            seen.add(key)
            callee = _call_name(node, source)
            spec = _FORMATTERS.get(callee)
            if spec is None:
                continue
            fact = _format_fact(
                path=path,
                node_id=node_id,
                function=function,
                source=source,
                function_text=function_text,
                function_start_byte=function_node.start_byte,
                call=node,
                formatter=callee,
                formatter_spec=spec,
                arrays=arrays,
            )
            if fact is not None:
                facts.append(fact)
    return tuple(sorted(facts, key=lambda item: item.fact_id))


def _format_fact(
    *,
    path: str,
    node_id: str,
    function: str,
    source: bytes,
    function_text: str,
    function_start_byte: int,
    call: Node,
    formatter: str,
    formatter_spec: tuple[bool, int, int | None, int],
    arrays: dict[str, tuple[int, int]],
) -> FormattedOutputFact | None:
    arguments_node = call.child_by_field_name("arguments")
    if arguments_node is None:
        return None
    arguments = list(arguments_node.named_children)
    bounded, destination_index, size_index, format_index = formatter_spec
    if max(destination_index, format_index, size_index or 0) >= len(arguments):
        return None
    destination = _text(arguments[destination_index], source).strip()
    destination_base = _base_identifier(destination)
    array = arrays.get(destination_base)
    destination_kind = (
        FormattedDestinationKind.FIXED_ARRAY
        if array is not None
        else FormattedDestinationKind.CALLER_BUFFER
        if destination_base
        else FormattedDestinationKind.UNKNOWN
    )
    capacity_bytes = array[0] if array else None
    declaration_line = array[1] if array else None
    size_expression = (
        _text(arguments[size_index], source).strip()
        if size_index is not None else ""
    )
    bound_matches = (
        bounded
        and capacity_bytes is not None
        and _bound_matches(size_expression, destination_base, capacity_bytes)
    )
    format_text = _text(arguments[format_index], source)
    format_literal = _literal_content(format_text)
    format_is_literal = format_literal is not None
    classes, dynamic, maximum, locale_sensitive = _format_shape(format_literal)
    expansion_class = _expansion_class(format_is_literal, classes, dynamic)
    result_subject = _result_subject(call, source)
    return_checked = _return_is_checked(
        function_text=function_text,
        call_offset=max(0, call.end_byte - function_start_byte),
        result_subject=result_subject,
        destination=destination_base,
    )
    guard_state = _guard_state(
        bounded=bounded,
        bound_matches=bound_matches,
        capacity_bytes=capacity_bytes,
        maximum_output_chars=maximum,
        expansion_class=expansion_class,
    )
    line = call.start_point[0] + 1
    identity = "\0".join((
        FORMATTED_OUTPUT_POLICY,
        path,
        node_id,
        str(line),
        destination,
        formatter,
        size_expression,
        ",".join(classes),
        str(dynamic),
        str(locale_sensitive),
        expansion_class.value,
        str(maximum),
    ))
    evidence = (
        f"destination_kind={destination_kind.value}; capacity={capacity_bytes}; "
        f"bounded_api={str(bounded).lower()}; bound_matches={str(bound_matches).lower()}; "
        f"expansion={expansion_class.value}; conversions={','.join(classes) or 'none'}; "
        f"maximum_output_chars={maximum}; locale_sensitive="
        f"{str(locale_sensitive).lower()}; terminator_bytes=1; "
        f"return_checked={str(return_checked).lower()}"
    )
    return FormattedOutputFact(
        fact_id="format_fact_" + hashlib.sha256(identity.encode()).hexdigest()[:20],
        node_id=node_id,
        path=path,
        function=function,
        line=line,
        declaration_line=declaration_line,
        destination=destination or "<unknown>",
        destination_kind=destination_kind,
        capacity_expression=size_expression,
        capacity_bytes=capacity_bytes,
        bounded_api=bounded,
        bound_matches_destination=bound_matches,
        format_is_literal=format_is_literal,
        conversion_classes=classes,
        dynamic_width_or_precision=dynamic,
        locale_sensitive=locale_sensitive,
        expansion_class=expansion_class,
        maximum_output_chars=maximum,
        return_checked=return_checked,
        guard_state=guard_state,
        evidence=evidence,
        confidence="high" if array is not None and format_is_literal else "medium",
    )


def _fixed_arrays(text: str, start_line: int) -> dict[str, tuple[int, int]]:
    return {
        match.group(1): (
            int(match.group(2)),
            start_line + text[:match.start()].count("\n"),
        )
        for match in _ARRAY_DECLARATION.finditer(text)
    }


def _format_shape(
    literal: str | None,
) -> tuple[tuple[str, ...], bool, int | None, bool]:
    if literal is None:
        return ("dynamic_format",), True, None, False
    classes = []
    dynamic = False
    locale_sensitive = False
    maximum: int | None = len(_DIRECTIVE.sub("", literal))
    for match in _DIRECTIVE.finditer(literal):
        directive = match.group(0)
        conversion = match.group(1)
        if conversion == "%":
            if maximum is not None:
                maximum += 1
            continue
        dynamic = dynamic or "*" in directive
        locale_sensitive = locale_sensitive or "'" in directive
        conversion_class, bound = _conversion_bound(
            conversion,
            long_double="L" in directive,
            precision=_precision(directive),
            alternate_form="#" in directive,
            locale_sensitive="'" in directive,
        )
        classes.append(conversion_class)
        if bound is None or dynamic:
            maximum = None
        elif maximum is not None:
            width = _minimum_width(directive)
            maximum += max(bound, width)
    return tuple(classes), dynamic, maximum, locale_sensitive


def _conversion_bound(
    conversion: str,
    *,
    long_double: bool,
    precision: int | None,
    alternate_form: bool,
    locale_sensitive: bool,
) -> tuple[str, int | None]:
    if conversion in "fF":
        integral_digits = 5_000 if long_double else 309
        fractional_digits = 6 if precision is None else precision
        decimal_point = int(fractional_digits > 0 or alternate_form)
        grouping = integral_digits - 1 if locale_sensitive else 0
        return (
            "floating_fixed",
            1 + integral_digits + grouping + decimal_point + fractional_digits,
        )
    if conversion in "eE":
        fractional_digits = 6 if precision is None else precision
        decimal_point = int(fractional_digits > 0 or alternate_form)
        return "floating_scientific", 1 + 1 + decimal_point + fractional_digits + 8
    if conversion in "gG":
        significant_digits = 6 if precision is None else max(1, precision)
        integral_digits = 5_000 if long_double else 309
        grouping = integral_digits - 1 if locale_sensitive else 0
        fixed = 1 + integral_digits + grouping + significant_digits + 1
        scientific = 1 + significant_digits + 9
        return "floating_general", max(fixed, scientific)
    if conversion in "aA":
        fractional_digits = (32 if long_double else 13) if precision is None else precision
        return "floating_hex", 1 + 2 + 1 + 1 + fractional_digits + 8
    if conversion in "di":
        return "signed_integer", 64
    if conversion in "ouxX":
        return "unsigned_integer", 64
    if conversion == "s":
        return "string", precision
    if conversion == "c":
        return "character", 1
    if conversion == "p":
        return "pointer", 32
    if conversion == "n":
        return "write_count", 0
    return "other", None


def _precision(directive: str) -> int | None:
    match = re.search(r"\.([0-9]+)", directive)
    return int(match.group(1)) if match else None


def _expansion_class(
    literal: bool,
    classes: tuple[str, ...],
    dynamic: bool,
) -> FormattedExpansionClass:
    if not literal:
        return FormattedExpansionClass.DYNAMIC_FORMAT
    if dynamic or "string" in classes:
        return FormattedExpansionClass.INPUT_DEPENDENT
    if classes:
        return FormattedExpansionClass.TYPE_DEPENDENT
    return FormattedExpansionClass.FIXED_LITERAL


def _guard_state(
    *,
    bounded: bool,
    bound_matches: bool,
    capacity_bytes: int | None,
    maximum_output_chars: int | None,
    expansion_class: FormattedExpansionClass,
) -> GuardState:
    if bounded and bound_matches:
        return GuardState.DOMINATES
    if bounded:
        return GuardState.UNKNOWN
    if (
        capacity_bytes is not None
        and maximum_output_chars is not None
        and maximum_output_chars + 1 <= capacity_bytes
    ):
        return GuardState.DOMINATES
    if capacity_bytes is not None and expansion_class is not FormattedExpansionClass.FIXED_LITERAL:
        return GuardState.ABSENT
    return GuardState.UNKNOWN


def _bound_matches(expression: str, destination: str, capacity: int) -> bool:
    compact = re.sub(r"\s+", "", expression)
    if compact in {f"sizeof({destination})", f"sizeof{destination}"}:
        return True
    return compact.isdigit() and int(compact) <= capacity


def _return_is_checked(
    *,
    function_text: str,
    call_offset: int,
    result_subject: str,
    destination: str,
) -> bool:
    if not result_subject:
        return False
    suffix = function_text[call_offset:]
    result = re.escape(result_subject)
    destination_pattern = re.escape(destination)
    return bool(re.search(
        rf"\bif\s*\([^)]*\b{result}\b[^)]*"
        rf"(?:<\s*0|>=\s*sizeof\s*\(\s*{destination_pattern}\s*\))",
        suffix,
        re.DOTALL,
    ))


def _minimum_width(directive: str) -> int:
    match = re.match(r"%(?:[1-9][0-9]*\$)?[-+ #0']*([0-9]+)", directive)
    return int(match.group(1)) if match else 0


def _literal_content(text: str) -> str | None:
    pieces = re.findall(r'"((?:\\.|[^"\\])*)"', text)
    if not pieces:
        return None
    remainder = re.sub(r'"(?:\\.|[^"\\])*"', "", text)
    if remainder.strip():
        return None
    return "".join(pieces)


def _base_identifier(expression: str) -> str:
    identifiers = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expression)
    return identifiers[-1] if identifiers else ""


def _result_subject(call: Node, source: bytes) -> str:
    parent = call.parent
    while parent is not None and parent.type in {
        "parenthesized_expression", "cast_expression", "conditional_expression"
    }:
        parent = parent.parent
    if parent is None or parent.type not in {"assignment_expression", "init_declarator"}:
        return ""
    left = (
        parent.child_by_field_name("left")
        if parent.type == "assignment_expression"
        else parent.child_by_field_name("declarator")
    )
    if left is None:
        return ""
    identifiers = [
        _text(item, source) for item in (left, *_walk(left))
        if item.type == "identifier"
    ]
    return identifiers[-1] if identifiers else ""


def _call_name(call: Node, source: bytes) -> str:
    function = call.child_by_field_name("function")
    return _text(function, source) if function is not None else ""


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode(errors="replace")


def _walk(node: Node):
    for child in node.children:
        yield child
        yield from _walk(child)
