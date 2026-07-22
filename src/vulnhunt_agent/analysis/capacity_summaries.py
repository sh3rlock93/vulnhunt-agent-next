"""Bounded direct-call propagation for C capacity summaries."""
from __future__ import annotations

import re

from .models import (
    CapacityCallSite,
    CapacityReturnKind,
    FunctionCapacitySummary,
)

CAPACITY_SUMMARY_POLICY = "c-capacity-summary-v2"
MAX_CAPACITY_CALL_DEPTH = 5


def propagate_capacity_summaries(
    summaries: tuple[FunctionCapacitySummary, ...],
    calls: tuple[CapacityCallSite, ...],
) -> tuple[FunctionCapacitySummary, ...]:
    """Propagate writes and return extents through resolved direct calls only."""
    by_node = {summary.node_id: summary for summary in summaries}
    ordered_calls = sorted(calls, key=lambda item: item.call_id)
    for _ in range(MAX_CAPACITY_CALL_DEPTH):
        changed = False
        for call in ordered_calls:
            if not call.direct or not call.target_node_id:
                continue
            caller = by_node.get(call.caller_id)
            callee = by_node.get(call.target_node_id)
            if caller is None or callee is None:
                continue
            next_depth = callee.propagation_depth + 1
            if next_depth > MAX_CAPACITY_CALL_DEPTH:
                continue
            bindings = dict(zip(callee.parameters, call.arguments, strict=False))
            caller_pointer_set = set(caller.pointer_parameters)
            written = set(caller.written_parameters)
            pass_through = set(caller.pass_through_parameters)
            extents = {
                parameter: set(values)
                for parameter, values in caller.write_extents.items()
            }
            propagated = set(caller.propagated_call_ids)
            for parameter in callee.written_parameters:
                actual = bindings.get(parameter, "")
                caller_parameter = _resolve_pointer_alias(
                    _argument_root(actual),
                    caller.pointer_aliases,
                )
                if caller_parameter not in caller_pointer_set:
                    continue
                written.add(caller_parameter)
                for extent in callee.write_extents.get(parameter, ("1",)):
                    extents.setdefault(caller_parameter, set()).add(
                        _substitute(extent, bindings)
                    )
                propagated.add(call.call_id)

            return_kind = caller.return_kind
            returned_call = any(
                (
                    call.result_subject
                    and expression == call.result_subject
                )
                or re.search(rf"\b{re.escape(call.callee)}\s*\(", expression)
                for expression in caller.return_expressions
            )
            if returned_call and callee.return_kind in {
                CapacityReturnKind.CONSUMED_OR_REQUIRED,
                CapacityReturnKind.PASS_THROUGH,
            }:
                return_kind = callee.return_kind
                propagated.add(call.call_id)
                if callee.return_kind is CapacityReturnKind.PASS_THROUGH:
                    for parameter in callee.pass_through_parameters:
                        caller_parameter = _argument_root(bindings.get(parameter, ""))
                        caller_parameter = _resolve_pointer_alias(
                            caller_parameter,
                            caller.pointer_aliases,
                        )
                        if caller_parameter in caller_pointer_set:
                            pass_through.add(caller_parameter)

            if propagated == set(caller.propagated_call_ids):
                continue

            update = caller.model_copy(update={
                "written_parameters": tuple(sorted(written)),
                "write_extents": {
                    parameter: tuple(sorted(values))
                    for parameter, values in sorted(extents.items())
                },
                "return_kind": return_kind,
                "pass_through_parameters": tuple(sorted(pass_through)),
                "propagated_call_ids": tuple(sorted(propagated)),
                "propagation_depth": max(caller.propagation_depth, next_depth),
            })
            if update != caller:
                by_node[caller.node_id] = update
                changed = True
        if not changed:
            break
    return tuple(sorted(by_node.values(), key=lambda item: item.summary_id))


def _argument_root(argument: str) -> str:
    value = re.sub(r"^(?:\([^()]*(?:\*|_t)\)\s*)+", "", argument).strip()
    match = re.match(r"(?:&\s*)?([A-Za-z_]\w*)", value)
    return match.group(1) if match is not None else ""


def _substitute(expression: str, bindings: dict[str, str]) -> str:
    result = expression
    for parameter, actual in sorted(bindings.items(), key=lambda item: -len(item[0])):
        result = re.sub(rf"\b{re.escape(parameter)}\b", f"({actual})", result)
    return " ".join(result.split())[:500]


def _resolve_pointer_alias(subject: str, aliases: dict[str, str]) -> str:
    seen = set()
    while subject in aliases and subject not in seen:
        seen.add(subject)
        subject = aliases[subject]
    return subject
