"""Conservative, source-derived C constraint facts for context hydration."""
from __future__ import annotations

import hashlib
import re

from .models import ConstraintFact, ConstraintKind

CONSTRAINT_POLICY = "c-constraint-v1"

_BOUND_NAMES = r"(?:SIZE_MAX|INT_MAX|UINT_MAX|LONG_MAX|ULONG_MAX|LLONG_MAX|ULLONG_MAX)"
_SUBJECT = r"[A-Za-z_][A-Za-z0-9_]*(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)*"
_FORWARD_BOUND = re.compile(
    rf"(?P<subject>{_SUBJECT})\s*(?P<operator>>=|<=|>|<)\s*"
    rf"(?:\([^)]*\)\s*)?(?P<bound>{_BOUND_NAMES}(?:\s*[-/]\s*[^;&|,)]+)?)"
)
_REVERSE_BOUND = re.compile(
    rf"(?P<bound>{_BOUND_NAMES}(?:\s*[-/]\s*[^;&|,)]+)?)\s*"
    rf"(?P<operator>>=|<=|>|<)\s*(?P<subject>{_SUBJECT})"
)
_POINTER_LOOP = re.compile(
    r"for\s*\([^;]{0,200}?\b(?P<pointer>[A-Za-z_]\w*)\s*\+=\s*"
    r"(?P<step>[^;]{1,80});[^;]{0,200};[^)]{0,200}?\b(?P=pointer)\s*\+=\s*"
    r"(?P=step)\)",
    re.DOTALL,
)
_COUNTER_INCREMENT = re.compile(r"\b(?P<counter>[A-Za-z_]\w*)\s*(?:\+\+|\+=\s*1)\b")
_REJECT = re.compile(r"\b(?:return|goto|break)\b")


def extract_constraint_facts(
    *,
    path: str,
    node_id: str,
    source: str,
    start_line: int,
) -> tuple[ConstraintFact, ...]:
    """Extract only explicit bounds and progress relationships from a function."""
    lines = source.splitlines()
    facts: list[ConstraintFact] = []
    for offset, line in enumerate(lines):
        if "if" not in line or "MAX" not in line:
            continue
        match = _FORWARD_BOUND.search(line) or _REVERSE_BOUND.search(line)
        if match is None:
            continue
        expression = _compact(line)
        rejection_window = " ".join(lines[offset : offset + 4])
        if _REJECT.search(rejection_window) is None:
            continue
        operator = match.group("operator")
        if match.re is _REVERSE_BOUND:
            operator = _reverse(operator)
        safe_relation = {
            ">": "<=",
            ">=": "<",
            "<": ">=",
            "<=": ">",
        }[operator]
        subject = match.group("subject")
        bound = _compact(match.group("bound"))
        kind = (
            ConstraintKind.BUFFER_SIZE_BOUND
            if re.search(r"size|len|limit|capacity|buffer|alloc|atts|count", subject, re.I)
            else ConstraintKind.NUMERIC_BOUND
        )
        line_number = start_line + offset
        facts.append(_fact(
            kind=kind,
            node_id=node_id,
            path=path,
            line=line_number,
            end_line=min(start_line + len(lines) - 1, line_number + 3),
            subject=subject,
            relation=safe_relation,
            bound=bound,
            expression=expression,
            evidence="rejecting guard establishes the bound on the continuing path",
            confidence="high",
        ))

    loop = _POINTER_LOOP.search(source)
    if loop is not None:
        increments = list(_COUNTER_INCREMENT.finditer(source[loop.end() :]))
        if increments:
            increment = increments[0]
            counter = increment.group("counter")
            line_number = start_line + source[: loop.start()].count("\n")
            facts.append(_fact(
                kind=ConstraintKind.MINIMUM_CONSUMPTION,
                node_id=node_id,
                path=path,
                line=line_number,
                end_line=start_line + source[: loop.end()].count("\n"),
                subject=counter,
                relation="<=",
                bound=f"input_span / ({_compact(loop.group('step'))})",
                expression=_compact(loop.group(0)),
                evidence=(
                    f"{counter} advances only inside a loop whose input pointer "
                    f"advances by {_compact(loop.group('step'))}"
                ),
                confidence="medium",
            ))

    return tuple(sorted(
        {item.fact_id: item for item in facts}.values(),
        key=lambda item: item.fact_id,
    ))


def _fact(
    *,
    kind: ConstraintKind,
    node_id: str,
    path: str,
    line: int,
    end_line: int,
    subject: str,
    relation: str,
    bound: str,
    expression: str,
    evidence: str,
    confidence: str,
) -> ConstraintFact:
    identity = "\0".join((
        CONSTRAINT_POLICY,
        kind.value,
        node_id,
        str(line),
        subject,
        relation,
        bound,
        expression,
    ))
    return ConstraintFact(
        fact_id="constraint_" + hashlib.sha256(identity.encode()).hexdigest()[:20],
        policy_version=CONSTRAINT_POLICY,
        kind=kind,
        node_id=node_id,
        path=path,
        line=line,
        end_line=max(line, end_line),
        subject=subject,
        relation=relation,
        bound=bound,
        expression=expression,
        evidence=evidence,
        confidence=confidence,
    )


def _reverse(operator: str) -> str:
    return {">": "<", ">=": "<=", "<": ">", "<=": ">="}[operator]


def _compact(value: str) -> str:
    return " ".join(value.strip().split())[:500]
