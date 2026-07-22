"""Conservative, source-cited feasibility checks for native candidates."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from ..domain.schemas import (
    CandidateFinding,
    CheckedArithmetic,
    FeasibilityAssessment,
    FeasibilityBound,
    FeasibilityBoundKind,
    FeasibilityStatus,
    ImmutableSourceRange,
)

FEASIBILITY_POLICY = "native-feasibility-v1"
EXTREME_TRIGGER_COUNT = 1 << 30

_DECLARATION = re.compile(
    r"\b(?P<type>int8_t|int16_t|int32_t|signed\s+char|signed\s+short|"
    r"short\s+int|short|signed\s+int|int)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:=\s*[^;]+)?;"
)
_POINTER_LOOP = re.compile(
    r"for\s*\(\s*(?P<pointer>[A-Za-z_]\w*)\s*\+=\s*"
    r"(?P<step>.+?)\s*;\s*;\s*(?P=pointer)\s*\+=\s*(?P=step)\s*\)",
    re.DOTALL,
)
_WHOLE_INPUT = re.compile(
    r"(?:token|input).{0,60}\bwhole\b|"
    r"\bwhole\b.{0,60}(?:token|input|tag)",
    re.IGNORECASE,
)
_TYPE_MAX = {
    "int8_t": 127,
    "signed char": 127,
    "int16_t": 32_767,
    "signed short": 32_767,
    "short int": 32_767,
    "short": 32_767,
    "int32_t": 2_147_483_647,
    "signed int": 2_147_483_647,
    "int": 2_147_483_647,
}


@dataclass(frozen=True)
class _CounterClaim:
    name: str
    type_name: str
    type_max: int
    declaration: ImmutableSourceRange
    increments: tuple[ImmutableSourceRange, ...]
    minimum_step: int
    progress: ImmutableSourceRange


def assess_native_feasibility(
    candidate: CandidateFinding,
    *,
    source_root: Path | None,
    source_snapshot: str,
    analysis: dict | None,
) -> FeasibilityAssessment:
    """Prove only contradictions supported by immutable source ranges.

    The checker intentionally recognizes a narrow, reusable shape: a bounded
    signed counter incremented at most once per advancing input-loop iteration,
    plus a related whole-input buffer whose checked size cannot exceed INT_MAX.
    Anything outside that shape remains feasible/extreme/unknown instead of
    being guessed false.
    """
    if source_root is None or not source_root.is_dir():
        return _unknown(candidate, source_snapshot, "source tree is unavailable")
    graph = (analysis or {}).get("graph") or {}
    target = _target_node(candidate, graph)
    if target is None:
        return _unknown(
            candidate,
            source_snapshot,
            "candidate location does not resolve to a C analysis node",
        )
    target_path = source_root / str(target["path"])
    if not target_path.is_file():
        return _unknown(candidate, source_snapshot, "candidate source file is missing")
    claim = _counter_claim(
        candidate,
        target,
        target_path,
        relative_path=str(target["path"]),
        source_snapshot=source_snapshot,
    )
    if claim is None:
        return _unknown(
            candidate,
            source_snapshot,
            "no source-backed bounded counter and input-progress relation was found",
        )

    required_count = claim.type_max + 1
    required_bytes = required_count * claim.minimum_step
    type_bound = _bound(
        kind=FeasibilityBoundKind.TYPE_LIMIT,
        subject=claim.name,
        relation="<=",
        value=claim.type_max,
        unit="items",
        expression=f"maximum value of source type {claim.type_name}",
        sources=(claim.declaration,),
    )
    trigger_bound = _bound(
        kind=FeasibilityBoundKind.TRIGGER_MINIMUM,
        subject=f"iterations required to overflow {claim.name}",
        relation=">=",
        value=required_count,
        unit="iterations",
        expression=f"{claim.type_max} + 1",
        sources=(claim.declaration, *claim.increments),
    )
    input_bound = _bound(
        kind=FeasibilityBoundKind.INPUT_MINIMUM,
        subject="attacker-controlled input required by the claimed trigger",
        relation=">=",
        value=required_bytes,
        unit="bytes",
        expression=f"{required_count} * {claim.minimum_step}",
        sources=(claim.progress, *claim.increments),
    )
    bounds = [type_bound, trigger_bound, input_bound]
    arithmetic = [
        CheckedArithmetic(
            operation="add",
            operands=(claim.type_max, 1),
            result=required_count,
            expression=f"{claim.type_max} + 1 = {required_count}",
            bound_ids=(type_bound.bound_id, trigger_bound.bound_id),
        ),
        CheckedArithmetic(
            operation="multiply",
            operands=(required_count, claim.minimum_step),
            result=required_bytes,
            expression=(
                f"{required_count} * {claim.minimum_step} = {required_bytes}"
            ),
            bound_ids=(trigger_bound.bound_id, input_bound.bound_id),
        ),
    ]

    maximum = _related_buffer_maximum(
        candidate,
        graph,
        target,
        source_root,
        source_snapshot=source_snapshot,
    )
    if maximum is not None:
        maximum_value, maximum_sources = maximum
        maximum_bound = _bound(
            kind=FeasibilityBoundKind.REACHABLE_MAXIMUM,
            subject="complete input object reachable by the public buffer path",
            relation="<=",
            value=maximum_value,
            unit="bytes",
            expression=f"checked signed buffer size <= {maximum_value}",
            sources=maximum_sources,
        )
        bounds.append(maximum_bound)
        contradiction = int(required_bytes > maximum_value)
        arithmetic.append(CheckedArithmetic(
            operation="compare_gt",
            operands=(required_bytes, maximum_value),
            result=contradiction,
            expression=f"{required_bytes} > {maximum_value} is {bool(contradiction)}",
            bound_ids=(input_bound.bound_id, maximum_bound.bound_id),
        ))
        if contradiction:
            return FeasibilityAssessment(
                policy_version=FEASIBILITY_POLICY,
                candidate_id=candidate.candidate_id,
                source_snapshot=source_snapshot,
                status=FeasibilityStatus.LOGICALLY_INFEASIBLE,
                bounds=tuple(bounds),
                arithmetic=tuple(arithmetic),
                rationale=(
                    "The claimed counter crossing requires more input bytes than "
                    "the related whole-input buffer can represent.",
                    "This is a source-backed logical contradiction, not a host-memory estimate.",
                ),
                confidence_adjustment=-1.0,
            )
        return FeasibilityAssessment(
            policy_version=FEASIBILITY_POLICY,
            candidate_id=candidate.candidate_id,
            source_snapshot=source_snapshot,
            status=FeasibilityStatus.FEASIBLE,
            bounds=tuple(bounds),
            arithmetic=tuple(arithmetic),
            rationale=(
                "The checked public-path maximum does not contradict the minimum trigger.",
                "Feasible means not statically refuted; reproduction is still required.",
            ),
        )

    status = (
        FeasibilityStatus.ENVIRONMENTALLY_EXTREME
        if required_count >= EXTREME_TRIGGER_COUNT
        else FeasibilityStatus.UNKNOWN
    )
    return FeasibilityAssessment(
        policy_version=FEASIBILITY_POLICY,
        candidate_id=candidate.candidate_id,
        source_snapshot=source_snapshot,
        status=status,
        bounds=tuple(bounds),
        arithmetic=tuple(arithmetic),
        rationale=(
            "The trigger is expensive, but no source-backed reachable maximum "
            "contradicts it. It must not be auto-refuted.",
        ),
        confidence_adjustment=-0.35 if status is FeasibilityStatus.ENVIRONMENTALLY_EXTREME else 0.0,
    )


def _target_node(candidate: CandidateFinding, graph: dict) -> dict | None:
    locations = (candidate.sink, candidate.entrypoint)
    for location in locations:
        if location is None:
            continue
        matches = [
            item for item in graph.get("nodes", [])
            if item.get("path") == location.path
            and int(item.get("line", 0)) <= location.line
            and int(item.get("end_line", 0)) >= location.line
        ]
        if matches:
            return min(
                matches,
                key=lambda item: int(item["end_line"]) - int(item["line"]),
            )
    return None


def _counter_claim(
    candidate: CandidateFinding,
    node: dict,
    path: Path,
    *,
    relative_path: str,
    source_snapshot: str,
) -> _CounterClaim | None:
    all_lines = path.read_text(errors="replace").splitlines()
    start = int(node["line"])
    end = min(int(node["end_line"]), len(all_lines))
    source = "\n".join(all_lines[start - 1 : end])
    claim_text = " ".join((
        candidate.title,
        candidate.attacker_capability,
        *candidate.impact,
    ))
    choices: list[tuple[int, re.Match[str], list[re.Match[str]]]] = []
    for declaration in _DECLARATION.finditer(source):
        type_name = " ".join(declaration.group("type").split())
        if type_name not in _TYPE_MAX:
            continue
        name = declaration.group("name")
        increments = list(re.finditer(
            rf"\b{re.escape(name)}\s*(?:\+\+|\+=\s*1)",
            source,
        ))
        if not increments:
            continue
        score = 0
        if re.search(rf"\b{re.escape(name)}\b", claim_text):
            score += 4
        if re.search(rf"\[\s*{re.escape(name)}\s*\]", source):
            score += 2
        choices.append((score, declaration, increments))
    if not choices:
        return None
    _, declaration, increments = max(
        choices,
        key=lambda item: (item[0], -item[1].start()),
    )
    name = declaration.group("name")
    loop = next(
        (
            item for item in _POINTER_LOOP.finditer(source)
            if item.start() < increments[0].start()
        ),
        None,
    )
    if loop is None:
        return None
    if len(increments) > 1 and not _mutually_exclusive_case_increments(
        source,
        loop,
        increments,
    ):
        return None
    minimum_step = _minimum_positive_step(loop.group("step"))
    if minimum_step is None:
        return None
    type_name = " ".join(declaration.group("type").split())
    return _CounterClaim(
        name=name,
        type_name=type_name,
        type_max=_TYPE_MAX[type_name],
        declaration=_range_for_match(
            path,
            all_lines,
            start,
            source,
            declaration,
            source_snapshot,
            relative_path,
        ),
        increments=tuple(
            _range_for_match(
                path,
                all_lines,
                start,
                source,
                increment,
                source_snapshot,
                relative_path,
            )
            for increment in increments
        ),
        minimum_step=minimum_step,
        progress=_range_for_match(
            path,
            all_lines,
            start,
            source,
            loop,
            source_snapshot,
            relative_path,
        ),
    )


def _mutually_exclusive_case_increments(
    source: str,
    loop: re.Match[str],
    increments: list[re.Match[str]],
) -> bool:
    case_positions = [
        match.start()
        for match in re.finditer(r"(?m)^\s*(?:case\s+[^:]+|default)\s*:", source)
        if match.start() > loop.end()
    ]
    owners: list[int] = []
    for increment in increments:
        prior = [position for position in case_positions if position < increment.start()]
        if not prior:
            return False
        owner = prior[-1]
        next_case = next(
            (position for position in case_positions if position > increment.end()),
            len(source),
        )
        if re.search(r"\bbreak\s*;", source[increment.end() : next_case]) is None:
            return False
        owners.append(owner)
    return len(set(owners)) == len(increments)


def _minimum_positive_step(expression: str) -> int | None:
    compact = " ".join(expression.split())
    if re.fullmatch(r"[1-9][0-9]*", compact):
        return int(compact)
    if "sizeof" in compact:
        return 1
    if re.search(r"(?:min.*byte|byte.*width|char.*width|MINBPC)", compact, re.I):
        return 1
    return None


def _related_buffer_maximum(
    candidate: CandidateFinding,
    graph: dict,
    target: dict,
    source_root: Path,
    *,
    source_snapshot: str,
) -> tuple[int, tuple[ImmutableSourceRange, ...]] | None:
    del candidate
    nodes = {item["node_id"]: item for item in graph.get("nodes", [])}
    aliases = {
        str(value)
        for value in (target.get("symbol"), *target.get("aliases", ()))
        if value
    }
    related_paths = {str(target["path"])}
    for edge in graph.get("edges", []):
        if str(edge.get("target", "")) == str(target["node_id"]):
            caller = nodes.get(str(edge.get("source", "")))
            if caller is not None:
                related_paths.add(str(caller["path"]))
    for call in graph.get("unresolved_calls", []):
        if str(call.get("callee", "")) in aliases:
            caller = nodes.get(str(call.get("source", "")))
            if caller is not None:
                related_paths.add(str(caller["path"]))

    facts = [
        item for item in graph.get("constraint_facts", [])
        if str(item.get("path", "")) in related_paths
        and re.search(
            r"\bINT_MAX\b\s*-\s*[A-Za-z_]\w*",
            str(item.get("bound", "")),
        )
    ]
    if not facts:
        return None
    for fact in sorted(facts, key=lambda item: str(item.get("fact_id", ""))):
        source_path = source_root / str(fact["path"])
        if not source_path.is_file():
            continue
        lines = source_path.read_text(errors="replace").splitlines()
        marker = _find_whole_input_marker(lines)
        if marker is None:
            continue
        fact_range = _source_range(
            source_path,
            lines,
            max(1, int(fact["line"]) - 40),
            int(fact.get("end_line", fact["line"])),
            source_snapshot,
            str(fact["path"]),
        )
        marker_range = _source_range(
            source_path,
            lines,
            marker[0],
            marker[1],
            source_snapshot,
            str(fact["path"]),
        )
        return 2_147_483_647, (fact_range, marker_range)
    return None


def _find_whole_input_marker(lines: list[str]) -> tuple[int, int] | None:
    for index in range(len(lines)):
        window = " ".join(lines[index : index + 3])
        if _WHOLE_INPUT.search(window):
            return index + 1, min(len(lines), index + 3)
    return None


def _range_for_match(
    path: Path,
    lines: list[str],
    source_start: int,
    source: str,
    match: re.Match[str],
    snapshot: str,
    relative_path: str,
) -> ImmutableSourceRange:
    line = source_start + source[: match.start()].count("\n")
    end_line = line + match.group(0).count("\n")
    return _source_range(path, lines, line, end_line, snapshot, relative_path)


def _source_range(
    path: Path,
    lines: list[str],
    line: int,
    end_line: int,
    snapshot: str,
    relative_path: str,
) -> ImmutableSourceRange:
    line = max(1, min(line, len(lines)))
    end_line = max(line, min(end_line, len(lines)))
    excerpt = "\n".join(lines[line - 1 : end_line]).strip()
    digest = hashlib.sha256(excerpt.encode()).hexdigest()
    return ImmutableSourceRange(
        source_snapshot=snapshot,
        path=relative_path,
        line=line,
        end_line=end_line,
        content_sha256=f"sha256:{digest}",
        excerpt=excerpt,
    )


def _bound(
    *,
    kind: FeasibilityBoundKind,
    subject: str,
    relation: str,
    value: int,
    unit: str,
    expression: str,
    sources: tuple[ImmutableSourceRange, ...],
) -> FeasibilityBound:
    payload = {
        "policy": FEASIBILITY_POLICY,
        "kind": kind.value,
        "subject": subject,
        "relation": relation,
        "value": value,
        "unit": unit,
        "expression": expression,
        "sources": [item.model_dump(mode="json") for item in sources],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return FeasibilityBound(
        bound_id="bound_" + hashlib.sha256(canonical.encode()).hexdigest()[:20],
        kind=kind,
        subject=subject,
        relation=relation,
        value=value,
        unit=unit,
        expression=expression,
        sources=sources,
    )


def _unknown(
    candidate: CandidateFinding,
    source_snapshot: str,
    reason: str,
) -> FeasibilityAssessment:
    return FeasibilityAssessment(
        policy_version=FEASIBILITY_POLICY,
        candidate_id=candidate.candidate_id,
        source_snapshot=source_snapshot,
        status=FeasibilityStatus.UNKNOWN,
        rationale=(reason,),
    )
