"""Whole-file signed source-to-allocation-to-write relationships."""
from __future__ import annotations

from collections import defaultdict, deque
import hashlib
from pathlib import Path
import re

from .models import (
    FunctionCapacitySummary,
    GraphNode,
    GuardState,
    SignedAllocationWriteChain,
)
from .risk_chains import is_allocator_name

SIGNED_ALLOCATION_WRITE_POLICY = "c-signed-allocation-write-v1"

_FIELD_DECLARATION = re.compile(
    r"(?m)^\s*(?P<type>(?:(?:const|volatile|signed|unsigned|short|long)\s+)*"
    r"(?:u?int(?:8|16|32|64)_t|int|long|short))\s+"
    r"(?P<declarators>[^;()]+);"
)
_ASSIGNMENT = re.compile(
    r"(?P<lhs>[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)*)\s*=\s*"
    r"(?!=)(?P<rhs>[^;]+);",
    re.DOTALL,
)
_GUARD = re.compile(r"\bif\s*\((?P<condition>.*?)\)", re.DOTALL)
_WRITE = re.compile(
    r"(?:\*\s*(?P<pointer>[A-Za-z_]\w*)(?:\s*\+\+)?|"
    r"(?P<array>[A-Za-z_]\w*)\s*\[[^]]+\])\s*=(?!=)"
)
_LOOP_BOUND = re.compile(
    r"\b(?:while|for)\s*\([^)]*\b(?P<bound>[A-Za-z_]\w*)\s*--",
    re.DOTALL,
)
_IDENTIFIER = re.compile(r"\b[A-Za-z_]\w*\b")
_CHECKED_ARITHMETIC = re.compile(
    r"__builtin_(?:add|mul|sub)_overflow|(?:checked|safe)\w*(?:add|mul|size)",
    re.IGNORECASE,
)
_IGNORED = {
    "if", "else", "while", "for", "return", "sizeof", "const", "volatile",
    "signed", "unsigned", "short", "long", "int", "char", "void", "NULL",
}


def build_signed_allocation_write_chains(
    *,
    repo: Path,
    source_files: list[str],
    nodes: tuple[GraphNode, ...],
    summaries: tuple[FunctionCapacitySummary, ...],
) -> tuple[SignedAllocationWriteChain, ...]:
    """Join signed field domains to later allocation and bounded writes."""
    field_types = _field_types(repo, source_files)
    signed_fields = {
        name for name, type_name in field_types.items()
        if not re.search(r"\bunsigned\b|\buint", type_name, re.I)
    }
    scalar_parameters = {
        _local_key(summary.node_id, parameter)
        for summary in summaries
        for parameter in summary.parameters
        if parameter not in summary.pointer_parameters
    }
    nodes_by_path: dict[str, list[GraphNode]] = defaultdict(list)
    for node in nodes:
        nodes_by_path[node.path].append(node)

    chains = []
    for path in sorted({item for item in source_files if Path(item).suffix.lower() == ".c"}):
        source_path = repo / path
        if not source_path.is_file():
            continue
        source = _strip_comments(source_path.read_text(errors="replace"))
        assignments = list(_ASSIGNMENT.finditer(source))
        forward: dict[str, set[str]] = defaultdict(set)
        reverse: dict[str, set[str]] = defaultdict(set)
        allocation_matches = []
        for match in assignments:
            assignment_line = _line(source, match.start())
            assignment_node = _node_at(nodes_by_path[path], assignment_line)
            if assignment_node is None:
                continue
            lhs = _value_key(match.group("lhs"), assignment_node.node_id)
            rhs = match.group("rhs")
            tokens = _semantic_keys(rhs, assignment_node.node_id)
            for token in tokens:
                forward[token].add(lhs)
                reverse[lhs].add(token)
            allocator = next(
                (name for name in _call_names(rhs) if is_allocator_name(name)),
                "",
            )
            if allocator:
                allocation_matches.append((match, lhs, rhs, allocator))

        writes = [
            write for write in _WRITE.finditer(source)
            if not _pointer_declaration(source, write)
        ]
        loops = list(_LOOP_BOUND.finditer(source))
        for field in sorted(signed_fields):
            guards = _field_guards(source, field)
            if not guards:
                continue
            domain, guard_state = _domain(guards)
            if domain == "unchecked":
                continue
            reachable = _reachable(_field_key(field), forward)
            for allocation, buffer_subject, expression, _ in allocation_matches:
                allocation_line = _line(source, allocation.start())
                allocation_node = _node_at(nodes_by_path[path], allocation_line)
                if allocation_node is None or not reachable.intersection(
                    _semantic_keys(expression, allocation_node.node_id)
                ):
                    continue
                allocation_reachable = _reachable(buffer_subject, forward)
                selected_writes = []
                for write in writes:
                    write_line = _line(source, write.start())
                    write_node = _node_at(nodes_by_path[path], write_line)
                    if write_node is None:
                        continue
                    subject = write.group("pointer") or write.group("array")
                    if _local_key(write_node.node_id, subject) in allocation_reachable:
                        selected_writes.append(write)
                if not selected_writes:
                    continue
                write_lines = tuple(sorted({_line(source, item.start()) for item in selected_writes}))
                source_line = min(line for line, _ in guards)
                guard_lines = tuple(sorted({line for line, _ in guards}))
                write_bound, write_bound_line = _nearest_loop_bound(
                    source, loops, selected_writes
                )
                bound_node = _node_at(nodes_by_path[path], write_bound_line)
                ancestors = _ancestors(write_bound, reverse) if write_bound else set()
                if write_bound and bound_node is not None:
                    ancestors = _ancestors(
                        _local_key(bound_node.node_id, write_bound),
                        reverse,
                    )
                independent = bool(ancestors.intersection(scalar_parameters))
                narrowing = any(
                    _raw_key(token) in field_types
                    and re.search(
                        r"\bunsigned\b|\buint",
                        field_types[_raw_key(token)],
                        re.I,
                    )
                    for token in reachable
                )
                checked = bool(_CHECKED_ARITHMETIC.search(expression))
                source_node = _node_at(nodes_by_path[path], source_line)
                write_node = _node_at(nodes_by_path[path], write_lines[0])
                if source_node is None or allocation_node is None or write_node is None:
                    continue
                write_unit = _write_unit(source, selected_writes)
                identity = "\0".join((
                    SIGNED_ALLOCATION_WRITE_POLICY,
                    path,
                    source_node.node_id,
                    allocation_node.node_id,
                    write_node.node_id,
                    str(source_line),
                    str(allocation_line),
                    *(str(line) for line in write_lines),
                ))
                unsafe = guard_state is not GuardState.DOMINATES
                chains.append(SignedAllocationWriteChain(
                    chain_id="signed_memory_" + hashlib.sha256(identity.encode()).hexdigest()[:20],
                    source_node_id=source_node.node_id,
                    allocation_node_id=allocation_node.node_id,
                    write_node_id=write_node.node_id,
                    paths=(path,),
                    source_line=source_line,
                    guard_lines=guard_lines,
                    allocation_line=allocation_line,
                    write_lines=write_lines,
                    source_signed=True,
                    source_domain=domain,
                    allocation_expression=" ".join(expression.split())[:500],
                    write_unit=write_unit,
                    independent_write_bound=independent,
                    narrowing_or_wrap=narrowing,
                    checked_arithmetic=checked,
                    boundary_cases=(
                        "negative",
                        "zero",
                        "largest_valid",
                        "narrowing_boundary",
                        "allocation_overflow",
                    ),
                    guard_state=guard_state,
                    score=95 if unsafe and independent else (80 if unsafe else 15),
                    confidence="high" if independent else "medium",
                    rationale=(
                        f"signed source domain={domain} reaches allocation arithmetic and "
                        f"{len(write_lines)} writes; independent write bound={independent}; "
                        f"checked arithmetic={checked}"
                    ),
                ))
    return tuple(sorted(
        {item.chain_id: item for item in chains}.values(),
        key=lambda item: item.chain_id,
    ))


def _field_types(repo: Path, source_files: list[str]) -> dict[str, str]:
    result = {}
    for relative in sorted(set(source_files)):
        if Path(relative).suffix.lower() != ".h":
            continue
        path = repo / relative
        if not path.is_file():
            continue
        for match in _FIELD_DECLARATION.finditer(_strip_comments(path.read_text(errors="replace"))):
            type_name = " ".join(match.group("type").split())
            for declarator in match.group("declarators").split(","):
                names = _IDENTIFIER.findall(declarator.split("=", 1)[0])
                if names:
                    result[names[-1]] = type_name
    return result


def _field_guards(source: str, field: str) -> list[tuple[int, str]]:
    result = []
    for match in _GUARD.finditer(source):
        condition = " ".join(match.group("condition").split())
        line = _line(source, match.start())
        line_end = _line_end_offset(source, line + 4)
        rejection_window = source[match.end():line_end]
        if (
            re.search(rf"(?:->|\.)\s*{re.escape(field)}\b", condition)
            and re.search(r"\b(?:return|goto)\b", rejection_window)
        ):
            result.append((line, condition))
    return result


def _domain(guards: list[tuple[int, str]]) -> tuple[str, GuardState]:
    text = " ".join(condition for _, condition in guards)
    field_access = r"[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)+"
    if re.search(rf"{field_access}\s*<=\s*0|{field_access}\s*<\s*1", text):
        return "nonnegative", GuardState.DOMINATES
    if re.search(rf"!\s*{field_access}|{field_access}\s*==\s*0", text):
        return "nonzero", GuardState.PARTIAL
    return "unchecked", GuardState.ABSENT


def _reachable(seed: str, edges: dict[str, set[str]]) -> set[str]:
    seen = {seed}
    queue = deque([seed])
    while queue and len(seen) < 256:
        current = queue.popleft()
        for target in sorted(edges.get(current, ())):
            if target not in seen:
                seen.add(target)
                queue.append(target)
    return seen


def _ancestors(seed: str, edges: dict[str, set[str]]) -> set[str]:
    return _reachable(seed, edges) if seed else set()


def _nearest_loop_bound(source: str, loops, writes) -> tuple[str, int]:
    first_write = min(item.start() for item in writes)
    candidates = [item for item in loops if 0 <= first_write - item.end() <= 2_000]
    if not candidates:
        return "", 0
    selected = max(candidates, key=lambda item: item.end())
    return selected.group("bound"), _line(source, selected.start())


def _write_unit(source: str, writes) -> int:
    lines = sorted(_line(source, item.start()) for item in writes)
    longest = current = 0
    previous = -10
    for line in lines:
        current = current + 1 if line - previous <= 1 else 1
        longest = max(longest, current)
        previous = line
    return max(1, longest)


def _node_at(nodes: list[GraphNode], line: int) -> GraphNode | None:
    return next((node for node in nodes if node.line <= line <= node.end_line), None)


def _terminal(expression: str) -> str:
    tokens = _IDENTIFIER.findall(expression)
    return tokens[-1] if tokens else ""


def _semantic_keys(expression: str, node_id: str) -> set[str]:
    calls = set(_call_names(expression))
    member_chains = re.findall(
        r"\b[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)+",
        expression,
    )
    member_parts = {
        token for chain in member_chains for token in _IDENTIFIER.findall(chain)
    }
    terminals = {_field_key(_terminal(chain)) for chain in member_chains}
    simple = {
        token for token in _IDENTIFIER.findall(expression)
        if token not in member_parts
        and token not in _IGNORED
        and token not in calls
        and not token.endswith("_t")
    }
    return {_local_key(node_id, token) for token in simple} | terminals


def _value_key(expression: str, node_id: str) -> str:
    terminal = _terminal(expression)
    return (
        _field_key(terminal)
        if re.search(r"->|\.", expression)
        else _local_key(node_id, terminal)
    )


def _field_key(name: str) -> str:
    return f"field:{name}"


def _local_key(node_id: str, name: str) -> str:
    return f"local:{node_id}:{name}"


def _raw_key(key: str) -> str:
    return key.rsplit(":", 1)[-1]


def _pointer_declaration(source: str, write: re.Match[str]) -> bool:
    line_start = source.rfind("\n", 0, write.start()) + 1
    prefix = source[line_start:write.start()]
    return bool(re.search(
        r"\b(?:char|short|int|long|float|double|u?int(?:8|16|32|64)_t)\s*$",
        prefix,
    ))


def _call_names(expression: str) -> tuple[str, ...]:
    return tuple(re.findall(r"\b([A-Za-z_]\w*)\s*\(", expression))


def _line(source: str, position: int) -> int:
    return source[:position].count("\n") + 1


def _line_end_offset(source: str, line: int) -> int:
    position = 0
    for _ in range(max(0, line - 1)):
        next_position = source.find("\n", position)
        if next_position < 0:
            return len(source)
        position = next_position + 1
    return position


def _strip_comments(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    return re.sub(r"//[^\n]*|/\*.*?\*/", replace, source, flags=re.DOTALL)
