"""Tree-sitter C call graph plus conservative security source/sink detection."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import tree_sitter_c
from tree_sitter import Language, Node, Parser

from ..indexer.tree_sitter_indexer import (
    CFunctionRegion,
    _c_function_name,
    c_function_regions,
)
from .models import (
    CAnalysisGraph,
    EdgeKind,
    GraphEdge,
    GraphNode,
    NodeKind,
    SecuritySignal,
    SignalRole,
    UnresolvedCall,
)

_C_LANGUAGE = Language(tree_sitter_c.language())
_ENTRYPOINT_NAMES = re.compile(
    r"^(?:main|yyparse|yylex|parse|decode|deserialize|load|read|receive|recv|"
    r"handle|process|scan|consume|import|open)(?:_|$)",
    re.IGNORECASE,
)
_CALL_PATTERN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_IGNORED_CALL_WORDS = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "_Alignof",
})

_SOURCE_CALLS: dict[str, tuple[str, int]] = {
    "atoi": ("integer_conversion", 3),
    "atol": ("integer_conversion", 3),
    "atoll": ("integer_conversion", 3),
    "strtol": ("integer_conversion", 3),
    "strtoul": ("integer_conversion", 3),
    "strtoll": ("integer_conversion", 3),
    "strtoull": ("integer_conversion", 3),
    "read": ("external_input", 4),
    "recv": ("external_input", 4),
    "recvfrom": ("external_input", 4),
    "fread": ("external_input", 4),
    "fgets": ("external_input", 4),
    "getline": ("external_input", 4),
    "getdelim": ("external_input", 4),
    "scanf": ("formatted_input", 4),
    "fscanf": ("formatted_input", 4),
    "sscanf": ("formatted_input", 4),
    "getenv": ("environment_input", 3),
    "getopt": ("argument_input", 3),
    "getopt_long": ("argument_input", 3),
}

_SINK_CALLS: dict[str, tuple[str, int]] = {
    "strcpy": ("unbounded_copy", 5),
    "strcat": ("unbounded_copy", 5),
    "stpcpy": ("unbounded_copy", 5),
    "sprintf": ("unbounded_format", 5),
    "vsprintf": ("unbounded_format", 5),
    "gets": ("unbounded_input", 5),
    "memcpy": ("memory_copy", 4),
    "memmove": ("memory_copy", 4),
    "malloc": ("allocation_size", 4),
    "calloc": ("allocation_size", 4),
    "realloc": ("allocation_size", 4),
    "alloca": ("allocation_size", 4),
    "ALLOC": ("allocation_size", 4),
    "system": ("command_execution", 5),
    "popen": ("command_execution", 5),
    "execl": ("command_execution", 5),
    "execle": ("command_execution", 5),
    "execlp": ("command_execution", 5),
    "execv": ("command_execution", 5),
    "execve": ("command_execution", 5),
    "execvp": ("command_execution", 5),
    "dlopen": ("dynamic_loading", 5),
    "fopen": ("path_operation", 4),
    "open": ("path_operation", 4),
    "freopen": ("path_operation", 4),
    "remove": ("path_operation", 4),
    "rename": ("path_operation", 4),
    "unlink": ("path_operation", 4),
    "chmod": ("path_operation", 4),
    "chown": ("path_operation", 4),
    "free": ("lifetime_release", 3),
}

_FORMAT_ARGUMENT = {
    "printf": 0,
    "vprintf": 0,
    "fprintf": 1,
    "vfprintf": 1,
    "syslog": 1,
}


@dataclass(frozen=True)
class _CallSite:
    caller_id: str
    path: str
    line: int
    callee: str


@dataclass(frozen=True)
class _Extracted:
    node: GraphNode
    calls: tuple[_CallSite, ...]
    signals: tuple[SecuritySignal, ...]


def build_c_analysis_graph(repo: Path, source_files: list[str]) -> CAnalysisGraph:
    """Build the same graph bytes for the same source tree and file list."""
    parser = Parser(_C_LANGUAGE)
    header_exports = _header_exports(repo, source_files)
    extracted: list[_Extracted] = []
    grammar_paths: dict[str, list[str]] = {"l": [], "y": []}

    for relative in sorted(dict.fromkeys(source_files)):
        suffix = Path(relative).suffix.lower()
        if suffix in {".c", ".h"}:
            extracted.extend(_extract_c_file(parser, repo, relative))
        elif suffix in {".l", ".y"}:
            grammar_paths[suffix[1:]].append(relative)
            extracted.append(_extract_grammar_file(repo, relative))

    nodes = sorted((item.node for item in extracted), key=lambda item: item.node_id)
    node_by_id = {item.node.node_id: item.node for item in extracted}
    calls = [call for item in extracted for call in item.calls]
    signals = sorted(
        (signal for item in extracted for signal in item.signals),
        key=lambda item: item.signal_id,
    )

    by_symbol: dict[str, list[GraphNode]] = {}
    for node in nodes:
        if node.kind is NodeKind.FUNCTION:
            by_symbol.setdefault(node.symbol, []).append(node)

    edges: list[GraphEdge] = []
    unresolved: list[UnresolvedCall] = []
    for call in sorted(calls, key=lambda item: (
        item.path, item.line, item.caller_id, item.callee
    )):
        targets = by_symbol.get(call.callee, [])
        if targets:
            target = _resolve_target(node_by_id[call.caller_id], targets)
            edges.append(_edge(
                call.caller_id,
                target.node_id,
                EdgeKind.CALL,
                call.path,
                call.line,
            ))
        elif (
            call.callee not in _SOURCE_CALLS
            and call.callee not in _SINK_CALLS
            and call.callee not in _FORMAT_ARGUMENT
        ):
            unresolved.append(UnresolvedCall(
                source=call.caller_id,
                path=call.path,
                line=call.line,
                callee=call.callee,
            ))

    for scanner in grammar_paths["l"]:
        scanner_id = _node_id(scanner, "<flex>", 1)
        for grammar in grammar_paths["y"]:
            edges.append(_edge(
                scanner_id,
                _node_id(grammar, "<bison>", 1),
                EdgeKind.PARSER_FLOW,
                scanner,
                1,
            ))

    edges = sorted(
        {item.edge_id: item for item in edges}.values(),
        key=lambda item: item.edge_id,
    )
    incoming = {edge.target for edge in edges}
    source_nodes = {
        signal.node_id for signal in signals if signal.role is SignalRole.SOURCE
    }
    entrypoints = []
    for node in nodes:
        exported = node.symbol in header_exports
        root_external = node.visibility == "external" and node.node_id not in incoming
        if (
            node.node_id in source_nodes
            or node.kind is NodeKind.GRAMMAR
            or node.symbol == "main"
            or (node.visibility == "external" and exported)
            or (root_external and _ENTRYPOINT_NAMES.search(node.symbol))
        ):
            entrypoints.append(node.node_id)

    critical_sinks = [
        signal.signal_id
        for signal in signals
        if signal.role is SignalRole.SINK and signal.risk >= 4
    ]
    return CAnalysisGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        signals=tuple(signals),
        entrypoint_ids=tuple(sorted(set(entrypoints))),
        critical_sink_ids=tuple(sorted(critical_sinks)),
        unresolved_calls=tuple(sorted(
            unresolved,
            key=lambda item: (item.path, item.line, item.source, item.callee),
        )),
    )


def _extract_c_file(parser: Parser, repo: Path, relative: str) -> list[_Extracted]:
    source = (repo / relative).read_bytes()
    root = parser.parse(source).root_node
    return [
        extracted
        for region in c_function_regions(root, source)
        if (extracted := _extract_c_function(relative, source, region)) is not None
    ]


def _extract_c_function(
    relative: str,
    source: bytes,
    region: CFunctionRegion,
) -> _Extracted | None:
    declarator = region.declarator
    name = _c_function_name(declarator, source)
    if not name:
        return None
    line = region.line
    node_id = _node_id(relative, name, line)
    prefix = source[region.start_byte:declarator.start_byte].decode(
        errors="replace"
    )
    visibility = "internal" if re.search(r"\bstatic\b", prefix) else "external"
    call_sites: list[_CallSite] = []
    signals: list[SecuritySignal] = []
    call_names: list[str] = []
    for body_node in region.body_nodes:
        for descendant in (body_node, *_walk(body_node)):
            if descendant.type == "call_expression":
                callee = _call_name(descendant, source)
                if not callee:
                    continue
                call_line = descendant.start_point[0] + 1
                call_names.append(callee)
                call_sites.append(_CallSite(
                    caller_id=node_id,
                    path=relative,
                    line=call_line,
                    callee=callee,
                ))
                source_spec = _SOURCE_CALLS.get(callee)
                if source_spec:
                    signals.append(_signal(
                        node_id, relative, call_line, SignalRole.SOURCE,
                        source_spec[0], callee, source_spec[1],
                    ))
                sink_spec = _SINK_CALLS.get(callee)
                if sink_spec:
                    signals.append(_signal(
                        node_id, relative, call_line, SignalRole.SINK,
                        sink_spec[0], callee, sink_spec[1],
                    ))
                format_signal = _dynamic_format_signal(
                    descendant, source, node_id, relative, callee
                )
                if format_signal is not None:
                    signals.append(format_signal)
            elif descendant.type in {"assignment_expression", "update_expression"}:
                left = descendant.child_by_field_name("left") or descendant
                subscript = _first_node_of_type(left, "subscript_expression")
                if subscript is not None:
                    index = subscript.child_by_field_name("index")
                    index_text = _text(index, source) if index is not None else ""
                    guard_detail = _index_guard_detail(
                        region.start_byte, descendant, index_text, source
                    )
                    guarded = "lower_guard=yes" in guard_detail and (
                        "upper_guard=yes" in guard_detail
                    )
                    signals.append(_signal(
                        node_id,
                        relative,
                        descendant.start_point[0] + 1,
                        SignalRole.SINK,
                        (
                            "array_index_write_guarded"
                            if guarded else "array_index_write"
                        ),
                        "subscript assignment",
                        2 if guarded else 5,
                        (
                            f"{guard_detail}; "
                            f"expression={_text(descendant, source)[:180]}"
                        ),
                    ))
    return _Extracted(
        node=GraphNode(
            node_id=node_id,
            path=relative,
            symbol=name,
            line=line,
            end_line=region.end_line,
            kind=NodeKind.FUNCTION,
            visibility=visibility,
            calls=tuple(sorted(set(call_names))),
        ),
        calls=tuple(call_sites),
        signals=tuple({item.signal_id: item for item in signals}.values()),
    )


def _extract_grammar_file(repo: Path, relative: str) -> _Extracted:
    text = (repo / relative).read_text(errors="replace")
    symbol = "<flex>" if Path(relative).suffix.lower() == ".l" else "<bison>"
    node_id = _node_id(relative, symbol, 1)
    calls: list[_CallSite] = []
    signals: list[SecuritySignal] = []
    names: list[str] = []
    for match in _CALL_PATTERN.finditer(_strip_c_comments(text)):
        callee = match.group(1)
        if callee in _IGNORED_CALL_WORDS:
            continue
        line = text[:match.start()].count("\n") + 1
        names.append(callee)
        calls.append(_CallSite(node_id, relative, line, callee))
        if callee in _SOURCE_CALLS:
            category, risk = _SOURCE_CALLS[callee]
            signals.append(_signal(
                node_id, relative, line, SignalRole.SOURCE, category, callee, risk
            ))
        if callee in _SINK_CALLS:
            category, risk = _SINK_CALLS[callee]
            signals.append(_signal(
                node_id, relative, line, SignalRole.SINK, category, callee, risk
            ))
    return _Extracted(
        node=GraphNode(
            node_id=node_id,
            path=relative,
            symbol=symbol,
            line=1,
            end_line=max(1, text.count("\n") + 1),
            kind=NodeKind.GRAMMAR,
            visibility="generated",
            calls=tuple(sorted(set(names))),
        ),
        calls=tuple(calls),
        signals=tuple({item.signal_id: item for item in signals}.values()),
    )


def _dynamic_format_signal(
    call: Node,
    source: bytes,
    node_id: str,
    path: str,
    callee: str,
) -> SecuritySignal | None:
    index = _FORMAT_ARGUMENT.get(callee)
    if index is None:
        return None
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return None
    values = [
        child for child in arguments.named_children
        if child.type not in {"comment"}
    ]
    if index >= len(values) or values[index].type in {
        "string_literal", "concatenated_string"
    }:
        return None
    return _signal(
        node_id,
        path,
        call.start_point[0] + 1,
        SignalRole.SINK,
        "dynamic_format_string",
        callee,
        5,
        _text(values[index], source)[:160],
    )


def _header_exports(repo: Path, source_files: list[str]) -> set[str]:
    exports: set[str] = set()
    for relative in source_files:
        if Path(relative).suffix.lower() != ".h":
            continue
        text = _strip_c_comments((repo / relative).read_text(errors="replace"))
        for match in re.finditer(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*;",
            text,
            re.MULTILINE,
        ):
            name = match.group(1)
            if name not in _IGNORED_CALL_WORDS:
                exports.add(name)
    return exports


def _resolve_target(caller: GraphNode, candidates: list[GraphNode]) -> GraphNode:
    same_file = [item for item in candidates if item.path == caller.path]
    return sorted(same_file or candidates, key=lambda item: item.node_id)[0]


def _call_name(node: Node, source: bytes) -> str:
    function = node.child_by_field_name("function")
    if function is None:
        return ""
    if function.type == "identifier":
        return _text(function, source)
    if function.type in {"field_expression", "qualified_identifier"}:
        field = function.child_by_field_name("field")
        if field is not None:
            return _text(field, source)
    return ""


def _signal(
    node_id: str,
    path: str,
    line: int,
    role: SignalRole,
    category: str,
    operation: str,
    risk: int,
    detail: str = "",
) -> SecuritySignal:
    identity = "\0".join((
        node_id, str(line), role.value, category, operation, detail
    ))
    digest = hashlib.sha256(identity.encode()).hexdigest()[:20]
    return SecuritySignal(
        signal_id=f"sig_{digest}",
        node_id=node_id,
        path=path,
        line=line,
        role=role,
        category=category,
        operation=operation,
        detail=detail,
        risk=risk,
    )


def _edge(
    source: str,
    target: str,
    kind: EdgeKind,
    path: str,
    line: int,
) -> GraphEdge:
    identity = "\0".join((source, target, kind.value, path, str(line)))
    digest = hashlib.sha256(identity.encode()).hexdigest()[:20]
    return GraphEdge(
        edge_id=f"edge_{digest}",
        source=source,
        target=target,
        kind=kind,
        path=path,
        line=line,
    )


def _node_id(path: str, symbol: str, line: int) -> str:
    return f"{path}::{symbol}@{line}"


def _nodes_of_type(root: Node, node_type: str) -> list[Node]:
    return [node for node in _walk(root) if node.type == node_type]


def _walk(root: Node):
    for child in root.children:
        yield child
        yield from _walk(child)


def _contains_type(root: Node, node_type: str) -> bool:
    return root.type == node_type or any(
        node.type == node_type for node in _walk(root)
    )


def _first_node_of_type(root: Node, node_type: str) -> Node | None:
    if root.type == node_type:
        return root
    return next((node for node in _walk(root) if node.type == node_type), None)


def _index_guard_detail(
    function_start_byte: int,
    assignment: Node,
    index_text: str,
    source: bytes,
) -> str:
    """Record a bounded heuristic; it is a prioritization hint, not a proof."""
    identifier = index_text.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier):
        return f"index={identifier or '<complex>'}; lower_guard=no; upper_guard=no"
    prefix = source[function_start_byte:assignment.start_byte].decode(
        errors="replace"
    )
    escaped = re.escape(identifier)
    lower_patterns = (
        rf"\b{escaped}\s*<\s*0\b",
        rf"\b{escaped}\s*>=\s*0\b",
        rf"\b0\s*<=\s*{escaped}\b",
        rf"\b0\s*>\s*{escaped}\b",
    )
    upper_patterns = (
        rf"\b{escaped}\s*(?:>|>=|<|<=)\s*(?:[A-Za-z_][A-Za-z0-9_]*|\d+)\b",
        rf"\b(?:[A-Za-z_][A-Za-z0-9_]*|\d+)\s*(?:>|>=)\s*{escaped}\b",
    )
    lower = any(re.search(pattern, prefix) for pattern in lower_patterns)
    upper = any(re.search(pattern, prefix) for pattern in upper_patterns)
    return (
        f"index={identifier}; lower_guard={'yes' if lower else 'no'}; "
        f"upper_guard={'yes' if upper else 'no'}"
    )


def _text(node: Node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode(errors="replace")


def _strip_c_comments(text: str) -> str:
    def preserve_offsets(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    return re.sub(
        r"/\*.*?\*/|//[^\n]*",
        preserve_offsets,
        text,
        flags=re.DOTALL,
    )
