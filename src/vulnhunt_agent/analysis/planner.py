"""Coverage-first AnalysisSlice planning over a deterministic C call graph."""
from __future__ import annotations

import hashlib
from collections import deque

from .models import (
    AnalysisSlice,
    CAnalysisGraph,
    CoveragePlan,
    GraphEdge,
    GraphNode,
    SecuritySignal,
)


def build_coverage_plan(graph: CAnalysisGraph) -> CoveragePlan:
    nodes = {item.node_id: item for item in graph.nodes}
    signals = {item.signal_id: item for item in graph.signals}
    adjacency: dict[str, list[str]] = {}
    edge_by_pair: dict[tuple[str, str], GraphEdge] = {}
    for edge in graph.edges:
        adjacency.setdefault(edge.source, []).append(edge.target)
        edge_by_pair.setdefault((edge.source, edge.target), edge)
    for targets in adjacency.values():
        targets.sort()

    slices: list[AnalysisSlice] = []
    covered_entries: set[str] = set()
    covered_sinks: set[str] = set()
    sink_items = [
        signals[signal_id]
        for signal_id in graph.critical_sink_ids
        if signal_id in signals and signals[signal_id].node_id in nodes
    ]
    source_entrypoints = {
        item.node_id
        for item in graph.signals
        if item.role.value == "source" and item.node_id in graph.entrypoint_ids
    }

    # Every critical sink gets the shortest available input-to-sink slice.
    for sink in sorted(sink_items, key=lambda item: item.signal_id):
        best = _best_entry_path(
            graph.entrypoint_ids,
            sink.node_id,
            adjacency,
            preferred=source_entrypoints,
        )
        if best is None:
            node_path: tuple[str, ...] = (sink.node_id,)
            entrypoint = sink.node_id
            rationale = "Critical sink is disconnected; review its local callers and guards."
        else:
            entrypoint, node_path = best
            covered_entries.add(entrypoint)
            rationale = "Shortest detected entrypoint-to-critical-sink call path."
        slices.append(_slice(
            entrypoint,
            sink,
            node_path,
            nodes,
            edge_by_pair,
            graph.signals,
            rationale,
        ))
        covered_sinks.add(sink.signal_id)

    # An entrypoint without a reachable critical sink still receives a context slice.
    for entrypoint in graph.entrypoint_ids:
        if entrypoint in covered_entries or entrypoint not in nodes:
            continue
        reachable = _nearest_sink(entrypoint, sink_items, adjacency)
        if reachable is None:
            slices.append(_slice(
                entrypoint,
                None,
                (entrypoint,),
                nodes,
                edge_by_pair,
                graph.signals,
                "Detected entrypoint has no resolved critical sink; inspect unresolved flow.",
            ))
            covered_entries.add(entrypoint)
        else:
            sink, node_path = reachable
            slices.append(_slice(
                entrypoint,
                sink,
                node_path,
                nodes,
                edge_by_pair,
                graph.signals,
                "Nearest critical sink reachable from this entrypoint.",
            ))
            covered_entries.add(entrypoint)
            covered_sinks.add(sink.signal_id)

    unique = {item.slice_id: item for item in slices}
    ordered = tuple(sorted(
        unique.values(), key=lambda item: (-item.risk, item.slice_id)
    ))
    file_reasons: dict[str, set[str]] = {}
    for item in ordered:
        for file_path in item.files:
            file_reasons.setdefault(file_path, set()).add(f"slice:{item.slice_id}")
        entry = nodes.get(item.entrypoint_id)
        if entry is not None:
            file_reasons.setdefault(entry.path, set()).add("detected-entrypoint")
        if item.sink_signal_id:
            sink = signals[item.sink_signal_id]
            file_reasons.setdefault(sink.path, set()).add(
                f"critical-sink:{sink.category}"
            )

    expected_entries = set(graph.entrypoint_ids)
    expected_sinks = set(graph.critical_sink_ids)
    return CoveragePlan(
        slices=ordered,
        selected_files=tuple(sorted(file_reasons)),
        file_reasons={
            path: tuple(sorted(reasons))
            for path, reasons in sorted(file_reasons.items())
        },
        covered_entrypoint_ids=tuple(sorted(covered_entries)),
        covered_sink_ids=tuple(sorted(covered_sinks)),
        uncovered_entrypoint_ids=tuple(sorted(expected_entries - covered_entries)),
        uncovered_sink_ids=tuple(sorted(expected_sinks - covered_sinks)),
    )


def _best_entry_path(
    entrypoints: tuple[str, ...],
    target: str,
    adjacency: dict[str, list[str]],
    *,
    preferred: set[str],
) -> tuple[str, tuple[str, ...]] | None:
    choices = []
    for entrypoint in entrypoints:
        path = _shortest_path(entrypoint, target, adjacency)
        if path is not None:
            choices.append((
                0 if entrypoint in preferred else 1,
                len(path),
                entrypoint,
                path,
            ))
    if not choices:
        return None
    _, _, entrypoint, path = min(choices)
    return entrypoint, path


def _nearest_sink(
    entrypoint: str,
    sinks: list[SecuritySignal],
    adjacency: dict[str, list[str]],
) -> tuple[SecuritySignal, tuple[str, ...]] | None:
    choices = []
    for sink in sinks:
        path = _shortest_path(entrypoint, sink.node_id, adjacency)
        if path is not None:
            choices.append((len(path), sink.signal_id, sink, path))
    if not choices:
        return None
    _, _, sink, path = min(choices, key=lambda item: (item[0], item[1], item[3]))
    return sink, path


def _shortest_path(
    source: str,
    target: str,
    adjacency: dict[str, list[str]],
) -> tuple[str, ...] | None:
    queue: deque[tuple[str, tuple[str, ...]]] = deque([
        (source, (source,))
    ])
    seen = {source}
    while queue:
        current, path = queue.popleft()
        if current == target:
            return path
        for child in adjacency.get(current, []):
            if child not in seen:
                seen.add(child)
                queue.append((child, (*path, child)))
    return None


def _slice(
    entrypoint_id: str,
    sink: SecuritySignal | None,
    node_ids: tuple[str, ...],
    nodes: dict[str, GraphNode],
    edge_by_pair: dict[tuple[str, str], GraphEdge],
    all_signals: tuple[SecuritySignal, ...],
    rationale: str,
) -> AnalysisSlice:
    edge_ids = tuple(
        edge_by_pair[(source, target)].edge_id
        for source, target in zip(node_ids, node_ids[1:])
        if (source, target) in edge_by_pair
    )
    node_set = set(node_ids)
    path_signals = [item for item in all_signals if item.node_id in node_set]
    categories = tuple(sorted({item.category for item in path_signals}))
    risk = max((item.risk for item in path_signals), default=1)
    files = tuple(sorted({nodes[node_id].path for node_id in node_ids}))
    identity = "\0".join((
        entrypoint_id,
        sink.signal_id if sink else "",
        *node_ids,
    ))
    digest = hashlib.sha256(identity.encode()).hexdigest()[:20]
    return AnalysisSlice(
        slice_id=f"slice_{digest}",
        entrypoint_id=entrypoint_id,
        sink_signal_id=sink.signal_id if sink else None,
        node_ids=node_ids,
        edge_ids=edge_ids,
        files=files,
        categories=categories,
        risk=risk,
        rationale=rationale,
    )
