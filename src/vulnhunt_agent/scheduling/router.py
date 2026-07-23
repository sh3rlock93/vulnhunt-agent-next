"""Deterministic security-signal to Hunter routing."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from ..analysis.models import CAnalysisGraph, CoveragePlan, SecuritySignal
from ..domain.schemas import (
    MAX_HUNTER_TARGET_NODES,
    MAX_HUNTER_TARGET_SIGNALS,
    HunterRoutingPlan,
    HunterWorkItem,
)
from .shadow import work_id_for

ROUTER_POLICY = "c-signal-router-v4"

BOUNDS = "c-bounds-integers"
LIFETIME = "c-memory-lifetime"
PARSER = "c-parser-state"
INJECTION = "c-injection-format"
CONCURRENCY = "c-concurrency-state"
ERRORS = "c-error-contracts"

_CATEGORY_HUNTERS: dict[str, tuple[str, ...]] = {
    "integer_conversion": (BOUNDS,),
    "formatted_input": (BOUNDS,),
    "external_input": (BOUNDS,),
    "array_index_write": (BOUNDS,),
    "array_index_write_guarded": (BOUNDS,),
    "cursor_index_read": (PARSER, BOUNDS),
    "unbounded_copy": (BOUNDS, LIFETIME),
    "unbounded_input": (BOUNDS,),
    "memory_copy": (BOUNDS, LIFETIME),
    "allocation_size": (BOUNDS, LIFETIME),
    "allocation_size_guarded": (BOUNDS,),
    "lifetime_release": (LIFETIME,),
    "dynamic_format_string": (INJECTION, BOUNDS),
    "unbounded_format": (INJECTION, BOUNDS),
    "command_execution": (INJECTION,),
    "dynamic_loading": (INJECTION,),
    "path_operation": (INJECTION,),
    "environment_input": (INJECTION,),
    "concurrency_state": (CONCURRENCY,),
    "error_contract": (ERRORS,),
}
_FALLBACKS = (BOUNDS, LIFETIME, PARSER, INJECTION, CONCURRENCY, ERRORS)


@dataclass(frozen=True)
class RoutingTargetBatch:
    """Pre-validation target unit shared by every selected specialist."""

    coverage_group: str
    index: int
    count: int
    target_node_ids: tuple[str, ...]
    target_signal_ids: tuple[str, ...]


def build_routing_plan(
    *,
    run_id: str,
    source_snapshot: str,
    selected_files: list[str],
    enabled_hunters: list[str],
    analysis: dict | None,
) -> HunterRoutingPlan:
    """Route each file to at most two relevant specialists.

    Critical sink files are forced into the plan even if an upstream selector
    accidentally omitted them. An unknown critical category receives a
    deterministic fallback rather than disappearing from coverage.
    """
    language = str((analysis or {}).get("language", ""))
    configured_scope = (analysis or {}).get("scan_scope") or {}
    if language != "c":
        return _fallback_language_plan(
            run_id=run_id,
            source_snapshot=source_snapshot,
            selected_files=selected_files,
            enabled_hunters=enabled_hunters,
            scan_scope=configured_scope,
        )

    graph = CAnalysisGraph.model_validate((analysis or {}).get("graph") or {})
    coverage = CoveragePlan.model_validate(
        (analysis or {}).get("coverage_plan") or {}
    )
    scan_scope = configured_scope
    scan_scope_digest = str(scan_scope.get("digest") or "") or None
    bounded_scope = scan_scope.get("mode", "full") != "full"
    signals = {item.signal_id: item for item in graph.signals}
    active_critical_ids = _active_critical_ids(analysis, graph)
    incremental = (analysis or {}).get("incremental_scope") or {}
    is_incremental = incremental.get("mode") == "incremental"
    changed_node_ids = set(incremental.get("changed_node_ids", ()))
    changed_line_ranges = incremental.get("changed_line_ranges") or {}
    critical = [
        signals[signal_id]
        for signal_id in active_critical_ids
        if signal_id in signals
    ]
    selected = (
        set(scan_scope.get("selected_files", ()))
        if bounded_scope
        else set(selected_files)
    )
    forced_files = tuple(sorted({
        signal.path for signal in critical if signal.path not in selected
    }))
    paths = sorted(selected | set(forced_files))
    enabled = tuple(sorted(dict.fromkeys(enabled_hunters)))
    items: list[HunterWorkItem] = []

    for path in paths:
        matching_slices = [
            item for item in coverage.slices if path in item.files
        ]
        node_ids = {
            node_id for item in matching_slices for node_id in item.node_ids
        }
        local_signals = [
            item for item in graph.signals
            if item.path == path and (not node_ids or item.node_id in node_ids)
        ]
        critical_local = sorted(
            (
                item for item in graph.signals
                if item.path == path and item.signal_id in active_critical_ids
            ),
            key=lambda item: item.signal_id,
        )
        local_signals = list({
            item.signal_id: item for item in (*local_signals, *critical_local)
        }.values())
        local_node_ids = {
            item.node_id for item in graph.nodes if item.path == path
        }
        target_node_ids = tuple(sorted(changed_node_ids & local_node_ids))
        direct_signal_ids = {
            item.signal_id
            for item in critical_local
            if item.node_id in target_node_ids
        }
        target_signal_ids = tuple(sorted(
            direct_signal_ids
            if is_incremental
            else {item.signal_id for item in critical_local}
        ))
        local_changed_ranges = {
            path: tuple(tuple(pair) for pair in changed_line_ranges[path])
        } if path in changed_line_ranges else {}
        routed = _route_file(
            path=path,
            local_signals=local_signals,
            matching_slices=matching_slices,
            all_signals=graph.signals,
            enabled=enabled,
            has_critical=bool(critical_local),
        )
        slice_ids = tuple(sorted(item.slice_id for item in matching_slices))
        risk = max(
            (
                *(item.risk for item in matching_slices),
                *(item.risk for item in local_signals),
                1,
            )
        )
        target_batches = _target_batches(
            path=path,
            target_node_ids=target_node_ids,
            target_signal_ids=target_signal_ids,
        )
        for batch in target_batches:
            for hunter, reasons in _route_target_batch(
                routed=routed,
                batch=batch,
                signals=signals,
            ):
                focus_reasons = list(reasons)
                if batch.target_node_ids:
                    focus_reasons.append("change-focus:direct-node")
                elif batch.target_signal_ids:
                    focus_reasons.append("change-focus:critical-sink")
                focus_reasons.extend((
                    f"coverage-group:{batch.coverage_group}",
                    f"target-batch:{batch.index + 1}/{batch.count}",
                ))
                items.append(HunterWorkItem(
                    work_id=work_id_for(
                        source_snapshot=source_snapshot,
                        planning_policy=ROUTER_POLICY,
                        slice_ids=slice_ids,
                        files=(path,),
                        hunter=hunter,
                        target_node_ids=batch.target_node_ids,
                        target_signal_ids=batch.target_signal_ids,
                        changed_line_ranges=local_changed_ranges,
                        scan_scope_digest=scan_scope_digest,
                    ),
                    run_id=run_id,
                    source_snapshot=source_snapshot,
                    scan_scope_digest=scan_scope_digest,
                    planning_policy=ROUTER_POLICY,
                    slice_ids=slice_ids,
                    target_node_ids=batch.target_node_ids,
                    target_signal_ids=batch.target_signal_ids,
                    changed_line_ranges=local_changed_ranges,
                    seed_file=path,
                    files=(path,),
                    hunter=hunter,
                    risk=risk,
                    required=bool(critical_local),
                    routing_reasons=tuple(sorted(set(focus_reasons))),
                ))

    covered = {
        signal.signal_id
        for signal in critical
        if any(item.seed_file == signal.path for item in items)
    }
    detected = set(active_critical_ids)
    return HunterRoutingPlan(
        policy_version=ROUTER_POLICY,
        legacy_sessions=len(set(selected_files)) * len(set(enabled_hunters)),
        work_items=tuple(sorted(
            items, key=lambda item: (item.seed_file, item.hunter, item.work_id)
        )),
        detected_critical_sink_ids=tuple(sorted(detected)),
        covered_critical_sink_ids=tuple(sorted(covered)),
        uncovered_critical_sink_ids=tuple(sorted(detected - covered)),
        forced_files=forced_files,
        scan_scope_digest=scan_scope_digest,
        scope_deferred_critical_sink_ids=tuple(
            scan_scope.get("scope_deferred_critical_sink_ids", ())
        ),
        repository_complete=bool(scan_scope.get("repository_complete", True)),
    )


def _active_critical_ids(
    analysis: dict | None,
    graph: CAnalysisGraph,
) -> tuple[str, ...]:
    incremental = (analysis or {}).get("incremental_scope") or {}
    scan_scope = (analysis or {}).get("scan_scope") or {}
    if scan_scope.get("mode", "full") != "full":
        active = set(scan_scope.get("in_scope_critical_sink_ids", []))
        return tuple(sorted(active & set(graph.critical_sink_ids)))
    if incremental.get("mode") == "incremental":
        active = set(incremental.get("critical_sink_ids", []))
        return tuple(sorted(active & set(graph.critical_sink_ids)))
    return graph.critical_sink_ids


def _target_batches(
    *,
    path: str,
    target_node_ids: tuple[str, ...],
    target_signal_ids: tuple[str, ...],
) -> tuple[RoutingTargetBatch, ...]:
    """Chunk every explicit target before HunterWorkItem validation."""
    nodes = tuple(sorted(dict.fromkeys(target_node_ids)))
    signals = tuple(sorted(dict.fromkeys(target_signal_ids)))
    node_chunks = tuple(
        nodes[index:index + MAX_HUNTER_TARGET_NODES]
        for index in range(0, len(nodes), MAX_HUNTER_TARGET_NODES)
    ) or ((),)
    signal_chunks = tuple(
        signals[index:index + MAX_HUNTER_TARGET_SIGNALS]
        for index in range(0, len(signals), MAX_HUNTER_TARGET_SIGNALS)
    ) or ((),)
    count = max(len(node_chunks), len(signal_chunks))
    batches = []
    for index in range(count):
        batch_nodes = node_chunks[index] if index < len(node_chunks) else ()
        batch_signals = signal_chunks[index] if index < len(signal_chunks) else ()
        identity = json.dumps(
            {
                "path": path,
                "target_node_ids": batch_nodes,
                "target_signal_ids": batch_signals,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        batches.append(RoutingTargetBatch(
            coverage_group=hashlib.sha256(identity.encode()).hexdigest()[:20],
            index=index,
            count=count,
            target_node_ids=batch_nodes,
            target_signal_ids=batch_signals,
        ))
    return tuple(batches)


def _route_file(
    *,
    path: str,
    local_signals: list[SecuritySignal],
    matching_slices: list,
    all_signals: tuple[SecuritySignal, ...],
    enabled: tuple[str, ...],
    has_critical: bool,
) -> list[tuple[str, list[str]]]:
    scores: dict[str, int] = defaultdict(int)
    reasons: dict[str, set[str]] = defaultdict(set)
    required_specialists: set[str] = set()
    critical_preferences: list[tuple[int, str, str]] = []

    if Path(path).suffix.lower() in {".l", ".y"}:
        scores[PARSER] += 1_000
        reasons[PARSER].add("grammar-source")

    for signal in local_signals:
        mapped = _CATEGORY_HUNTERS.get(signal.category, ())
        if not mapped and signal.risk >= 4:
            mapped = (_critical_fallback(enabled),)
            reasons[mapped[0]].add(f"critical-fallback:{signal.category}")
        for position, hunter in enumerate(mapped):
            scores[hunter] += signal.risk * 100 - position * 10
            reasons[hunter].add(
                f"signal:{signal.category}:{signal.operation}:risk-{signal.risk}"
            )
        if signal.risk >= 4 and mapped:
            required_specialists.add(mapped[0])
            if signal.category != "cursor_index_read":
                critical_preferences.append((
                    -signal.risk,
                    signal.signal_id,
                    mapped[0],
                ))

    contextual = _context_signals(matching_slices, all_signals)
    grammar_context = any(
        Path(file_path).suffix.lower() in {".l", ".y"}
        for item in matching_slices
        for file_path in item.files
    )
    if has_critical and grammar_context and Path(path).suffix.lower() not in {".l", ".y"}:
        scores[PARSER] += 400
        reasons[PARSER].add("cross-file-parser-flow")
        required_specialists.add(PARSER)
    for signal in contextual:
        for hunter in _CATEGORY_HUNTERS.get(signal.category, ())[:1]:
            scores[hunter] += signal.risk * 10
            reasons[hunter].add(f"slice-context:{signal.category}")

    eligible = set(enabled) | required_specialists
    if has_critical and not eligible:
        eligible.add(_critical_fallback(enabled))
    ranked = [
        hunter for hunter, _ in sorted(
            scores.items(), key=lambda item: (-item[1], item[0])
        )
        if hunter in eligible
    ]
    if not ranked:
        fallback = next(iter(enabled), "")
        if not fallback and has_critical:
            fallback = _critical_fallback(enabled)
        if not fallback:
            return []
        ranked = [fallback]
        reasons[fallback].add("fallback:no-specialized-signal")

    preferred = (
        sorted(critical_preferences)[0][2]
        if critical_preferences else ""
    )
    selected = [preferred] if preferred else ranked[:1]
    if has_critical and _cross_file_risk_five(matching_slices):
        if grammar_context and PARSER not in selected:
            selected.append(PARSER)
        else:
            secondary = next(
                (hunter for hunter in ranked if hunter not in selected),
                "",
            )
            if secondary:
                selected.append(secondary)
    selected = list(dict.fromkeys(selected))
    return [
        (hunter, sorted(reasons[hunter] or {"fallback:deterministic"}))
        for hunter in selected
    ]


def _route_target_batch(
    *,
    routed: list[tuple[str, list[str]]],
    batch: RoutingTargetBatch,
    signals: dict[str, SecuritySignal],
) -> list[tuple[str, list[str]]]:
    cursor_targets = [
        signals[signal_id]
        for signal_id in batch.target_signal_ids
        if signal_id in signals
        and signals[signal_id].category == "cursor_index_read"
        and signals[signal_id].risk >= 4
    ]
    if not cursor_targets:
        return routed
    parser_reasons = sorted({
        "required:cursor-transition",
        *(
            f"signal:{signal.category}:{signal.operation}:risk-{signal.risk}"
            for signal in cursor_targets
        ),
    })
    existing = {hunter: reasons for hunter, reasons in routed}
    if PARSER in existing:
        parser_reasons = sorted(set(parser_reasons) | set(existing[PARSER]))
    ordered = [(PARSER, parser_reasons)]
    ordered.extend(
        (hunter, reasons)
        for hunter, reasons in routed
        if hunter != PARSER
    )
    return ordered[:2]


def _context_signals(
    slices: list,
    signals: tuple[SecuritySignal, ...],
) -> list[SecuritySignal]:
    node_ids = {node_id for item in slices for node_id in item.node_ids}
    return [item for item in signals if item.node_id in node_ids]


def _cross_file_risk_five(slices: list) -> bool:
    return any(item.risk >= 5 and len(item.files) > 1 for item in slices)


def _critical_fallback(enabled: tuple[str, ...]) -> str:
    return next((hunter for hunter in _FALLBACKS if hunter in enabled), BOUNDS)


def _fallback_language_plan(
    *,
    run_id: str,
    source_snapshot: str,
    selected_files: list[str],
    enabled_hunters: list[str],
    scan_scope: dict,
) -> HunterRoutingPlan:
    scan_scope_digest = str(scan_scope.get("digest") or "") or None
    hunter = next(iter(enabled_hunters), "")
    items = []
    if hunter:
        for path in sorted(dict.fromkeys(selected_files)):
            items.append(HunterWorkItem(
                work_id=work_id_for(
                    source_snapshot=source_snapshot,
                    planning_policy=ROUTER_POLICY,
                    slice_ids=(),
                    files=(path,),
                    hunter=hunter,
                    scan_scope_digest=scan_scope_digest,
                ),
                run_id=run_id,
                source_snapshot=source_snapshot,
                scan_scope_digest=scan_scope_digest,
                planning_policy=ROUTER_POLICY,
                seed_file=path,
                files=(path,),
                hunter=hunter,
                routing_reasons=("fallback:non-c-language",),
            ))
    return HunterRoutingPlan(
        policy_version=ROUTER_POLICY,
        legacy_sessions=len(set(selected_files)) * len(set(enabled_hunters)),
        work_items=tuple(items),
        scan_scope_digest=scan_scope_digest,
        repository_complete=bool(scan_scope.get("repository_complete", True)),
    )
