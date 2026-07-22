"""Bounded graph context passed to each file-scoped Hunter."""
from __future__ import annotations

from ..domain.schemas import HunterWorkItem

MAX_RELATED_CONTEXT_NODES = 16
MAX_CONTEXT_CONSTRAINTS = 24


def context_for_file(
    analysis: dict | None,
    path: str,
    *,
    max_slices: int = 12,
) -> dict:
    if not analysis or analysis.get("language") != "c":
        return {}
    graph = analysis.get("graph") or {}
    plan = analysis.get("coverage_plan") or {}
    nodes = {item["node_id"]: item for item in graph.get("nodes", [])}
    signals = {item["signal_id"]: item for item in graph.get("signals", [])}
    matching = [
        item for item in plan.get("slices", [])
        if path in item.get("files", [])
    ][:max_slices]
    if not matching:
        return {}
    compact = []
    for item in matching:
        compact.append({
            "slice_id": item["slice_id"],
            "risk": item["risk"],
            "categories": item.get("categories", []),
            "rationale": item["rationale"],
            "path": [
                {
                    "node_id": node_id,
                    "file": nodes[node_id]["path"],
                    "symbol": nodes[node_id]["symbol"],
                    "line": nodes[node_id]["line"],
                }
                for node_id in item["node_ids"]
                if node_id in nodes
            ],
            "sink": signals.get(item.get("sink_signal_id")),
        })
    return {
        "policy_version": plan.get("policy_version", ""),
        "target_file": path,
        "slices": compact,
        "file_reasons": plan.get("file_reasons", {}).get(path, []),
    }


def context_for_work_item(
    analysis: dict | None,
    work_item: HunterWorkItem,
    *,
    max_slices: int = 6,
) -> dict:
    """Exact multi-file slice context for one stable Hunter work item."""
    if not analysis or analysis.get("language") != "c":
        return {
            "target_file": work_item.seed_file,
            "context_files": list(work_item.files),
            "slices": [],
        }
    graph = analysis.get("graph") or {}
    plan = analysis.get("coverage_plan") or {}
    nodes = {item["node_id"]: item for item in graph.get("nodes", [])}
    signals = {item["signal_id"]: item for item in graph.get("signals", [])}
    related_nodes = _related_nodes(graph, work_item)
    constraint_facts = _constraint_facts(graph, work_item, related_nodes)
    risk_chains = _select_focus_chains(
        _matching_risk_chains(graph, work_item),
        work_item.focus_chain_ids,
        support_limit=6,
    )
    capacity_chains = _select_focus_chains(
        matching_capacity_risk_chains(graph, work_item),
        work_item.focus_chain_ids,
        support_limit=3,
    )
    selected_ids = set(work_item.slice_ids)
    matching = [
        item for item in plan.get("slices", [])
        if item.get("slice_id") in selected_ids
    ][:max_slices]
    compact = []
    for item in matching:
        compact.append({
            "slice_id": item["slice_id"],
            "risk": item["risk"],
            "categories": item.get("categories", []),
            "rationale": item["rationale"],
            "path": [
                {
                    "node_id": node_id,
                    "file": nodes[node_id]["path"],
                    "symbol": nodes[node_id]["symbol"],
                    "line": nodes[node_id]["line"],
                }
                for node_id in item["node_ids"]
                if node_id in nodes
                and nodes[node_id]["path"] in work_item.files
            ],
            "sink": signals.get(item.get("sink_signal_id")),
        })
    return {
        "policy_version": plan.get("policy_version", ""),
        "work_id": work_item.work_id,
        "target_file": work_item.seed_file,
        "context_files": list(work_item.files),
        "slice_ids": list(work_item.slice_ids),
        "risk": work_item.risk,
        "required": work_item.required,
        "routing_reasons": list(work_item.routing_reasons),
        "scan_scope_digest": work_item.scan_scope_digest,
        "focus_chain_ids": list(work_item.focus_chain_ids),
        "full_snapshot_context": True,
        "related_nodes": related_nodes,
        "constraint_policy_version": (
            constraint_facts[0].get("policy_version", "")
            if constraint_facts else "c-constraint-v1"
        ),
        "constraint_facts": constraint_facts,
        "risk_chain_policy_version": (
            risk_chains[0].get("policy_version", "") if risk_chains else ""
        ),
        "risk_chains": [_compact_risk_chain(item) for item in risk_chains],
        "capacity_risk_chain_policy_version": (
            capacity_chains[0].get("policy_version", "") if capacity_chains else ""
        ),
        "capacity_risk_chains": capacity_chains,
        "change_focus": {
            "target_node_ids": list(work_item.target_node_ids),
            "target_signal_ids": list(work_item.target_signal_ids),
            "changed_line_ranges": {
                path: [list(pair) for pair in ranges]
                for path, ranges in work_item.changed_line_ranges.items()
            },
        },
        "slices": compact,
    }


def matching_risk_chains(graph: dict, work_item: HunterWorkItem) -> list[dict]:
    """Public deterministic matching used by context packets and cache keys."""
    return matching_risk_chains_for_targets(
        graph,
        target_signal_ids=set(work_item.target_signal_ids),
        target_node_ids=set(work_item.target_node_ids),
    )


def matching_capacity_risk_chains(
    graph: dict,
    work_item: HunterWorkItem,
) -> list[dict]:
    return matching_capacity_risk_chains_for_targets(
        graph,
        target_signal_ids=set(work_item.target_signal_ids),
        target_node_ids=set(work_item.target_node_ids),
    )


def matching_capacity_risk_chains_for_targets(
    graph: dict,
    *,
    target_signal_ids: set[str],
    target_node_ids: set[str],
) -> list[dict]:
    matching = []
    for chain in graph.get("capacity_risk_chains", []):
        chain_signals = set(chain.get("allocation_signal_ids", ())) | set(
            chain.get("write_signal_ids", ())
        )
        if (
            target_signal_ids & chain_signals
            or target_node_ids & set(chain.get("node_ids", ()))
        ):
            matching.append(chain)
    priority = {
        "complete_unchecked_capacity_path": 0,
        "complete_unknown_guard_path": 1,
        "partial_capacity_path": 2,
        "isolated_allocation_or_write": 3,
    }
    return sorted(
        matching,
        key=lambda item: (
            priority.get(str(item.get("priority_class", "")), 4),
            -int(item.get("score", 0)),
            str(item.get("chain_id", "")),
        ),
    )


def _matching_risk_chains(graph: dict, work_item: HunterWorkItem) -> list[dict]:
    return matching_risk_chains(graph, work_item)


def _focus_first(chains: list[dict], focus_chain_ids: tuple[str, ...]) -> list[dict]:
    order = {chain_id: index for index, chain_id in enumerate(focus_chain_ids)}
    return sorted(
        chains,
        key=lambda chain: (
            0 if str(chain.get("chain_id", "")) in order else 1,
            order.get(str(chain.get("chain_id", "")), len(order)),
        ),
    )


def _select_focus_chains(
    chains: list[dict],
    focus_chain_ids: tuple[str, ...] | set[str],
    *,
    support_limit: int,
) -> list[dict]:
    ordered_focus_ids = (
        focus_chain_ids
        if isinstance(focus_chain_ids, tuple)
        else tuple(sorted(focus_chain_ids))
    )
    ordered = _focus_first(chains, ordered_focus_ids)
    focus = set(focus_chain_ids)
    focused = [
        chain for chain in ordered
        if str(chain.get("chain_id", "")) in focus
    ]
    supporting = [
        chain for chain in ordered
        if str(chain.get("chain_id", "")) not in focus
    ]
    return [*focused, *supporting[:support_limit]]


def matching_risk_chains_for_targets(
    graph: dict,
    *,
    target_signal_ids: set[str],
    target_node_ids: set[str],
) -> list[dict]:
    matching = []
    for chain in graph.get("risk_chains", []):
        chain_signals = set(chain.get("allocation_signal_ids", ())) | set(
            chain.get("sink_signal_ids", ())
        )
        if (
            target_signal_ids & chain_signals
            or chain.get("node_id") in target_node_ids
        ):
            matching.append(chain)
    return sorted(
        matching,
        key=lambda item: (-int(item.get("score", 0)), str(item.get("chain_id", ""))),
    )


def _compact_risk_chain(chain: dict) -> dict:
    return {
        "chain_id": chain.get("chain_id", ""),
        "policy_version": chain.get("policy_version", ""),
        "path": chain.get("path", ""),
        "function": chain.get("function", ""),
        "score": int(chain.get("score", 0)),
        "confidence": chain.get("confidence", ""),
        "guard_state": chain.get("guard_state", "unknown"),
        "source_signal_ids": list(chain.get("source_signal_ids", ())),
        "source_variables": list(chain.get("source_variables", ())),
        "source_lines": list(chain.get("source_lines", ())),
        "transform_steps": list(chain.get("transform_steps", ()))[:8],
        "guard_lines": list(chain.get("guard_lines", ())),
        "allocation_signal_ids": list(chain.get("allocation_signal_ids", ())),
        "sink_signal_ids": list(chain.get("sink_signal_ids", ())),
        "sink_lines": list(chain.get("sink_lines", ())),
        "rationale": chain.get("rationale", ""),
    }


def _related_nodes(graph: dict, work_item: HunterWorkItem) -> list[dict]:
    nodes = {item["node_id"]: item for item in graph.get("nodes", [])}
    signals = {item["signal_id"]: item for item in graph.get("signals", [])}
    target_ids = set(work_item.target_node_ids)
    target_ids.update(
        signals[signal_id]["node_id"]
        for signal_id in work_item.target_signal_ids
        if signal_id in signals
    )
    aliases = {
        alias
        for node_id in target_ids
        for alias in (
            nodes.get(node_id, {}).get("symbol", ""),
            *nodes.get(node_id, {}).get("aliases", ()),
        )
        if alias
    }
    relationships: dict[str, tuple[str, str]] = {}
    for edge in graph.get("edges", []):
        source = str(edge.get("source", ""))
        target = str(edge.get("target", ""))
        if target in target_ids and source in nodes:
            relationships[source] = ("caller", str(edge.get("kind", "call")))
        if source in target_ids and target in nodes:
            relationships.setdefault(
                target,
                ("callee", str(edge.get("kind", "call"))),
            )
    for call in graph.get("unresolved_calls", []):
        source = str(call.get("source", ""))
        if source in nodes and str(call.get("callee", "")) in aliases:
            relationships[source] = (
                "caller",
                f"indirect:{call.get('callee', '')}",
            )
    ordered = sorted(
        relationships.items(),
        key=lambda item: (
            0 if item[1][0] == "caller" else 1,
            item[0],
        ),
    )[:MAX_RELATED_CONTEXT_NODES]
    return [
        {
            "node_id": node_id,
            "path": nodes[node_id]["path"],
            "symbol": nodes[node_id]["symbol"],
            "line": int(nodes[node_id]["line"]),
            "end_line": int(nodes[node_id]["end_line"]),
            "relationship": relationship,
            "via": via,
        }
        for node_id, (relationship, via) in ordered
    ]


def _constraint_facts(
    graph: dict,
    work_item: HunterWorkItem,
    related_nodes: list[dict],
) -> list[dict]:
    signals = {item["signal_id"]: item for item in graph.get("signals", [])}
    target_ids = set(work_item.target_node_ids)
    target_ids.update(
        signals[signal_id]["node_id"]
        for signal_id in work_item.target_signal_ids
        if signal_id in signals
    )
    related_ids = {item["node_id"] for item in related_nodes}
    kind_rank = {
        "buffer_size_bound": 0,
        "numeric_bound": 1,
        "dominant_guard": 2,
        "minimum_consumption": 3,
        "narrowing": 4,
    }
    facts = [
        {**item, "relevance": "target" if item.get("node_id") in target_ids else "related"}
        for item in graph.get("constraint_facts", [])
        if item.get("node_id") in target_ids | related_ids
    ]
    return sorted(
        facts,
        key=lambda item: (
            0 if item["relevance"] == "target" else 1,
            kind_rank.get(str(item.get("kind", "")), 9),
            str(item.get("fact_id", "")),
        ),
    )[:MAX_CONTEXT_CONSTRAINTS]
