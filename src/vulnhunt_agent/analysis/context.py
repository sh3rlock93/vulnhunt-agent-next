"""Bounded graph context passed to each file-scoped Hunter."""
from __future__ import annotations

from ..domain.schemas import HunterWorkItem


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
    risk_chains = _matching_risk_chains(graph, work_item)
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
        "risk_chain_policy_version": (
            risk_chains[0].get("policy_version", "") if risk_chains else ""
        ),
        "risk_chains": [
            _compact_risk_chain(item) for item in risk_chains[:6]
        ],
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


def _matching_risk_chains(graph: dict, work_item: HunterWorkItem) -> list[dict]:
    return matching_risk_chains(graph, work_item)


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
