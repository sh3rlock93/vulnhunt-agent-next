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
    max_slices: int = 16,
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
        "slices": compact,
    }
