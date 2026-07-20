"""Bounded graph context passed to each file-scoped Hunter."""
from __future__ import annotations


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
