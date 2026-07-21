"""Legacy-equivalent planning used to establish a measurable M8 baseline."""
from __future__ import annotations

import hashlib
import json

from ..domain.schemas import HunterWorkItem

SHADOW_POLICY = "legacy-cartesian-shadow-v1"


def work_id_for(
    *,
    source_snapshot: str,
    planning_policy: str,
    slice_ids: tuple[str, ...],
    files: tuple[str, ...],
    hunter: str,
    pass_index: int = 1,
    target_node_ids: tuple[str, ...] = (),
    target_signal_ids: tuple[str, ...] = (),
    changed_line_ranges: dict[str, tuple[tuple[int, int], ...]] | None = None,
) -> str:
    identity = {
        "source_snapshot": source_snapshot,
        "planning_policy": planning_policy,
        "slice_ids": sorted(slice_ids),
        "files": sorted(files),
        "hunter": hunter,
        "pass_index": pass_index,
        "target_node_ids": sorted(target_node_ids),
        "target_signal_ids": sorted(target_signal_ids),
        "changed_line_ranges": {
            path: sorted(ranges)
            for path, ranges in sorted((changed_line_ranges or {}).items())
        },
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return "work_" + hashlib.sha256(canonical.encode()).hexdigest()


def build_shadow_plan(
    *,
    run_id: str,
    source_snapshot: str,
    selected_files: list[str],
    hunters: list[str],
    analysis: dict | None,
) -> tuple[HunterWorkItem, ...]:
    """Return the exact legacy file × Hunter plan without changing execution."""
    plan = (analysis or {}).get("coverage_plan") or {}
    slices = list(plan.get("slices", []))
    items: list[HunterWorkItem] = []
    for path in sorted(dict.fromkeys(selected_files)):
        matching = [
            item for item in slices
            if path in item.get("files", [])
        ]
        slice_ids = tuple(sorted(
            item["slice_id"] for item in matching if item.get("slice_id")
        ))
        risk = max((int(item.get("risk", 1)) for item in matching), default=1)
        for hunter in sorted(dict.fromkeys(hunters)):
            files = (path,)
            items.append(HunterWorkItem(
                work_id=work_id_for(
                    source_snapshot=source_snapshot,
                    planning_policy=SHADOW_POLICY,
                    slice_ids=slice_ids,
                    files=files,
                    hunter=hunter,
                ),
                run_id=run_id,
                source_snapshot=source_snapshot,
                planning_policy=SHADOW_POLICY,
                slice_ids=slice_ids,
                seed_file=path,
                files=files,
                hunter=hunter,
                risk=risk,
                required=any(
                    item.get("sink_signal_id") and int(item.get("risk", 1)) >= 4
                    for item in matching
                ),
                routing_reasons=("shadow:legacy-cartesian",),
            ))
    return tuple(items)
