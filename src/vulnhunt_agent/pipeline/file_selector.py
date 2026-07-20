"""Step: FileSelector — pick which files Hunters will run on.

Merges filter output with optional ranker scores. UI edits `selected` in place;
the rest of file_selector.json is owned by this step.
"""
from __future__ import annotations

from ..core.events import EventBus
from ..core.run_store import RunStore
from .registry import Step, register


DEFAULT_THRESHOLD = 5


async def run_file_selector(store: RunStore, bus: EventBus) -> None:
    filtered = store.load_step("filtered_files") or {}
    ranked = store.load_step("ranked_files") or {}
    analysis = store.load_step("analysis_graph") or {}
    prev = store.load_step("file_selector") or {}

    bus.emit("step_start", step="file_selector")

    scores = {r["path"]: int(r.get("score", 0)) for r in ranked.get("all", [])}
    plan = analysis.get("coverage_plan") or {}
    incremental = analysis.get("incremental_scope") or {}
    incremental_mode = incremental.get("mode") == "incremental"
    full_planned = set(plan.get("selected_files", []))
    planned = (
        set(incremental.get("selected_files", []))
        if incremental_mode
        else full_planned
    )
    reasons = plan.get("file_reasons", {})
    priorities: dict[str, int] = {}
    slice_ids: dict[str, list[str]] = {}
    for item in plan.get("slices", []):
        for path in item.get("files", []):
            priorities[path] = max(priorities.get(path, 0), int(item.get("risk", 0)))
            slice_ids.setdefault(path, []).append(item["slice_id"])
    files = []
    for p in filtered.get("source_files", []):
        item = {
            "path": p,
            "score": scores.get(p, 0),
            "analysis_priority": priorities.get(p, 0),
            "coverage_reasons": list(reasons.get(p, [])),
            "slice_ids": sorted(slice_ids.get(p, [])),
        }
        if incremental_mode:
            item["in_incremental_scope"] = p in planned
        files.append(item)
    files.sort(key=lambda f: (
        -f["analysis_priority"], -f["score"], f["path"]
    ))

    # Preserve user's selection across re-runs (e.g. when rank fires this again).
    # Fall back to score>=5 default only on first build.
    prev_selected = prev.get("selected")
    previous_incremental = prev.get("incremental_scope") or {}
    same_incremental_scope = (
        not incremental_mode
        or (
            previous_incremental.get("base_commit")
            == incremental.get("base_commit")
            and previous_incremental.get("head_commit")
            == incremental.get("head_commit")
        )
    )
    if prev_selected is not None and same_incremental_scope:
        valid = {f["path"] for f in files}
        selected = [p for p in prev_selected if p in valid]
    elif incremental_mode:
        selected = [p for p in planned if p in {f["path"] for f in files}]
    elif scores:
        selected = [
            f["path"] for f in files
            if f["path"] in planned or f["score"] >= DEFAULT_THRESHOLD
        ]
    else:
        selected = [f["path"] for f in files if f["path"] in planned]

    result = {
        "files": files,
        "selected": selected,
        "coverage_complete": not plan.get("uncovered_entrypoint_ids")
        and not plan.get("uncovered_sink_ids"),
        "coverage_selected": sorted(planned),
    }
    if incremental_mode:
        result.update({
            "full_coverage_selected": sorted(full_planned),
            "incremental_scope": incremental,
        })
    store.save_step("file_selector", result)
    bus.emit("step_done", step="file_selector",
             total=len(files), selected=len(selected),
             ranked=bool(scores), coverage_selected=len(planned))


register(Step(
    name="file_selector",
    title="5. File Selector",
    fn=run_file_selector,
    depends_on=["analysis_graph"],   # rank remains optional
))
