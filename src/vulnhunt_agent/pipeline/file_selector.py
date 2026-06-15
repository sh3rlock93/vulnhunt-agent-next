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
    prev = store.load_step("file_selector") or {}

    bus.emit("step_start", step="file_selector")

    scores = {r["path"]: int(r.get("score", 0)) for r in ranked.get("all", [])}
    files = [
        {"path": p, "score": scores.get(p, 0)}
        for p in filtered.get("source_files", [])
    ]
    files.sort(key=lambda f: (-f["score"], f["path"]))

    # Preserve user's selection across re-runs (e.g. when rank fires this again).
    # Fall back to score>=5 default only on first build.
    prev_selected = prev.get("selected")
    if prev_selected is not None:
        valid = {f["path"] for f in files}
        selected = [p for p in prev_selected if p in valid]
    elif scores:
        selected = [f["path"] for f in files if f["score"] >= DEFAULT_THRESHOLD]
    else:
        selected = []

    store.save_step("file_selector", {"files": files, "selected": selected})
    bus.emit("step_done", step="file_selector",
             total=len(files), selected=len(selected),
             ranked=bool(scores))


register(Step(
    name="file_selector",
    title="3. File Selector",
    fn=run_file_selector,
    depends_on=["filtered_files"],   # rank is optional, not in deps
))
