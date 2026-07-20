"""Hunt step view: hunter picker + per-hunter queue table.

Each row = one (file, hunter) pair = one HunterAgent task. File-level state
(cluster_status, reviews) is tracked on disk for debugging but hidden from
the queue table — operators want hunter progress, not pipeline phases.
"""
from __future__ import annotations

import json

import streamlit as st

from ...agents.queue import HuntQueueStore
from ...agents.durable_queue import DurableHuntQueueStore
from ...core.run_store import RunStore
from ...prompts import hunters_for
from ...sandbox import language_of


def render_hunt_view(store: RunStore) -> None:
    _render_hunter_picker(store)
    plan = store.load_step("hunt_plan") or {}
    if plan:
        mode = plan.get("mode", "legacy")
        scheduled = plan.get("scheduled_sessions", len(plan.get("work_items", [])))
        legacy = plan.get("legacy_pairs", scheduled)
        reduction = plan.get("session_reduction_percent", 0)
        st.caption(
            f"Scheduler: {mode} · {scheduled} sessions "
            f"(legacy {legacy}, {reduction:.1f}% reduction) · "
            f"critical sinks {len(plan.get('covered_critical_sink_ids', []))}/"
            f"{len(plan.get('detected_critical_sink_ids', []))} covered"
        )
        if plan.get("uncovered_critical_sink_ids"):
            st.error(
                "Critical sinks were not routed: "
                + ", ".join(plan["uncovered_critical_sink_ids"])
            )

    durable = DurableHuntQueueStore(
        store.dir / "hunters",
        store.dir / "state.db",
        store.dir.name,
    )
    qstore = (
        durable
        if durable.has_durable_tasks()
        else HuntQueueStore(store.dir / "hunters")
    )
    queue = qstore.load()

    st.divider()
    c1, c2 = st.columns([5, 1])
    c1.markdown("**Queue**")
    if c2.button("🔄 Refresh", key="hunt_refresh", use_container_width=True):
        st.rerun()

    if not queue.tasks:
        st.caption("queue not initialized yet — click Refresh in a moment")
        return

    rows = list(_iter_hunter_rows(queue))

    counts = {"done": 0, "running": 0, "pending": 0, "failed": 0}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    cols = st.columns(4)
    for col, key in zip(cols, ("done", "running", "pending", "failed")):
        col.metric(key, counts.get(key, 0))

    if counts.get("failed") and st.button("Reset failed → pending"):
        n = qstore.reset_failed()
        st.success(f"reset {n}")
        st.rerun()

    st.dataframe(rows, use_container_width=True, hide_index=True)


def _iter_hunter_rows(queue) -> list[dict]:
    """Flatten file × hunter sub-tasks into hunter-level rows."""
    out = []
    for t in queue.tasks:
        for sub in t.hunters:
            out.append({
                "status": sub.status,
                "hunter": sub.name,
                "file": t.file,
                "context_files": len(t.files) or 1,
                "slices": len(t.slice_ids),
                "risk": t.risk,
                "required": t.required,
                "findings": sub.findings_count,
                "started_at": sub.started_at.replace("T", " ") if sub.started_at else "",
                "error": sub.error[:80] if sub.error else "",
            })
    return out


def _render_hunter_picker(store: RunStore) -> None:
    cfg = store.load_config() or {}
    env = cfg.get("environment")
    if not env:
        st.caption("Hunters: pick an environment in the sidebar first.")
        return
    lang = language_of(env)

    sel_path = store.dir / "steps" / "hunter_selection.json"
    legacy = store.dir / "steps" / "category_selection.json"
    has_saved_selection = sel_path.exists() or legacy.exists()
    if not sel_path.exists() and legacy.exists():
        # Older runs stored selection under "categories"; migrate.
        saved = json.loads(legacy.read_text()).get("categories", [])
    elif sel_path.exists():
        saved = json.loads(sel_path.read_text()).get("hunters", [])
    else:
        saved = []
    selected = set(saved)
    available = hunters_for(lang)
    if not has_saved_selection:
        selected = {hunter.name for hunter in available if hunter.default}
        sel_path.parent.mkdir(parents=True, exist_ok=True)
        sel_path.write_text(json.dumps(
            {"hunters": sorted(selected)}, indent=2
        ))

    if len(available) <= 1:
        names = [h.name for h in available]
        if set(names) != selected:
            sel_path.parent.mkdir(parents=True, exist_ok=True)
            sel_path.write_text(json.dumps({"hunters": names}, indent=2))
        title = available[0].title if available else "(none)"
        st.caption(f"Hunter ({lang}) — {title}")
        return

    st.caption(f"Hunters ({lang})")
    cols = st.columns(3)
    new_selected: list[str] = []
    for i, h in enumerate(available):
        col = cols[i % 3]
        on = col.checkbox(
            h.title, value=(h.name in selected),
            help=h.description, key=f"hunt_pick_{h.name}",
        )
        if on:
            new_selected.append(h.name)

    if set(new_selected) != selected:
        sel_path.parent.mkdir(parents=True, exist_ok=True)
        sel_path.write_text(json.dumps({"hunters": new_selected}, indent=2))
