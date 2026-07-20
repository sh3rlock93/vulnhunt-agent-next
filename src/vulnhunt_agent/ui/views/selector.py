"""File Selector view: pick which files to hunt."""
from __future__ import annotations

import streamlit as st

from ...core.run_store import RunStore


def render_selector_view(store: RunStore) -> None:
    data = store.load_step("file_selector") or {}
    files = data.get("files") or []
    saved = set(data.get("selected") or [])
    if not files:
        st.caption("no files yet")
        return

    rows = [
        {
            "selected": f["path"] in saved,
            "risk": f.get("analysis_priority", 0),
            "score": f["score"],
            "coverage": ", ".join(f.get("coverage_reasons", [])),
            "file": f["path"],
        }
        for f in files
    ]
    rows.sort(key=lambda r: (
        not r["selected"], -r["risk"], -r["score"], r["file"]
    ))

    query = st.text_input("Search file", "", key="selector_search").strip().lower()
    shown = [r for r in rows if not query or query in r["file"].lower()]

    save_bar = st.empty()
    edited = st.data_editor(
        shown,
        column_config={
            "selected": st.column_config.CheckboxColumn("✓", width="small"),
            "risk": st.column_config.NumberColumn(
                "Graph risk", disabled=True, width="small"
            ),
            "score": st.column_config.NumberColumn("Score", disabled=True, width="small"),
            "coverage": st.column_config.TextColumn("Coverage", disabled=True),
            "file": st.column_config.TextColumn("File", disabled=True),
        },
        hide_index=True, use_container_width=True, key="selector_editor",
    )

    picked = [r["file"] for r in edited if r["selected"]]
    shown_paths = {r["file"] for r in shown}
    with save_bar.container():
        c1, c2, c3, c4 = st.columns([3, 1, 1, 1])
        c1.caption(
            f"Selected: {len(picked)} / {len(rows)}  ·  "
            f"shown: {len(shown)}  ·  saved: {len(saved)}"
        )
        select_all = c2.button(
            "Select shown", use_container_width=True, key="selector_all",
        )
        clear_shown = c3.button(
            "Clear shown", use_container_width=True, key="selector_clear",
        )
        save_clicked = c4.button(
            "💾 Save", use_container_width=True,
            key="selector_save", type="primary",
        )

    if select_all:
        data["selected"] = sorted(saved | shown_paths)
        store.save_step("file_selector", data)
        st.toast(f"Selected {len(shown_paths)} shown files", icon="✅")
        st.rerun()
    if clear_shown:
        data["selected"] = sorted(saved - shown_paths)
        store.save_step("file_selector", data)
        st.toast(f"Cleared {len(shown_paths & saved)} shown files", icon="🗑️")
        st.rerun()
    if save_clicked:
        data["selected"] = picked
        store.save_step("file_selector", data)
        st.toast(f"Saved {len(picked)} files", icon="✅")
        st.rerun()
