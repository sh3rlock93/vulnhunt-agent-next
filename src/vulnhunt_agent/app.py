"""Streamlit entrypoint. Composes the UI from `ui/` modules."""
from __future__ import annotations

import streamlit as st
from streamlit_autorefresh import st_autorefresh

from vulnhunt_agent.core import proc_lock
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.pipeline import STEPS
from vulnhunt_agent.ui.cost import render_cost_block
from vulnhunt_agent.ui.sidebar import sidebar
from vulnhunt_agent.ui.steps import BACKGROUND_STEPS, render_running_banner, render_step
from vulnhunt_agent.ui.views import render_final_report

st.set_page_config(page_title="Vulnerability Hunting Agent", layout="wide")


def main_panel(store: RunStore) -> None:
    st.title("Vulnerability Hunting Agent")

    if any(proc_lock.is_running(store.dir, s) for s in BACKGROUND_STEPS):
        st_autorefresh(interval=3000, key="bg_poll")

    render_running_banner(store)

    for step in STEPS:
        render_step(store, step)

    render_final_report(store)

    st.divider()
    st.header("Cost")
    render_cost_block(store)


def main() -> None:
    store = sidebar()
    if store is None:
        st.info("Create or select a run from the sidebar.")
        return
    main_panel(store)


main()
