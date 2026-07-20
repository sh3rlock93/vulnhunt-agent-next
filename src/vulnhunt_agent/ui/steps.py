"""Per-step UI: status, Run/Clear buttons, and a banner for live processes.

Long steps (hunt) run as detached subprocesses tracked via PID lockfiles.
Short steps run inline with a spinner so results show up immediately.
"""
from __future__ import annotations

import asyncio
import subprocess
import sys

import streamlit as st

from ..core import proc_lock
from ..core.events import EventBus
from ..core.run_store import RunStore
from .result_cards import render_prepare_progress, render_prepare_settings, render_result_card
from .views import render_hunt_view, render_selector_view


# Steps that may run for many minutes. Everything else is fast enough to run
# inline with a spinner.
BACKGROUND_STEPS = {"hunt", "sandbox_prepare"}


def render_running_banner(store: RunStore) -> None:
    pass


def render_step(store: RunStore, step) -> None:
    running = proc_lock.is_running(store.dir, step.name)
    done = store.has_step(step.name)
    deps_ok = all(store.has_step(d) for d in step.depends_on)
    status = _status_label(running, done, deps_ok)

    can_clear = done and not running

    with st.expander(f"{step.title}  ·  {status}", expanded=True):
        _action_buttons(store, step, running=running, deps_ok=deps_ok, can_clear=can_clear)
        _render_step_body(store, step, done, running)


def _status_label(running: bool, done: bool, deps_ok: bool) -> str:
    if running:
        return ":blue-background[▶ running]"
    if done:
        return ":green-background[✓ done]"
    if deps_ok:
        return ":gray-background[⏸ pending]"
    return ":gray-background[🔒 locked]"


def _action_buttons(store: RunStore, step, *, running: bool, deps_ok: bool, can_clear: bool) -> None:
    can_run = deps_ok and not running
    c1, c2, c3, _ = st.columns([1, 1, 1, 5])
    if c1.button("Run", key=f"run_{step.name}", disabled=not can_run,
                 use_container_width=True, type="primary" if can_run else "secondary"):
        _run_step(store, step)
        st.rerun()
    if c2.button("Stop", key=f"stop_{step.name}", disabled=not running,
                 use_container_width=True):
        proc_lock.stop(store.dir, step.name)
        st.rerun()
    if c3.button("Clear", key=f"clear_{step.name}", disabled=not can_clear,
                 use_container_width=True):
        (store.dir / "steps" / f"{step.name}.json").unlink(missing_ok=True)
        st.rerun()


def _render_step_body(store: RunStore, step, done: bool, running: bool) -> None:
    if step.name == "sandbox_prepare":
        if running:
            render_prepare_progress(store)
            return
        if done:
            render_result_card(store, step.name)
        render_prepare_settings(store)
        return
    if done:
        render_result_card(store, step.name)
    if step.name == "file_selector" and done:
        render_selector_view(store)
    elif step.name == "hunt":
        render_hunt_view(store)


def _run_step(store: RunStore, step) -> None:
    """Background for long-running steps; inline + spinner for short ones."""
    # Custom-image prepare finishes in <1s — run inline so the UI doesn't
    # flash a Refresh button for a job that's already done.
    cfg = store.load_config() or {}
    if step.name == "sandbox_prepare" and (cfg.get("prepare_mode") or "auto") == "custom":
        bus = EventBus(store.dir / "events.jsonl")
        with st.spinner("Registering custom image..."):
            asyncio.run(step.fn(store, bus))
        return

    if step.name in BACKGROUND_STEPS:
        # Emit a marker step_start now so the progress UI shows *this* run's
        # events from the first render, not the previous run's tail.
        EventBus(store.dir / "events.jsonl").emit("step_start", step=step.name)

        log_fh = (store.dir / f".{step.name}.log").open("ab")
        proc = subprocess.Popen(
            [sys.executable, "-m", "vulnhunt_agent._runner",
             store.dir.name, step.name],
            stdout=log_fh, stderr=log_fh,
            start_new_session=True,
        )
        # Write PID lockfile from the parent immediately. Child rewrites it
        # with the same PID once imports finish; child's finally unlinks it.
        # Without this, the first rerun shows "pending" because the child
        # hasn't finished importing yet.
        (store.dir / f".{step.name}.pid").write_text(str(proc.pid))
        return

    bus = EventBus(store.dir / "events.jsonl")
    with st.spinner(f"Running {step.title}..."):
        asyncio.run(step.fn(store, bus))
