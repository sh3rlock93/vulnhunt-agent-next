"""Run a single pipeline step in a detached process.

Usage:  python -m vulnhunt_agent._runner <run_id> <step_name>

Writes a PID lockfile on start and removes it on exit (success or crash).
The Streamlit UI uses these lockfiles to track which steps are live.

SIGTERM is converted to KeyboardInterrupt so the `finally` block (and the
sandbox cleanup atexit handler) gets to run before the process exits — this is
how we avoid leaking docker containers when the user clicks "Stop" in the UI.
"""
from __future__ import annotations

import asyncio
import os
import signal
import sys
import traceback

from .core.events import EventBus
from .core.run_store import RUNS_ROOT, RunStore
from .pipeline import STEPS


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: python -m vulnhunt_agent._runner <run_id> <step>")

    run_id, step_name = sys.argv[1], sys.argv[2]
    step = next((s for s in STEPS if s.name == step_name), None)
    if step is None:
        raise SystemExit(f"unknown step: {step_name}")

    signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)

    store = RunStore(RUNS_ROOT / run_id)
    bus = EventBus(store.dir / "events.jsonl")
    lock = store.dir / f".{step_name}.pid"
    lock.write_text(str(os.getpid()))
    try:
        asyncio.run(step.fn(store, bus))
    except KeyboardInterrupt:
        bus.emit("step_stopped", step=step_name)
        raise
    except Exception:
        bus.emit("step_error", step=step_name, traceback=traceback.format_exc())
        raise
    finally:
        lock.unlink(missing_ok=True)


def _raise_keyboard_interrupt(signum, frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    main()
