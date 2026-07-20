"""Step 1: create and register the immutable source snapshot."""
from __future__ import annotations

from ..core.events import EventBus
from ..core.run_store import RunStore
from ..core.v2_run import ensure_source_snapshot
from .registry import Step, register


async def run_source_snapshot(store: RunStore, bus: EventBus) -> None:
    bus.emit("step_start", step="source_snapshot")
    snapshot = ensure_source_snapshot(store)
    result = snapshot.model_dump(mode="json")
    store.save_step("source_snapshot", result)
    bus.emit(
        "step_done",
        step="source_snapshot",
        snapshot=snapshot.snapshot_artifact,
        files=snapshot.file_count,
        bytes=snapshot.total_bytes,
    )


register(Step(
    name="source_snapshot",
    title="1. Immutable Source Snapshot",
    fn=run_source_snapshot,
    depends_on=[],
))
