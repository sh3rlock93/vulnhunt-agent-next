"""Step 2: deterministic C call/dataflow graph and coverage plan."""
from __future__ import annotations

from pathlib import Path

from ..analysis import (
    build_c_analysis_graph,
    build_coverage_plan,
    build_incremental_scope,
)
from ..analysis.models import CAnalysisGraph, IncrementalScope
from ..core.events import EventBus
from ..core.run_store import RunStore
from ..core.v2_run import advance_run
from ..domain.states import RunState
from ..sandbox import language_of
from .registry import Step, register


async def run_analysis_graph(store: RunStore, bus: EventBus) -> None:
    config = store.load_config() or {}
    filtered = store.load_step("filtered_files") or {}
    language = language_of(config["environment"])
    source_files = list(filtered.get("source_files", []))
    bus.emit(
        "step_start",
        step="analysis_graph",
        language=language,
        files=len(source_files),
    )

    if language == "c":
        graph = build_c_analysis_graph(Path(config["repo_path"]), source_files)
        plan = build_coverage_plan(graph)
        incremental = build_incremental_scope(
            Path(config["repo_path"]),
            base_ref=config.get("scan_base_ref"),
            head_ref=config.get("scan_head_ref"),
            graph=graph,
            coverage=plan,
        )
    else:
        graph = CAnalysisGraph(language=language)
        plan = build_coverage_plan(graph)
        incremental = IncrementalScope(
            mode="full",
            fallback_reason="non_c_environment",
        )

    result = {
        "language": language,
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": plan.model_dump(mode="json"),
        "incremental_scope": incremental.model_dump(mode="json"),
        "summary": {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "entrypoints": len(graph.entrypoint_ids),
            "critical_sinks": len(graph.critical_sink_ids),
            "slices": len(plan.slices),
            "selected_files": len(plan.selected_files),
            "coverage_complete": plan.complete,
            "scan_mode": incremental.mode,
            "changed_files": len(incremental.changed_files),
            "impacted_files": len(incremental.selected_files),
            "file_reduction_percent": incremental.file_reduction_percent,
            "incremental_fallback_reason": incremental.fallback_reason,
        },
    }
    store.save_step("analysis_graph", result)
    advance_run(
        store,
        RunState.PLANNING,
        reason="analysis graph and coverage planning started",
    )
    bus.emit("step_done", step="analysis_graph", **result["summary"])


register(Step(
    name="analysis_graph",
    title="3. C Analysis Graph",
    fn=run_analysis_graph,
    depends_on=["filtered_files"],
))
