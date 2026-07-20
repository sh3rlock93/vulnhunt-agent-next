"""Step 2: deterministic C call/dataflow graph and coverage plan."""
from __future__ import annotations

from pathlib import Path

from ..analysis import build_c_analysis_graph, build_coverage_plan
from ..analysis.models import CAnalysisGraph
from ..core.events import EventBus
from ..core.run_store import RunStore
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
    else:
        graph = CAnalysisGraph(language=language)
        plan = build_coverage_plan(graph)

    result = {
        "language": language,
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": plan.model_dump(mode="json"),
        "summary": {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "entrypoints": len(graph.entrypoint_ids),
            "critical_sinks": len(graph.critical_sink_ids),
            "slices": len(plan.slices),
            "selected_files": len(plan.selected_files),
            "coverage_complete": plan.complete,
        },
    }
    store.save_step("analysis_graph", result)
    bus.emit("step_done", step="analysis_graph", **result["summary"])


register(Step(
    name="analysis_graph",
    title="2. C Analysis Graph",
    fn=run_analysis_graph,
    depends_on=["filtered_files"],
))
