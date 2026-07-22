"""Step 2: deterministic C call/dataflow graph and coverage plan."""
from __future__ import annotations

from pathlib import Path

from ..analysis import (
    build_c_analysis_graph,
    build_coverage_plan,
    build_incremental_scope,
    build_scan_scope,
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
        scope_mode = str(config.get("scan_scope_mode") or "full")
        if scope_mode != "full" and (
            config.get("scan_base_ref") or config.get("scan_head_ref")
        ):
            raise ValueError(
                "explicit bounded scope cannot be combined with Git diff refs"
            )
        scan_scope = build_scan_scope(
            Path(config["repo_path"]),
            source_files=source_files,
            graph=graph,
            coverage=plan,
            mode=scope_mode,
            include_paths=config.get("scan_scope_include_paths") or (),
            exclude_paths=config.get("scan_scope_exclude_paths") or (),
        )
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
        scan_scope = build_scan_scope(
            Path(config["repo_path"]),
            source_files=source_files,
            graph=graph,
            coverage=plan,
            mode=str(config.get("scan_scope_mode") or "full"),
            include_paths=config.get("scan_scope_include_paths") or (),
            exclude_paths=config.get("scan_scope_exclude_paths") or (),
        )

    result = {
        "language": language,
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": plan.model_dump(mode="json"),
        "incremental_scope": incremental.model_dump(mode="json"),
        "scan_scope": scan_scope.model_dump(mode="json"),
        "summary": {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "entrypoints": len(graph.entrypoint_ids),
            "critical_sinks": len(graph.critical_sink_ids),
            "risk_chains": len(graph.risk_chains),
            "constraint_facts": len(graph.constraint_facts),
            "critical_risk_chains": sum(
                item.score >= 80 and item.guard_state.value != "dominates"
                for item in graph.risk_chains
            ),
            "slices": len(plan.slices),
            "selected_files": len(plan.selected_files),
            "coverage_complete": plan.complete,
            "scan_mode": incremental.mode,
            "changed_files": len(incremental.changed_files),
            "impacted_files": len(incremental.selected_files),
            "file_reduction_percent": incremental.file_reduction_percent,
            "incremental_fallback_reason": incremental.fallback_reason,
            "scope_mode": scan_scope.mode.value,
            "scope_selected_files": len(scan_scope.selected_files),
            "scope_deferred_critical_sinks": len(
                scan_scope.scope_deferred_critical_sink_ids
            ),
            "repository_complete": scan_scope.repository_complete,
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
