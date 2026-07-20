"""Deterministic analysis graphs, coverage plans, and Hunter context."""

from .c_graph import build_c_analysis_graph
from .context import context_for_file, context_for_work_item
from .context_cache import (
    CONTEXT_CACHE_POLICY,
    SharedContextCache,
    context_cache_key,
)
from .incremental import INCREMENTAL_POLICY, build_incremental_scope
from .models import (
    AnalysisSlice,
    CAnalysisGraph,
    CoveragePlan,
    EdgeKind,
    GraphEdge,
    GraphNode,
    IncrementalScope,
    NodeKind,
    SecuritySignal,
    SignalRole,
)
from .planner import build_coverage_plan

__all__ = [
    "AnalysisSlice",
    "CAnalysisGraph",
    "CoveragePlan",
    "EdgeKind",
    "GraphEdge",
    "GraphNode",
    "IncrementalScope",
    "NodeKind",
    "SecuritySignal",
    "SignalRole",
    "build_c_analysis_graph",
    "build_coverage_plan",
    "context_for_file",
    "context_for_work_item",
    "CONTEXT_CACHE_POLICY",
    "SharedContextCache",
    "INCREMENTAL_POLICY",
    "build_incremental_scope",
    "context_cache_key",
]
