"""Deterministic analysis graphs, coverage plans, and Hunter context."""

from .c_graph import build_c_analysis_graph
from .context import context_for_file, context_for_work_item
from .models import (
    AnalysisSlice,
    CAnalysisGraph,
    CoveragePlan,
    EdgeKind,
    GraphEdge,
    GraphNode,
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
    "NodeKind",
    "SecuritySignal",
    "SignalRole",
    "build_c_analysis_graph",
    "build_coverage_plan",
    "context_for_file",
    "context_for_work_item",
]
