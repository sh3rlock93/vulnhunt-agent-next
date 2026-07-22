"""Deterministic analysis graphs, coverage plans, and Hunter context."""

from .c_graph import build_c_analysis_graph
from .capacity import (
    CAPACITY_FACT_POLICY,
    MAX_ALIAS_HOPS,
    MAX_CAPACITY_TRANSFORMS,
    extract_capacity_facts,
)
from .context import context_for_file, context_for_work_item
from .context_cache import (
    CONTEXT_CACHE_POLICY,
    SharedContextCache,
    context_cache_key,
)
from .constraints import CONSTRAINT_POLICY, extract_constraint_facts
from .incremental import INCREMENTAL_POLICY, build_incremental_scope
from .scope import SCAN_SCOPE_POLICY, build_scan_scope
from .models import (
    AnalysisSlice,
    CAnalysisGraph,
    CapacityFact,
    CapacityFactKind,
    ConstraintFact,
    ConstraintKind,
    CoveragePlan,
    EdgeKind,
    GraphEdge,
    GraphNode,
    GuardState,
    IncrementalScope,
    NodeKind,
    RiskChain,
    RiskTransform,
    SecuritySignal,
    SignalRole,
)
from .planner import build_coverage_plan
from .risk_chains import RISK_CHAIN_POLICY

__all__ = [
    "AnalysisSlice",
    "CAnalysisGraph",
    "CapacityFact",
    "CapacityFactKind",
    "ConstraintFact",
    "ConstraintKind",
    "CoveragePlan",
    "EdgeKind",
    "GraphEdge",
    "GraphNode",
    "GuardState",
    "IncrementalScope",
    "NodeKind",
    "RiskChain",
    "RiskTransform",
    "SecuritySignal",
    "SignalRole",
    "RISK_CHAIN_POLICY",
    "build_c_analysis_graph",
    "build_coverage_plan",
    "context_for_file",
    "context_for_work_item",
    "CONTEXT_CACHE_POLICY",
    "CONSTRAINT_POLICY",
    "SharedContextCache",
    "INCREMENTAL_POLICY",
    "SCAN_SCOPE_POLICY",
    "build_incremental_scope",
    "build_scan_scope",
    "context_cache_key",
    "extract_constraint_facts",
    "CAPACITY_FACT_POLICY",
    "MAX_ALIAS_HOPS",
    "MAX_CAPACITY_TRANSFORMS",
    "extract_capacity_facts",
]
