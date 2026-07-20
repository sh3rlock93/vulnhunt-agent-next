"""Validated, deterministic contracts for C security-analysis graphs."""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class AnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class NodeKind(StrEnum):
    FUNCTION = "function"
    GRAMMAR = "grammar"


class EdgeKind(StrEnum):
    CALL = "call"
    PARSER_FLOW = "parser_flow"


class SignalRole(StrEnum):
    SOURCE = "source"
    SINK = "sink"


class GraphNode(AnalysisModel):
    node_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    symbol: str = Field(min_length=1)
    line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    kind: NodeKind
    visibility: str = Field(pattern=r"^(external|internal|generated)$")
    calls: tuple[str, ...] = ()


class GraphEdge(AnalysisModel):
    edge_id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    target: str = Field(min_length=1)
    kind: EdgeKind
    path: str = Field(min_length=1)
    line: int = Field(ge=1)


class SecuritySignal(AnalysisModel):
    signal_id: str = Field(min_length=1)
    node_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    line: int = Field(ge=1)
    role: SignalRole
    category: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    detail: str = ""
    risk: int = Field(ge=1, le=5)


class UnresolvedCall(AnalysisModel):
    source: str = Field(min_length=1)
    path: str = Field(min_length=1)
    line: int = Field(ge=1)
    callee: str = Field(min_length=1)


class CAnalysisGraph(AnalysisModel):
    schema_version: int = 1
    language: str = "c"
    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()
    signals: tuple[SecuritySignal, ...] = ()
    entrypoint_ids: tuple[str, ...] = ()
    critical_sink_ids: tuple[str, ...] = ()
    unresolved_calls: tuple[UnresolvedCall, ...] = ()


class AnalysisSlice(AnalysisModel):
    slice_id: str = Field(min_length=1)
    entrypoint_id: str = Field(min_length=1)
    sink_signal_id: str | None = None
    node_ids: tuple[str, ...] = Field(min_length=1)
    edge_ids: tuple[str, ...] = ()
    files: tuple[str, ...] = Field(min_length=1)
    categories: tuple[str, ...] = ()
    risk: int = Field(ge=1, le=5)
    rationale: str = Field(min_length=1)


class CoveragePlan(AnalysisModel):
    policy_version: str = "c-coverage-v1"
    slices: tuple[AnalysisSlice, ...] = ()
    selected_files: tuple[str, ...] = ()
    file_reasons: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    covered_entrypoint_ids: tuple[str, ...] = ()
    covered_sink_ids: tuple[str, ...] = ()
    uncovered_entrypoint_ids: tuple[str, ...] = ()
    uncovered_sink_ids: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.uncovered_entrypoint_ids and not self.uncovered_sink_ids
