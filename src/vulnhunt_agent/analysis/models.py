"""Validated, deterministic contracts for C security-analysis graphs."""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


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


class GuardState(StrEnum):
    ABSENT = "absent"
    PARTIAL = "partial"
    DOMINATES = "dominates"
    UNKNOWN = "unknown"


class InvariantObligationKind(StrEnum):
    INTEGER_MEMORY_RELATION = "integer_memory_relation"
    CAPACITY_RELATION = "capacity_relation"
    CURSOR_LENGTH_RELATION = "cursor_length_relation"
    FORMATTED_OUTPUT_EXPANSION = "formatted_output_expansion"
    STATEFUL_OUTPUT_CAPACITY = "stateful_output_capacity"


class InvariantClosureState(StrEnum):
    PROVED_SAFE = "proved_safe"
    CANDIDATE = "candidate"
    UNRESOLVED_WITH_EVIDENCE = "unresolved_with_evidence"


class ObligationEvidenceRange(AnalysisModel):
    path: str = Field(min_length=1)
    line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    structural_role: str = Field(
        pattern=r"^(?:source|transform|guard|allocation|state|access|relation)$"
    )

    @model_validator(mode="after")
    def validate_range(self) -> "ObligationEvidenceRange":
        if self.end_line < self.line:
            raise ValueError("obligation evidence end must not precede start")
        return self


class InvariantObligation(AnalysisModel):
    obligation_id: str = Field(pattern=r"^obligation_[0-9a-f]{20}$")
    policy_version: str = "invariant-obligation-v1"
    kind: InvariantObligationKind
    structural_facts: tuple[str, ...] = Field(min_length=1)
    evidence_ranges: tuple[ObligationEvidenceRange, ...] = Field(min_length=1)
    required_hunters: tuple[str, ...] = Field(min_length=1)
    source_fact_ids: tuple[str, ...] = Field(min_length=1)
    target_node_ids: tuple[str, ...] = ()
    target_signal_ids: tuple[str, ...] = ()
    confidence: str = Field(pattern=r"^(?:low|medium|high)$")
    rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_sets(self) -> "InvariantObligation":
        for label, values in (
            ("required Hunters", self.required_hunters),
            ("source fact IDs", self.source_fact_ids),
            ("target node IDs", self.target_node_ids),
            ("target signal IDs", self.target_signal_ids),
        ):
            if len(set(values)) != len(values):
                raise ValueError(f"obligation {label} must be unique")
        evidence_keys = {
            (item.path, item.line, item.end_line, item.structural_role)
            for item in self.evidence_ranges
        }
        if len(evidence_keys) != len(self.evidence_ranges):
            raise ValueError("obligation evidence ranges must be unique")
        return self


class InvariantObligationDisposition(AnalysisModel):
    obligation_id: str = Field(pattern=r"^obligation_[0-9a-f]{20}$")
    policy_version: str = "invariant-obligation-closure-v1"
    state: InvariantClosureState
    evidence_ranges: tuple[ObligationEvidenceRange, ...] = Field(min_length=1)
    rationale: str = Field(min_length=1)
    candidate_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_candidate_link(self) -> "InvariantObligationDisposition":
        if self.state is InvariantClosureState.CANDIDATE and not self.candidate_ids:
            raise ValueError("candidate obligation closure requires a candidate ID")
        if self.state is not InvariantClosureState.CANDIDATE and self.candidate_ids:
            raise ValueError("non-candidate obligation closure cannot link candidates")
        evidence_keys = {
            (item.path, item.line, item.end_line, item.structural_role)
            for item in self.evidence_ranges
        }
        if len(evidence_keys) != len(self.evidence_ranges):
            raise ValueError("obligation closure evidence ranges must be unique")
        if len(set(self.candidate_ids)) != len(self.candidate_ids):
            raise ValueError("obligation closure candidate IDs must be unique")
        return self


class ConstraintKind(StrEnum):
    NUMERIC_BOUND = "numeric_bound"
    BUFFER_SIZE_BOUND = "buffer_size_bound"
    MINIMUM_CONSUMPTION = "minimum_consumption"
    DOMINANT_GUARD = "dominant_guard"
    NARROWING = "narrowing"


class CapacityFactKind(StrEnum):
    ALLOCATION = "allocation"
    ALIAS = "alias"
    ADVANCE = "advance"
    WRITE = "write"
    GUARD = "guard"
    GROWTH = "growth"


class FormattedDestinationKind(StrEnum):
    FIXED_ARRAY = "fixed_array"
    CALLER_BUFFER = "caller_buffer"
    UNKNOWN = "unknown"


class FormattedExpansionClass(StrEnum):
    FIXED_LITERAL = "fixed_literal"
    TYPE_DEPENDENT = "type_dependent"
    INPUT_DEPENDENT = "input_dependent"
    DYNAMIC_FORMAT = "dynamic_format"


class OutputComponentKind(StrEnum):
    DATA = "data"
    PREFIX = "prefix"
    SEPARATOR = "separator"
    ESCAPE = "escape"
    TERMINATOR = "terminator"
    POINTER_ADVANCE = "pointer_advance"


class CursorFactKind(StrEnum):
    READ = "read"
    ADVANCE = "advance"
    GUARD = "guard"


class CapacityReturnKind(StrEnum):
    NONE = "none"
    STATUS = "status"
    PASS_THROUGH = "pass_through"
    CONSUMED_OR_REQUIRED = "consumed_or_required"
    UNKNOWN = "unknown"


class CapacityPriorityClass(StrEnum):
    COMPLETE_UNCHECKED = "complete_unchecked_capacity_path"
    COMPLETE_UNKNOWN_GUARD = "complete_unknown_guard_path"
    PARTIAL = "partial_capacity_path"
    ISOLATED = "isolated_allocation_or_write"


class GraphNode(AnalysisModel):
    node_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    symbol: str = Field(min_length=1)
    line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    kind: NodeKind
    visibility: str = Field(pattern=r"^(external|internal|generated)$")
    calls: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()


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


class RiskTransform(AnalysisModel):
    line: int = Field(ge=1)
    target: str = Field(min_length=1)
    expression: str = Field(min_length=1)
    operations: tuple[str, ...] = ()
    operand_types: tuple[str, ...] = ()
    narrowing_or_wrap: bool = False


class RiskChain(AnalysisModel):
    chain_id: str = Field(pattern=r"^risk_[0-9a-f]{20}$")
    policy_version: str = "c-risk-chain-v1"
    node_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    function: str = Field(min_length=1)
    source_signal_ids: tuple[str, ...] = ()
    source_variables: tuple[str, ...] = Field(min_length=1)
    source_lines: tuple[int, ...] = Field(min_length=1)
    transform_steps: tuple[RiskTransform, ...] = Field(min_length=1)
    guard_state: GuardState
    guard_lines: tuple[int, ...] = ()
    allocation_signal_ids: tuple[str, ...] = Field(min_length=1)
    sink_signal_ids: tuple[str, ...] = ()
    sink_lines: tuple[int, ...] = Field(min_length=1)
    score: int = Field(ge=0, le=100)
    confidence: str = Field(pattern=r"^(low|medium|high)$")
    rationale: str = Field(min_length=1)


class ConstraintFact(AnalysisModel):
    fact_id: str = Field(pattern=r"^constraint_[0-9a-f]{20}$")
    policy_version: str = "c-constraint-v1"
    kind: ConstraintKind
    node_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    subject: str = Field(min_length=1)
    relation: str = Field(pattern=r"^(?:<=|<|>=|>|==|!=)$")
    bound: str = Field(min_length=1)
    expression: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    confidence: str = Field(pattern=r"^(?:low|medium|high)$")


class CapacityFact(AnalysisModel):
    fact_id: str = Field(pattern=r"^capacity_[0-9a-f]{20}$")
    policy_version: str = "c-capacity-fact-v2"
    kind: CapacityFactKind
    node_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    function: str = Field(min_length=1)
    line: int = Field(ge=1)
    subject: str = Field(min_length=1)
    base: str = ""
    element_count: str = ""
    element_size: str = ""
    offset: str = ""
    remaining_capacity: str = ""
    write_extent: str = ""
    relation: str = ""
    guard_effect: str = Field(default="unknown", pattern=r"^(?:unknown|reject|grow)$")
    dominates: bool = False
    evidence: str = Field(min_length=1)
    confidence: str = Field(pattern=r"^(?:low|medium|high)$")
    alias_depth: int = Field(default=0, ge=0, le=8)
    transform_depth: int = Field(default=0, ge=0, le=12)


class CapacityCallSite(AnalysisModel):
    call_id: str = Field(pattern=r"^capacity_call_[0-9a-f]{20}$")
    policy_version: str = "c-capacity-summary-v2"
    caller_id: str = Field(min_length=1)
    target_node_id: str = ""
    path: str = Field(min_length=1)
    line: int = Field(ge=1)
    callee: str = Field(min_length=1)
    arguments: tuple[str, ...] = ()
    result_subject: str = ""
    direct: bool = True


class FormattedOutputFact(AnalysisModel):
    fact_id: str = Field(pattern=r"^format_fact_[0-9a-f]{20}$")
    policy_version: str = "c-formatted-output-v1"
    node_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    function: str = Field(min_length=1)
    line: int = Field(ge=1)
    declaration_line: int | None = Field(default=None, ge=1)
    destination: str = Field(min_length=1)
    destination_kind: FormattedDestinationKind
    capacity_expression: str = ""
    capacity_bytes: int | None = Field(default=None, ge=1)
    bounded_api: bool
    bound_matches_destination: bool = False
    format_is_literal: bool
    conversion_classes: tuple[str, ...] = ()
    dynamic_width_or_precision: bool = False
    locale_sensitive: bool = False
    expansion_class: FormattedExpansionClass
    maximum_output_chars: int | None = Field(default=None, ge=0)
    terminator_bytes: int = Field(default=1, ge=1)
    return_checked: bool = False
    guard_state: GuardState
    evidence: str = Field(min_length=1)
    confidence: str = Field(pattern=r"^(?:low|medium|high)$")


class StatefulOutputFact(AnalysisModel):
    fact_id: str = Field(pattern=r"^output_state_[0-9a-f]{20}$")
    policy_version: str = "c-stateful-output-v1"
    node_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    function: str = Field(min_length=1)
    line: int = Field(ge=1)
    guard_line: int = Field(ge=1)
    transition_ordinal: int = Field(ge=1)
    first_iteration_overhead: int = Field(ge=0)
    subsequent_iteration_overhead: int = Field(ge=0)
    guarded_subsequent_overhead: int = Field(ge=0)
    terminator_reserve: int = Field(ge=0)
    component_kinds: tuple[OutputComponentKind, ...] = Field(min_length=1)
    transition_updates_guard_term: bool
    exact_fit_allowed: bool
    empty_list_terminator_safe: bool
    guard_state: GuardState
    evidence: str = Field(min_length=1)
    confidence: str = Field(pattern=r"^(?:low|medium|high)$")


class FunctionCapacitySummary(AnalysisModel):
    summary_id: str = Field(pattern=r"^capacity_summary_[0-9a-f]{20}$")
    policy_version: str = "c-capacity-summary-v2"
    node_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    function: str = Field(min_length=1)
    parameters: tuple[str, ...] = ()
    pointer_parameters: tuple[str, ...] = ()
    pointer_aliases: dict[str, str] = Field(default_factory=dict)
    written_parameters: tuple[str, ...] = ()
    write_extents: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    return_expressions: tuple[str, ...] = ()
    return_kind: CapacityReturnKind = CapacityReturnKind.NONE
    pass_through_parameters: tuple[str, ...] = ()
    guard_fact_ids: tuple[str, ...] = ()
    failure_returns: tuple[str, ...] = ()
    propagated_call_ids: tuple[str, ...] = ()
    propagation_depth: int = Field(default=0, ge=0, le=5)


class CapacityRiskChain(AnalysisModel):
    chain_id: str = Field(pattern=r"^capacity_risk_[0-9a-f]{20}$")
    policy_version: str = "c-capacity-risk-chain-v3"
    root_cause_group: str = Field(pattern=r"^capacity_group_[0-9a-f]{20}$")
    allocation_fact_id: str = Field(pattern=r"^capacity_[0-9a-f]{20}$")
    root_node_id: str = Field(min_length=1)
    root_path: str = Field(min_length=1)
    root_function: str = Field(min_length=1)
    base: str = Field(min_length=1)
    element_count: str = Field(min_length=1)
    element_size: str = Field(min_length=1)
    node_ids: tuple[str, ...] = Field(min_length=1)
    paths: tuple[str, ...] = Field(min_length=1)
    fact_ids: tuple[str, ...] = Field(min_length=1)
    call_ids: tuple[str, ...] = ()
    summary_ids: tuple[str, ...] = ()
    source_signal_ids: tuple[str, ...] = ()
    allocation_signal_ids: tuple[str, ...] = ()
    write_signal_ids: tuple[str, ...] = ()
    return_consumption_call_ids: tuple[str, ...] = ()
    pointer_advance_fact_ids: tuple[str, ...] = ()
    write_fact_ids: tuple[str, ...] = ()
    guard_fact_ids: tuple[str, ...] = ()
    safe_growth_fact_ids: tuple[str, ...] = ()
    guard_state: GuardState
    missing_elements: tuple[str, ...] = ()
    evidence_lines: dict[str, tuple[int, ...]] = Field(default_factory=dict)
    priority_class: CapacityPriorityClass
    score: int = Field(ge=0, le=100)
    confidence: str = Field(pattern=r"^(?:low|medium|high)$")
    entrypoint_reachable: bool = False
    rationale: str = Field(min_length=1)


class CursorFact(AnalysisModel):
    fact_id: str = Field(pattern=r"^cursor_[0-9a-f]{20}$")
    policy_version: str = "c-cursor-access-v1"
    kind: CursorFactKind
    node_id: str = Field(min_length=1)
    path: str = Field(min_length=1)
    function: str = Field(min_length=1)
    line: int = Field(ge=1)
    subject: str = Field(min_length=1)
    bound: str = Field(min_length=1)
    access_index: str = ""
    delta: int = 0
    callee: str = ""
    macro: str = ""
    control: str = Field(
        default="none",
        pattern=r"^(?:none|loop_entry|reject_fallthrough|positive_branch)$",
    )
    controlled_start_line: int = Field(default=0, ge=0)
    controlled_end_line: int = Field(default=0, ge=0)
    evidence: str = Field(min_length=1)
    confidence: str = Field(pattern=r"^(?:low|medium|high)$")


class CursorTransitionChain(AnalysisModel):
    chain_id: str = Field(pattern=r"^cursor_transition_[0-9a-f]{20}$")
    policy_version: str = "c-cursor-transition-v1"
    caller_node_id: str = Field(min_length=1)
    reader_node_id: str = Field(min_length=1)
    paths: tuple[str, ...] = Field(min_length=1)
    fact_ids: tuple[str, ...] = Field(min_length=1)
    guard_fact_ids: tuple[str, ...] = ()
    advance_fact_id: str = Field(pattern=r"^cursor_[0-9a-f]{20}$")
    read_fact_id: str = Field(pattern=r"^cursor_[0-9a-f]{20}$")
    call_line: int = Field(ge=1)
    subject: str = Field(min_length=1)
    bound: str = Field(min_length=1)
    required_access_index: int = Field(ge=0)
    observed_guard_index: int | None = Field(default=None, ge=0)
    guard_state: GuardState
    evidence_lines: dict[str, tuple[int, ...]] = Field(default_factory=dict)
    score: int = Field(ge=0, le=100)
    confidence: str = Field(pattern=r"^(?:low|medium|high)$")
    rationale: str = Field(min_length=1)


class CAnalysisGraph(AnalysisModel):
    schema_version: int = 2
    language: str = "c"
    nodes: tuple[GraphNode, ...] = ()
    edges: tuple[GraphEdge, ...] = ()
    signals: tuple[SecuritySignal, ...] = ()
    entrypoint_ids: tuple[str, ...] = ()
    critical_sink_ids: tuple[str, ...] = ()
    risk_chains: tuple[RiskChain, ...] = ()
    constraint_facts: tuple[ConstraintFact, ...] = ()
    capacity_facts: tuple[CapacityFact, ...] = ()
    capacity_calls: tuple[CapacityCallSite, ...] = ()
    capacity_summaries: tuple[FunctionCapacitySummary, ...] = ()
    formatted_output_facts: tuple[FormattedOutputFact, ...] = ()
    stateful_output_facts: tuple[StatefulOutputFact, ...] = ()
    capacity_risk_chains: tuple[CapacityRiskChain, ...] = ()
    cursor_facts: tuple[CursorFact, ...] = ()
    cursor_transition_chains: tuple[CursorTransitionChain, ...] = ()
    invariant_obligations: tuple[InvariantObligation, ...] = ()
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


class IncrementalScope(AnalysisModel):
    policy_version: str = "c-git-diff-v1"
    mode: str = Field(pattern=r"^(full|incremental)$")
    base_ref: str = ""
    head_ref: str = ""
    base_commit: str = ""
    head_commit: str = ""
    merge_base_commit: str = ""
    fallback_reason: str = ""
    changed_files: tuple[str, ...] = ()
    changed_line_ranges: dict[str, tuple[tuple[int, int], ...]] = Field(
        default_factory=dict
    )
    changed_node_ids: tuple[str, ...] = ()
    expanded_node_ids: tuple[str, ...] = ()
    selected_slice_ids: tuple[str, ...] = ()
    selected_files: tuple[str, ...] = ()
    critical_sink_ids: tuple[str, ...] = ()
    full_selected_files: int = Field(default=0, ge=0)

    @property
    def file_reduction_percent(self) -> float:
        if not self.full_selected_files:
            return 0.0
        return round(
            (1 - len(self.selected_files) / self.full_selected_files) * 100,
            2,
        )
