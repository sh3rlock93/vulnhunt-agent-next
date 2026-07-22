"""Cross-file capacity risk chains assembled from bounded C facts."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import re

from .capacity_summaries import MAX_CAPACITY_CALL_DEPTH
from .models import (
    CapacityCallSite,
    CapacityFact,
    CapacityFactKind,
    CapacityPriorityClass,
    CapacityReturnKind,
    CapacityRiskChain,
    FunctionCapacitySummary,
    GraphEdge,
    GuardState,
    SecuritySignal,
    SignalRole,
)

CAPACITY_RISK_CHAIN_POLICY = "c-capacity-risk-chain-v3"
_RELEASE_CALLEE = re.compile(r"(?:free|dealloc|delete)$", re.IGNORECASE)
_MEMORY_WRITE_EVIDENCE = re.compile(r"\b(?:memcpy|memmove|memset)\s+writes\b")
_SIZING_HELPER = re.compile(
    r"\b[A-Za-z_]\w*(?:size|width|height|capacity|extent)\w*\s*\(",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _State:
    node_id: str
    tainted: tuple[str, ...]
    depth: int


def build_capacity_risk_chains(
    *,
    facts: tuple[CapacityFact, ...],
    calls: tuple[CapacityCallSite, ...],
    summaries: tuple[FunctionCapacitySummary, ...],
    signals: tuple[SecuritySignal, ...],
    edges: tuple[GraphEdge, ...],
    entrypoint_ids: tuple[str, ...],
) -> tuple[CapacityRiskChain, ...]:
    """Build one deterministic bounded chain per concrete allocation fact."""
    facts_by_node: dict[str, list[CapacityFact]] = {}
    for fact in facts:
        facts_by_node.setdefault(fact.node_id, []).append(fact)
    calls_by_caller: dict[str, list[CapacityCallSite]] = {}
    for call in calls:
        calls_by_caller.setdefault(call.caller_id, []).append(call)
    summary_by_node = {summary.node_id: summary for summary in summaries}
    reachable = _entrypoint_reachable(edges, entrypoint_ids)
    allocations = sorted(
        (fact for fact in facts if fact.kind is CapacityFactKind.ALLOCATION),
        key=lambda item: item.fact_id,
    )
    return tuple(
        _chain_for_allocation(
            allocation,
            facts_by_node=facts_by_node,
            calls_by_caller=calls_by_caller,
            summary_by_node=summary_by_node,
            signals=signals,
            entrypoint_reachable=allocation.node_id in reachable,
        )
        for allocation in allocations
    )


def _chain_for_allocation(
    allocation: CapacityFact,
    *,
    facts_by_node: dict[str, list[CapacityFact]],
    calls_by_caller: dict[str, list[CapacityCallSite]],
    summary_by_node: dict[str, FunctionCapacitySummary],
    signals: tuple[SecuritySignal, ...],
    entrypoint_reachable: bool,
) -> CapacityRiskChain:
    queue = deque([_State(allocation.node_id, (allocation.subject,), 0)])
    visited: set[tuple[str, tuple[str, ...]]] = set()
    selected_facts: dict[str, CapacityFact] = {allocation.fact_id: allocation}
    selected_calls: dict[str, CapacityCallSite] = {}
    selected_summaries: dict[str, FunctionCapacitySummary] = {}
    return_calls: set[str] = set()
    nodes: set[str] = {allocation.node_id}

    while queue:
        state = queue.popleft()
        key = (state.node_id, state.tainted)
        if key in visited:
            continue
        visited.add(key)
        tainted = _expand_local_aliases(
            set(state.tainted), facts_by_node.get(state.node_id, ())
        )
        for fact in facts_by_node.get(state.node_id, ()):
            if fact.kind is CapacityFactKind.GUARD:
                selected_facts[fact.fact_id] = fact
            elif fact.subject in tainted or fact.base in tainted:
                selected_facts[fact.fact_id] = fact

        if state.depth >= MAX_CAPACITY_CALL_DEPTH:
            continue
        for call in sorted(calls_by_caller.get(state.node_id, ()), key=lambda item: item.call_id):
            if (
                not call.direct
                or not call.target_node_id
                or _RELEASE_CALLEE.search(call.callee)
            ):
                continue
            summary = summary_by_node.get(call.target_node_id)
            if summary is None:
                continue
            bindings = tuple(zip(summary.parameters, call.arguments, strict=False))
            target_tainted = tuple(sorted({
                parameter
                for parameter, actual in bindings
                if _argument_root(actual) in tainted
            }))
            if not target_tainted:
                continue
            selected_calls[call.call_id] = call
            selected_summaries[summary.summary_id] = summary
            nodes.add(call.target_node_id)
            if (
                call.result_subject
                and summary.return_kind is CapacityReturnKind.CONSUMED_OR_REQUIRED
            ):
                return_calls.add(call.call_id)
                for fact in facts_by_node.get(state.node_id, ()):
                    if (
                        fact.kind is CapacityFactKind.ADVANCE
                        and (fact.subject in tainted or fact.base in tainted)
                        and re.search(
                            rf"\b{re.escape(call.result_subject)}\b",
                            f"{fact.offset} {fact.evidence}",
                        )
                    ):
                        selected_facts[fact.fact_id] = fact
            queue.append(_State(
                call.target_node_id,
                target_tainted,
                state.depth + 1,
            ))

    memory_extent_subjects = {
        subject
        for fact in selected_facts.values()
        if fact.kind is CapacityFactKind.WRITE
        and _MEMORY_WRITE_EVIDENCE.search(fact.evidence)
        for subject in _tokens(fact.write_extent)
    }
    for node_id in tuple(nodes):
        for fact in facts_by_node.get(node_id, ()):
            if (
                fact.kind is CapacityFactKind.WRITE
                and fact.subject in memory_extent_subjects
                and "=" in fact.evidence
            ):
                selected_facts[fact.fact_id] = fact

    fact_values = tuple(selected_facts.values())
    write_facts = tuple(
        fact for fact in fact_values if fact.kind is CapacityFactKind.WRITE
    )
    advances = tuple(
        fact for fact in fact_values if fact.kind is CapacityFactKind.ADVANCE
    )
    extracted_guards = tuple(
        fact for fact in fact_values if fact.kind is CapacityFactKind.GUARD
    )
    growth_facts = tuple(
        fact for fact in fact_values if fact.kind is CapacityFactKind.GROWTH
    )
    guard_state, guards, safe_growth = _classify_capacity_guards(
        allocation=allocation,
        guards=extracted_guards,
        growth_facts=growth_facts,
        advances=advances,
        writes=write_facts,
        calls=tuple(selected_calls.values()),
    )
    chain_facts = tuple(
        fact for fact in fact_values
        if fact.kind is not CapacityFactKind.GUARD or fact in guards
    )
    signal_nodes = nodes
    source_signals = tuple(sorted(
        signal.signal_id for signal in signals
        if signal.node_id in signal_nodes and signal.role is SignalRole.SOURCE
    ))
    allocation_signals = tuple(sorted(
        signal.signal_id for signal in signals
        if signal.node_id == allocation.node_id
        and signal.line == allocation.line
        and signal.category.startswith("allocation_size")
    ))
    write_locations = {(fact.node_id, fact.line) for fact in write_facts}
    write_signals = tuple(sorted(
        signal.signal_id for signal in signals
        if (signal.node_id, signal.line) in write_locations
        and signal.role is SignalRole.SINK
    ))
    cross_call_write = bool(
        selected_calls
        and any(fact.node_id != allocation.node_id for fact in write_facts)
    )
    complete = bool(write_facts and (return_calls or advances or cross_call_write))
    bounded_write_derivation = _has_bounded_write_derivation(write_facts)
    if complete and guard_state is GuardState.ABSENT and bounded_write_derivation:
        priority = CapacityPriorityClass.COMPLETE_UNKNOWN_GUARD
        score = 75
        confidence = "medium"
    elif complete and guard_state is GuardState.ABSENT:
        priority = CapacityPriorityClass.COMPLETE_UNCHECKED
        score = 95
        confidence = "high"
    elif complete and guard_state is GuardState.DOMINATES:
        priority = CapacityPriorityClass.PARTIAL
        score = 35
        confidence = "high"
    elif complete and guard_state is GuardState.PARTIAL:
        priority = CapacityPriorityClass.COMPLETE_UNKNOWN_GUARD
        score = 75
        confidence = "medium"
    elif complete:
        priority = CapacityPriorityClass.COMPLETE_UNKNOWN_GUARD
        score = 85
        confidence = "medium"
    elif write_facts or return_calls or advances or selected_calls:
        priority = CapacityPriorityClass.PARTIAL
        score = 50 if guard_state in {GuardState.DOMINATES, GuardState.PARTIAL} else 60
        confidence = "medium"
    else:
        priority = CapacityPriorityClass.ISOLATED
        score = 30
        confidence = "low"
    score = min(100, score + (5 if entrypoint_reachable else 0))

    missing = set()
    if not source_signals:
        missing.add("source")
    if not any(fact.kind is CapacityFactKind.ALIAS for fact in fact_values):
        missing.add("alias")
    if not selected_calls:
        missing.add("call_path")
    if not return_calls:
        missing.add("return_consumption")
    if not advances:
        missing.add("pointer_advance")
    if not write_facts:
        missing.add("write")

    evidence_lines: dict[str, set[int]] = {}
    for fact in chain_facts:
        evidence_lines.setdefault(fact.path, set()).add(fact.line)
    for call in selected_calls.values():
        evidence_lines.setdefault(call.path, set()).add(call.line)
    paths = tuple(sorted(evidence_lines))
    identity = "\0".join((
        CAPACITY_RISK_CHAIN_POLICY,
        allocation.fact_id,
        *(sorted(fact.fact_id for fact in chain_facts)),
        *sorted(selected_calls),
    ))
    root_identity = "\0".join((
        allocation.node_id,
        allocation.base,
        allocation.element_count,
        allocation.element_size,
    ))
    return CapacityRiskChain(
        chain_id="capacity_risk_" + hashlib.sha256(identity.encode()).hexdigest()[:20],
        root_cause_group=(
            "capacity_group_" + hashlib.sha256(root_identity.encode()).hexdigest()[:20]
        ),
        allocation_fact_id=allocation.fact_id,
        root_node_id=allocation.node_id,
        root_path=allocation.path,
        root_function=allocation.function,
        base=allocation.base,
        element_count=allocation.element_count or "unknown",
        element_size=allocation.element_size or "1",
        node_ids=tuple(sorted(nodes)),
        paths=paths or (allocation.path,),
        fact_ids=tuple(sorted(fact.fact_id for fact in chain_facts)),
        call_ids=tuple(sorted(selected_calls)),
        summary_ids=tuple(sorted(selected_summaries)),
        source_signal_ids=source_signals,
        allocation_signal_ids=allocation_signals,
        write_signal_ids=write_signals,
        return_consumption_call_ids=tuple(sorted(return_calls)),
        pointer_advance_fact_ids=tuple(sorted(fact.fact_id for fact in advances)),
        write_fact_ids=tuple(sorted(fact.fact_id for fact in write_facts)),
        guard_fact_ids=tuple(sorted(fact.fact_id for fact in guards)),
        safe_growth_fact_ids=tuple(sorted(fact.fact_id for fact in safe_growth)),
        guard_state=guard_state,
        missing_elements=tuple(sorted(missing)),
        evidence_lines={
            path: tuple(sorted(lines)) for path, lines in sorted(evidence_lines.items())
        },
        priority_class=priority,
        score=score,
        confidence=confidence,
        entrypoint_reachable=entrypoint_reachable,
        rationale=(
            f"{priority.value}: allocation {allocation.subject} reaches "
            f"{len(write_facts)} writes through {len(selected_calls)} direct calls; "
            f"return_consumption={bool(return_calls)}; advances={len(advances)}; "
            f"guard={guard_state.value}; "
            f"bounded_write_derivation={bounded_write_derivation}"
        ),
    )


def _has_bounded_write_derivation(
    writes: tuple[CapacityFact, ...],
) -> bool:
    derivations: dict[tuple[str, str], list[CapacityFact]] = {}
    for fact in writes:
        if "=" in fact.evidence:
            derivations.setdefault((fact.node_id, fact.subject), []).append(fact)
    safe = False
    unsafe = False
    for fact in writes:
        if not _MEMORY_WRITE_EVIDENCE.search(fact.evidence):
            continue
        for subject in _tokens(fact.write_extent):
            candidates = derivations.get((fact.node_id, subject), ())
            if not candidates:
                continue
            if any(_SIZING_HELPER.search(item.evidence) for item in candidates):
                safe = True
            else:
                unsafe = True
    return safe and not unsafe


def _classify_capacity_guards(
    *,
    allocation: CapacityFact,
    guards: tuple[CapacityFact, ...],
    growth_facts: tuple[CapacityFact, ...],
    advances: tuple[CapacityFact, ...],
    writes: tuple[CapacityFact, ...],
    calls: tuple[CapacityCallSite, ...],
) -> tuple[GuardState, tuple[CapacityFact, ...], tuple[CapacityFact, ...]]:
    capacity_terms = _tokens(
        f"{allocation.base} {allocation.element_count} {allocation.remaining_capacity}"
    )
    activity_terms = _tokens(" ".join((
        *(f"{fact.offset} {fact.evidence}" for fact in advances),
        *(f"{fact.write_extent} {fact.evidence}" for fact in writes),
        *(" ".join((*call.arguments, call.result_subject)) for call in calls),
    )))
    activity_terms -= capacity_terms
    growth_by_subject = {fact.subject: fact for fact in growth_facts}
    hazard_lines: dict[str, list[int]] = {}
    for fact in (*advances, *writes):
        hazard_lines.setdefault(fact.node_id, []).append(fact.line)
    for call in calls:
        hazard_lines.setdefault(call.caller_id, []).append(call.line)

    relevant: list[CapacityFact] = []
    safe: list[CapacityFact] = []
    safe_growth: list[CapacityFact] = []
    for guard in guards:
        guard_tokens = _tokens(f"{guard.subject} {guard.relation}")
        guarded_growth = sorted(set(growth_by_subject).intersection(guard_tokens))
        null_growth_guard = (
            guarded_growth
            and "NULL" in guard.relation
            and guard.guard_effect == "reject"
        )
        cap_overlap = bool(capacity_terms.intersection(guard_tokens)) or any(
            _is_capacity_name(token) for token in guard_tokens
        )
        activity_overlap = bool(activity_terms.intersection(guard_tokens))
        if not null_growth_guard and not (cap_overlap and activity_overlap):
            continue
        relevant.append(guard)
        earliest_hazard = min(hazard_lines.get(guard.node_id, (10**9,)))
        dominates = guard.dominates and guard.line <= earliest_hazard
        if null_growth_guard and dominates:
            safe.append(guard)
            safe_growth.extend(growth_by_subject[name] for name in guarded_growth)
        elif dominates and _reject_establishes_safe(guard, capacity_terms, activity_terms):
            safe.append(guard)

    if safe:
        state = GuardState.DOMINATES
    elif relevant and any(
        _reject_establishes_safe(guard, capacity_terms, activity_terms)
        for guard in relevant
    ):
        state = GuardState.PARTIAL
    elif relevant:
        state = GuardState.UNKNOWN
    else:
        state = GuardState.ABSENT
    return (
        state,
        tuple(sorted(relevant, key=lambda item: item.fact_id)),
        tuple(sorted({fact.fact_id: fact for fact in safe_growth}.values(),
                     key=lambda item: item.fact_id)),
    )


def _reject_establishes_safe(
    guard: CapacityFact,
    capacity_terms: set[str],
    activity_terms: set[str],
) -> bool:
    if guard.guard_effect != "reject":
        return False
    if re.search(r"overflow|safe|checked", guard.relation, re.IGNORECASE):
        return True
    match = re.search(r"(.+?)\s*(<=|<|>=|>)\s*(.+)", guard.relation)
    if match is None:
        return False
    left, operator, right = match.groups()
    left_tokens = _tokens(left)
    right_tokens = _tokens(right)
    left_capacity = bool(left_tokens & capacity_terms) or any(
        _is_capacity_name(token) for token in left_tokens
    )
    right_capacity = bool(right_tokens & capacity_terms) or any(
        _is_capacity_name(token) for token in right_tokens
    )
    left_activity = bool(left_tokens & activity_terms)
    right_activity = bool(right_tokens & activity_terms)
    return (
        left_activity and right_capacity and operator in {">", ">="}
    ) or (
        left_capacity and right_activity and operator in {"<", "<="}
    )


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"\b[A-Za-z_]\w*\b", value)) - {
        "if", "return", "sizeof", "NULL", "const", "int", "unsigned",
    }


def _is_capacity_name(value: str) -> bool:
    return bool(re.search(
        r"capacity|remaining|remain|available|limit|alloc(?:ated)?|(?:^|_)end$",
        value,
        re.IGNORECASE,
    ))


def _expand_local_aliases(
    tainted: set[str],
    facts: list[CapacityFact] | tuple[CapacityFact, ...],
) -> set[str]:
    for _ in range(8):
        added = {
            fact.subject for fact in facts
            if fact.kind is CapacityFactKind.ALIAS and fact.base in tainted
        } - tainted
        if not added:
            break
        tainted.update(added)
    return tainted


def _argument_root(argument: str) -> str:
    value = re.sub(r"^(?:\([^()]*(?:\*|_t)\)\s*)+", "", argument).strip()
    match = re.match(r"(?:&\s*)?([A-Za-z_]\w*)", value)
    return match.group(1) if match is not None else ""


def _entrypoint_reachable(
    edges: tuple[GraphEdge, ...],
    entrypoint_ids: tuple[str, ...],
) -> set[str]:
    outgoing: dict[str, set[str]] = {}
    for edge in edges:
        outgoing.setdefault(edge.source, set()).add(edge.target)
    reachable = set(entrypoint_ids)
    queue = deque(sorted(entrypoint_ids))
    while queue:
        source = queue.popleft()
        for target in sorted(outgoing.get(source, ())):
            if target in reachable:
                continue
            reachable.add(target)
            queue.append(target)
    return reachable
