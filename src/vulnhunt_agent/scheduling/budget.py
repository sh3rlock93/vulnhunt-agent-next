"""Hard Hunter budgets and deterministic priority allocation."""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import threading
import time
import uuid
from dataclasses import dataclass, replace
from typing import Callable

from ..core.llm import LLMResponse
from ..analysis.models import CapacityPriorityClass, CapacityRiskChain, RiskChain
from ..domain.schemas import BudgetPolicy, BudgetUsage, HunterWorkItem

LEGACY_BUDGET_POLICY = "hunter-budget-allocation-v1"
NATIVE_DIVERSE_POLICY = "c-budget-v8"
NATIVE_CHAIN_SHARE = 0.50
NATIVE_SEED_DIVERSITY_SHARE = 0.25
NATIVE_HIGH_RISK_SHARE = 1 / 6
NATIVE_EARLY_SEED_CAP = 2
CAPACITY_ADMISSION_UNIT_POLICY = "capacity-admission-unit-v1"
WORK_INPUT_FAIRNESS_POLICY = "work-input-fairness-v3"


class BudgetExceededError(RuntimeError):
    """A model call cannot start or finish within the configured hard budget."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"Hunter budget exhausted: {reason}")


@dataclass(frozen=True)
class BudgetAllocation:
    admitted_work_ids: tuple[str, ...]
    deferred: dict[str, str]
    critical_slots: int
    high_risk_slots: int
    retry_slots: int
    general_slots: int
    policy_version: str = LEGACY_BUDGET_POLICY
    chain_critical_slots: int = 0
    chain_revisit_slots: int = 0
    component_diverse_slots: int = 0
    seed_diverse_slots: int = 0
    high_risk_non_chain_slots: int = 0
    borrowed_slots: int = 0
    duplicate_coverage_deferred: int = 0
    seed_cap_exceptions: int = 0
    decisions: tuple["AdmissionDecision", ...] = ()
    ranking: tuple["AdmissionRankingRecord", ...] = ()
    capacity_units: tuple["CapacityAdmissionUnit", ...] = ()


@dataclass(frozen=True)
class CapacityAdmissionUnit:
    """One canonical schedulable representative for a capacity root cause."""

    unit_id: str
    policy_version: str
    root_cause_group: str
    priority_class: str
    representative_chain_id: str
    representative_work_id: str
    chain_ids: tuple[str, ...]
    work_ids: tuple[str, ...]
    required_paths: tuple[str, ...]
    evidence_lines: dict[str, tuple[int, ...]]


@dataclass(frozen=True)
class WorkInputBudgetPlan:
    """Deterministic per-work caps and protected critical input budget.

    ``critical_first_call_reserve`` keeps its serialized name for run-artifact
    compatibility. Under v3 the unused portion remains protected until the
    work reaches a terminal state, rather than ending after its first call.
    """

    policy_version: str
    per_work_input_limit: int
    critical_first_call_reserve: int
    work_input_limits: dict[str, int]
    critical_work_ids: tuple[str, ...]


@dataclass(frozen=True)
class AdmissionDecision:
    work_id: str
    rank: int
    quota: str
    component: str
    seed_file: str
    score: int
    score_components: dict[str, int]
    reason: str
    seed_family: str = ""
    coverage_group: str = ""
    logical_chain_group: str = ""
    logical_chain_groups: tuple[str, ...] = ()
    capacity_unit_ids: tuple[str, ...] = ()
    cap_exception: bool = False


@dataclass(frozen=True)
class AdmissionRankingRecord:
    """Auditable pre-admission position and terminal scheduling disposition."""

    record_id: str
    work_id: str
    pre_admission_rank: int
    component: str
    seed_file: str
    score: int
    score_components: dict[str, int]
    chain_ids: tuple[str, ...]
    missing_chain_elements: tuple[str, ...]
    guard_states: tuple[str, ...]
    priority_class: str
    disposition: str
    reason: str
    seed_family: str = ""
    coverage_group: str = ""
    logical_chain_group: str = ""
    logical_chain_groups: tuple[str, ...] = ()
    capacity_unit_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class AdmissionEvent:
    sequence: int
    work_id: str
    event: str
    reason: str = ""
    provider_started: bool = False
    promoted_work_id: str = ""
    usage: dict | None = None


class RecyclableAdmissionLedger:
    """Track admission slots without counting work that never reached a provider."""

    def __init__(self, allocation: BudgetAllocation):
        self._active = set(allocation.admitted_work_ids)
        self._waiting = [
            work_id for work_id, reason in allocation.deferred.items()
            if reason == "max_hunter_sessions"
        ]
        self._started: set[str] = set()
        self._terminal: set[str] = set()
        self._events: list[AdmissionEvent] = []
        self._retry_slots = allocation.retry_slots
        self._retry_needed = False

    def mark_provider_started(self, work_id: str) -> None:
        if work_id not in self._active or work_id in self._terminal:
            raise ValueError(f"provider start for inactive admission: {work_id}")
        if work_id in self._started:
            return
        self._started.add(work_id)
        self._record(work_id, "provider_started", provider_started=True)

    def finish(
        self,
        work_id: str,
        *,
        status: str,
        reason: str = "",
        recyclable: bool = False,
        usage: BudgetUsage | None = None,
    ) -> str | None:
        if work_id not in self._active or work_id in self._terminal:
            return None
        started = work_id in self._started
        if started and status in {"failed", "budget_deferred", "cancelled"}:
            self._retry_needed = True
        promoted = ""
        if recyclable and not started and self._waiting:
            promoted = self._waiting.pop(0)
            self._active.add(promoted)
        self._terminal.add(work_id)
        self._record(
            work_id,
            status,
            reason=reason,
            provider_started=started,
            promoted_work_id=promoted,
            usage=usage.model_dump(mode="json") if usage is not None else None,
        )
        return promoted or None

    def borrow_unused_retry(self) -> str | None:
        """Promote one waiting item after all initial work finishes without retry need."""
        if (
            self._retry_slots <= 0
            or self._retry_needed
            or not self._waiting
            or self._active - self._terminal
        ):
            return None
        promoted = self._waiting.pop(0)
        self._active.add(promoted)
        self._retry_slots -= 1
        self._record(
            promoted,
            "retry_borrowed",
            reason="unused retry reservation borrowed after initial work completed",
            promoted_work_id=promoted,
        )
        return promoted

    def snapshot(self) -> dict:
        return {
            "policy_version": "recyclable-admission-v1",
            "active_work_ids": sorted(self._active - self._terminal),
            "waiting_work_ids": list(self._waiting),
            "provider_started_work_ids": sorted(self._started),
            "terminal_work_ids": sorted(self._terminal),
            "recycled_slots": sum(bool(item.promoted_work_id) for item in self._events),
            "retry_slots_remaining": self._retry_slots,
            "retry_needed": self._retry_needed,
            "events": [
                {
                    "sequence": item.sequence,
                    "work_id": item.work_id,
                    "event": item.event,
                    "reason": item.reason,
                    "provider_started": item.provider_started,
                    "promoted_work_id": item.promoted_work_id,
                    "usage": item.usage,
                }
                for item in self._events
            ],
        }

    def _record(
        self,
        work_id: str,
        event: str,
        *,
        reason: str = "",
        provider_started: bool = False,
        promoted_work_id: str = "",
        usage: dict | None = None,
    ) -> None:
        self._events.append(AdmissionEvent(
            sequence=len(self._events) + 1,
            work_id=work_id,
            event=event,
            reason=reason,
            provider_started=provider_started,
            promoted_work_id=promoted_work_id,
            usage=usage,
        ))


@dataclass(frozen=True)
class _AdmissionCandidate:
    item: HunterWorkItem
    component: str
    risk_chain_score: int
    capacity_chain_score: int
    capacity_evidence_score: int
    priority_class: str
    entrypoint_reachable: bool
    seed_family: str
    coverage_group: str
    logical_chain_group: str
    logical_chain_groups: tuple[str, ...]
    chain_ids: tuple[str, ...]
    risk_chain_ids: tuple[str, ...]
    capacity_chain_ids: tuple[str, ...]
    capacity_unit_ids: tuple[str, ...]
    risk_missing_chain_elements: tuple[str, ...]
    risk_guard_states: tuple[str, ...]
    risk_entrypoint_reachable: bool
    missing_chain_elements: tuple[str, ...]
    guard_states: tuple[str, ...]

    @property
    def chain_score(self) -> int:
        return max(self.risk_chain_score, self.capacity_chain_score)


@dataclass(frozen=True)
class _CallReservation:
    reservation_id: str
    input_tokens: int
    output_tokens: int
    work_id: str = ""


def allocate_work_items(
    work_items: tuple[HunterWorkItem, ...],
    policy: BudgetPolicy,
    *,
    consumed_sessions: int = 0,
    risk_chains: tuple[RiskChain, ...] = (),
    capacity_chains: tuple[CapacityRiskChain, ...] = (),
    entrypoint_ids: tuple[str, ...] = (),
    native_full_scan: bool = False,
) -> BudgetAllocation:
    """Admit work deterministically with 60/30/10 critical/high/retry intent.

    Unused class reservations are borrowed in strict risk order. A retry reserve
    is held only when the initial backlog would otherwise fill the remaining
    session budget; small scans are never deferred merely to keep empty slots.
    """
    if native_full_scan:
        return _allocate_native_diverse(
            work_items,
            policy,
            consumed_sessions=consumed_sessions,
            risk_chains=risk_chains,
            capacity_chains=capacity_chains,
            entrypoint_ids=entrypoint_ids,
        )

    remaining = max(0, policy.max_hunter_sessions - consumed_sessions)
    ordered = sorted(
        work_items,
        key=lambda item: (-int(item.required), -item.risk, item.work_id),
    )
    nominal_retry = (
        max(1, math.ceil(policy.max_hunter_sessions * 0.10))
        if policy.max_retries_per_work_item and remaining > 1
        else 0
    )
    retry_slots = (
        min(nominal_retry, remaining - 1)
        if len(ordered) > remaining
        else min(nominal_retry, max(0, remaining - len(ordered)))
    )
    initial_capacity = max(0, remaining - retry_slots)
    critical_target = min(initial_capacity, math.ceil(policy.max_hunter_sessions * 0.60))
    high_target = min(
        max(0, initial_capacity - critical_target),
        math.floor(policy.max_hunter_sessions * 0.30),
    )

    critical = [item for item in ordered if item.required]
    high = [item for item in ordered if not item.required and item.risk >= 4]
    general = [item for item in ordered if not item.required and item.risk < 4]
    picked: list[HunterWorkItem] = []

    def take(source: list[HunterWorkItem], count: int) -> None:
        for item in source[:count]:
            if item not in picked:
                picked.append(item)

    take(critical, critical_target)
    take(high, high_target)
    for item in (*critical, *high, *general):
        if len(picked) >= initial_capacity:
            break
        if item not in picked:
            picked.append(item)

    admitted = {item.work_id for item in picked}
    deferred = {
        item.work_id: "max_hunter_sessions"
        for item in ordered
        if item.work_id not in admitted
    }
    critical_slots = sum(item.required for item in picked)
    high_slots = sum(not item.required and item.risk >= 4 for item in picked)
    return BudgetAllocation(
        admitted_work_ids=tuple(item.work_id for item in picked),
        deferred=deferred,
        critical_slots=critical_slots,
        high_risk_slots=high_slots,
        retry_slots=retry_slots,
        general_slots=len(picked) - critical_slots - high_slots,
        decisions=tuple(
            AdmissionDecision(
                work_id=item.work_id,
                rank=index,
                quota="legacy_priority",
                component=_component_for(item.seed_file),
                seed_file=item.seed_file,
                score=int(item.required) * 20 + item.risk * 10,
                score_components={
                    "required": int(item.required) * 20,
                    "sink_severity": item.risk * 10,
                    "risk_chain": 0,
                    "entrypoint_reachability": 0,
                    "component_novelty": 0,
                },
                reason="legacy 60/30/10 deterministic priority",
            )
            for index, item in enumerate(picked, start=1)
        ),
        ranking=tuple(
            _legacy_ranking_record(
                item,
                pre_admission_rank=index,
                disposition=("admitted" if item.work_id in admitted else "budget_deferred"),
                reason=(
                    "legacy 60/30/10 deterministic priority"
                    if item.work_id in admitted else "max_hunter_sessions"
                ),
            )
            for index, item in enumerate(ordered, start=1)
        ),
    )


def apply_admission_focus(
    work_items: tuple[HunterWorkItem, ...],
    allocation: BudgetAllocation,
    *,
    capacity_chains: tuple[CapacityRiskChain, ...] = (),
) -> tuple[HunterWorkItem, ...]:
    """Attach auditable ranking chains without changing stable work identities."""
    ranked_chain_ids = {
        record.work_id: record.chain_ids
        for record in allocation.ranking
        if record.chain_ids
    }
    capacity_by_id = {chain.chain_id: chain for chain in capacity_chains}
    representative_chains: dict[str, list[CapacityRiskChain]] = {}
    for unit in allocation.capacity_units:
        chain = capacity_by_id.get(unit.representative_chain_id)
        if chain is not None:
            representative_chains.setdefault(
                unit.representative_work_id, []
            ).append(chain)
    focused = []
    for item in work_items:
        primary_capacity = min(
            representative_chains.get(item.work_id, ()),
            key=lambda chain: (
                _capacity_priority_rank(chain.priority_class.value),
                -chain.score,
                chain.chain_id,
            ),
            default=None,
        )
        chain_ids = (
            (primary_capacity.chain_id,)
            if primary_capacity is not None
            else ranked_chain_ids.get(item.work_id, item.focus_chain_ids)
        )
        target_signal_ids = item.target_signal_ids
        if primary_capacity is not None:
            capacity_signal_ids = {
                *primary_capacity.source_signal_ids,
                *primary_capacity.allocation_signal_ids,
                *primary_capacity.write_signal_ids,
            }
            narrowed = tuple(
                signal_id
                for signal_id in item.target_signal_ids
                if signal_id in capacity_signal_ids
            )
            if narrowed:
                target_signal_ids = narrowed
        if (
            chain_ids == item.focus_chain_ids
            and target_signal_ids == item.target_signal_ids
        ):
            focused.append(item)
            continue
        focused.append(HunterWorkItem.model_validate({
            **item.model_dump(mode="python"),
            "focus_chain_ids": chain_ids,
            "target_signal_ids": target_signal_ids,
        }))
    return tuple(focused)


def build_work_input_budget(
    work_items: tuple[HunterWorkItem, ...],
    allocation: BudgetAllocation,
    policy: BudgetPolicy,
) -> WorkInputBudgetPlan:
    """Protect every critical first call and allow critical-chain completion."""
    admitted = tuple(allocation.admitted_work_ids)
    base_share = max(
        1,
        policy.max_input_tokens // max(1, len(admitted)),
    )
    critical_chain_work_ids = {
        decision.work_id
        for decision in allocation.decisions
        if decision.quota == "chain_critical"
    }
    work_input_limits = {
        work_id: min(
            policy.max_input_tokens,
            base_share * (6 if work_id in critical_chain_work_ids else 2),
        )
        for work_id in admitted
    }
    per_work_limit = max(work_input_limits.values(), default=base_share)
    by_work_id = {item.work_id: item for item in work_items}
    protected_work_ids = critical_chain_work_ids or {
        work_id
        for work_id in admitted
        if by_work_id.get(work_id) is not None and by_work_id[work_id].required
    }
    critical_work_ids = tuple(
        work_id for work_id in admitted if work_id in protected_work_ids
    )
    return WorkInputBudgetPlan(
        policy_version=WORK_INPUT_FAIRNESS_POLICY,
        per_work_input_limit=per_work_limit,
        critical_first_call_reserve=min(
            base_share,
            max(32_000, base_share // 2),
        ),
        work_input_limits=work_input_limits,
        critical_work_ids=critical_work_ids,
    )


def _allocate_native_diverse(
    work_items: tuple[HunterWorkItem, ...],
    policy: BudgetPolicy,
    *,
    consumed_sessions: int,
    risk_chains: tuple[RiskChain, ...],
    capacity_chains: tuple[CapacityRiskChain, ...],
    entrypoint_ids: tuple[str, ...],
) -> BudgetAllocation:
    """Admit full native work with fair seed and recyclable class reservations."""
    remaining = max(0, policy.max_hunter_sessions - consumed_sessions)
    chain_by_signal: dict[str, list[RiskChain]] = {}
    chain_by_node: dict[str, list[RiskChain]] = {}
    for chain in risk_chains:
        for signal_id in (*chain.allocation_signal_ids, *chain.sink_signal_ids):
            chain_by_signal.setdefault(signal_id, []).append(chain)
        chain_by_node.setdefault(chain.node_id, []).append(chain)
    capacity_by_signal: dict[str, list[CapacityRiskChain]] = {}
    capacity_by_node: dict[str, list[CapacityRiskChain]] = {}
    for chain in capacity_chains:
        for signal_id in (*chain.allocation_signal_ids, *chain.write_signal_ids):
            capacity_by_signal.setdefault(signal_id, []).append(chain)
        for node_id in chain.node_ids:
            capacity_by_node.setdefault(node_id, []).append(chain)
    entrypoints = set(entrypoint_ids)

    candidates = []
    for item in work_items:
        matching = {
            chain.chain_id: chain
            for signal_id in item.target_signal_ids
            for chain in chain_by_signal.get(signal_id, ())
        }
        for node_id in item.target_node_ids:
            for chain in chain_by_node.get(node_id, ()):
                matching[chain.chain_id] = chain
        matching_capacity = {
            chain.chain_id: chain
            for signal_id in item.target_signal_ids
            for chain in capacity_by_signal.get(signal_id, ())
        }
        for node_id in item.target_node_ids:
            for chain in capacity_by_node.get(node_id, ()):
                matching_capacity[chain.chain_id] = chain
        priority = min(
            (chain.priority_class.value for chain in matching_capacity.values()),
            key=_capacity_priority_rank,
            default="unclassified",
        )
        best_capacity = min(
            matching_capacity.values(),
            key=lambda chain: (
                _capacity_priority_rank(chain.priority_class.value),
                -chain.score,
                -_capacity_evidence_score(chain),
                chain.chain_id,
            ),
            default=None,
        )
        logical_chain_group = (
            best_capacity.root_cause_group if best_capacity is not None else ""
        )
        logical_chain_groups = tuple(sorted({
            chain.root_cause_group for chain in matching_capacity.values()
        }))
        risk_missing = _missing_chain_elements(tuple(matching.values()))
        missing = set(risk_missing)
        if matching_capacity:
            missing.discard("risk_chain")
            missing.update(
                element
                for chain in matching_capacity.values()
                for element in chain.missing_elements
            )
        candidates.append(_AdmissionCandidate(
            item=item,
            component=_component_for(item.seed_file),
            risk_chain_score=max((chain.score for chain in matching.values()), default=0),
            capacity_chain_score=max(
                (chain.score for chain in matching_capacity.values()), default=0
            ),
            capacity_evidence_score=max(
                (_capacity_evidence_score(chain) for chain in matching_capacity.values()),
                default=0,
            ),
            priority_class=priority,
            entrypoint_reachable=any(
                chain.node_id in entrypoints for chain in matching.values()
            ) or any(chain.entrypoint_reachable for chain in matching_capacity.values()),
            seed_family=_seed_family(item.seed_file),
            coverage_group=logical_chain_group or _coverage_group(item),
            logical_chain_group=logical_chain_group,
            logical_chain_groups=logical_chain_groups,
            chain_ids=tuple(sorted((*matching, *matching_capacity))),
            risk_chain_ids=tuple(sorted(matching)),
            capacity_chain_ids=tuple(sorted(matching_capacity)),
            capacity_unit_ids=(),
            risk_missing_chain_elements=risk_missing,
            risk_guard_states=tuple(sorted({
                chain.guard_state.value for chain in matching.values()
            })),
            risk_entrypoint_reachable=any(
                chain.node_id in entrypoints for chain in matching.values()
            ),
            missing_chain_elements=tuple(sorted(missing)),
            guard_states=tuple(sorted({
                chain.guard_state.value for chain in matching.values()
            } | {
                chain.guard_state.value for chain in matching_capacity.values()
            })),
        ))
    candidates, capacity_units = _canonicalize_capacity_candidates(
        candidates,
        capacity_chains,
    )
    ordered = sorted(candidates, key=_candidate_order)

    nominal_retry = (
        (1 if policy.max_hunter_sessions <= 12 else 2)
        if policy.max_retries_per_work_item else 0
    )
    retry_slots = (
        min(nominal_retry, max(0, remaining - 1))
        if len(ordered) > remaining else 0
    )
    capacity = max(0, remaining - retry_slots)
    selected: list[_AdmissionCandidate] = []
    selected_ids: set[str] = set()
    selected_components: set[str] = set()
    selected_seed_families: set[str] = set()
    selected_coverage_groups: set[str] = set()
    selected_specialist_chain_groups: set[tuple[str, str]] = set()
    seed_counts: dict[str, int] = {}
    decisions: list[AdmissionDecision] = []
    cap_exceptions = 0

    eligible_critical_seeds = {
        candidate.seed_family for candidate in ordered if candidate.item.required
    }
    diversity_goal = min(3, len(eligible_critical_seeds), capacity)

    def admit(
        candidate: _AdmissionCandidate,
        *,
        quota: str,
        reason: str,
        allow_duplicate_group: bool = True,
        cap_exception: bool = False,
    ) -> bool:
        nonlocal cap_exceptions
        if len(selected) >= capacity or candidate.item.work_id in selected_ids:
            return False
        if (
            not allow_duplicate_group
            and not candidate.logical_chain_groups
            and candidate.coverage_group in selected_coverage_groups
        ):
            return False
        specialist_chain_groups = _specialist_chain_groups(candidate)
        if (
            specialist_chain_groups
            and specialist_chain_groups <= selected_specialist_chain_groups
        ):
            return False
        novelty = 10 if candidate.component not in selected_components else 0
        seed_novelty = 15 if candidate.seed_family not in selected_seed_families else 0
        score_components = {
            "risk_chain": candidate.risk_chain_score,
            "capacity_chain": candidate.capacity_chain_score,
            "capacity_evidence": candidate.capacity_evidence_score,
            "required": int(candidate.item.required) * 20,
            "sink_severity": candidate.item.risk * 10,
            "entrypoint_reachability": int(candidate.entrypoint_reachable) * 10,
            "component_novelty": novelty,
            "seed_novelty": seed_novelty,
        }
        selected.append(candidate)
        selected_ids.add(candidate.item.work_id)
        selected_components.add(candidate.component)
        selected_seed_families.add(candidate.seed_family)
        selected_coverage_groups.add(candidate.coverage_group)
        selected_specialist_chain_groups.update(specialist_chain_groups)
        seed_counts[candidate.seed_family] = (
            seed_counts.get(candidate.seed_family, 0) + 1
        )
        cap_exceptions += int(cap_exception)
        decisions.append(AdmissionDecision(
            work_id=candidate.item.work_id,
            rank=len(selected),
            quota=quota,
            component=candidate.component,
            seed_file=candidate.item.seed_file,
            score=sum(score_components.values()),
            score_components=score_components,
            reason=reason,
            seed_family=candidate.seed_family,
            coverage_group=candidate.coverage_group,
            logical_chain_group=candidate.logical_chain_group,
            logical_chain_groups=candidate.logical_chain_groups,
            capacity_unit_ids=candidate.capacity_unit_ids,
            cap_exception=cap_exception,
        ))
        return True

    chain_slots = 0
    chain_target = min(
        capacity,
        max(1, math.ceil(policy.max_hunter_sessions * NATIVE_CHAIN_SHARE)),
    )
    seed_capped_critical: list[_AdmissionCandidate] = []
    for candidate in ordered:
        if chain_slots >= chain_target:
            break
        if not _is_chain_critical(candidate):
            continue
        before_diversity = len(selected_seed_families) < diversity_goal
        at_cap = seed_counts.get(candidate.seed_family, 0) >= NATIVE_EARLY_SEED_CAP
        only_eligible_seed = len(eligible_critical_seeds) <= 1
        if before_diversity and at_cap and not only_eligible_seed:
            seed_capped_critical.append(candidate)
            continue
        exception = before_diversity and at_cap and only_eligible_seed
        if admit(
            candidate,
            quota="chain_critical",
            reason=(
                "single eligible critical seed owns every chain; early cap exception"
                if exception else
                "complete capacity class or general critical risk chain"
            ),
            cap_exception=exception,
        ):
            chain_slots += 1

    seed_slots = 0
    seed_target = min(
        max(0, capacity - len(selected)),
        max(1, math.ceil(policy.max_hunter_sessions * NATIVE_SEED_DIVERSITY_SHARE)),
    )
    for candidate in ordered:
        if seed_slots >= seed_target:
            break
        if not candidate.item.required:
            continue
        if candidate.seed_family in selected_seed_families:
            continue
        if admit(
            candidate,
            quota="seed_diverse",
            reason="first admitted critical work from a distinct seed file",
        ):
            seed_slots += 1

    chain_revisit_slots = 0
    for candidate in seed_capped_critical:
        if chain_slots >= chain_target or len(selected) >= capacity:
            break
        if admit(
            candidate,
            quota="chain_critical_revisit",
            reason=(
                "uncovered critical root cause revisited after seed diversity"
            ),
            cap_exception=True,
        ):
            chain_slots += 1
            chain_revisit_slots += 1

    high_slots = 0
    high_target = min(
        max(0, capacity - len(selected)),
        max(1, math.ceil(policy.max_hunter_sessions * NATIVE_HIGH_RISK_SHARE)),
    )
    for candidate in ordered:
        if high_slots >= high_target:
            break
        if _is_chain_critical(candidate) or candidate.item.risk < 4:
            continue
        if (
            len(selected_seed_families) < diversity_goal
            and seed_counts.get(candidate.seed_family, 0) >= NATIVE_EARLY_SEED_CAP
        ):
            continue
        if admit(
            candidate,
            quota="high_risk_non_chain",
            reason="high-risk work retained outside a critical risk chain",
        ):
            high_slots += 1

    borrowed_slots = 0
    duplicate_work_ids: set[str] = set()
    for candidate in ordered:
        if len(selected) >= capacity:
            break
        if (
            not candidate.logical_chain_groups
            and candidate.coverage_group in selected_coverage_groups
        ):
            duplicate_work_ids.add(candidate.item.work_id)
            continue
        before_diversity = len(selected_seed_families) < diversity_goal
        at_cap = seed_counts.get(candidate.seed_family, 0) >= NATIVE_EARLY_SEED_CAP
        only_eligible_seed = len(eligible_critical_seeds) <= 1
        if before_diversity and at_cap and not only_eligible_seed:
            continue
        exception = before_diversity and at_cap and only_eligible_seed
        if admit(
            candidate,
            quota="borrowed",
            reason=(
                "unused quota borrowed with single-seed cap exception"
                if exception else
                "unused class reservation borrowed in deterministic risk order"
            ),
            allow_duplicate_group=False,
            cap_exception=exception,
        ):
            borrowed_slots += 1

    deferred = {
        candidate.item.work_id: (
            "duplicate_capacity_chain"
            if (
                _specialist_chain_groups(candidate)
                and _specialist_chain_groups(candidate)
                <= selected_specialist_chain_groups
            )
            else "duplicate_coverage_group"
            if candidate.item.work_id in duplicate_work_ids
            else "max_hunter_sessions"
        )
        for candidate in ordered
        if candidate.item.work_id not in selected_ids
    }
    critical_slots = sum(candidate.item.required for candidate in selected)
    total_high = sum(
        not candidate.item.required and candidate.item.risk >= 4
        for candidate in selected
    )
    return BudgetAllocation(
        admitted_work_ids=tuple(candidate.item.work_id for candidate in selected),
        deferred=deferred,
        critical_slots=critical_slots,
        high_risk_slots=total_high,
        retry_slots=retry_slots,
        general_slots=len(selected) - critical_slots - total_high,
        policy_version=NATIVE_DIVERSE_POLICY,
        chain_critical_slots=chain_slots,
        chain_revisit_slots=chain_revisit_slots,
        seed_diverse_slots=seed_slots,
        high_risk_non_chain_slots=high_slots,
        borrowed_slots=borrowed_slots,
        duplicate_coverage_deferred=sum(
            reason in {"duplicate_coverage_group", "duplicate_capacity_chain"}
            for reason in deferred.values()
        ),
        seed_cap_exceptions=cap_exceptions,
        decisions=tuple(decisions),
        ranking=_native_ranking_records(
            ordered,
            decisions=tuple(decisions),
            deferred=deferred,
        ),
        capacity_units=capacity_units,
    )


def _canonicalize_capacity_candidates(
    candidates: list[_AdmissionCandidate],
    capacity_chains: tuple[CapacityRiskChain, ...],
) -> tuple[list[_AdmissionCandidate], tuple[CapacityAdmissionUnit, ...]]:
    """Keep one auditable scheduling representative for each capacity root."""
    chains_by_id = {chain.chain_id: chain for chain in capacity_chains}
    candidates_by_group: dict[str, list[_AdmissionCandidate]] = {}
    chain_ids_by_group: dict[str, set[str]] = {}
    for candidate in candidates:
        for chain_id in candidate.capacity_chain_ids:
            chain = chains_by_id.get(chain_id)
            if chain is None:
                continue
            candidates_by_group.setdefault(chain.root_cause_group, []).append(
                candidate
            )
            chain_ids_by_group.setdefault(chain.root_cause_group, set()).add(
                chain_id
            )

    units = []
    units_by_work: dict[str, list[CapacityAdmissionUnit]] = {}
    represented_units_by_work: dict[str, list[CapacityAdmissionUnit]] = {}
    for group in sorted(candidates_by_group):
        group_chains = tuple(
            chains_by_id[chain_id]
            for chain_id in sorted(chain_ids_by_group[group])
        )
        representative_chain = min(
            group_chains,
            key=lambda chain: (
                _capacity_priority_rank(chain.priority_class.value),
                -chain.score,
                -_capacity_evidence_score(chain),
                chain.chain_id,
            ),
        )
        eligible = {
            candidate.item.work_id: candidate
            for candidate in candidates_by_group[group]
            if representative_chain.chain_id in candidate.capacity_chain_ids
        }
        representative = min(
            eligible.values(),
            key=lambda candidate: (
                candidate.item.seed_file != representative_chain.root_path,
                _hunter_priority(candidate.item.hunter),
                len(candidate.capacity_chain_ids),
                _candidate_order(candidate),
            ),
        )
        evidence_lines = {
            path: tuple(lines)
            for path, lines in sorted(representative_chain.evidence_lines.items())
        }
        unit = CapacityAdmissionUnit(
            unit_id=_capacity_unit_id(group),
            policy_version=CAPACITY_ADMISSION_UNIT_POLICY,
            root_cause_group=group,
            priority_class=representative_chain.priority_class.value,
            representative_chain_id=representative_chain.chain_id,
            representative_work_id=representative.item.work_id,
            chain_ids=tuple(chain.chain_id for chain in group_chains),
            work_ids=tuple(sorted({
                candidate.item.work_id
                for candidate in candidates_by_group[group]
            })),
            required_paths=representative_chain.paths,
            evidence_lines=evidence_lines,
        )
        units.append(unit)
        for work_id in unit.work_ids:
            units_by_work.setdefault(work_id, []).append(unit)
        represented_units_by_work.setdefault(
            representative.item.work_id, []
        ).append(unit)

    canonical = []
    for candidate in candidates:
        associated = tuple(sorted(
            units_by_work.get(candidate.item.work_id, ()),
            key=lambda unit: unit.unit_id,
        ))
        represented = tuple(sorted(
            represented_units_by_work.get(candidate.item.work_id, ()),
            key=lambda unit: unit.unit_id,
        ))
        if not represented:
            logical_groups = tuple(
                unit.root_cause_group for unit in associated
            )
            canonical.append(replace(
                candidate,
                capacity_chain_score=0,
                capacity_evidence_score=0,
                priority_class="unclassified",
                entrypoint_reachable=candidate.risk_entrypoint_reachable,
                coverage_group=(
                    logical_groups[0]
                    if logical_groups else _coverage_group(candidate.item)
                ),
                logical_chain_group=(logical_groups[0] if logical_groups else ""),
                logical_chain_groups=logical_groups,
                chain_ids=candidate.risk_chain_ids,
                capacity_chain_ids=(),
                capacity_unit_ids=tuple(unit.unit_id for unit in associated),
                missing_chain_elements=candidate.risk_missing_chain_elements,
                guard_states=candidate.risk_guard_states,
            ))
            continue
        representative_chains = tuple(
            chains_by_id[unit.representative_chain_id]
            for unit in represented
        )
        best_chain = min(
            representative_chains,
            key=lambda chain: (
                _capacity_priority_rank(chain.priority_class.value),
                -chain.score,
                -_capacity_evidence_score(chain),
                chain.chain_id,
            ),
        )
        missing = set(candidate.risk_missing_chain_elements)
        missing.discard("risk_chain")
        missing.update(
            element
            for chain in representative_chains
            for element in chain.missing_elements
        )
        canonical.append(replace(
            candidate,
            capacity_chain_score=max(chain.score for chain in representative_chains),
            capacity_evidence_score=max(
                _capacity_evidence_score(chain) for chain in representative_chains
            ),
            priority_class=best_chain.priority_class.value,
            entrypoint_reachable=(
                candidate.risk_entrypoint_reachable
                or any(chain.entrypoint_reachable for chain in representative_chains)
            ),
            coverage_group=best_chain.root_cause_group,
            logical_chain_group=best_chain.root_cause_group,
            logical_chain_groups=tuple(
                unit.root_cause_group for unit in associated
            ),
            chain_ids=tuple(sorted((
                *candidate.risk_chain_ids,
                *(chain.chain_id for chain in representative_chains),
            ))),
            capacity_chain_ids=tuple(sorted(
                chain.chain_id for chain in representative_chains
            )),
            capacity_unit_ids=tuple(unit.unit_id for unit in associated),
            missing_chain_elements=tuple(sorted(missing)),
            guard_states=tuple(sorted({
                *candidate.risk_guard_states,
                *(chain.guard_state.value for chain in representative_chains),
            })),
        ))
    return canonical, tuple(units)


def _capacity_unit_id(root_cause_group: str) -> str:
    canonical = f"{CAPACITY_ADMISSION_UNIT_POLICY}\0{root_cause_group}"
    return "capacity_unit_" + hashlib.sha256(canonical.encode()).hexdigest()[:20]


def _specialist_chain_groups(
    candidate: _AdmissionCandidate,
) -> set[tuple[str, str]]:
    """Keep capacity cost units shared without conflating Hunter expertise."""
    return {
        (group, candidate.item.hunter)
        for group in candidate.logical_chain_groups
    }


def _native_ranking_records(
    ordered: list[_AdmissionCandidate],
    *,
    decisions: tuple[AdmissionDecision, ...],
    deferred: dict[str, str],
) -> tuple[AdmissionRankingRecord, ...]:
    admitted = {decision.work_id: decision for decision in decisions}
    records = []
    for rank, candidate in enumerate(ordered, start=1):
        decision = admitted.get(candidate.item.work_id)
        static_components = {
            "risk_chain": candidate.risk_chain_score,
            "capacity_chain": candidate.capacity_chain_score,
            "capacity_evidence": candidate.capacity_evidence_score,
            "required": int(candidate.item.required) * 20,
            "sink_severity": candidate.item.risk * 10,
            "entrypoint_reachability": int(candidate.entrypoint_reachable) * 10,
            "component_novelty": 0,
            "seed_novelty": 0,
        }
        reason = decision.reason if decision else deferred[candidate.item.work_id]
        disposition = (
            "admitted"
            if decision else
            "duplicate_deferred"
            if reason in {"duplicate_coverage_group", "duplicate_capacity_chain"} else
            "budget_deferred"
        )
        records.append(AdmissionRankingRecord(
            record_id=_ranking_record_id(candidate.item.work_id),
            work_id=candidate.item.work_id,
            pre_admission_rank=rank,
            component=candidate.component,
            seed_file=candidate.item.seed_file,
            score=sum(static_components.values()),
            score_components=static_components,
            chain_ids=candidate.chain_ids,
            missing_chain_elements=candidate.missing_chain_elements,
            guard_states=candidate.guard_states,
            priority_class=candidate.priority_class,
            disposition=disposition,
            reason=reason,
            seed_family=candidate.seed_family,
            coverage_group=candidate.coverage_group,
            logical_chain_group=candidate.logical_chain_group,
            logical_chain_groups=candidate.logical_chain_groups,
            capacity_unit_ids=candidate.capacity_unit_ids,
        ))
    return tuple(records)


def _legacy_ranking_record(
    item: HunterWorkItem,
    *,
    pre_admission_rank: int,
    disposition: str,
    reason: str,
) -> AdmissionRankingRecord:
    components = {
        "risk_chain": 0,
        "capacity_chain": 0,
        "capacity_evidence": 0,
        "required": int(item.required) * 20,
        "sink_severity": item.risk * 10,
        "entrypoint_reachability": 0,
        "component_novelty": 0,
        "seed_novelty": 0,
    }
    return AdmissionRankingRecord(
        record_id=_ranking_record_id(item.work_id),
        work_id=item.work_id,
        pre_admission_rank=pre_admission_rank,
        component=_component_for(item.seed_file),
        seed_file=item.seed_file,
        score=sum(components.values()),
        score_components=components,
        chain_ids=(),
        missing_chain_elements=("risk_chain",),
        guard_states=(),
        priority_class="unclassified",
        disposition=disposition,
        reason=reason,
        seed_family=_seed_family(item.seed_file),
        coverage_group=_coverage_group(item),
        logical_chain_group="",
        logical_chain_groups=(),
    )


def _missing_chain_elements(chains: tuple[RiskChain, ...]) -> tuple[str, ...]:
    if not chains:
        return ("risk_chain",)
    missing = set()
    if not any(chain.source_variables for chain in chains):
        missing.add("source")
    if not any(chain.transform_steps for chain in chains):
        missing.add("transform")
    if not any(chain.allocation_signal_ids for chain in chains):
        missing.add("allocation")
    if not any(chain.sink_signal_ids for chain in chains):
        missing.add("write_sink")
    return tuple(sorted(missing))


def _ranking_record_id(work_id: str) -> str:
    canonical = f"{NATIVE_DIVERSE_POLICY}\0{work_id}"
    return "ranking_" + hashlib.sha256(canonical.encode()).hexdigest()[:20]


def _candidate_order(
    candidate: _AdmissionCandidate,
) -> tuple[int, int, int, int, int, int, int, str, str, str]:
    return (
        _capacity_priority_rank(candidate.priority_class),
        -candidate.chain_score,
        -candidate.capacity_evidence_score,
        _hunter_priority(candidate.item.hunter),
        -int(candidate.item.required),
        -candidate.item.risk,
        -int(candidate.entrypoint_reachable),
        candidate.component,
        candidate.seed_family,
        _work_tie_key(candidate.item),
    )


def _capacity_evidence_score(chain: CapacityRiskChain) -> int:
    """Break categorical ties with generic end-to-end capacity evidence."""
    score = 0
    score += 40 if len(chain.paths) > 1 else 0
    score += 30 if chain.return_consumption_call_ids else 0
    score += 20 if chain.pointer_advance_fact_ids else 0
    score += 10 if chain.write_fact_ids else 0
    return score


def _work_tie_key(item: HunterWorkItem) -> str:
    canonical = json.dumps(
        {
            "planning_policy": item.planning_policy,
            "slice_ids": item.slice_ids,
            "target_node_ids": item.target_node_ids,
            "target_signal_ids": item.target_signal_ids,
            "seed_file": item.seed_file,
            "files": item.files,
            "hunter": item.hunter,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _is_chain_critical(candidate: _AdmissionCandidate) -> bool:
    return candidate.priority_class in {
        CapacityPriorityClass.COMPLETE_UNCHECKED.value,
        CapacityPriorityClass.COMPLETE_UNKNOWN_GUARD.value,
    } or candidate.risk_chain_score >= 80


def _hunter_priority(hunter: str) -> int:
    return 0 if hunter == "c-bounds-integers" else 1


def _capacity_priority_rank(priority: str) -> int:
    return {
        CapacityPriorityClass.COMPLETE_UNCHECKED.value: 0,
        CapacityPriorityClass.COMPLETE_UNKNOWN_GUARD.value: 1,
        CapacityPriorityClass.PARTIAL.value: 2,
        CapacityPriorityClass.ISOLATED.value: 3,
        "unclassified": 4,
    }.get(priority, 4)


def _component_for(path: str) -> str:
    return path.split("/", 1)[0] if "/" in path else "(root)"


def _seed_family(path: str) -> str:
    return path.replace("\\", "/").casefold()


def _coverage_group(item: HunterWorkItem) -> str:
    targets = tuple(sorted(
        item.target_signal_ids
        or item.target_node_ids
        or item.slice_ids
        or (item.seed_file,)
    ))
    canonical = json.dumps(
        {
            "hunter": item.hunter,
            "targets": targets,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "coverage_" + hashlib.sha256(canonical.encode()).hexdigest()[:20]


def adaptive_iteration_limit(
    item: HunterWorkItem,
    *,
    configured_cap: int,
    attempt: int = 1,
    has_evidence: bool = False,
) -> int:
    """Return the 6/18/40 iteration tier, bounded by the operator's cap."""
    if has_evidence or attempt > 1:
        tier = 40
    elif item.required or item.risk >= 4:
        tier = 18
    else:
        tier = 6
    return max(1, min(configured_cap, tier))


def adaptive_output_token_limit(
    item: HunterWorkItem,
    *,
    configured_cap: int = 4_000,
) -> int:
    """Size one response for its bounded target contract instead of the repo."""
    targets = max(len(item.target_signal_ids), len(item.target_node_ids), 1)
    tier = 1_600 + min(targets, 6) * 300 + (600 if item.required else 0)
    return max(800, min(configured_cap, tier))


class BudgetController:
    """Concurrency-safe token and wall-clock reservations for model calls."""

    def __init__(
        self,
        policy: BudgetPolicy,
        usage: list[BudgetUsage] | None = None,
        *,
        work_input_budget: WorkInputBudgetPlan | None = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.policy = policy
        self._clock = clock
        self._lock = threading.Lock()
        prior = usage or []
        self._input_tokens = sum(
            item.input_tokens + item.cache_read_tokens + item.cache_write_tokens
            for item in prior
        )
        self._output_tokens = sum(item.output_tokens for item in prior)
        self._work_input_budget = work_input_budget
        self._work_input_tokens: dict[str, int] = {}
        for item in prior:
            self._work_input_tokens[item.work_id] = (
                self._work_input_tokens.get(item.work_id, 0)
                + item.input_tokens
                + item.cache_read_tokens
                + item.cache_write_tokens
            )
        critical_work_ids = (
            set(work_input_budget.critical_work_ids)
            if work_input_budget is not None else set()
        )
        # The controller cannot infer terminal work state from usage alone.
        # The pipeline narrows this set to each active priority wave and calls
        # finish_work only when a work item actually becomes terminal.
        self._pending_critical_work_ids = critical_work_ids
        prior_seconds = sum(item.wall_time_ms for item in prior) / 1000
        allowance = max(0.0, policy.max_wall_clock_minutes * 60 - prior_seconds)
        self._deadline = clock() + allowance
        self._reservations: dict[str, _CallReservation] = {}

    def activate_priority_window(self, work_ids: tuple[str, ...]) -> None:
        """Protect only critical work eligible to execute in the current wave."""
        with self._lock:
            critical_work_ids = (
                set(self._work_input_budget.critical_work_ids)
                if self._work_input_budget is not None else set()
            )
            self._pending_critical_work_ids = set(work_ids) & critical_work_ids

    def finish_work(self, work_id: str) -> None:
        """Release a critical reserve only after its work becomes terminal."""
        with self._lock:
            self._pending_critical_work_ids.discard(work_id)

    def _protected_critical_input(self, *, excluding_work_id: str = "") -> int:
        if self._work_input_budget is None:
            return 0
        protected = 0
        reserve = self._work_input_budget.critical_first_call_reserve
        for critical_work_id in self._pending_critical_work_ids:
            if critical_work_id == excluding_work_id:
                continue
            reserved = sum(
                item.input_tokens
                for item in self._reservations.values()
                if item.work_id == critical_work_id
            )
            consumed = self._work_input_tokens.get(critical_work_id, 0)
            protected += max(0, reserve - consumed - reserved)
        return protected

    def reserve_call(
        self,
        *,
        input_upper_bound: int,
        requested_output_tokens: int,
        work_id: str = "",
    ) -> _CallReservation:
        input_upper_bound = max(1, input_upper_bound)
        requested_output_tokens = max(1, requested_output_tokens)
        with self._lock:
            if self._clock() >= self._deadline:
                raise BudgetExceededError("max_wall_clock_minutes")
            reserved_input = sum(item.input_tokens for item in self._reservations.values())
            reserved_output = sum(item.output_tokens for item in self._reservations.values())
            remaining_input = (
                self.policy.max_input_tokens - self._input_tokens - reserved_input
            )
            remaining_output = (
                self.policy.max_output_tokens - self._output_tokens - reserved_output
            )
            if self._work_input_budget is not None and work_id:
                work_limit = self._work_input_budget.work_input_limits.get(work_id)
                if work_limit is not None:
                    work_reserved = sum(
                        item.input_tokens
                        for item in self._reservations.values()
                        if item.work_id == work_id
                    )
                    work_remaining = (
                        work_limit
                        - self._work_input_tokens.get(work_id, 0)
                        - work_reserved
                    )
                    if input_upper_bound > work_remaining:
                        raise BudgetExceededError("max_input_tokens_per_work")
                protected_critical = self._protected_critical_input(
                    excluding_work_id=work_id,
                )
                if input_upper_bound > remaining_input - protected_critical:
                    raise BudgetExceededError("critical_input_reserve")
            if input_upper_bound > remaining_input:
                raise BudgetExceededError("max_input_tokens")
            if remaining_output <= 0:
                raise BudgetExceededError("max_output_tokens")
            reservation = _CallReservation(
                reservation_id=uuid.uuid4().hex,
                input_tokens=input_upper_bound,
                output_tokens=min(requested_output_tokens, remaining_output),
                work_id=work_id,
            )
            self._reservations[reservation.reservation_id] = reservation
            return reservation

    def complete_call(
        self,
        reservation: _CallReservation,
        response: LLMResponse | None,
    ) -> None:
        with self._lock:
            self._reservations.pop(reservation.reservation_id, None)
            if response is None:
                return
            self._input_tokens += (
                response.input_tokens
                + response.cache_read_tokens
                + response.cache_write_tokens
            )
            if reservation.work_id:
                self._work_input_tokens[reservation.work_id] = (
                    self._work_input_tokens.get(reservation.work_id, 0)
                    + response.input_tokens
                    + response.cache_read_tokens
                    + response.cache_write_tokens
                )
            self._output_tokens += response.output_tokens

    def remaining_seconds(self) -> float:
        with self._lock:
            return max(0.0, self._deadline - self._clock())

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            reserved_input = sum(item.input_tokens for item in self._reservations.values())
            reserved_output = sum(item.output_tokens for item in self._reservations.values())
            return {
                "input_tokens": self._input_tokens,
                "output_tokens": self._output_tokens,
                "reserved_input_tokens": reserved_input,
                "reserved_output_tokens": reserved_output,
                "input_fairness_policy": (
                    self._work_input_budget.policy_version
                    if self._work_input_budget is not None else "disabled"
                ),
                "per_work_input_limit": (
                    self._work_input_budget.per_work_input_limit
                    if self._work_input_budget is not None else 0
                ),
                "protected_critical_input_tokens": (
                    self._protected_critical_input()
                    if self._work_input_budget is not None else 0
                ),
                "pending_critical_work_ids": sorted(
                    self._pending_critical_work_ids
                ),
                "work_input_tokens": dict(sorted(self._work_input_tokens.items())),
                "remaining_seconds": max(0.0, self._deadline - self._clock()),
                "exhausted": (
                    self._input_tokens >= self.policy.max_input_tokens
                    or self._output_tokens >= self.policy.max_output_tokens
                    or self._clock() >= self._deadline
                ),
            }


class BudgetedLLMClient:
    """Drop-in client that reserves shared budget before every provider call."""

    def __init__(
        self,
        delegate,
        controller: BudgetController,
        *,
        work_id: str = "",
        on_call_started: Callable[[], None] | None = None,
    ):
        self.delegate = delegate
        self.controller = controller
        self.model_id = str(getattr(delegate, "model_id", "unknown"))
        self.transport = str(getattr(delegate, "transport", "bedrock_converse"))
        self.work_id = work_id
        self.on_call_started = on_call_started or (lambda: None)
        self.started_calls = 0

    async def chat(self, **kwargs) -> LLMResponse:
        requested = int(kwargs.get("max_tokens") or 1)
        reservation = self.controller.reserve_call(
            input_upper_bound=_input_token_upper_bound(kwargs),
            requested_output_tokens=requested,
            work_id=self.work_id,
        )
        kwargs["max_tokens"] = reservation.output_tokens
        timeout = self.controller.remaining_seconds()
        if timeout <= 0:
            self.controller.complete_call(reservation, None)
            raise BudgetExceededError("max_wall_clock_minutes")
        try:
            self.started_calls += 1
            self.on_call_started()
            response = await asyncio.wait_for(
                self.delegate.chat(**kwargs),
                timeout=timeout,
            )
        except TimeoutError as exc:
            self.controller.complete_call(reservation, None)
            raise BudgetExceededError("max_wall_clock_minutes") from exc
        except BaseException:
            self.controller.complete_call(reservation, None)
            raise
        self.controller.complete_call(reservation, response)
        return response


def _input_token_upper_bound(kwargs: dict) -> int:
    """Use UTF-8 bytes as a conservative tokenizer-independent upper bound."""
    envelope = {
        "messages": kwargs.get("messages") or [],
        "system": kwargs.get("system") or "",
        "tools": kwargs.get("tools") or [],
    }
    return max(
        1,
        len(json.dumps(envelope, ensure_ascii=False, default=str).encode("utf-8")),
    )
