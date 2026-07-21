"""Hard Hunter budgets and deterministic priority allocation."""
from __future__ import annotations

import asyncio
import json
import math
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable

from ..core.llm import LLMResponse
from ..analysis.models import RiskChain
from ..domain.schemas import BudgetPolicy, BudgetUsage, HunterWorkItem

LEGACY_BUDGET_POLICY = "hunter-budget-allocation-v1"
NATIVE_DIVERSE_POLICY = "c-diverse-admission-v1"


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
    component_diverse_slots: int = 0
    high_risk_non_chain_slots: int = 0
    decisions: tuple["AdmissionDecision", ...] = ()


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


@dataclass(frozen=True)
class _AdmissionCandidate:
    item: HunterWorkItem
    component: str
    chain_score: int
    entrypoint_reachable: bool


@dataclass(frozen=True)
class _CallReservation:
    reservation_id: str
    input_tokens: int
    output_tokens: int


def allocate_work_items(
    work_items: tuple[HunterWorkItem, ...],
    policy: BudgetPolicy,
    *,
    consumed_sessions: int = 0,
    risk_chains: tuple[RiskChain, ...] = (),
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
    )


def _allocate_native_diverse(
    work_items: tuple[HunterWorkItem, ...],
    policy: BudgetPolicy,
    *,
    consumed_sessions: int,
    risk_chains: tuple[RiskChain, ...],
    entrypoint_ids: tuple[str, ...],
) -> BudgetAllocation:
    """Admit full native work with chain, component, and retry reservations."""
    remaining = max(0, policy.max_hunter_sessions - consumed_sessions)
    chain_by_signal: dict[str, list[RiskChain]] = {}
    chain_by_node: dict[str, list[RiskChain]] = {}
    for chain in risk_chains:
        for signal_id in (*chain.allocation_signal_ids, *chain.sink_signal_ids):
            chain_by_signal.setdefault(signal_id, []).append(chain)
        chain_by_node.setdefault(chain.node_id, []).append(chain)
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
        candidates.append(_AdmissionCandidate(
            item=item,
            component=_component_for(item.seed_file),
            chain_score=max((chain.score for chain in matching.values()), default=0),
            entrypoint_reachable=any(
                chain.node_id in entrypoints for chain in matching.values()
            ),
        ))
    ordered = sorted(candidates, key=_candidate_order)

    nominal_retry = 2 if policy.max_retries_per_work_item else 0
    retry_slots = (
        min(nominal_retry, max(0, remaining - 1))
        if len(ordered) > remaining else 0
    )
    capacity = max(0, remaining - retry_slots)
    selected: list[_AdmissionCandidate] = []
    selected_ids: set[str] = set()
    selected_components: set[str] = set()
    seed_counts: dict[str, int] = {}
    decisions: list[AdmissionDecision] = []

    def admit(candidate: _AdmissionCandidate, *, quota: str, reason: str) -> bool:
        if len(selected) >= capacity or candidate.item.work_id in selected_ids:
            return False
        novelty = 10 if candidate.component not in selected_components else 0
        score_components = {
            "risk_chain": candidate.chain_score,
            "required": int(candidate.item.required) * 20,
            "sink_severity": candidate.item.risk * 10,
            "entrypoint_reachability": int(candidate.entrypoint_reachable) * 10,
            "component_novelty": novelty,
        }
        selected.append(candidate)
        selected_ids.add(candidate.item.work_id)
        selected_components.add(candidate.component)
        seed_counts[candidate.item.seed_file] = (
            seed_counts.get(candidate.item.seed_file, 0) + 1
        )
        decisions.append(AdmissionDecision(
            work_id=candidate.item.work_id,
            rank=len(selected),
            quota=quota,
            component=candidate.component,
            seed_file=candidate.item.seed_file,
            score=sum(score_components.values()),
            score_components=score_components,
            reason=reason,
        ))
        return True

    chain_slots = 0
    for candidate in ordered:
        if chain_slots >= min(14, capacity):
            break
        if candidate.chain_score < 80:
            continue
        if seed_counts.get(candidate.item.seed_file, 0) >= 4:
            continue
        if admit(
            candidate,
            quota="chain_critical",
            reason="risk chain score is at least 80 without a dominating guard",
        ):
            chain_slots += 1

    component_slots = 0
    component_target = min(5, max(0, capacity - len(selected)))
    diversity_seen: set[str] = set()
    for candidate in ordered:
        if component_slots >= component_target:
            break
        if not candidate.item.required:
            continue
        if candidate.component in selected_components or candidate.component in diversity_seen:
            continue
        if seed_counts.get(candidate.item.seed_file, 0) >= 4:
            continue
        if admit(
            candidate,
            quota="component_diverse",
            reason="first admitted critical work from an uncovered top-level component",
        ):
            diversity_seen.add(candidate.component)
            component_slots += 1

    high_slots = 0
    high_target = min(3, max(0, capacity - len(selected)))
    for candidate in ordered:
        if high_slots >= high_target:
            break
        if candidate.chain_score >= 80 or candidate.item.risk < 4:
            continue
        if seed_counts.get(candidate.item.seed_file, 0) >= 4:
            continue
        if admit(
            candidate,
            quota="high_risk_non_chain",
            reason="high-risk work retained outside a critical risk chain",
        ):
            high_slots += 1

    for candidate in ordered:
        if len(selected) >= capacity:
            break
        admit(
            candidate,
            quota="borrowed",
            reason="unused native quota borrowed in deterministic risk order",
        )

    deferred = {
        candidate.item.work_id: "max_hunter_sessions"
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
        component_diverse_slots=component_slots,
        high_risk_non_chain_slots=high_slots,
        decisions=tuple(decisions),
    )


def _candidate_order(candidate: _AdmissionCandidate) -> tuple[int, int, int, int, str, str]:
    return (
        -candidate.chain_score,
        -int(candidate.item.required),
        -candidate.item.risk,
        -int(candidate.entrypoint_reachable),
        candidate.component,
        candidate.item.work_id,
    )


def _component_for(path: str) -> str:
    return path.split("/", 1)[0] if "/" in path else "(root)"


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
        prior_seconds = sum(item.wall_time_ms for item in prior) / 1000
        allowance = max(0.0, policy.max_wall_clock_minutes * 60 - prior_seconds)
        self._deadline = clock() + allowance
        self._reservations: dict[str, _CallReservation] = {}

    def reserve_call(
        self,
        *,
        input_upper_bound: int,
        requested_output_tokens: int,
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
            if input_upper_bound > remaining_input:
                raise BudgetExceededError("max_input_tokens")
            if remaining_output <= 0:
                raise BudgetExceededError("max_output_tokens")
            reservation = _CallReservation(
                reservation_id=uuid.uuid4().hex,
                input_tokens=input_upper_bound,
                output_tokens=min(requested_output_tokens, remaining_output),
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
            self._output_tokens += response.output_tokens

    def remaining_seconds(self) -> float:
        with self._lock:
            return max(0.0, self._deadline - self._clock())

    def snapshot(self) -> dict[str, int | float | bool]:
        with self._lock:
            reserved_input = sum(item.input_tokens for item in self._reservations.values())
            reserved_output = sum(item.output_tokens for item in self._reservations.values())
            return {
                "input_tokens": self._input_tokens,
                "output_tokens": self._output_tokens,
                "reserved_input_tokens": reserved_input,
                "reserved_output_tokens": reserved_output,
                "remaining_seconds": max(0.0, self._deadline - self._clock()),
                "exhausted": (
                    self._input_tokens >= self.policy.max_input_tokens
                    or self._output_tokens >= self.policy.max_output_tokens
                    or self._clock() >= self._deadline
                ),
            }


class BudgetedLLMClient:
    """Drop-in client that reserves shared budget before every provider call."""

    def __init__(self, delegate, controller: BudgetController):
        self.delegate = delegate
        self.controller = controller
        self.model_id = str(getattr(delegate, "model_id", "unknown"))
        self.transport = str(getattr(delegate, "transport", "bedrock_converse"))

    async def chat(self, **kwargs) -> LLMResponse:
        requested = int(kwargs.get("max_tokens") or 1)
        reservation = self.controller.reserve_call(
            input_upper_bound=_input_token_upper_bound(kwargs),
            requested_output_tokens=requested,
        )
        kwargs["max_tokens"] = reservation.output_tokens
        timeout = self.controller.remaining_seconds()
        if timeout <= 0:
            self.controller.complete_call(reservation, None)
            raise BudgetExceededError("max_wall_clock_minutes")
        try:
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
