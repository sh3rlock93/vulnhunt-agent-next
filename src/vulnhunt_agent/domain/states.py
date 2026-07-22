"""Explicit run and finding state machines.

Prompts may propose a state, but only these transition tables can authorize it.
"""
from __future__ import annotations

from enum import StrEnum


class RunState(StrEnum):
    CREATED = "created"
    SNAPSHOTTING = "snapshotting"
    INDEXING = "indexing"
    PLANNING = "planning"
    BUILDING = "building"
    HUNTING = "hunting"
    REPRODUCING = "reproducing"
    REVIEWING = "reviewing"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingState(StrEnum):
    HYPOTHESIS = "hypothesis"
    STATICALLY_SUPPORTED = "statically_supported"
    POC_READY = "poc_ready"
    REPRODUCTION_PENDING = "reproduction_pending"
    REPRODUCED = "reproduced"
    REVIEWER_VERIFIED = "reviewer_verified"
    REPORTABLE = "reportable"
    REJECTED = "rejected"
    UNCLEAR = "unclear"
    ENVIRONMENT_BLOCKED = "environment_blocked"
    POLICY_BLOCKED = "policy_blocked"
    STATICALLY_REFUTED = "statically_refuted"
    RESOURCE_INFEASIBLE = "resource_infeasible"
    VERIFICATION_DEFERRED = "verification_deferred"


class StateTransitionError(ValueError):
    """Raised when code attempts a transition that is not in the policy table."""


RUN_SEQUENCE = (
    RunState.CREATED,
    RunState.SNAPSHOTTING,
    RunState.INDEXING,
    RunState.PLANNING,
    RunState.BUILDING,
    RunState.HUNTING,
    RunState.REPRODUCING,
    RunState.REVIEWING,
    RunState.REPORTING,
    RunState.COMPLETED,
)

RUN_TRANSITIONS: dict[RunState, frozenset[RunState]] = {
    state: frozenset({RUN_SEQUENCE[index + 1], RunState.FAILED, RunState.CANCELLED})
    for index, state in enumerate(RUN_SEQUENCE[:-1])
}
RUN_TRANSITIONS.update(
    {
        RunState.COMPLETED: frozenset(),
        RunState.FAILED: frozenset(),
        RunState.CANCELLED: frozenset(),
    }
)

_FINDING_TERMINALS = frozenset({
    FindingState.REJECTED,
    FindingState.UNCLEAR,
    FindingState.STATICALLY_REFUTED,
    FindingState.RESOURCE_INFEASIBLE,
    FindingState.VERIFICATION_DEFERRED,
})
FINDING_TRANSITIONS: dict[FindingState, frozenset[FindingState]] = {
    FindingState.HYPOTHESIS: frozenset(
        {FindingState.STATICALLY_SUPPORTED, FindingState.ENVIRONMENT_BLOCKED}
    )
    | _FINDING_TERMINALS,
    FindingState.STATICALLY_SUPPORTED: frozenset(
        {FindingState.POC_READY, FindingState.ENVIRONMENT_BLOCKED}
    )
    | _FINDING_TERMINALS,
    FindingState.POC_READY: frozenset(
        {FindingState.REPRODUCTION_PENDING, FindingState.ENVIRONMENT_BLOCKED}
    )
    | _FINDING_TERMINALS,
    FindingState.REPRODUCTION_PENDING: frozenset(
        {FindingState.REPRODUCED, FindingState.ENVIRONMENT_BLOCKED}
    )
    | _FINDING_TERMINALS,
    FindingState.REPRODUCED: frozenset({FindingState.REVIEWER_VERIFIED})
    | _FINDING_TERMINALS,
    FindingState.REVIEWER_VERIFIED: frozenset(
        {FindingState.REPORTABLE, FindingState.POLICY_BLOCKED}
    )
    | _FINDING_TERMINALS,
    FindingState.ENVIRONMENT_BLOCKED: frozenset({
        FindingState.REPRODUCTION_PENDING,
        FindingState.VERIFICATION_DEFERRED,
    }),
    FindingState.POLICY_BLOCKED: frozenset({FindingState.REVIEWER_VERIFIED}),
    FindingState.REPORTABLE: frozenset(),
    FindingState.REJECTED: frozenset(),
    FindingState.UNCLEAR: frozenset(),
    FindingState.STATICALLY_REFUTED: frozenset(),
    FindingState.RESOURCE_INFEASIBLE: frozenset(),
    FindingState.VERIFICATION_DEFERRED: frozenset(),
}


def require_run_transition(current: RunState, target: RunState) -> None:
    _require_transition("run", current, target, RUN_TRANSITIONS)


def require_finding_transition(current: FindingState, target: FindingState) -> None:
    _require_transition("finding", current, target, FINDING_TRANSITIONS)


def _require_transition(state_type: str, current, target, transitions: dict) -> None:
    if target not in transitions[current]:
        raise StateTransitionError(
            f"illegal {state_type} transition: {current.value} -> {target.value}"
        )
