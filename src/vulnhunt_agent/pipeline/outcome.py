"""Honest, scope-aware terminal outcome classification for scan runs."""
from __future__ import annotations

from enum import StrEnum
from typing import Any

RUN_OUTCOME_POLICY = "run-outcome-v1"


class RunOutcome(StrEnum):
    VALID_COMPLETE = "valid_complete"
    VALID_BUDGET_LIMITED = "valid_budget_limited"
    INVALID_EXECUTION = "invalid_execution"
    INTERRUPTED = "interrupted"


def classify_run_outcome(
    summary: dict[str, Any],
    *,
    plan: dict[str, Any] | None = None,
    scan_scope: dict[str, Any] | None = None,
    source_snapshot: str | None = None,
    invalid_reason: str = "",
    interrupted: bool = False,
) -> dict[str, Any]:
    """Return a validated-by-construction accounting record.

    A zero-finding statement is never emitted for invalid or interrupted work.
    Budget-limited runs may state that no finding was observed only when the
    exact incomplete scope and deferred counts travel with that statement.
    """
    plan = plan or {}
    scope = scan_scope or {}
    targets = summary.get("target_completion") or {}
    allocation = plan.get("budget_allocation") or {}
    total_findings = summary.get("total_findings")
    failed = _count(summary, "failed")
    pending = _count(summary, "pending")
    running = _count(summary, "running")
    budget_deferred = _count(summary, "budget_deferred")
    target_deferred = _count(targets, "deferred")
    target_missing = _count(targets, "missing")

    if invalid_reason or failed:
        outcome = RunOutcome.INVALID_EXECUTION
        reason = invalid_reason or "hunter_work_failed"
    elif interrupted or pending or running:
        outcome = RunOutcome.INTERRUPTED
        reason = "operator_or_process_interruption"
    elif target_missing:
        outcome = RunOutcome.INVALID_EXECUTION
        reason = "target_disposition_missing"
    elif budget_deferred or target_deferred:
        outcome = RunOutcome.VALID_BUDGET_LIMITED
        reason = "declared_work_deferred"
    else:
        outcome = RunOutcome.VALID_COMPLETE
        reason = "all_in_scope_work_terminal"

    valid = outcome in {
        RunOutcome.VALID_COMPLETE,
        RunOutcome.VALID_BUDGET_LIMITED,
    }
    zero_findings = (
        valid
        and isinstance(total_findings, int)
        and not isinstance(total_findings, bool)
        and total_findings == 0
    )
    mode = str(scope.get("mode") or "full")
    selected_files = len(scope.get("selected_files") or ())
    scope_deferred = len(scope.get("scope_deferred_critical_sink_ids") or ())
    unadmitted_budget_deferred = len(plan.get("budget_deferred_work_ids") or ())
    if "budget_deferred_work_ids" not in plan:
        unadmitted_budget_deferred = budget_deferred
    admitted_deferred = max(
        budget_deferred - unadmitted_budget_deferred,
        0,
    )
    label = ""
    if zero_findings:
        accounting = (
            f"{selected_files} files; {scope_deferred} scope-deferred critical "
            f"targets; {unadmitted_budget_deferred} unadmitted budget-deferred "
            f"work; {admitted_deferred} admitted deferred work; "
            f"{target_deferred} deferred targets"
        )
        if outcome is RunOutcome.VALID_COMPLETE:
            label = f"0 findings in completed {mode} scope ({accounting})"
        else:
            label = (
                "0 findings in completed work; scan is budget-limited "
                f"for {mode} scope ({accounting})"
            )

    admitted = int(allocation.get("admitted_sessions", 0) or 0) + int(
        allocation.get("recycled_slots", 0) or 0
    )
    completed = _count(summary, "done")
    return {
        "policy_version": RUN_OUTCOME_POLICY,
        "outcome": outcome.value,
        "reason": reason,
        "valid": valid,
        "complete": outcome is RunOutcome.VALID_COMPLETE,
        "trustworthy": outcome not in {
            RunOutcome.INVALID_EXECUTION,
            RunOutcome.INTERRUPTED,
        },
        "zero_findings": zero_findings,
        "zero_finding_label": label,
        "source_snapshot": source_snapshot,
        "scope": {
            "policy_version": scope.get("policy_version", "scan-scope-v1"),
            "digest": scope.get("digest"),
            "mode": mode,
            "repository_complete": bool(scope.get("repository_complete", mode == "full")),
            "selected_files": selected_files,
            "scope_deferred_critical_targets": scope_deferred,
        },
        "work": {
            "planned": _count(summary, "total"),
            "admitted": admitted,
            "completed": completed,
            "budget_deferred": budget_deferred,
            "unadmitted_budget_deferred": unadmitted_budget_deferred,
            "admitted_deferred": admitted_deferred,
            "failed": failed,
            "pending": pending,
            "running": running,
        },
        "targets": {
            "total": _count(targets, "total"),
            "finding": _count(targets, "finding"),
            "no_finding": _count(targets, "no_finding"),
            "deferred": target_deferred,
            "missing": target_missing,
            "all_admitted_terminal": (
                target_missing == 0
                and pending == 0
                and running == 0
                and not interrupted
            ),
        },
        "findings": total_findings,
    }


def _count(value: dict[str, Any], key: str) -> int:
    raw = value.get(key, 0)
    return int(raw) if isinstance(raw, int) and not isinstance(raw, bool) else 0
