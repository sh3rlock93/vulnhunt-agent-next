"""Shared native planning entry points and semantic parity contracts."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any

from ..analysis import CAnalysisGraph
from ..domain.schemas import BudgetPolicy, HunterRoutingPlan, HunterWorkItem
from .budget import (
    BudgetAllocation,
    WorkInputBudgetPlan,
    allocate_work_items,
    apply_admission_focus,
    build_work_input_budget,
)
from .router import build_routing_plan
from .slices import build_slice_work_items
from .obligations import bind_invariant_obligations

NATIVE_PLAN_CONTRACT_POLICY = "native-plan-contract-v1"


@dataclass(frozen=True)
class NativeWorkPlan:
    """Provider-independent routing and bounded work for one native scan."""

    routing: HunterRoutingPlan
    work_items: tuple[HunterWorkItem, ...]
    selected_files: tuple[str, ...]
    enabled_hunters: tuple[str, ...]
    source_snapshot: str
    analysis: dict[str, Any]


@dataclass(frozen=True)
class NativeAdmissionPlan:
    """One deterministic admission decision over a native work plan."""

    work_items: tuple[HunterWorkItem, ...]
    allocation: BudgetAllocation
    input_budget: WorkInputBudgetPlan
    contract: dict[str, Any]


def build_native_work_plan(
    *,
    run_id: str,
    source_snapshot: str,
    selected_files: list[str],
    enabled_hunters: list[str],
    analysis: dict[str, Any],
) -> NativeWorkPlan:
    """Build native routing and slice work through one production path."""
    routing = build_routing_plan(
        run_id=run_id,
        source_snapshot=source_snapshot,
        selected_files=selected_files,
        enabled_hunters=enabled_hunters,
        analysis=analysis,
    )
    graph = CAnalysisGraph.model_validate(analysis.get("graph") or {})
    work_items = bind_invariant_obligations(
        build_slice_work_items(routing, analysis),
        graph,
    )
    return NativeWorkPlan(
        routing=routing,
        work_items=work_items,
        selected_files=tuple(sorted(dict.fromkeys(selected_files))),
        enabled_hunters=tuple(sorted(dict.fromkeys(enabled_hunters))),
        source_snapshot=source_snapshot,
        analysis=analysis,
    )


def allocate_native_work_plan(
    plan: NativeWorkPlan,
    policy: BudgetPolicy,
    *,
    eligible_work_ids: set[str] | None = None,
    consumed_sessions: int = 0,
    native_full_scan: bool = True,
    include_capacity_chains: bool = True,
) -> NativeAdmissionPlan:
    """Allocate native work and persist a run-independent semantic contract."""
    graph = CAnalysisGraph.model_validate(plan.analysis.get("graph") or {})
    eligible = (
        plan.work_items
        if eligible_work_ids is None
        else tuple(
            item for item in plan.work_items if item.work_id in eligible_work_ids
        )
    )
    allocation = allocate_work_items(
        eligible,
        policy,
        consumed_sessions=consumed_sessions,
        risk_chains=graph.risk_chains,
        capacity_chains=(graph.capacity_risk_chains if include_capacity_chains else ()),
        invariant_obligations=graph.invariant_obligations,
        entrypoint_ids=graph.entrypoint_ids,
        native_full_scan=native_full_scan,
    )
    focused = apply_admission_focus(
        plan.work_items,
        allocation,
        capacity_chains=graph.capacity_risk_chains,
    )
    input_budget = build_work_input_budget(focused, allocation, policy)
    contract = _plan_contract(
        plan,
        focused,
        allocation,
        input_budget,
        policy,
        eligible_work_ids={item.work_id for item in eligible},
        consumed_sessions=consumed_sessions,
        native_full_scan=native_full_scan,
        include_capacity_chains=include_capacity_chains,
    )
    return NativeAdmissionPlan(
        work_items=focused,
        allocation=allocation,
        input_budget=input_budget,
        contract=contract,
    )


def _plan_contract(
    plan: NativeWorkPlan,
    work_items: tuple[HunterWorkItem, ...],
    allocation: BudgetAllocation,
    input_budget: WorkInputBudgetPlan,
    policy: BudgetPolicy,
    *,
    eligible_work_ids: set[str],
    consumed_sessions: int,
    native_full_scan: bool,
    include_capacity_chains: bool,
) -> dict[str, Any]:
    graph = plan.analysis.get("graph") or {}
    work_keys = {
        item.work_id: _normalized_work_key(item)
        for item in work_items
    }
    semantic = {
        "policy_version": NATIVE_PLAN_CONTRACT_POLICY,
        "source_snapshot": plan.source_snapshot,
        "graph_sha256": _sha256_json(graph),
        "selected_files": list(plan.selected_files),
        "enabled_hunters": list(plan.enabled_hunters),
        "budget": policy.model_dump(mode="json"),
        "consumed_sessions": consumed_sessions,
        "native_full_scan": native_full_scan,
        "include_capacity_chains": include_capacity_chains,
        "eligible_work_ids": sorted(eligible_work_ids),
        "work_items": [
            _semantic_work_item(item)
            for item in sorted(work_items, key=lambda item: item.work_id)
        ],
        "allocation": {
            "policy_version": allocation.policy_version,
            "admitted_work_ids": list(allocation.admitted_work_ids),
            "deferred": dict(sorted(allocation.deferred.items())),
            "decisions": [asdict(item) for item in allocation.decisions],
            "ranking": [asdict(item) for item in allocation.ranking],
            "capacity_units": [
                asdict(item) for item in allocation.capacity_units
            ],
            "obligation_required_slots": allocation.obligation_required_slots,
            "obligation_admissions": [
                asdict(item) for item in allocation.obligation_admissions
            ],
            "input_fairness": asdict(input_budget),
            "required_specialist_slots": allocation.required_specialist_slots,
            "retry_slots": allocation.retry_slots,
        },
    }
    return {
        "policy_version": NATIVE_PLAN_CONTRACT_POLICY,
        "semantic_sha256": _sha256_json(semantic),
        "normalized_semantic_sha256": _sha256_json({
            "policy_version": NATIVE_PLAN_CONTRACT_POLICY,
            "graph_sha256": semantic["graph_sha256"],
            "selected_files": semantic["selected_files"],
            "enabled_hunters": semantic["enabled_hunters"],
            "budget": semantic["budget"],
            "consumed_sessions": consumed_sessions,
            "native_full_scan": native_full_scan,
            "include_capacity_chains": include_capacity_chains,
            "work_items": sorted(
                (_normalized_work_item(item) for item in work_items),
                key=_sha256_json,
            ),
            "allocation": _normalized_allocation(
                allocation,
                input_budget,
                work_keys,
            ),
        }),
        "graph_sha256": semantic["graph_sha256"],
        "enabled_hunters": list(plan.enabled_hunters),
        "selected_files": len(plan.selected_files),
        "work_items": len(work_items),
        "admitted_sessions": len(allocation.admitted_work_ids),
        "deferred_sessions": len(allocation.deferred),
        "capacity_units": [
            asdict(item) for item in allocation.capacity_units
        ],
        "obligation_required_slots": allocation.obligation_required_slots,
        "obligation_admissions": [
            asdict(item) for item in allocation.obligation_admissions
        ],
        "input_fairness": asdict(input_budget),
    }


def _semantic_work_item(item: HunterWorkItem) -> dict[str, Any]:
    payload = item.model_dump(mode="json")
    payload.pop("run_id", None)
    return payload


def _normalized_work_item(item: HunterWorkItem) -> dict[str, Any]:
    payload = _semantic_work_item(item)
    payload.pop("work_id", None)
    payload.pop("source_snapshot", None)
    # The opaque scope digest binds an executable work item to one discovery
    # artifact.  The normalized contract already records the selected files
    # and every semantic target, so retaining this identity digest would make
    # equivalent deterministic and authenticated plans compare unequal.
    payload.pop("scan_scope_digest", None)
    return payload


def _normalized_work_key(item: HunterWorkItem) -> str:
    return "normalized_work_" + _sha256_json(_normalized_work_item(item))[:20]


def _normalized_allocation(
    allocation: BudgetAllocation,
    input_budget: WorkInputBudgetPlan,
    work_keys: dict[str, str],
) -> dict[str, Any]:
    def work_key(work_id: str) -> str:
        return work_keys.get(work_id, "unknown_work")

    decisions = []
    for decision in allocation.decisions:
        payload = asdict(decision)
        payload["work_key"] = work_key(payload.pop("work_id"))
        decisions.append(payload)
    ranking = []
    for record in allocation.ranking:
        payload = asdict(record)
        payload.pop("record_id", None)
        payload["work_key"] = work_key(payload.pop("work_id"))
        ranking.append(payload)
    capacity_units = []
    for unit in allocation.capacity_units:
        payload = asdict(unit)
        payload["representative_work_key"] = work_key(
            payload.pop("representative_work_id")
        )
        payload["work_keys"] = sorted(
            work_key(work_id) for work_id in payload.pop("work_ids")
        )
        capacity_units.append(payload)
    obligation_admissions = []
    for obligation_record in allocation.obligation_admissions:
        payload = asdict(obligation_record)
        payload["work_key"] = work_key(payload.pop("work_id"))
        obligation_admissions.append(payload)
    return {
        "policy_version": allocation.policy_version,
        "admitted_work_keys": [
            work_key(work_id) for work_id in allocation.admitted_work_ids
        ],
        "deferred": sorted(
            (work_key(work_id), reason)
            for work_id, reason in allocation.deferred.items()
        ),
        "decisions": decisions,
        "ranking": ranking,
        "capacity_units": capacity_units,
        "obligation_required_slots": allocation.obligation_required_slots,
        "obligation_admissions": obligation_admissions,
        "required_specialist_slots": allocation.required_specialist_slots,
        "input_fairness": {
            "policy_version": input_budget.policy_version,
            "per_work_input_limit": input_budget.per_work_input_limit,
            "critical_first_call_reserve": (
                input_budget.critical_first_call_reserve
            ),
            "work_input_limits": sorted(
                (work_key(work_id), limit)
                for work_id, limit in input_budget.work_input_limits.items()
            ),
            "critical_work_keys": [
                work_key(work_id) for work_id in input_budget.critical_work_ids
            ],
        },
        "retry_slots": allocation.retry_slots,
    }


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()
