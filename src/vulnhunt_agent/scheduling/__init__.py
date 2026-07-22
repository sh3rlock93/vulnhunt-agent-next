"""Cost-aware Hunter scheduling contracts and metrics."""

from .budget import (
    AdmissionDecision,
    AdmissionEvent,
    AdmissionRankingRecord,
    BudgetAllocation,
    BudgetController,
    BudgetedLLMClient,
    BudgetExceededError,
    CAPACITY_ADMISSION_UNIT_POLICY,
    CapacityAdmissionUnit,
    NATIVE_DIVERSE_POLICY,
    RecyclableAdmissionLedger,
    adaptive_iteration_limit,
    adaptive_output_token_limit,
    allocate_work_items,
    apply_admission_focus,
)
from .metrics import estimate_cost_usd, total_usage
from .planning import (
    NATIVE_PLAN_CONTRACT_POLICY,
    NativeAdmissionPlan,
    NativeWorkPlan,
    allocate_native_work_plan,
    build_native_work_plan,
)
from .router import ROUTER_POLICY, build_routing_plan
from .shadow import build_shadow_plan, work_id_for
from .slices import (
    MAX_CONTEXT_FILES,
    SLICE_WORK_POLICY,
    build_slice_work_items,
    group_overlapping_slices,
)

__all__ = [
    "AdmissionDecision",
    "AdmissionEvent",
    "AdmissionRankingRecord",
    "BudgetAllocation",
    "BudgetController",
    "BudgetedLLMClient",
    "BudgetExceededError",
    "CAPACITY_ADMISSION_UNIT_POLICY",
    "CapacityAdmissionUnit",
    "NATIVE_DIVERSE_POLICY",
    "NATIVE_PLAN_CONTRACT_POLICY",
    "NativeAdmissionPlan",
    "NativeWorkPlan",
    "RecyclableAdmissionLedger",
    "ROUTER_POLICY",
    "MAX_CONTEXT_FILES",
    "SLICE_WORK_POLICY",
    "adaptive_iteration_limit",
    "adaptive_output_token_limit",
    "allocate_work_items",
    "allocate_native_work_plan",
    "apply_admission_focus",
    "build_slice_work_items",
    "build_native_work_plan",
    "build_routing_plan",
    "build_shadow_plan",
    "estimate_cost_usd",
    "group_overlapping_slices",
    "total_usage",
    "work_id_for",
]
