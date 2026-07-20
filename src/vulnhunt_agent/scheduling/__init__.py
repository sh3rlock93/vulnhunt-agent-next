"""Cost-aware Hunter scheduling contracts and metrics."""

from .budget import (
    BudgetAllocation,
    BudgetController,
    BudgetedLLMClient,
    BudgetExceededError,
    adaptive_iteration_limit,
    allocate_work_items,
)
from .metrics import estimate_cost_usd, total_usage
from .router import ROUTER_POLICY, build_routing_plan
from .shadow import build_shadow_plan, work_id_for
from .slices import (
    MAX_CONTEXT_FILES,
    SLICE_WORK_POLICY,
    build_slice_work_items,
    group_overlapping_slices,
)

__all__ = [
    "BudgetAllocation",
    "BudgetController",
    "BudgetedLLMClient",
    "BudgetExceededError",
    "ROUTER_POLICY",
    "MAX_CONTEXT_FILES",
    "SLICE_WORK_POLICY",
    "adaptive_iteration_limit",
    "allocate_work_items",
    "build_slice_work_items",
    "build_routing_plan",
    "build_shadow_plan",
    "estimate_cost_usd",
    "group_overlapping_slices",
    "total_usage",
    "work_id_for",
]
