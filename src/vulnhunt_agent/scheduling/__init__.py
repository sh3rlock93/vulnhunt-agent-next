"""Cost-aware Hunter scheduling contracts and metrics."""

from .metrics import estimate_cost_usd, total_usage
from .shadow import build_shadow_plan, work_id_for

__all__ = [
    "build_shadow_plan",
    "estimate_cost_usd",
    "total_usage",
    "work_id_for",
]
