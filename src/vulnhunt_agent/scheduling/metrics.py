"""Provider-neutral usage aggregation and optional API cost estimation."""
from __future__ import annotations

from ..core import settings
from ..domain.schemas import BudgetUsage

_COUNTERS = (
    "sessions",
    "calls",
    "iterations",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "tool_calls",
    "repeated_reads",
    "poc_writes",
    "exec_calls",
    "wall_time_ms",
)


def estimate_cost_usd(usage: BudgetUsage) -> float | None:
    spec = settings.by_id(usage.model_id)
    if spec is None or spec.input_per_m is None or spec.output_per_m is None:
        return None
    prices = {
        "input_tokens": spec.input_per_m,
        "output_tokens": spec.output_per_m,
        "cache_read_tokens": spec.cache_read_per_m,
        "cache_write_tokens": spec.cache_write_per_m,
    }
    if any(value is None for value in prices.values()):
        return None
    total = 0.0
    for field, price in prices.items():
        if price is None:
            return None
        total += getattr(usage, field) * price / 1_000_000
    return total


def with_estimated_cost(usage: BudgetUsage) -> BudgetUsage:
    return usage.model_copy(update={"estimated_cost_usd": estimate_cost_usd(usage)})


def total_usage(items: list[BudgetUsage]) -> dict[str, int | float | None]:
    total: dict[str, int | float | None] = {
        field: sum(getattr(item, field) for item in items)
        for field in _COUNTERS
    }
    costs = [item.estimated_cost_usd for item in items]
    total["estimated_cost_usd"] = (
        sum(float(cost) for cost in costs if cost is not None)
        if costs and all(cost is not None for cost in costs)
        else None
    )
    return total
