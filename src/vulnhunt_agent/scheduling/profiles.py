"""Named Hunter budget profiles without changing legacy custom budgets."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

CUSTOM_PROFILE = "custom"
STANDARD_12_PROFILE = "standard-12"
DEEP_16_PROFILE = "deep-16"
HUNTER_BUDGET_PROFILE_NAMES = (
    CUSTOM_PROFILE,
    STANDARD_12_PROFILE,
    DEEP_16_PROFILE,
)
STANDARD_SESSION_BOUNDARY = 12


@dataclass(frozen=True)
class HunterBudgetProfile:
    """A complete, auditable Hunter budget rather than a session-only preset."""

    name: str
    max_hunter_sessions: int
    max_input_tokens: int
    max_output_tokens: int
    max_wall_clock_minutes: int
    max_retries_per_work_item: int
    soft_input_token_stop: int
    standard_session_boundary: int = STANDARD_SESSION_BOUNDARY
    extension_early_stop: bool = False

    @property
    def max_model_tokens(self) -> int:
        return self.max_input_tokens + self.max_output_tokens

    def config(self) -> dict[str, Any]:
        return {
            "hunter_budget_profile": self.name,
            "budget_max_hunter_sessions": self.max_hunter_sessions,
            "budget_max_input_tokens": self.max_input_tokens,
            "budget_max_output_tokens": self.max_output_tokens,
            "budget_max_wall_clock_minutes": self.max_wall_clock_minutes,
            "budget_max_retries_per_work_item": self.max_retries_per_work_item,
            "budget_soft_input_token_stop": self.soft_input_token_stop,
            "budget_standard_session_boundary": self.standard_session_boundary,
            "budget_extension_early_stop": self.extension_early_stop,
        }

    def artifact(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "max_model_tokens": self.max_model_tokens,
        }


STANDARD_12 = HunterBudgetProfile(
    name=STANDARD_12_PROFILE,
    max_hunter_sessions=12,
    max_input_tokens=2_000_000,
    max_output_tokens=200_000,
    max_wall_clock_minutes=60,
    max_retries_per_work_item=1,
    soft_input_token_stop=1_500_000,
)

DEEP_16 = HunterBudgetProfile(
    name=DEEP_16_PROFILE,
    max_hunter_sessions=16,
    max_input_tokens=2_300_000,
    max_output_tokens=200_000,
    max_wall_clock_minutes=90,
    max_retries_per_work_item=1,
    soft_input_token_stop=2_300_000,
    extension_early_stop=True,
)

_NAMED_PROFILES = {
    STANDARD_12.name: STANDARD_12,
    DEEP_16.name: DEEP_16,
}


def hunter_budget_profile(name: str) -> HunterBudgetProfile | None:
    """Return a named immutable profile; custom budgets intentionally return None."""
    normalized = str(name or CUSTOM_PROFILE).strip().lower()
    if normalized == CUSTOM_PROFILE:
        return None
    try:
        return _NAMED_PROFILES[normalized]
    except KeyError as exc:
        raise ValueError(f"unknown Hunter budget profile: {name}") from exc


def resolve_hunter_budget_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Expand a named profile or normalize a backward-compatible custom budget."""
    resolved = dict(config)
    name = str(resolved.get("hunter_budget_profile") or CUSTOM_PROFILE)
    profile = hunter_budget_profile(name)
    if profile is not None:
        resolved.update(profile.config())
        return resolved

    max_sessions = _positive_int(
        resolved.get("budget_max_hunter_sessions"),
        default=100,
    )
    max_input = _positive_int(
        resolved.get("budget_max_input_tokens"),
        default=2_000_000,
    )
    max_output = _positive_int(
        resolved.get("budget_max_output_tokens"),
        default=200_000,
    )
    resolved.update({
        "hunter_budget_profile": CUSTOM_PROFILE,
        "budget_max_hunter_sessions": max_sessions,
        "budget_max_input_tokens": max_input,
        "budget_max_output_tokens": max_output,
        "budget_max_wall_clock_minutes": _positive_int(
            resolved.get("budget_max_wall_clock_minutes"),
            default=60,
        ),
        "budget_max_retries_per_work_item": _nonnegative_int(
            resolved.get("budget_max_retries_per_work_item"),
            default=1,
        ),
        "budget_soft_input_token_stop": min(
            max_input,
            _positive_int(
                resolved.get("budget_soft_input_token_stop"),
                default=1_500_000,
            ),
        ),
        "budget_standard_session_boundary": min(
            max_sessions,
            _positive_int(
                resolved.get("budget_standard_session_boundary"),
                default=STANDARD_SESSION_BOUNDARY,
            ),
        ),
        "budget_extension_early_stop": bool(
            resolved.get("budget_extension_early_stop", False)
        ),
    })
    return resolved


def budget_profile_artifact(config: Mapping[str, Any]) -> dict[str, Any]:
    """Return the effective profile contract stored with a Hunter plan."""
    resolved = resolve_hunter_budget_config(config)
    profile = hunter_budget_profile(str(resolved["hunter_budget_profile"]))
    if profile is not None:
        return profile.artifact()
    max_input = int(resolved["budget_max_input_tokens"])
    max_output = int(resolved["budget_max_output_tokens"])
    return {
        "name": CUSTOM_PROFILE,
        "max_hunter_sessions": int(resolved["budget_max_hunter_sessions"]),
        "max_input_tokens": max_input,
        "max_output_tokens": max_output,
        "max_wall_clock_minutes": int(
            resolved["budget_max_wall_clock_minutes"]
        ),
        "max_retries_per_work_item": int(
            resolved["budget_max_retries_per_work_item"]
        ),
        "soft_input_token_stop": int(resolved["budget_soft_input_token_stop"]),
        "standard_session_boundary": int(
            resolved["budget_standard_session_boundary"]
        ),
        "extension_early_stop": bool(resolved["budget_extension_early_stop"]),
        "max_model_tokens": max_input + max_output,
    }


def _positive_int(value: Any, *, default: int) -> int:
    parsed = int(value) if value is not None else default
    if parsed < 1:
        raise ValueError("Hunter budget values must be positive")
    return parsed


def _nonnegative_int(value: Any, *, default: int) -> int:
    parsed = int(value) if value is not None else default
    if parsed < 0:
        raise ValueError("Hunter retry budget must be non-negative")
    return parsed
