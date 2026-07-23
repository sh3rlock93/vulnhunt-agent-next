"""Capability-aware planning for Reviewer-requested experiments.

The planner sits between a declarative review request and an executable
reproduction variant.  Its primary safety property is that changing argv is
not treated as implementing an experiment unless the existing PoC can consume
arguments and already contains the execution topology requested by the
Reviewer.
"""
from __future__ import annotations

import re
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from ..domain.schemas import ReproductionSpec, ReproductionVariantRequest
from ..infrastructure.artifacts import ArtifactStore


EXPERIMENT_PLANNING_POLICY = "experiment-planning-v1"


class ExperimentPlanStatus(StrEnum):
    READY = "ready"
    REQUIRES_HARNESS = "requires_harness"
    REQUIRES_SNAPSHOT = "requires_snapshot"
    UNSUPPORTED = "unsupported"


class ExperimentStrategy(StrEnum):
    ARGUMENT_VARIANT = "argument_variant"
    ENVIRONMENT_VARIANT = "environment_variant"
    NEW_HARNESS = "new_harness"
    FIXED_REVISION = "fixed_revision"


class ExperimentPlan(BaseModel):
    """Persistable decision binding a request to one execution strategy."""

    model_config = ConfigDict(extra="forbid")

    policy_version: str = EXPERIMENT_PLANNING_POLICY
    request_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    candidate_id: str = Field(min_length=1)
    base_reproduction_group: str = Field(min_length=1)
    base_poc_artifact: str = Field(min_length=1)
    status: ExperimentPlanStatus
    strategy: ExperimentStrategy
    rationale: str = Field(min_length=1, max_length=1000)
    required_capabilities: tuple[str, ...] = ()
    conformance_checks: tuple[str, ...] = ()
    remaining_requirement: str = Field(default="", max_length=1000)


class ExperimentPlanner(Protocol):
    async def plan(
        self,
        request: ReproductionVariantRequest,
        base: ReproductionSpec,
    ) -> ExperimentPlan: ...


class CapabilityAwareExperimentPlanner:
    """Fail closed when the existing PoC cannot express an experiment.

    This gate is intentionally deterministic.  It does not ask a model to
    claim that a command implements a requested behavior; it inspects the
    immutable PoC artifact and the requested mutation class instead.
    """

    def __init__(self, artifacts: ArtifactStore):
        self.artifacts = artifacts

    async def plan(
        self,
        request: ReproductionVariantRequest,
        base: ReproductionSpec,
    ) -> ExperimentPlan:
        request = ReproductionVariantRequest.model_validate(request)
        base = ReproductionSpec.model_validate(base)
        common = {
            "request_id": request.request_id,
            "run_id": request.run_id,
            "candidate_id": request.candidate_id,
            "base_reproduction_group": request.base_reproduction_group,
            "base_poc_artifact": base.poc_artifact,
        }
        if request.variant_type.value == "fixed_revision":
            return ExperimentPlan(
                **common,
                status=ExperimentPlanStatus.REQUIRES_SNAPSHOT,
                strategy=ExperimentStrategy.FIXED_REVISION,
                rationale=(
                    "A fixed-revision control requires a separately approved immutable "
                    "source snapshot; it cannot reuse the vulnerable run snapshot."
                ),
                required_capabilities=("approved_fixed_source_snapshot",),
                conformance_checks=("source_snapshot_changed", "revision_identity_verified"),
                remaining_requirement=(
                    "Prepare and approve the fixed revision as a separate immutable snapshot."
                ),
            )
        if request.variant_type.value == "config_toggle":
            return ExperimentPlan(
                **common,
                status=ExperimentPlanStatus.READY,
                strategy=ExperimentStrategy.ENVIRONMENT_VARIANT,
                rationale="The requested control fits the bounded environment-only mutation.",
                required_capabilities=("environment_override",),
                conformance_checks=("argv_preserved", "environment_changed"),
            )

        try:
            source = self.artifacts.read_bytes(base.poc_artifact).decode(errors="replace")
        except (FileNotFoundError, ValueError, OSError, RuntimeError) as exc:
            return ExperimentPlan(
                **common,
                status=ExperimentPlanStatus.UNSUPPORTED,
                strategy=ExperimentStrategy.NEW_HARNESS,
                rationale=f"The immutable PoC cannot be inspected: {exc}",
                required_capabilities=("readable_immutable_poc",),
                remaining_requirement="Restore the immutable PoC artifact and re-plan.",
            )

        path = PurePosixPath(base.poc_path)
        if not _poc_accepts_arguments(path.suffix.casefold(), source):
            return ExperimentPlan(
                **common,
                status=ExperimentPlanStatus.REQUIRES_HARNESS,
                strategy=ExperimentStrategy.NEW_HARNESS,
                rationale=(
                    "The requested input mutation cannot be represented by argv because the "
                    "immutable PoC does not consume command-line arguments."
                ),
                required_capabilities=("new_or_argument_aware_harness",),
                conformance_checks=("requested_input_is_consumed",),
                remaining_requirement=(
                    "Synthesize and independently validate a harness that consumes the "
                    "requested control input."
                ),
            )

        missing = _missing_topology_capabilities(request.requested_change, source)
        if missing:
            joined = ", ".join(missing)
            return ExperimentPlan(
                **common,
                status=ExperimentPlanStatus.REQUIRES_HARNESS,
                strategy=ExperimentStrategy.NEW_HARNESS,
                rationale=(
                    "The Reviewer requested execution topology that the immutable PoC does "
                    f"not implement: {joined}."
                ),
                required_capabilities=tuple(missing),
                conformance_checks=(
                    "requested_topology_observed",
                    "direct_sink_shortcut_absent",
                ),
                remaining_requirement=(
                    "Create a separately validated harness implementing the requested topology."
                ),
            )

        return ExperimentPlan(
            **common,
            status=ExperimentPlanStatus.READY,
            strategy=ExperimentStrategy.ARGUMENT_VARIANT,
            rationale=(
                "The immutable PoC consumes argv and already contains the topology required "
                "by the requested experiment."
            ),
            required_capabilities=("argument_aware_poc",),
            conformance_checks=(
                "argv_changed",
                "environment_preserved",
                "requested_input_is_consumed",
            ),
        )


_ARGUMENT_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    ".c": (
        re.compile(r"\bmain\s*\(\s*int\s+\w+\s*,", re.MULTILINE),
        re.compile(r"(?:\bargv\s*\[|\bgetopt(?:_long)?\s*\()"),
    ),
    ".cc": (
        re.compile(r"\bmain\s*\([^)]*\bargv\b", re.DOTALL),
        re.compile(r"(?:\bargv\s*\[|\bgetopt(?:_long)?\s*\()"),
    ),
    ".cpp": (
        re.compile(r"\bmain\s*\([^)]*\bargv\b", re.DOTALL),
        re.compile(r"(?:\bargv\s*\[|\bgetopt(?:_long)?\s*\()"),
    ),
    ".cxx": (
        re.compile(r"\bmain\s*\([^)]*\bargv\b", re.DOTALL),
        re.compile(r"(?:\bargv\s*\[|\bgetopt(?:_long)?\s*\()"),
    ),
    ".py": (re.compile(r"\b(?:sys\.argv|argparse|click\.|typer\.)"),),
    ".js": (re.compile(r"\bprocess\.argv\b"),),
    ".mjs": (re.compile(r"\bprocess\.argv\b"),),
    ".rb": (re.compile(r"\bARGV\b"),),
    ".sh": (re.compile(r"(?:\$\{?[1-9@*]\}?|\bgetopts\b)"),),
}


def _poc_accepts_arguments(suffix: str, source: str) -> bool:
    patterns = _ARGUMENT_PATTERNS.get(suffix)
    if not patterns:
        return False
    return all(pattern.search(source) for pattern in patterns)


def _missing_topology_capabilities(requested_change: str, source: str) -> list[str]:
    request = " ".join(requested_change.casefold().split())
    source_folded = source.casefold()
    missing: list[str] = []
    requests_real_transport = any(term in request for term in (
        "end-to-end",
        "real tcp",
        "actual tcp",
        "actual socket",
        "separate client",
        "normal tcp",
        "socket receive",
        "receive-and-reply",
        "receive, framing",
        "must not call",
        "직접 호출하지",
        "실제 tcp",
        "별도 클라이언트",
    ))
    if requests_real_transport:
        has_client = bool(re.search(r"\b(?:connect|modbus_connect)\s*\(", source_folded))
        has_server_receive = bool(re.search(
            r"\b(?:accept|recv|read|modbus_receive)\s*\(", source_folded
        ))
        if not has_client:
            missing.append("separate_transport_client")
        if not has_server_receive:
            missing.append("server_receive_path")
    requests_new_harness = any(term in request for term in (
        "new harness",
        "replace the harness",
        "modify the harness",
        "instrumented server",
        "새 harness",
        "하네스 생성",
    ))
    if requests_new_harness:
        missing.append("new_harness_source")
    return list(dict.fromkeys(missing))


def validate_compiled_experiment(
    plan: ExperimentPlan,
    base: ReproductionSpec,
    compiled: ReproductionSpec,
    *,
    poc_source: str,
) -> None:
    """Verify that a compiled variant stays within its approved plan."""

    plan = ExperimentPlan.model_validate(plan)
    base = ReproductionSpec.model_validate(base)
    compiled = ReproductionSpec.model_validate(compiled)
    if plan.status is not ExperimentPlanStatus.READY:
        raise ValueError(f"experiment plan is not executable: {plan.status.value}")
    if plan.base_poc_artifact != base.poc_artifact:
        raise ValueError("experiment plan is bound to another PoC artifact")
    if plan.strategy is ExperimentStrategy.ARGUMENT_VARIANT:
        if compiled.argv == base.argv or compiled.env != base.env:
            raise ValueError("compiled experiment violates its argument-only plan")
        new_options = {
            value
            for value in compiled.argv[1:]
            if value.startswith("-") and value not in base.argv[1:]
        }
        missing_options = sorted(
            option for option in new_options if option not in poc_source
        )
        if missing_options:
            raise ValueError(
                "immutable PoC does not implement compiled options: "
                + ", ".join(missing_options)
            )
    elif plan.strategy is ExperimentStrategy.ENVIRONMENT_VARIANT:
        if compiled.argv != base.argv or compiled.env == base.env:
            raise ValueError("compiled experiment violates its environment-only plan")
        changed_names = {
            name
            for name, value in compiled.env.items()
            if base.env.get(name) != value
        }
        missing_names = sorted(name for name in changed_names if name not in poc_source)
        if missing_names:
            raise ValueError(
                "immutable PoC does not consume compiled environment controls: "
                + ", ".join(missing_names)
            )
    else:
        raise ValueError(f"unsupported executable strategy: {plan.strategy.value}")
