"""Compile declarative Reviewer requests into leased Reproducer work."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from ..core.jsonx import try_extract_object
from ..domain.schemas import (
    OracleSpec,
    ReproductionSpec,
    ReproductionVariantRequest,
    ReproductionVariantType,
)
from ..infrastructure.artifacts import ArtifactStore
from ..infrastructure.sqlite_repository import SqliteRepository
from ..sandbox.base import SandboxBackend
from .planning import (
    CapabilityAwareExperimentPlanner,
    ExperimentPlan,
    ExperimentPlanner,
    ExperimentPlanStatus,
    validate_compiled_experiment,
)
from .service import ReproductionOutcome, ReproductionStatus, ReproducerService

VARIANT_POLICY = "reproduction-variant-v1"

_COMPILER_PROMPT = """You compile a declarative security experiment into a
strict patch of an existing reproduction. You cannot add setup commands, change
the executable, PoC, source snapshot, image, working directory, or timeout.

Return only:
{
  "argv": ["<same executable>", "<arguments>"],
  "env_overrides": {"NAME": "value"},
  "oracle": {
    "type": "exit_code|stdout_regex|stderr_regex|combined_regex",
    "expected_exit_code": null,
    "pattern": null
  }
}

For safe_input and alternate_trigger, change argv and leave env_overrides empty.
For config_toggle, preserve argv and provide only changed env values. Choose an oracle that passes when
the requested control behaves as intended. Never output a shell command."""


class VariantExecutionPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    argv: tuple[str, ...] = Field(min_length=1, max_length=256)
    env_overrides: dict[str, str] = Field(default_factory=dict, max_length=16)
    oracle: OracleSpec


class VariantCompiler(Protocol):
    async def compile(
        self,
        request: ReproductionVariantRequest,
        base: ReproductionSpec,
    ) -> ReproductionSpec: ...


class LLMVariantCompiler:
    """No-tool compiler whose output is checked against a narrow allowlist."""

    def __init__(self, client, *, max_attempts: int = 2, max_tokens: int = 1_200):
        self.client = client
        self.max_attempts = max_attempts
        self.max_tokens = max_tokens

    async def compile(
        self,
        request: ReproductionVariantRequest,
        base: ReproductionSpec,
    ) -> ReproductionSpec:
        request = ReproductionVariantRequest.model_validate(request)
        base = ReproductionSpec.model_validate(base)
        if request.variant_type is ReproductionVariantType.FIXED_REVISION:
            raise ValueError(
                "fixed_revision requires a separately approved source snapshot"
            )
        user = json.dumps({
            "policy": VARIANT_POLICY,
            "request": request.model_dump(mode="json"),
            "base": {
                "argv": list(base.argv),
                "env_names": sorted(base.env),
                "oracle": base.oracle.model_dump(mode="json"),
            },
        }, indent=2, ensure_ascii=False)
        messages: list[dict] = [{
            "role": "user",
            "content": [{"text": user}],
        }]
        last_error = "variant compiler did not return JSON"
        for _ in range(self.max_attempts):
            response = await self.client.chat(
                messages=messages,
                system=_COMPILER_PROMPT,
                max_tokens=self.max_tokens,
            )
            parsed = try_extract_object(response.text)
            if parsed is not None:
                try:
                    patch = VariantExecutionPatch.model_validate(parsed)
                    return compile_variant_spec(request, base, patch)
                except ValueError as exc:
                    last_error = str(exc)
            messages.append({"role": "assistant", "content": response.content_blocks})
            messages.append({
                "role": "user",
                "content": [{"text": "Invalid variant patch: " + last_error}],
            })
        raise ValueError(last_error)


def compile_variant_spec(
    request: ReproductionVariantRequest,
    base: ReproductionSpec,
    patch: VariantExecutionPatch,
) -> ReproductionSpec:
    """Apply only the mutation class authorized by the declarative request."""
    request = ReproductionVariantRequest.model_validate(request)
    base = ReproductionSpec.model_validate(base)
    patch = VariantExecutionPatch.model_validate(patch)
    if request.variant_type is ReproductionVariantType.FIXED_REVISION:
        raise ValueError("fixed_revision cannot reuse the vulnerable run snapshot")
    if patch.argv[0] != base.argv[0]:
        raise ValueError("variant cannot change the reproduction executable")
    if request.variant_type is ReproductionVariantType.CONFIG_TOGGLE:
        if patch.argv != base.argv:
            raise ValueError("config_toggle cannot change argv")
        if not patch.env_overrides:
            raise ValueError("config_toggle must provide env overrides")
    else:
        if patch.env_overrides:
            raise ValueError(f"{request.variant_type.value} cannot change env")
        if patch.argv == base.argv:
            raise ValueError(f"{request.variant_type.value} must change argv")
    return base.model_copy(update={
        "reproduction_id": request.request_id,
        "argv": patch.argv,
        "env": {**base.env, **patch.env_overrides},
        "oracle": patch.oracle,
        "attempts": 2,
    })


@dataclass(frozen=True)
class VariantExecutionResult:
    request_id: str
    outcome: ReproductionOutcome
    plan: ExperimentPlan | None = None


class ReproductionVariantExecutor:
    def __init__(
        self,
        repository: SqliteRepository,
        artifacts: ArtifactStore,
        backend: SandboxBackend,
        compiler: VariantCompiler,
        *,
        planner: ExperimentPlanner | None = None,
        worker_id: str | None = None,
        lease_seconds: int = 900,
    ):
        self.repository = repository
        self.artifacts = artifacts
        self.backend = backend
        self.compiler = compiler
        self.planner = planner or CapabilityAwareExperimentPlanner(artifacts)
        self.worker_id = worker_id or f"variant-{uuid.uuid4().hex[:16]}"
        self.lease_seconds = lease_seconds

    async def execute(
        self,
        request: ReproductionVariantRequest,
    ) -> VariantExecutionResult:
        request = ReproductionVariantRequest.model_validate(request)
        task = _task(
            self.repository,
            request.run_id,
            "reproduction_variant",
            request.request_id,
        )
        if task is None or task["payload"] != request.model_dump(mode="json"):
            raise ValueError("variant request is not the persisted task payload")
        if task["status"] == "planning_deferred":
            plan = _stored_plan(self.repository, request)
            return VariantExecutionResult(
                request_id=request.request_id,
                outcome=ReproductionOutcome(
                    reproduction_id=request.request_id,
                    status=ReproductionStatus.ENVIRONMENT_BLOCKED,
                    error=(
                        plan.rationale if plan is not None
                        else str(task.get("last_error") or "experiment planning deferred")
                    ),
                ),
                plan=plan,
            )
        terminal_statuses = {
            item.value: item
            for item in (
                ReproductionStatus.REPRODUCED,
                ReproductionStatus.FAILED,
                ReproductionStatus.FLAKY,
                ReproductionStatus.UNVERIFIED,
                ReproductionStatus.ENVIRONMENT_BLOCKED,
            )
        }
        if task["status"] in terminal_statuses:
            evidence = tuple(
                item
                for item in self.repository.list_candidate_evidence(
                    request.candidate_id
                )
                if item.reproduction_group == request.request_id
            )
            return VariantExecutionResult(
                request_id=request.request_id,
                outcome=ReproductionOutcome(
                    reproduction_id=request.request_id,
                    status=terminal_statuses[task["status"]],
                    evidence=evidence,
                    error=str(task.get("last_error") or ""),
                ),
                plan=_stored_plan(self.repository, request),
            )
        lease = self.repository.acquire_task_lease(
            request.run_id,
            "reproduction_variant",
            request.request_id,
            worker_id=self.worker_id,
            lease_seconds=self.lease_seconds,
            max_attempts=3,
        )
        if lease is None:
            return VariantExecutionResult(
                request_id=request.request_id,
                outcome=ReproductionOutcome(
                    reproduction_id=request.request_id,
                    status=ReproductionStatus.IN_PROGRESS,
                    error="variant task is leased or already terminal",
                ),
                plan=_stored_plan(self.repository, request),
            )
        try:
            base_task = _task(
                self.repository,
                request.run_id,
                "reproduction",
                request.base_reproduction_group,
            )
            if base_task is None:
                raise ValueError("base reproduction task is missing")
            base = ReproductionSpec.model_validate(base_task["payload"])
            plan = await self.planner.plan(request, base)
            if plan.status is not ExperimentPlanStatus.READY:
                _persist_plan(self.repository, plan, self.worker_id, self.lease_seconds)
                self.repository.finish_task_lease(
                    lease,
                    status="planning_deferred",
                    error=plan.rationale,
                )
                return VariantExecutionResult(
                    request_id=request.request_id,
                    outcome=ReproductionOutcome(
                        reproduction_id=request.request_id,
                        status=ReproductionStatus.ENVIRONMENT_BLOCKED,
                        error=plan.rationale,
                    ),
                    plan=plan,
                )
            spec = await self.compiler.compile(request, base)
            _validate_compiled_identity(request, base, spec)
            try:
                validate_compiled_experiment(
                    plan,
                    base,
                    spec,
                    poc_source=self.artifacts.read_bytes(base.poc_artifact).decode(
                        errors="replace"
                    ),
                )
            except ValueError as exc:
                plan = plan.model_copy(update={
                    "status": ExperimentPlanStatus.UNSUPPORTED,
                    "rationale": f"Compiled experiment failed conformance: {exc}",
                    "remaining_requirement": (
                        "Provide a harness whose source consumes every compiled control."
                    ),
                })
                _persist_plan(self.repository, plan, self.worker_id, self.lease_seconds)
                self.repository.finish_task_lease(
                    lease,
                    status="planning_deferred",
                    error=plan.rationale,
                )
                return VariantExecutionResult(
                    request_id=request.request_id,
                    outcome=ReproductionOutcome(
                        reproduction_id=request.request_id,
                        status=ReproductionStatus.ENVIRONMENT_BLOCKED,
                        error=plan.rationale,
                    ),
                    plan=plan,
                )
            _persist_plan(self.repository, plan, self.worker_id, self.lease_seconds)
            outcome = await ReproducerService(
                self.repository,
                self.artifacts,
                self.backend,
                worker_id=self.worker_id,
                lease_seconds=self.lease_seconds,
            ).reproduce_variant(spec, lease)
            return VariantExecutionResult(request.request_id, outcome, plan)
        except Exception as exc:
            self.repository.finish_task_lease(
                lease,
                status="failed",
                error=str(exc),
            )
            return VariantExecutionResult(
                request_id=request.request_id,
                outcome=ReproductionOutcome(
                    reproduction_id=request.request_id,
                    status=ReproductionStatus.ENVIRONMENT_BLOCKED,
                    error=str(exc),
                ),
                plan=_stored_plan(self.repository, request),
            )


def _task(
    repository: SqliteRepository,
    run_id: str,
    task_type: str,
    task_key: str,
) -> dict | None:
    return next(
        (
            item for item in repository.list_tasks(run_id)
            if item["task_type"] == task_type and item["task_key"] == task_key
        ),
        None,
    )


def _persist_plan(
    repository: SqliteRepository,
    plan: ExperimentPlan,
    worker_id: str,
    lease_seconds: int,
) -> None:
    payload = plan.model_dump(mode="json")
    created = repository.ensure_task(
        plan.run_id,
        "experiment_plan",
        plan.request_id,
        payload=payload,
    )
    if not created:
        stored = _task(repository, plan.run_id, "experiment_plan", plan.request_id)
        if stored is None or stored["payload"] != payload:
            raise ValueError("experiment plan changed during replay")
        if stored["status"] == plan.status.value:
            return
        if stored["status"] not in {"pending", "running"}:
            raise ValueError(
                "experiment plan task has incompatible status: " + stored["status"]
            )
    lease = repository.acquire_task_lease(
        plan.run_id,
        "experiment_plan",
        plan.request_id,
        worker_id=worker_id,
        lease_seconds=lease_seconds,
        max_attempts=2,
    )
    if lease is None:
        raise RuntimeError("experiment plan task could not be leased")
    repository.finish_task_lease(lease, status=plan.status.value)


def _stored_plan(
    repository: SqliteRepository,
    request: ReproductionVariantRequest,
) -> ExperimentPlan | None:
    task = _task(repository, request.run_id, "experiment_plan", request.request_id)
    if task is None:
        return None
    return ExperimentPlan.model_validate(task["payload"])


def _validate_compiled_identity(
    request: ReproductionVariantRequest,
    base: ReproductionSpec,
    compiled: ReproductionSpec,
) -> None:
    if compiled.reproduction_id != request.request_id:
        raise ValueError("compiled variant ID does not match its request")
    immutable = (
        "run_id",
        "candidate_id",
        "source_snapshot",
        "image",
        "poc_artifact",
        "poc_path",
        "setup_argvs",
        "cwd",
        "timeout_seconds",
        "capture_files",
    )
    changed = [name for name in immutable if getattr(compiled, name) != getattr(base, name)]
    if changed:
        raise ValueError("compiled variant changed immutable fields: " + ", ".join(changed))
    if compiled.attempts != 2:
        raise ValueError("compiled variant must use exactly two clean attempts")
    if compiled.argv[0] != base.argv[0]:
        raise ValueError("compiled variant changed the reproduction executable")
    if request.variant_type is ReproductionVariantType.CONFIG_TOGGLE:
        if compiled.argv != base.argv or compiled.env == base.env:
            raise ValueError("compiled config_toggle violates its mutation boundary")
    elif request.variant_type in {
        ReproductionVariantType.SAFE_INPUT,
        ReproductionVariantType.ALTERNATE_TRIGGER,
    }:
        if compiled.argv == base.argv or compiled.env != base.env:
            raise ValueError(
                f"compiled {request.variant_type.value} violates its mutation boundary"
            )
    else:
        raise ValueError("compiled fixed_revision lacks an approved snapshot")
