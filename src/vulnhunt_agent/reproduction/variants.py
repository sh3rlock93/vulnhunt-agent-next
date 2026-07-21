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


class ReproductionVariantExecutor:
    def __init__(
        self,
        repository: SqliteRepository,
        artifacts: ArtifactStore,
        backend: SandboxBackend,
        compiler: VariantCompiler,
        *,
        worker_id: str | None = None,
        lease_seconds: int = 900,
    ):
        self.repository = repository
        self.artifacts = artifacts
        self.backend = backend
        self.compiler = compiler
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
        terminal_statuses = {
            item.value: item
            for item in (
                ReproductionStatus.REPRODUCED,
                ReproductionStatus.FAILED,
                ReproductionStatus.FLAKY,
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
            spec = await self.compiler.compile(request, base)
            _validate_compiled_identity(request, base, spec)
            outcome = await ReproducerService(
                self.repository,
                self.artifacts,
                self.backend,
                worker_id=self.worker_id,
                lease_seconds=self.lease_seconds,
            ).reproduce_variant(spec, lease)
            return VariantExecutionResult(request.request_id, outcome)
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
