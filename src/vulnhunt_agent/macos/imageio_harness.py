"""VM-only execution contract for the native ImageIO harness.

This module is control-plane code.  It hashes and stages opaque bytes but never
parses an image.  A backend is admitted only when it attests that execution is
inside a disposable Apple-silicon macOS VM booted from the requested clean
snapshot with *zero* virtual network devices.  A NAT, host-only, firewall, or
"default deny" network is intentionally not equivalent to this requirement.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol

from pydantic import Field, model_validator

from ..domain.schemas import DomainModel, SHA256_PATTERN
from .imageio_inventory import ImageIOAPIRoute

_HARNESS_ROUTES = frozenset(ImageIOAPIRoute) - {ImageIOAPIRoute.TYPE_IDENTIFIERS}
_GUEST_INPUT_PATH = "/private/tmp/vulnhunt-imageio/input.bin"
_CANARY_INTERPOSER_REVISION = "m16-canary-interposer-v1"


class ImageIOVMExitReason(StrEnum):
    EXITED = "exited"
    NONZERO_EXIT = "nonzero_exit"
    SIGNALED = "signaled"
    TIMEOUT = "timeout"
    RESOURCE_LIMIT = "resource_limit"
    LAUNCH_ERROR = "launch_error"


class ImageIOHarnessLimits(DomainModel):
    """Limits that the VM backend must enforce, not merely record."""

    wall_time_seconds: int = Field(default=20, ge=1, le=300)
    cpu_time_seconds: int = Field(default=15, ge=1, le=300)
    max_input_bytes: int = Field(default=32 * 1024 * 1024, ge=1, le=128 * 1024 * 1024)
    max_process_memory_bytes: int = Field(
        default=2 * 1024 * 1024 * 1024,
        ge=64 * 1024 * 1024,
        le=16 * 1024 * 1024 * 1024,
    )
    max_output_bytes: int = Field(default=4 * 1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    max_open_files: int = Field(default=64, ge=8, le=256)
    incremental_chunk_bytes: int = Field(default=4096, ge=1, le=1024 * 1024)
    max_decoded_bytes: int = Field(
        default=512 * 1024 * 1024,
        ge=1024 * 1024,
        le=4 * 1024 * 1024 * 1024,
    )

    @model_validator(mode="after")
    def validate_cpu_limit(self) -> "ImageIOHarnessLimits":
        if self.cpu_time_seconds > self.wall_time_seconds:
            raise ValueError("CPU time limit may not exceed wall time limit")
        return self


class ImageIOVMEnvironment(DomainModel):
    """Immutable identity requested by a frozen ImageIO campaign."""

    environment_id: str = Field(pattern=r"^imageio-vm-[a-z0-9][a-z0-9-]{2,100}$")
    manager: str = Field(min_length=1, max_length=80)
    product_version: str = Field(pattern=r"^[0-9]+(?:\.[0-9]+){1,2}$")
    build_version: str = Field(pattern=r"^[0-9A-Za-z]+$")
    architecture: Literal["arm64"] = "arm64"
    image_sha256: str = Field(pattern=SHA256_PATTERN)
    clean_snapshot_id: str = Field(min_length=1, max_length=200)
    disposable_clone_id: str = Field(min_length=1, max_length=200)
    harness_guest_path: str = "/opt/vulnhunt/bin/imageio-harness"
    virtualization_framework: Literal["com.apple.Virtualization"] = (
        "com.apple.Virtualization"
    )
    network_mode: Literal["no_network_devices"] = "no_network_devices"
    disposable: Literal[True] = True
    host_execution_allowed: Literal[False] = False

    @model_validator(mode="after")
    def validate_guest_path(self) -> "ImageIOVMEnvironment":
        _validate_absolute_guest_path(self.harness_guest_path, label="harness guest path")
        return self


class ImageIOCanaryInterposer(DomainModel):
    schema_version: Literal["imageio-canary-interposer-v1"] = (
        "imageio-canary-interposer-v1"
    )
    source_revision: Literal["m16-canary-interposer-v1"] = (
        "m16-canary-interposer-v1"
    )
    binary_sha256: str = Field(pattern=SHA256_PATTERN)
    guest_path: str = (
        "/Users/vulnhunt/Library/Application Support/VulnHunt/bin/"
        "imageio-canary-interposer.dylib"
    )
    canary_value: int = Field(ge=0, le=255)
    minimum_allocation_bytes: int = Field(default=1, ge=1, le=4 * 1024 * 1024 * 1024)
    maximum_allocation_bytes: int = Field(
        default=512 * 1024 * 1024,
        ge=1,
        le=4 * 1024 * 1024 * 1024,
    )
    human_review_approved: Literal[True]
    host_injection_allowed: Literal[False] = False
    third_party_injection_allowed: Literal[False] = False

    @model_validator(mode="after")
    def validate_interposer(self) -> "ImageIOCanaryInterposer":
        _validate_absolute_guest_path(self.guest_path, label="canary interposer path")
        if not self.guest_path.endswith("/imageio-canary-interposer.dylib"):
            raise ValueError("canary interposer must use the fixed guest filename")
        if self.minimum_allocation_bytes > self.maximum_allocation_bytes:
            raise ValueError("canary allocation range is inverted")
        return self


class ImageIOVMIsolationAttestation(DomainModel):
    """Observed VM state immediately before and after one harness process."""

    environment_id: str
    manager: str
    product_version: str
    build_version: str
    architecture: Literal["arm64"]
    image_sha256: str = Field(pattern=SHA256_PATTERN)
    snapshot_id: str
    clone_id: str
    runtime_instance_id: str = Field(min_length=1, max_length=200)
    runtime_configuration_sha256: str = Field(pattern=SHA256_PATTERN)
    security_configuration_sha256: str = Field(pattern=SHA256_PATTERN)
    boot_id: str = Field(min_length=1, max_length=200)
    observed_at: datetime
    virtualization_framework: Literal["com.apple.Virtualization"]
    execution_boundary: Literal["macos_virtual_machine"]
    network_device_count: Literal[0]
    outbound_network_enabled: Literal[False]
    clean_snapshot: Literal[True]
    disposable_clone: Literal[True]
    executed_on_host: Literal[False]

    @model_validator(mode="after")
    def require_aware_observation(self) -> "ImageIOVMIsolationAttestation":
        if self.observed_at.tzinfo is None:
            raise ValueError("VM attestation time must include a timezone")
        return self


@dataclass(frozen=True)
class ImageIOVMCommand:
    environment: ImageIOVMEnvironment
    route: ImageIOAPIRoute
    input_path: Path
    input_sha256: str
    input_size_bytes: int
    guest_input_path: str
    argv: tuple[str, ...]
    limits: ImageIOHarnessLimits
    canary_interposer: ImageIOCanaryInterposer | None = None
    capture_crash_log: bool = True


@dataclass(frozen=True)
class ImageIOVMCommandResult:
    environment_id: str
    boot_id: str
    argv: tuple[str, ...]
    guest_input_sha256: str
    enforced_limits: ImageIOHarnessLimits
    exit_code: int | None
    terminating_signal: int | None
    timed_out: bool
    launch_error: str | None
    duration_ms: int
    stdout: bytes
    stderr: bytes
    crash_log: bytes | None
    memory_limit_exceeded: bool = False
    crash_log_truncated: bool = False
    canary_interposer_sha256: str | None = None
    canary_value: int | None = None


class ImageIOVMRunner(Protocol):
    """Concrete implementations must use a VM, never a host subprocess."""

    def attest(
        self,
        environment: ImageIOVMEnvironment,
    ) -> ImageIOVMIsolationAttestation: ...

    def execute(self, command: ImageIOVMCommand) -> ImageIOVMCommandResult: ...


class ImageIOHarnessEvidence(DomainModel):
    schema_version: str = "imageio-harness-evidence-v1"
    environment_id: str
    boot_id: str
    route: ImageIOAPIRoute
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    input_size_bytes: int = Field(ge=0)
    argv: tuple[str, ...] = Field(min_length=1, max_length=32)
    limits: ImageIOHarnessLimits
    exit_reason: ImageIOVMExitReason
    exit_code: int | None
    terminating_signal: int | None
    memory_limit_exceeded: bool = False
    crash_log_truncated: bool = False
    duration_ms: int = Field(ge=0)
    stdout_sha256: str = Field(pattern=SHA256_PATTERN)
    stderr_sha256: str = Field(pattern=SHA256_PATTERN)
    crash_log_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    pre_attestation_sha256: str = Field(pattern=SHA256_PATTERN)
    post_attestation_sha256: str = Field(pattern=SHA256_PATTERN)
    canary_interposer_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    canary_value: int | None = Field(default=None, ge=0, le=255)
    evidence_complete: bool
    evidence_gaps: tuple[str, ...] = ()
    raw_artifacts_public: Literal[False] = False

    @model_validator(mode="after")
    def validate_evidence_completeness(self) -> "ImageIOHarnessEvidence":
        if self.evidence_complete == bool(self.evidence_gaps):
            raise ValueError("complete evidence must have no gaps and incomplete evidence must")
        if self.exit_reason is ImageIOVMExitReason.SIGNALED and self.crash_log_sha256 is None:
            if "signaled process has no captured crash log" not in self.evidence_gaps:
                raise ValueError("a signaled process without a crash log must record the gap")
        if self.crash_log_truncated:
            if self.crash_log_sha256 is not None:
                raise ValueError("a truncated crash log may not have an artifact digest")
            if "crash log exceeded the capture limit" not in self.evidence_gaps:
                raise ValueError("a truncated crash log must record the evidence gap")
        if (self.canary_interposer_sha256 is None) != (self.canary_value is None):
            raise ValueError("canary digest and byte must be recorded together")
        return self


@dataclass(frozen=True)
class PrivateImageIOHarnessRun:
    """Raw artifacts remain in memory until written outside the Git worktree."""

    evidence: ImageIOHarnessEvidence
    input_path: Path
    stdout: bytes
    stderr: bytes
    crash_log: bytes | None


def run_imageio_harness(
    *,
    runner: ImageIOVMRunner,
    environment: ImageIOVMEnvironment,
    route: ImageIOAPIRoute,
    input_path: Path,
    limits: ImageIOHarnessLimits | None = None,
    canary_interposer: ImageIOCanaryInterposer | None = None,
) -> PrivateImageIOHarnessRun:
    """Execute one route after fail-closed VM isolation attestation."""

    if route not in _HARNESS_ROUTES:
        raise ValueError(f"{route.value} is inventory-only and cannot execute an input")
    active_limits = limits or ImageIOHarnessLimits()
    if canary_interposer is not None:
        if route is not ImageIOAPIRoute.RAW_PIXEL_COPY:
            raise ValueError("canary interposition is limited to the raw-pixel route")
        if canary_interposer.maximum_allocation_bytes > active_limits.max_decoded_bytes:
            raise ValueError("canary allocation ceiling exceeds the decoded-byte limit")
    source = _validate_input_path(input_path)
    input_size = source.stat().st_size
    if input_size > active_limits.max_input_bytes:
        raise ValueError(
            f"input is {input_size} bytes; limit is {active_limits.max_input_bytes}"
        )
    input_sha256 = _sha256_file(source)
    argv = (
        environment.harness_guest_path,
        "--route",
        route.value,
        "--input",
        _GUEST_INPUT_PATH,
        "--chunk-size",
        str(active_limits.incremental_chunk_bytes),
        "--max-input-bytes",
        str(active_limits.max_input_bytes),
        "--max-decoded-bytes",
        str(active_limits.max_decoded_bytes),
        "--wall-time-seconds",
        str(active_limits.wall_time_seconds),
        "--cpu-time-seconds",
        str(active_limits.cpu_time_seconds),
        "--max-process-memory-bytes",
        str(active_limits.max_process_memory_bytes),
        "--max-open-files",
        str(active_limits.max_open_files),
    )
    command = ImageIOVMCommand(
        environment=environment,
        route=route,
        input_path=source,
        input_sha256=input_sha256,
        input_size_bytes=input_size,
        guest_input_path=_GUEST_INPUT_PATH,
        argv=argv,
        limits=active_limits,
        canary_interposer=canary_interposer,
    )

    before = runner.attest(environment)
    _validate_attestation(environment, before)
    result = runner.execute(command)
    after = runner.attest(environment)
    _validate_attestation(environment, after)
    _validate_execution_identity(command, result, before, after)
    _validate_output_limits(result, active_limits)

    exit_reason = _exit_reason(result)
    gaps: list[str] = []
    if exit_reason is ImageIOVMExitReason.SIGNALED and result.crash_log is None:
        gaps.append("signaled process has no captured crash log")
    if exit_reason is ImageIOVMExitReason.LAUNCH_ERROR:
        gaps.append("harness process did not launch")
    if result.crash_log_truncated:
        gaps.append("crash log exceeded the capture limit")

    evidence = ImageIOHarnessEvidence(
        environment_id=environment.environment_id,
        boot_id=before.boot_id,
        route=route,
        input_sha256=input_sha256,
        input_size_bytes=input_size,
        argv=argv,
        limits=active_limits,
        exit_reason=exit_reason,
        exit_code=result.exit_code,
        terminating_signal=result.terminating_signal,
        memory_limit_exceeded=result.memory_limit_exceeded,
        crash_log_truncated=result.crash_log_truncated,
        duration_ms=result.duration_ms,
        stdout_sha256=_sha256_bytes(result.stdout),
        stderr_sha256=_sha256_bytes(result.stderr),
        crash_log_sha256=(
            _sha256_bytes(result.crash_log) if result.crash_log is not None else None
        ),
        pre_attestation_sha256=_model_sha256(before),
        post_attestation_sha256=_model_sha256(after),
        canary_interposer_sha256=result.canary_interposer_sha256,
        canary_value=result.canary_value,
        evidence_complete=not gaps,
        evidence_gaps=tuple(gaps),
    )
    return PrivateImageIOHarnessRun(
        evidence=evidence,
        input_path=source,
        stdout=result.stdout,
        stderr=result.stderr,
        crash_log=result.crash_log,
    )


def write_private_harness_run(target: Path, run: PrivateImageIOHarnessRun) -> None:
    """Write a run once, with private permissions, outside every Git worktree."""

    resolved = target.expanduser().resolve()
    if _is_inside_git_worktree(resolved):
        raise ValueError("private ImageIO artifacts may not be written inside a Git worktree")
    if resolved.exists():
        raise FileExistsError(f"private run directory already exists: {resolved}")

    resolved.mkdir(parents=True, mode=0o700)
    _write_private(
        resolved / "evidence.json",
        (
            json.dumps(run.evidence.model_dump(mode="json"), indent=2, sort_keys=True)
            + "\n"
        ).encode(),
    )
    shutil.copyfile(run.input_path, resolved / "input.bin")
    os.chmod(resolved / "input.bin", 0o600)
    if _sha256_file(resolved / "input.bin") != run.evidence.input_sha256:
        raise RuntimeError("private trigger copy does not match recorded input digest")
    _write_private(resolved / "stdout.bin", run.stdout)
    _write_private(resolved / "stderr.bin", run.stderr)
    if run.crash_log is not None:
        _write_private(resolved / "crash.log", run.crash_log)


def _validate_attestation(
    expected: ImageIOVMEnvironment,
    observed: ImageIOVMIsolationAttestation,
) -> None:
    comparisons = {
        "environment ID": (expected.environment_id, observed.environment_id),
        "VM manager": (expected.manager, observed.manager),
        "product version": (expected.product_version, observed.product_version),
        "build version": (expected.build_version, observed.build_version),
        "architecture": (expected.architecture, observed.architecture),
        "VM image digest": (expected.image_sha256, observed.image_sha256),
        "clean snapshot": (expected.clean_snapshot_id, observed.snapshot_id),
        "disposable clone": (expected.disposable_clone_id, observed.clone_id),
        "virtualization framework": (
            expected.virtualization_framework,
            observed.virtualization_framework,
        ),
    }
    for label, (wanted, actual) in comparisons.items():
        if wanted != actual:
            raise RuntimeError(f"{label} attestation mismatch: {actual!r} != {wanted!r}")


def _validate_execution_identity(
    command: ImageIOVMCommand,
    result: ImageIOVMCommandResult,
    before: ImageIOVMIsolationAttestation,
    after: ImageIOVMIsolationAttestation,
) -> None:
    if before.boot_id != after.boot_id:
        raise RuntimeError("VM rebooted or was replaced during harness execution")
    if before.runtime_instance_id != after.runtime_instance_id:
        raise RuntimeError("VM runtime instance changed during harness execution")
    if before.runtime_configuration_sha256 != after.runtime_configuration_sha256:
        raise RuntimeError("VM runtime configuration changed during harness execution")
    if before.security_configuration_sha256 != after.security_configuration_sha256:
        raise RuntimeError("VM security configuration changed during harness execution")
    if result.environment_id != command.environment.environment_id:
        raise RuntimeError("execution result came from a different VM environment")
    if result.boot_id != before.boot_id:
        raise RuntimeError("execution result came from a different VM boot")
    if result.argv != command.argv:
        raise RuntimeError("VM backend did not execute the exact requested argv")
    if result.guest_input_sha256 != command.input_sha256:
        raise RuntimeError("guest input digest does not match the requested trigger")
    if result.enforced_limits != command.limits:
        raise RuntimeError("VM backend did not enforce the exact requested resource limits")
    expected_canary_sha256 = (
        command.canary_interposer.binary_sha256
        if command.canary_interposer is not None
        else None
    )
    expected_canary_value = (
        command.canary_interposer.canary_value
        if command.canary_interposer is not None
        else None
    )
    if (
        result.canary_interposer_sha256 != expected_canary_sha256
        or result.canary_value != expected_canary_value
    ):
        raise RuntimeError("VM backend changed or omitted the canary interposer identity")


def _validate_output_limits(
    result: ImageIOVMCommandResult,
    limits: ImageIOHarnessLimits,
) -> None:
    for label, payload in (
        ("stdout", result.stdout),
        ("stderr", result.stderr),
        ("crash log", result.crash_log or b""),
    ):
        if len(payload) > limits.max_output_bytes:
            raise RuntimeError(f"VM backend exceeded the {label} capture limit")
    if result.duration_ms < 0:
        raise RuntimeError("VM backend returned a negative duration")
    if result.duration_ms > limits.wall_time_seconds * 1000 + 1000:
        raise RuntimeError("VM backend did not enforce the wall-time limit")


def _exit_reason(result: ImageIOVMCommandResult) -> ImageIOVMExitReason:
    if result.memory_limit_exceeded:
        if result.timed_out or result.launch_error is not None:
            raise RuntimeError(
                "a memory-limited process cannot also time out or have a launch error"
            )
        if result.terminating_signal is None or result.exit_code is not None:
            raise RuntimeError("memory-limit termination must preserve its signal outcome")
        return ImageIOVMExitReason.RESOURCE_LIMIT
    if result.timed_out:
        if result.launch_error is not None:
            raise RuntimeError("a timed-out process cannot also have a launch error")
        return ImageIOVMExitReason.TIMEOUT
    if result.launch_error is not None:
        if result.exit_code is not None or result.terminating_signal is not None:
            raise RuntimeError("a launch error cannot include process exit status")
        return ImageIOVMExitReason.LAUNCH_ERROR
    if result.terminating_signal is not None:
        if result.exit_code is not None:
            raise RuntimeError("a signaled process cannot also include an exit code")
        return ImageIOVMExitReason.SIGNALED
    if result.exit_code is None:
        raise RuntimeError("VM backend returned no process outcome")
    if result.exit_code == 0:
        return ImageIOVMExitReason.EXITED
    return ImageIOVMExitReason.NONZERO_EXIT


def _validate_input_path(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError("ImageIO input may not be a symbolic link")
    resolved = expanded.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("ImageIO input must be a regular file")
    return resolved


def _validate_absolute_guest_path(value: str, *, label: str) -> None:
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in value:
        raise ValueError(f"{label} must be an absolute normalized POSIX path")


def _is_inside_git_worktree(path: Path) -> bool:
    candidates = (path, *path.parents)
    return any((candidate / ".git").exists() for candidate in candidates)


def _write_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    os.chmod(path, 0o600)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _model_sha256(model: DomainModel) -> str:
    payload = json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return _sha256_bytes(payload)
