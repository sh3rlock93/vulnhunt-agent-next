"""Networkless UTM transport for the disposable ImageIO VM harness.

Apple Virtualization macOS guests do not support ``utmctl exec``.  This
adapter therefore exchanges bounded jobs through one explicitly configured
VirtioFS directory.  The guest worker stages every input onto its private
filesystem before execution; the shared directory is only a transport.
"""
from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import secrets
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import Field, model_validator

from ..domain.schemas import DomainModel, SHA256_PATTERN
from .imageio_harness import (
    ImageIOHarnessLimits,
    ImageIOVMCommand,
    ImageIOVMCommandResult,
    ImageIOVMEnvironment,
    ImageIOVMIsolationAttestation,
)

_QUEUE_SCHEMA = "imageio-vm-job-v1"
_RESULT_SCHEMA = "imageio-vm-job-result-v1"
_SESSION_SCHEMA = "imageio-vm-session-v1"
_HEARTBEAT_SCHEMA = "imageio-vm-heartbeat-v1"
_MAX_CONTROL_BYTES = 1024 * 1024
_JOB_ID_PATTERN = r"^[0-9a-f]{32}$"
_VM_UUID_PATTERN = (
    r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
)


class ImageIOUTMProvisioning(DomainModel):
    """Frozen host-side identity for one clean UTM base VM."""

    vm_uuid: str = Field(pattern=_VM_UUID_PATTERN)
    config_path: Path
    configuration_sha256: str = Field(pattern=SHA256_PATTERN)
    security_configuration_sha256: str = Field(pattern=SHA256_PATTERN)
    base_image_path: Path
    base_image_sha256: str = Field(pattern=SHA256_PATTERN)
    base_image_size_bytes: int = Field(gt=0)
    base_image_mtime_ns: int = Field(gt=0)
    clean_snapshot_id: str = Field(min_length=1, max_length=200)
    worker_sha256: str = Field(pattern=SHA256_PATTERN)
    harness_sha256: str = Field(pattern=SHA256_PATTERN)
    job_runner_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_config_path(self) -> "ImageIOUTMProvisioning":
        if self.config_path.name != "config.plist":
            raise ValueError("UTM provisioning must identify config.plist")
        if self.base_image_path.suffix != ".img":
            raise ValueError("UTM provisioning must identify the base disk image")
        return self


class ImageIOUTMHostObservation(DomainModel):
    """Host-observed state that a guest cannot forge through the bridge."""

    vm_uuid: str = Field(pattern=_VM_UUID_PATTERN)
    status: Literal["started", "stopped"]
    configuration_sha256: str = Field(pattern=SHA256_PATTERN)
    security_configuration_sha256: str = Field(pattern=SHA256_PATTERN)
    virtualization_backend: Literal["Apple"]
    network_device_count: int = Field(ge=0)
    disposable_session: bool
    clean_snapshot: bool
    observed_at: datetime

    @model_validator(mode="after")
    def require_aware_time(self) -> "ImageIOUTMHostObservation":
        if self.observed_at.tzinfo is None:
            raise ValueError("UTM host observation must include a timezone")
        return self


class ImageIOVMGuestHeartbeat(DomainModel):
    """Fresh guest identity emitted by the installed launch agent."""

    schema_version: Literal["imageio-vm-heartbeat-v1"]
    environment_id: str
    manager: str
    product_version: str
    build_version: str
    architecture: Literal["arm64"]
    image_sha256: str = Field(pattern=SHA256_PATTERN)
    snapshot_id: str
    clone_id: str
    boot_id: str = Field(min_length=1, max_length=200)
    observed_at: datetime
    execution_boundary: Literal["macos_virtual_machine"]
    executed_on_host: Literal[False]
    worker_sha256: str = Field(pattern=SHA256_PATTERN)
    harness_sha256: str = Field(pattern=SHA256_PATTERN)
    job_runner_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def require_aware_time(self) -> "ImageIOVMGuestHeartbeat":
        if self.observed_at.tzinfo is None:
            raise ValueError("VM heartbeat must include a timezone")
        return self


class ImageIOVMQueueResult(DomainModel):
    schema_version: Literal["imageio-vm-job-result-v1"]
    job_id: str = Field(pattern=_JOB_ID_PATTERN)
    environment_id: str
    boot_id: str
    argv: tuple[str, ...] = Field(min_length=1, max_length=32)
    guest_input_sha256: str = Field(pattern=SHA256_PATTERN)
    enforced_limits: ImageIOHarnessLimits
    exit_code: int | None
    terminating_signal: int | None
    timed_out: bool
    memory_limit_exceeded: bool
    launch_error: str | None
    duration_ms: int = Field(ge=0)
    crash_log_present: bool
    crash_log_truncated: bool


class UTMCLI(Protocol):
    def statuses(self) -> dict[str, str]: ...

    def clone(self, vm_uuid: str, clone_name: str) -> str: ...

    def start(self, vm_uuid: str) -> None: ...

    def request_stop(self, vm_uuid: str) -> None: ...

    def delete(self, vm_uuid: str) -> None: ...


class SubprocessUTMCLI:
    """Small, shell-free wrapper around the signed UTM command line tool."""

    def __init__(self, executable: Path = Path("/opt/homebrew/bin/utmctl")) -> None:
        self._executable = executable.expanduser().resolve()

    def statuses(self) -> dict[str, str]:
        return {uuid: status for uuid, (status, _) in self._list_entries().items()}

    def clone(self, vm_uuid: str, clone_name: str) -> str:
        if not re.fullmatch(r"VulnHunt-M13-[A-Za-z0-9-]{1,100}", clone_name):
            raise ValueError("unsafe disposable UTM clone name")
        before = set(self._list_entries())
        self._run("clone", "--hide", vm_uuid, "--name", clone_name)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            entries = self._list_entries()
            candidates = [
                uuid
                for uuid, (status, name) in entries.items()
                if uuid not in before and status == "stopped" and name == clone_name
            ]
            if len(candidates) == 1:
                return candidates[0]
            if len(candidates) > 1:
                break
            time.sleep(0.25)
        raise RuntimeError("UTM did not register exactly one disposable clone")

    def start(self, vm_uuid: str) -> None:
        self._run("start", "--hide", vm_uuid)

    def request_stop(self, vm_uuid: str) -> None:
        self._run("stop", "--request", vm_uuid)

    def delete(self, vm_uuid: str) -> None:
        self._run("delete", "--hide", vm_uuid)

    def _list_entries(self) -> dict[str, tuple[str, str]]:
        completed = self._run("list")
        entries: dict[str, tuple[str, str]] = {}
        for line in completed.stdout.splitlines()[1:]:
            fields = line.split(maxsplit=2)
            if len(fields) == 3:
                entries[fields[0]] = (fields[1], fields[2])
        return entries

    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                (str(self._executable), *arguments),
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"UTM command failed: {arguments[0]}") from exc


class UTMAppleConfigInspector:
    """Inspect the immutable UTM plist and live status from the host."""

    def __init__(
        self,
        provisioning: ImageIOUTMProvisioning,
        cli: UTMCLI,
        *,
        vm_uuid: str | None = None,
        config_path: Path | None = None,
        disposable_session: bool,
        require_exact_configuration: bool = True,
    ) -> None:
        self._provisioning = provisioning
        self._cli = cli
        self._vm_uuid = vm_uuid or provisioning.vm_uuid
        self._config_path = config_path or provisioning.config_path
        self._disposable_session = disposable_session
        self._require_exact_configuration = require_exact_configuration

    def observe(self) -> ImageIOUTMHostObservation:
        payload = _read_regular_file(
            self._config_path.expanduser().resolve(strict=True),
            maximum=_MAX_CONTROL_BYTES,
        )
        digest = _sha256_bytes(payload)
        try:
            configuration = plistlib.loads(payload)
        except plistlib.InvalidFileException as exc:
            raise RuntimeError("UTM config.plist is not a valid property list") from exc
        if not isinstance(configuration, dict):
            raise RuntimeError("UTM config.plist root must be a dictionary")
        networks = configuration.get("Network")
        if not isinstance(networks, list):
            raise RuntimeError("UTM config.plist does not contain a Network array")
        backend = configuration.get("Backend")
        if backend != "Apple":
            raise RuntimeError("UTM VM is not using the Apple backend")
        information = configuration.get("Information")
        if not isinstance(information, dict) or information.get("UUID") != self._vm_uuid:
            raise RuntimeError("UTM config.plist UUID does not match the registered VM")
        security_digest = _security_configuration_sha256(configuration)
        status = self._cli.statuses().get(self._vm_uuid)
        if status not in {"started", "stopped"}:
            raise RuntimeError("provisioned UTM VM is not registered")
        expected_digest = (
            self._provisioning.configuration_sha256
            if self._require_exact_configuration
            else self._provisioning.security_configuration_sha256
        )
        observed_digest = digest if self._require_exact_configuration else security_digest
        return ImageIOUTMHostObservation(
            vm_uuid=self._vm_uuid,
            status=status,
            configuration_sha256=digest,
            security_configuration_sha256=security_digest,
            virtualization_backend=backend,
            network_device_count=len(networks),
            disposable_session=self._disposable_session,
            clean_snapshot=observed_digest == expected_digest,
            observed_at=datetime.now(UTC),
        )


@dataclass(frozen=True)
class ImageIOVMBridgePaths:
    root: Path
    control: Path
    inbox: Path
    outbox: Path

    @classmethod
    def from_root(cls, root: Path) -> "ImageIOVMBridgePaths":
        resolved = root.expanduser().resolve()
        if _is_inside_git_worktree(resolved):
            raise ValueError("ImageIO VM bridge may not be inside a Git worktree")
        return cls(
            root=resolved,
            control=resolved / "control",
            inbox=resolved / "inbox",
            outbox=resolved / "outbox",
        )

    def prepare(self) -> None:
        for directory in (self.root, self.control, self.inbox, self.outbox):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError(f"unsafe ImageIO bridge directory: {directory}")
            os.chmod(directory, 0o700)


class UTMSharedDirectoryRunner:
    """Execute exact ImageIO jobs through a live, networkless guest worker."""

    def __init__(
        self,
        *,
        environment: ImageIOVMEnvironment,
        provisioning: ImageIOUTMProvisioning,
        bridge_root: Path,
        inspector: UTMAppleConfigInspector,
        runtime_vm_uuid: str | None = None,
        heartbeat_max_age_seconds: float = 10.0,
        worker_response_grace_seconds: float = 10.0,
        poll_interval_seconds: float = 0.1,
    ) -> None:
        if environment.image_sha256 != provisioning.base_image_sha256:
            raise ValueError("environment image digest does not match UTM provisioning")
        if environment.clean_snapshot_id != provisioning.clean_snapshot_id:
            raise ValueError("environment snapshot does not match UTM provisioning")
        self._environment = environment
        self._provisioning = provisioning
        self._runtime_vm_uuid = runtime_vm_uuid or provisioning.vm_uuid
        self._paths = ImageIOVMBridgePaths.from_root(bridge_root)
        self._paths.prepare()
        self._inspector = inspector
        self._heartbeat_max_age_seconds = heartbeat_max_age_seconds
        self._worker_response_grace_seconds = worker_response_grace_seconds
        self._poll_interval_seconds = poll_interval_seconds
        self._last_boot_id: str | None = None

    def attest(
        self,
        environment: ImageIOVMEnvironment,
    ) -> ImageIOVMIsolationAttestation:
        if environment != self._environment:
            raise RuntimeError("runner was asked to attest a different environment")
        host = self._inspector.observe()
        self._validate_host_observation(host)
        heartbeat = ImageIOVMGuestHeartbeat.model_validate(
            _read_json(self._paths.control / "heartbeat.json")
        )
        self._validate_heartbeat(heartbeat)
        self._last_boot_id = heartbeat.boot_id
        return ImageIOVMIsolationAttestation(
            environment_id=environment.environment_id,
            manager=environment.manager,
            product_version=heartbeat.product_version,
            build_version=heartbeat.build_version,
            architecture=heartbeat.architecture,
            image_sha256=environment.image_sha256,
            snapshot_id=environment.clean_snapshot_id,
            clone_id=environment.disposable_clone_id,
            runtime_instance_id=host.vm_uuid,
            runtime_configuration_sha256=host.configuration_sha256,
            security_configuration_sha256=host.security_configuration_sha256,
            boot_id=heartbeat.boot_id,
            observed_at=heartbeat.observed_at,
            virtualization_framework="com.apple.Virtualization",
            execution_boundary="macos_virtual_machine",
            network_device_count=0,
            outbound_network_enabled=False,
            clean_snapshot=True,
            disposable_clone=True,
            executed_on_host=False,
        )

    def execute(self, command: ImageIOVMCommand) -> ImageIOVMCommandResult:
        if command.environment != self._environment:
            raise RuntimeError("runner was asked to execute in a different environment")
        if self._last_boot_id is None:
            raise RuntimeError("VM must be attested immediately before job submission")
        job_id = secrets.token_hex(16)
        request = {
            "schema_version": _QUEUE_SCHEMA,
            "job_id": job_id,
            "environment_id": command.environment.environment_id,
            "boot_id": self._last_boot_id,
            "route": command.route.value,
            "input_sha256": command.input_sha256,
            "input_size_bytes": command.input_size_bytes,
            "guest_input_path": command.guest_input_path,
            "argv": list(command.argv),
            "limits": command.limits.model_dump(mode="json"),
        }
        job_directory = self._stage_job(job_id, command, request)
        result_directory = self._paths.outbox / job_id
        deadline = time.monotonic() + (
            command.limits.wall_time_seconds + self._worker_response_grace_seconds
        )
        try:
            while time.monotonic() < deadline:
                result_path = result_directory / "result.json"
                if result_path.exists():
                    return self._load_result(job_id, result_directory, command)
                time.sleep(self._poll_interval_seconds)
            return ImageIOVMCommandResult(
                environment_id=command.environment.environment_id,
                boot_id=self._last_boot_id,
                argv=command.argv,
                guest_input_sha256=command.input_sha256,
                enforced_limits=command.limits,
                exit_code=None,
                terminating_signal=None,
                timed_out=False,
                launch_error="VM worker did not return a result before its response deadline",
                duration_ms=command.limits.wall_time_seconds * 1000,
                stdout=b"",
                stderr=b"",
                crash_log=None,
                crash_log_truncated=False,
            )
        finally:
            _remove_job_directory(job_directory, self._paths.inbox)
            _remove_job_directory(result_directory, self._paths.outbox)

    def _validate_host_observation(self, observed: ImageIOUTMHostObservation) -> None:
        if observed.vm_uuid != self._runtime_vm_uuid:
            raise RuntimeError("UTM observation came from a different VM")
        if observed.status != "started":
            raise RuntimeError("UTM VM is not started")
        if observed.network_device_count != 0:
            raise RuntimeError("UTM VM still has one or more network devices")
        if not observed.disposable_session:
            raise RuntimeError("UTM VM was not started with --disposable")
        if not observed.clean_snapshot:
            raise RuntimeError("UTM VM did not start from the frozen clean snapshot")

    def _validate_heartbeat(self, heartbeat: ImageIOVMGuestHeartbeat) -> None:
        comparisons = {
            "environment ID": (self._environment.environment_id, heartbeat.environment_id),
            "VM manager": (self._environment.manager, heartbeat.manager),
            "product version": (
                self._environment.product_version,
                heartbeat.product_version,
            ),
            "build version": (self._environment.build_version, heartbeat.build_version),
            "architecture": (self._environment.architecture, heartbeat.architecture),
            "image digest": (self._environment.image_sha256, heartbeat.image_sha256),
            "snapshot ID": (self._environment.clean_snapshot_id, heartbeat.snapshot_id),
            "clone ID": (self._environment.disposable_clone_id, heartbeat.clone_id),
            "worker digest": (self._provisioning.worker_sha256, heartbeat.worker_sha256),
            "harness digest": (
                self._provisioning.harness_sha256,
                heartbeat.harness_sha256,
            ),
            "job runner digest": (
                self._provisioning.job_runner_sha256,
                heartbeat.job_runner_sha256,
            ),
        }
        for label, (expected, actual) in comparisons.items():
            if expected != actual:
                raise RuntimeError(f"guest heartbeat {label} mismatch")
        age = (datetime.now(UTC) - heartbeat.observed_at).total_seconds()
        if age < -1 or age > self._heartbeat_max_age_seconds:
            raise RuntimeError("guest heartbeat is stale")

    def _stage_job(
        self,
        job_id: str,
        command: ImageIOVMCommand,
        request: dict[str, object],
    ) -> Path:
        temporary = self._paths.inbox / f".{job_id}.tmp"
        target = self._paths.inbox / job_id
        temporary.mkdir(mode=0o700)
        try:
            staged_input = temporary / "input.bin"
            shutil.copyfile(command.input_path, staged_input)
            os.chmod(staged_input, 0o600)
            if _sha256_file(staged_input) != command.input_sha256:
                raise RuntimeError("staged VM input digest changed during copy")
            _write_json(temporary / "request.json", request)
            os.replace(temporary, target)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return target

    def _load_result(
        self,
        job_id: str,
        directory: Path,
        command: ImageIOVMCommand,
    ) -> ImageIOVMCommandResult:
        result = ImageIOVMQueueResult.model_validate(
            _read_json(directory / "result.json")
        )
        if result.job_id != job_id:
            raise RuntimeError("VM worker result job ID mismatch")
        stdout = _read_optional_artifact(
            directory / "stdout.bin", maximum=command.limits.max_output_bytes
        )
        stderr = _read_optional_artifact(
            directory / "stderr.bin", maximum=command.limits.max_output_bytes
        )
        crash_log = (
            _read_optional_artifact(
                directory / "crash.log", maximum=command.limits.max_output_bytes
            )
            if result.crash_log_present
            else None
        )
        if stdout is None or stderr is None:
            raise RuntimeError("VM worker omitted stdout or stderr artifacts")
        if result.crash_log_present and crash_log is None:
            raise RuntimeError("VM worker declared but omitted its crash log")
        return ImageIOVMCommandResult(
            environment_id=result.environment_id,
            boot_id=result.boot_id,
            argv=result.argv,
            guest_input_sha256=result.guest_input_sha256,
            enforced_limits=result.enforced_limits,
            exit_code=result.exit_code,
            terminating_signal=result.terminating_signal,
            timed_out=result.timed_out,
            launch_error=result.launch_error,
            duration_ms=result.duration_ms,
            stdout=stdout,
            stderr=stderr,
            crash_log=crash_log,
            memory_limit_exceeded=result.memory_limit_exceeded,
            crash_log_truncated=result.crash_log_truncated,
        )


class UTMDisposableImageIOVM:
    """Run an Apple-backend VM only through a short-lived APFS clone.

    UTM 4.7's ``--disposable`` flag is not supported by its Apple
    Virtualization backend.  UTM's own clone operation uses ``copyfile`` with
    APFS clone and sparse flags, so each run receives an isolated copy-on-write
    package which is deleted after shutdown.  The frozen base is never booted
    by this class.
    """

    def __init__(
        self,
        *,
        environment: ImageIOVMEnvironment,
        provisioning: ImageIOUTMProvisioning,
        bridge_root: Path,
        cli: UTMCLI,
        startup_timeout_seconds: float = 120.0,
    ) -> None:
        self._environment = environment
        self._provisioning = provisioning
        self._paths = ImageIOVMBridgePaths.from_root(bridge_root)
        self._paths.prepare()
        self._cli = cli
        self._startup_timeout_seconds = startup_timeout_seconds
        self._runner: UTMSharedDirectoryRunner | None = None
        self._clone_vm_uuid: str | None = None
        self._clone_config_path: Path | None = None
        self._lock_descriptor: int | None = None

    def start(self) -> UTMSharedDirectoryRunner:
        if self._clone_vm_uuid is not None:
            raise RuntimeError("disposable ImageIO VM is already active")
        self._acquire_bridge_lock()
        try:
            self._validate_frozen_base()
            clone_name = f"VulnHunt-M13-{secrets.token_hex(8)}"
            clone_uuid = self._cli.clone(self._provisioning.vm_uuid, clone_name)
            if clone_uuid == self._provisioning.vm_uuid:
                raise RuntimeError("UTM returned the frozen base as its disposable clone")
            self._clone_vm_uuid = clone_uuid
            self._clone_config_path = self._clone_path(clone_name) / "config.plist"
            clone_inspector = UTMAppleConfigInspector(
                self._provisioning,
                self._cli,
                vm_uuid=clone_uuid,
                config_path=self._clone_config_path,
                disposable_session=True,
                require_exact_configuration=False,
            )
            clone_observed = clone_inspector.observe()
            if clone_observed.status != "stopped":
                raise RuntimeError("new disposable UTM clone is not stopped")
            if clone_observed.network_device_count != 0:
                raise RuntimeError("new disposable UTM clone has a network device")
            if not clone_observed.clean_snapshot:
                raise RuntimeError("new disposable UTM clone changed the security configuration")
            _write_json(
                self._paths.control / "session.json",
                {
                    "schema_version": _SESSION_SCHEMA,
                    "environment_id": self._environment.environment_id,
                    "manager": self._environment.manager,
                    "product_version": self._environment.product_version,
                    "build_version": self._environment.build_version,
                    "architecture": self._environment.architecture,
                    "image_sha256": self._environment.image_sha256,
                    "snapshot_id": self._environment.clean_snapshot_id,
                    "clone_id": self._environment.disposable_clone_id,
                    "harness_guest_path": self._environment.harness_guest_path,
                },
            )
            (self._paths.control / "heartbeat.json").unlink(missing_ok=True)
            self._cli.start(clone_uuid)
            runner = UTMSharedDirectoryRunner(
                environment=self._environment,
                provisioning=self._provisioning,
                bridge_root=self._paths.root,
                inspector=clone_inspector,
                runtime_vm_uuid=clone_uuid,
            )
            deadline = time.monotonic() + self._startup_timeout_seconds
            last_error: Exception | None = None
            while time.monotonic() < deadline:
                try:
                    runner.attest(self._environment)
                    self._runner = runner
                    return runner
                except (OSError, ValueError, RuntimeError) as exc:
                    last_error = exc
                    time.sleep(0.25)
            raise RuntimeError("disposable ImageIO VM worker did not become ready") from last_error
        except BaseException:
            try:
                self._cleanup_clone()
            except Exception as cleanup_error:
                raise RuntimeError("failed to clean an unusable disposable UTM clone") from cleanup_error
            self._release_bridge_lock()
            raise

    def close(self) -> None:
        self._cleanup_clone()
        self._runner = None
        self._release_bridge_lock()

    def _acquire_bridge_lock(self) -> None:
        if self._lock_descriptor is not None:
            raise RuntimeError("ImageIO VM bridge lock is already held")
        lock_path = self._paths.control / "active.lock"
        try:
            self._lock_descriptor = os.open(
                lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError as exc:
            raise RuntimeError("ImageIO VM bridge already has an active or stale run") from exc

    def _release_bridge_lock(self) -> None:
        if self._lock_descriptor is None:
            return
        os.close(self._lock_descriptor)
        self._lock_descriptor = None
        (self._paths.control / "active.lock").unlink()

    def _validate_frozen_base(self) -> None:
        stopped_inspector = UTMAppleConfigInspector(
            self._provisioning,
            self._cli,
            disposable_session=False,
        )
        observed = stopped_inspector.observe()
        if observed.status != "stopped":
            raise RuntimeError("clean UTM base must be stopped before cloning")
        if observed.network_device_count != 0:
            raise RuntimeError("clean UTM base still has one or more network devices")
        if not observed.clean_snapshot:
            raise RuntimeError("clean UTM base configuration digest changed")
        image_path = self._provisioning.base_image_path.expanduser()
        if image_path.is_symlink():
            raise RuntimeError("clean UTM base image may not be a symbolic link")
        metadata = image_path.resolve(strict=True).stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("clean UTM base image is not a regular file")
        if (
            metadata.st_size != self._provisioning.base_image_size_bytes
            or metadata.st_mtime_ns != self._provisioning.base_image_mtime_ns
        ):
            raise RuntimeError("clean UTM base image metadata changed after hashing")

    def _clone_path(self, clone_name: str) -> Path:
        base_package = self._provisioning.config_path.expanduser().resolve().parent
        if base_package.suffix != ".utm":
            raise RuntimeError("frozen UTM config is not inside a VM package")
        return base_package.parent / f"{clone_name}.utm"

    def _cleanup_clone(self) -> None:
        clone_uuid = self._clone_vm_uuid
        if clone_uuid is None:
            return
        statuses = self._cli.statuses()
        clone_exists = self._clone_config_path is not None and self._clone_config_path.exists()
        if clone_uuid not in statuses and not clone_exists:
            self._clone_vm_uuid = None
            self._clone_config_path = None
            return
        if statuses.get(clone_uuid) == "started":
            self._cli.request_stop(clone_uuid)
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if self._cli.statuses().get(clone_uuid) == "stopped":
                    break
                time.sleep(0.25)
        if self._cli.statuses().get(clone_uuid) != "stopped":
            raise RuntimeError("refusing to delete a disposable UTM clone that is not stopped")
        self._cli.delete(clone_uuid)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            registered = clone_uuid in self._cli.statuses()
            on_disk = self._clone_config_path is not None and self._clone_config_path.exists()
            if not registered and not on_disk:
                self._clone_vm_uuid = None
                self._clone_config_path = None
                return
            time.sleep(0.25)
        raise RuntimeError("UTM did not remove the disposable clone completely")

    def __enter__(self) -> UTMSharedDirectoryRunner:
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.close()


def _read_json(path: Path) -> object:
    payload = _read_regular_file(path, maximum=_MAX_CONTROL_BYTES)
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid VM bridge JSON: {path.name}") from exc


def _write_json(path: Path, payload: object) -> None:
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _read_optional_artifact(path: Path, *, maximum: int) -> bytes | None:
    if not path.exists():
        return None
    return _read_regular_file(path, maximum=maximum)


def _read_regular_file(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeError(f"cannot open VM bridge file: {path.name}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"VM bridge path is not a regular file: {path.name}")
        if metadata.st_size > maximum:
            raise RuntimeError(f"VM bridge file exceeds its limit: {path.name}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(maximum + 1)
        if len(payload) > maximum:
            raise RuntimeError(f"VM bridge file exceeds its limit: {path.name}")
        return payload
    finally:
        os.close(descriptor)


def _remove_job_directory(path: Path, parent: Path) -> None:
    if not path.exists():
        return
    resolved_parent = parent.resolve()
    resolved = path.resolve()
    if resolved.parent != resolved_parent or not path.name.replace(".", "").isalnum():
        raise RuntimeError("refusing to remove an unsafe VM bridge job path")
    shutil.rmtree(resolved)


def _is_inside_git_worktree(path: Path) -> bool:
    return any((candidate / ".git").exists() for candidate in (path, *path.parents))


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _security_configuration_sha256(configuration: dict[str, Any]) -> str:
    """Hash every UTM setting except clone-specific display identity."""

    security_configuration = {
        key: value for key, value in configuration.items() if key != "Information"
    }
    payload = plistlib.dumps(
        security_configuration,
        fmt=plistlib.FMT_BINARY,
        sort_keys=True,
    )
    return _sha256_bytes(payload)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()
