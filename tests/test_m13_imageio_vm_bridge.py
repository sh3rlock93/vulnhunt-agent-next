from __future__ import annotations

import hashlib
import json
import plistlib
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnhunt_agent.macos.imageio_harness import (
    ImageIOHarnessLimits,
    ImageIOVMCommand,
    ImageIOVMEnvironment,
)
from vulnhunt_agent.macos.imageio_inventory import ImageIOAPIRoute
from vulnhunt_agent.macos.imageio_vm_bridge import (
    ImageIOUTMProvisioning,
    UTMAppleConfigInspector,
    UTMDisposableImageIOVM,
    UTMSharedDirectoryRunner,
)

VM_UUID = "92A960BE-06F1-47EC-AFBB-FD077A16C895"
CLONE_UUID = "7B4E7D17-6B28-49E6-B22E-0F8C9449D23A"
IMAGE_SHA = "sha256:" + "a" * 64
WORKER_SHA = "sha256:" + "b" * 64
HARNESS_SHA = "sha256:" + "c" * 64
JOB_RUNNER_SHA = "sha256:" + "d" * 64
JOB_ID = "1" * 32


class FakeUTMCLI:
    def __init__(
        self,
        *,
        status: str,
        base_config_path: Path,
        on_start: object | None = None,
    ) -> None:
        self.entries = {VM_UUID: status}
        self.base_config_path = base_config_path
        self.on_start = on_start
        self.cloned: list[tuple[str, str]] = []
        self.started: list[str] = []
        self.stopped: list[str] = []
        self.deleted: list[str] = []
        self.clone_paths: dict[str, Path] = {}

    def statuses(self) -> dict[str, str]:
        return dict(self.entries)

    def clone(self, vm_uuid: str, clone_name: str) -> str:
        self.cloned.append((vm_uuid, clone_name))
        clone_path = self.base_config_path.parent.parent / f"{clone_name}.utm"
        clone_path.mkdir()
        configuration = plistlib.loads(self.base_config_path.read_bytes())
        configuration["Information"]["Name"] = clone_name
        configuration["Information"]["UUID"] = CLONE_UUID
        (clone_path / "config.plist").write_bytes(
            plistlib.dumps(configuration, sort_keys=True)
        )
        self.clone_paths[CLONE_UUID] = clone_path
        self.entries[CLONE_UUID] = "stopped"
        return CLONE_UUID

    def start(self, vm_uuid: str) -> None:
        self.started.append(vm_uuid)
        self.entries[vm_uuid] = "started"
        if callable(self.on_start):
            self.on_start()

    def request_stop(self, vm_uuid: str) -> None:
        self.stopped.append(vm_uuid)
        self.entries[vm_uuid] = "stopped"

    def delete(self, vm_uuid: str) -> None:
        self.deleted.append(vm_uuid)
        self.entries.pop(vm_uuid)
        shutil.rmtree(self.clone_paths.pop(vm_uuid))


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _security_sha256(payload: bytes) -> str:
    configuration = plistlib.loads(payload)
    configuration.pop("Information")
    return _sha256(
        plistlib.dumps(configuration, fmt=plistlib.FMT_BINARY, sort_keys=True)
    )


def _environment() -> ImageIOVMEnvironment:
    return ImageIOVMEnvironment(
        environment_id="imageio-vm-stable-clean-01",
        manager="UTM-Apple-Virtualization",
        product_version="26.6",
        build_version="25G72",
        image_sha256=IMAGE_SHA,
        clean_snapshot_id="stable-clean-v1",
        disposable_clone_id="stable-disposable-0001",
        harness_guest_path=(
            "/Users/vulnhunt/Library/Application Support/VulnHunt/bin/imageio-harness"
        ),
    )


def _provisioning(
    tmp_path: Path,
    *,
    networks: list[object] | None = None,
) -> tuple[ImageIOUTMProvisioning, FakeUTMCLI]:
    config_path = tmp_path / "ImageIO.utm" / "config.plist"
    config_path.parent.mkdir()
    payload = plistlib.dumps(
        {
            "Backend": "Apple",
            "Information": {"Name": "ImageIO", "UUID": VM_UUID},
            "Network": networks if networks is not None else [],
        },
        sort_keys=True,
    )
    config_path.write_bytes(payload)
    image_path = config_path.parent / "Data" / "base.img"
    image_path.parent.mkdir()
    image_path.write_bytes(b"frozen test VM image")
    image_metadata = image_path.stat()
    provisioning = ImageIOUTMProvisioning(
        vm_uuid=VM_UUID,
        config_path=config_path,
        configuration_sha256=_sha256(payload),
        security_configuration_sha256=_security_sha256(payload),
        base_image_path=image_path,
        base_image_sha256=IMAGE_SHA,
        base_image_size_bytes=image_metadata.st_size,
        base_image_mtime_ns=image_metadata.st_mtime_ns,
        clean_snapshot_id="stable-clean-v1",
        worker_sha256=WORKER_SHA,
        harness_sha256=HARNESS_SHA,
        job_runner_sha256=JOB_RUNNER_SHA,
    )
    return provisioning, FakeUTMCLI(status="started", base_config_path=config_path)


def _heartbeat_payload(
    *,
    observed_at: datetime | None = None,
    worker_sha256: str = WORKER_SHA,
) -> dict[str, object]:
    environment = _environment()
    return {
        "schema_version": "imageio-vm-heartbeat-v1",
        "environment_id": environment.environment_id,
        "manager": environment.manager,
        "product_version": environment.product_version,
        "build_version": environment.build_version,
        "architecture": "arm64",
        "image_sha256": environment.image_sha256,
        "snapshot_id": environment.clean_snapshot_id,
        "clone_id": environment.disposable_clone_id,
        "boot_id": "guest-boot-0001",
        "observed_at": (observed_at or datetime.now(UTC)).isoformat(),
        "execution_boundary": "macos_virtual_machine",
        "executed_on_host": False,
        "worker_sha256": worker_sha256,
        "harness_sha256": HARNESS_SHA,
        "job_runner_sha256": JOB_RUNNER_SHA,
    }


def _write_heartbeat(bridge_root: Path, payload: dict[str, object] | None = None) -> None:
    control = bridge_root / "control"
    control.mkdir(parents=True, exist_ok=True)
    (control / "heartbeat.json").write_text(
        json.dumps(payload or _heartbeat_payload()),
        encoding="utf-8",
    )


def _runner(
    tmp_path: Path,
    *,
    networks: list[object] | None = None,
) -> tuple[UTMSharedDirectoryRunner, Path]:
    provisioning, cli = _provisioning(tmp_path, networks=networks)
    bridge_root = tmp_path / "private-bridge"
    _write_heartbeat(bridge_root)
    inspector = UTMAppleConfigInspector(provisioning, cli, disposable_session=True)
    return (
        UTMSharedDirectoryRunner(
            environment=_environment(),
            provisioning=provisioning,
            bridge_root=bridge_root,
            inspector=inspector,
            poll_interval_seconds=0.001,
        ),
        bridge_root,
    )


def _command(tmp_path: Path) -> ImageIOVMCommand:
    source = tmp_path / "opaque.bin"
    source.write_bytes(b"opaque ImageIO transport input")
    limits = ImageIOHarnessLimits()
    environment = _environment()
    digest = _sha256(source.read_bytes())
    argv = (
        environment.harness_guest_path,
        "--route",
        "full_decode",
        "--input",
        "/private/tmp/vulnhunt-imageio/input.bin",
        "--chunk-size",
        str(limits.incremental_chunk_bytes),
        "--max-input-bytes",
        str(limits.max_input_bytes),
        "--max-decoded-bytes",
        str(limits.max_decoded_bytes),
        "--wall-time-seconds",
        str(limits.wall_time_seconds),
        "--cpu-time-seconds",
        str(limits.cpu_time_seconds),
        "--max-process-memory-bytes",
        str(limits.max_process_memory_bytes),
        "--max-open-files",
        str(limits.max_open_files),
    )
    return ImageIOVMCommand(
        environment=environment,
        route=ImageIOAPIRoute.FULL_DECODE,
        input_path=source,
        input_sha256=digest,
        input_size_bytes=source.stat().st_size,
        guest_input_path="/private/tmp/vulnhunt-imageio/input.bin",
        argv=argv,
        limits=limits,
    )


def test_attestation_combines_host_network_state_and_fresh_guest_identity(
    tmp_path: Path,
) -> None:
    runner, _ = _runner(tmp_path)

    observed = runner.attest(_environment())

    assert observed.network_device_count == 0
    assert observed.outbound_network_enabled is False
    assert observed.disposable_clone is True
    assert observed.executed_on_host is False
    assert observed.boot_id == "guest-boot-0001"
    assert observed.runtime_instance_id == VM_UUID
    assert observed.runtime_configuration_sha256.startswith("sha256:")
    assert observed.security_configuration_sha256.startswith("sha256:")


def test_attestation_fails_closed_for_a_configured_network_device(tmp_path: Path) -> None:
    runner, _ = _runner(tmp_path, networks=[{"Mode": "Shared"}])

    with pytest.raises(RuntimeError, match="network devices"):
        runner.attest(_environment())


@pytest.mark.parametrize("failure", ["stale", "worker_digest"])
def test_attestation_rejects_stale_or_unfrozen_guest_worker(
    tmp_path: Path,
    failure: str,
) -> None:
    runner, bridge_root = _runner(tmp_path)
    payload = _heartbeat_payload(
        observed_at=(
            datetime.now(UTC) - timedelta(minutes=1)
            if failure == "stale"
            else datetime.now(UTC)
        ),
        worker_sha256=("sha256:" + "e" * 64 if failure == "worker_digest" else WORKER_SHA),
    )
    _write_heartbeat(bridge_root, payload)

    expected = "stale" if failure == "stale" else "worker digest mismatch"
    with pytest.raises(RuntimeError, match=expected):
        runner.attest(_environment())


def test_queue_round_trip_preserves_exact_identity_limits_and_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, bridge_root = _runner(tmp_path)
    command = _command(tmp_path)
    runner.attest(_environment())
    monkeypatch.setattr(
        "vulnhunt_agent.macos.imageio_vm_bridge.secrets.token_hex",
        lambda _: JOB_ID,
    )
    result_directory = bridge_root / "outbox" / JOB_ID
    result_directory.mkdir()
    (result_directory / "stdout.bin").write_bytes(b'{"image_created":true}\n')
    (result_directory / "stderr.bin").write_bytes(b"")
    (result_directory / "result.json").write_text(
        json.dumps(
            {
                "schema_version": "imageio-vm-job-result-v1",
                "job_id": JOB_ID,
                "environment_id": command.environment.environment_id,
                "boot_id": "guest-boot-0001",
                "argv": list(command.argv),
                "guest_input_sha256": command.input_sha256,
                "enforced_limits": command.limits.model_dump(mode="json"),
                "exit_code": 0,
                "terminating_signal": None,
                "timed_out": False,
                "memory_limit_exceeded": False,
                "launch_error": None,
                "duration_ms": 12,
                "crash_log_present": False,
                "crash_log_truncated": False,
            }
        ),
        encoding="utf-8",
    )

    result = runner.execute(command)

    assert result.argv == command.argv
    assert result.guest_input_sha256 == command.input_sha256
    assert result.enforced_limits == command.limits
    assert result.stdout == b'{"image_created":true}\n'
    assert not (bridge_root / "inbox" / JOB_ID).exists()
    assert not result_directory.exists()


def test_disposable_lifecycle_writes_session_before_start_and_requests_stop(
    tmp_path: Path,
) -> None:
    provisioning, cli = _provisioning(tmp_path)
    cli.entries[VM_UUID] = "stopped"
    bridge_root = tmp_path / "private-bridge"

    def write_started_heartbeat() -> None:
        session = json.loads((bridge_root / "control" / "session.json").read_text())
        assert session["harness_guest_path"] == _environment().harness_guest_path
        _write_heartbeat(bridge_root)

    cli.on_start = write_started_heartbeat
    vm = UTMDisposableImageIOVM(
        environment=_environment(),
        provisioning=provisioning,
        bridge_root=bridge_root,
        cli=cli,
        startup_timeout_seconds=0.2,
    )

    runner = vm.start()
    assert isinstance(runner, UTMSharedDirectoryRunner)
    assert cli.cloned[0][0] == VM_UUID
    assert cli.started == [CLONE_UUID]
    vm.close()
    assert cli.stopped == [CLONE_UUID]
    assert cli.deleted == [CLONE_UUID]
    assert cli.statuses() == {VM_UUID: "stopped"}
    assert not (bridge_root / "control" / "active.lock").exists()


def test_disposable_lifecycle_rejects_changed_base_before_cloning(tmp_path: Path) -> None:
    provisioning, cli = _provisioning(tmp_path)
    cli.entries[VM_UUID] = "stopped"
    provisioning.base_image_path.write_bytes(b"changed after the frozen digest")
    vm = UTMDisposableImageIOVM(
        environment=_environment(),
        provisioning=provisioning,
        bridge_root=tmp_path / "private-bridge",
        cli=cli,
    )

    with pytest.raises(RuntimeError, match="image metadata changed"):
        vm.start()

    assert cli.cloned == []


def test_failed_disposable_start_stops_and_deletes_its_clone(tmp_path: Path) -> None:
    provisioning, cli = _provisioning(tmp_path)
    cli.entries[VM_UUID] = "stopped"
    vm = UTMDisposableImageIOVM(
        environment=_environment(),
        provisioning=provisioning,
        bridge_root=tmp_path / "private-bridge",
        cli=cli,
        startup_timeout_seconds=0.01,
    )

    with pytest.raises(RuntimeError, match="worker did not become ready"):
        vm.start()

    assert cli.stopped == [CLONE_UUID]
    assert cli.deleted == [CLONE_UUID]
    assert cli.statuses() == {VM_UUID: "stopped"}
    assert not (tmp_path / "private-bridge" / "control" / "active.lock").exists()


def test_disposable_lifecycle_rejects_a_concurrent_or_stale_bridge_lock(
    tmp_path: Path,
) -> None:
    provisioning, cli = _provisioning(tmp_path)
    cli.entries[VM_UUID] = "stopped"
    bridge_root = tmp_path / "private-bridge"
    control = bridge_root / "control"
    control.mkdir(parents=True)
    (control / "active.lock").write_bytes(b"")
    vm = UTMDisposableImageIOVM(
        environment=_environment(),
        provisioning=provisioning,
        bridge_root=bridge_root,
        cli=cli,
    )

    with pytest.raises(RuntimeError, match="active or stale run"):
        vm.start()

    assert cli.cloned == []


def test_guest_worker_reconstructs_argv_and_contains_no_network_client() -> None:
    repository_root = Path(__file__).resolve().parents[1]
    worker = (repository_root / "tools/macos/imageio_vm_worker.swift").read_text()
    harness = (repository_root / "tools/macos/imageio_harness.swift").read_text()
    installer = (repository_root / "tools/macos/install_imageio_vm_worker.sh").read_text()

    assert "request.argv == expectedArgv" in worker
    assert "copyItem(" in worker
    assert 'URL(fileURLWithPath: guestInputPath)' in worker
    for forbidden in ("URLSession", "Network.framework", "socket(", "connect(", "curl "):
        assert forbidden not in worker
        assert forbidden not in harness
        assert forbidden not in installer
