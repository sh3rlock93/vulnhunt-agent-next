from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.imageio_harness import (
    ImageIOCanaryInterposer,
    ImageIOHarnessLimits,
    ImageIOVMCommand,
    ImageIOVMCommandResult,
    ImageIOVMEnvironment,
    ImageIOVMExitReason,
    ImageIOVMIsolationAttestation,
    run_imageio_harness,
    write_private_harness_run,
)
from vulnhunt_agent.macos.imageio_inventory import ImageIOAPIRoute

NOW = datetime(2026, 7, 30, tzinfo=UTC)
IMAGE_SHA = "sha256:" + "a" * 64


def _environment() -> ImageIOVMEnvironment:
    return ImageIOVMEnvironment(
        environment_id="imageio-vm-stable-clean-01",
        manager="test-virtualization-runner",
        product_version="26.6",
        build_version="25G84",
        image_sha256=IMAGE_SHA,
        clean_snapshot_id="stable-clean-v1",
        disposable_clone_id="stable-run-0001",
    )


def _attestation(
    environment: ImageIOVMEnvironment,
    *,
    boot_id: str = "boot-0001",
) -> ImageIOVMIsolationAttestation:
    return ImageIOVMIsolationAttestation(
        environment_id=environment.environment_id,
        manager=environment.manager,
        product_version=environment.product_version,
        build_version=environment.build_version,
        architecture="arm64",
        image_sha256=environment.image_sha256,
        snapshot_id=environment.clean_snapshot_id,
        clone_id=environment.disposable_clone_id,
        runtime_instance_id="runtime-vm-0001",
        runtime_configuration_sha256="sha256:" + "b" * 64,
        security_configuration_sha256="sha256:" + "c" * 64,
        boot_id=boot_id,
        observed_at=NOW,
        virtualization_framework="com.apple.Virtualization",
        execution_boundary="macos_virtual_machine",
        network_device_count=0,
        outbound_network_enabled=False,
        clean_snapshot=True,
        disposable_clone=True,
        executed_on_host=False,
    )


class FakeVMRunner:
    def __init__(
        self,
        *,
        attestations: list[ImageIOVMIsolationAttestation] | None = None,
        exit_code: int | None = 0,
        terminating_signal: int | None = None,
        timed_out: bool = False,
        memory_limit_exceeded: bool = False,
        launch_error: str | None = None,
        stdout: bytes = b'{"source_created":false}\n',
        stderr: bytes = b"",
        crash_log: bytes | None = None,
        crash_log_truncated: bool = False,
    ) -> None:
        self.attestations = attestations
        self.exit_code = exit_code
        self.terminating_signal = terminating_signal
        self.timed_out = timed_out
        self.memory_limit_exceeded = memory_limit_exceeded
        self.launch_error = launch_error
        self.stdout = stdout
        self.stderr = stderr
        self.crash_log = crash_log
        self.crash_log_truncated = crash_log_truncated
        self.attest_calls = 0
        self.commands: list[ImageIOVMCommand] = []

    def attest(
        self,
        environment: ImageIOVMEnvironment,
    ) -> ImageIOVMIsolationAttestation:
        index = self.attest_calls
        self.attest_calls += 1
        if self.attestations is not None:
            return self.attestations[index]
        return _attestation(environment)

    def execute(self, command: ImageIOVMCommand) -> ImageIOVMCommandResult:
        self.commands.append(command)
        return ImageIOVMCommandResult(
            environment_id=command.environment.environment_id,
            boot_id="boot-0001",
            argv=command.argv,
            guest_input_sha256=command.input_sha256,
            enforced_limits=command.limits,
            exit_code=self.exit_code,
            terminating_signal=self.terminating_signal,
            timed_out=self.timed_out,
            launch_error=self.launch_error,
            duration_ms=125,
            stdout=self.stdout,
            stderr=self.stderr,
            crash_log=self.crash_log,
            memory_limit_exceeded=self.memory_limit_exceeded,
            crash_log_truncated=self.crash_log_truncated,
            canary_interposer_sha256=(
                command.canary_interposer.binary_sha256
                if command.canary_interposer is not None
                else None
            ),
            canary_value=(
                command.canary_interposer.canary_value
                if command.canary_interposer is not None
                else None
            ),
        )


@pytest.mark.parametrize(
    "route",
    [
        ImageIOAPIRoute.DATA_PROPERTIES,
        ImageIOAPIRoute.IMAGE_PROPERTIES,
        ImageIOAPIRoute.THUMBNAIL_DECODE,
        ImageIOAPIRoute.FULL_DECODE,
        ImageIOAPIRoute.INCREMENTAL_DECODE,
        ImageIOAPIRoute.RAW_PIXEL_COPY,
    ],
)
def test_each_harness_route_runs_only_after_two_vm_attestations(
    tmp_path: Path,
    route: ImageIOAPIRoute,
) -> None:
    trigger = tmp_path / "opaque.bin"
    trigger.write_bytes(b"not decoded by the Python control plane")
    runner = FakeVMRunner()

    run = run_imageio_harness(
        runner=runner,
        environment=_environment(),
        route=route,
        input_path=trigger,
    )

    assert runner.attest_calls == 2
    assert len(runner.commands) == 1
    command = runner.commands[0]
    assert command.route is route
    assert command.argv[0] == "/opt/vulnhunt/bin/imageio-harness"
    assert command.argv[1:5] == (
        "--route",
        route.value,
        "--input",
        "/private/tmp/vulnhunt-imageio/input.bin",
    )
    assert "--max-input-bytes" in command.argv
    assert "--max-decoded-bytes" in command.argv
    assert "--wall-time-seconds" in command.argv
    assert "--cpu-time-seconds" in command.argv
    assert "--max-process-memory-bytes" in command.argv
    assert "--max-open-files" in command.argv
    assert run.evidence.argv == command.argv
    assert run.evidence.input_sha256 == (
        "sha256:" + hashlib.sha256(trigger.read_bytes()).hexdigest()
    )
    assert run.evidence.exit_reason is ImageIOVMExitReason.EXITED
    assert run.evidence.evidence_complete is True
    assert run.evidence.raw_artifacts_public is False


def test_inventory_route_cannot_accept_an_image(tmp_path: Path) -> None:
    trigger = tmp_path / "opaque.bin"
    trigger.write_bytes(b"opaque")
    runner = FakeVMRunner()

    with pytest.raises(ValueError, match="inventory-only"):
        run_imageio_harness(
            runner=runner,
            environment=_environment(),
            route=ImageIOAPIRoute.TYPE_IDENTIFIERS,
            input_path=trigger,
        )

    assert runner.attest_calls == 0
    assert runner.commands == []


def test_canary_requires_reviewed_raw_vm_route(tmp_path: Path) -> None:
    trigger = tmp_path / "opaque.bin"
    trigger.write_bytes(b"opaque")
    runner = FakeVMRunner(
        stdout=b'{"raw_pixels_copied":true}\n',
    )
    canary = ImageIOCanaryInterposer(
        binary_sha256="sha256:" + "f" * 64,
        canary_value=165,
        maximum_allocation_bytes=16 * 1024 * 1024,
        human_review_approved=True,
    )

    run = run_imageio_harness(
        runner=runner,
        environment=_environment(),
        route=ImageIOAPIRoute.RAW_PIXEL_COPY,
        input_path=trigger,
        canary_interposer=canary,
    )

    assert runner.commands[0].canary_interposer == canary
    assert run.evidence.canary_interposer_sha256 == canary.binary_sha256
    assert run.evidence.canary_value == 165
    with pytest.raises(ValueError, match="limited to the raw-pixel route"):
        run_imageio_harness(
            runner=runner,
            environment=_environment(),
            route=ImageIOAPIRoute.FULL_DECODE,
            input_path=trigger,
            canary_interposer=canary,
        )


def test_environment_rejects_any_networked_or_host_execution_mode() -> None:
    base = _environment().model_dump()
    with pytest.raises(ValidationError, match="no_network_devices"):
        ImageIOVMEnvironment.model_validate({**base, "network_mode": "default_deny"})
    with pytest.raises(ValidationError, match="False"):
        ImageIOVMEnvironment.model_validate({**base, "host_execution_allowed": True})


def test_attestation_schema_requires_zero_network_devices() -> None:
    payload = _attestation(_environment()).model_dump()
    with pytest.raises(ValidationError, match="less than or equal to 0|Input should be 0"):
        ImageIOVMIsolationAttestation.model_validate(
            {**payload, "network_device_count": 1}
        )


def test_execution_fails_if_vm_reboots_between_attestations(tmp_path: Path) -> None:
    trigger = tmp_path / "opaque.bin"
    trigger.write_bytes(b"opaque")
    environment = _environment()
    runner = FakeVMRunner(
        attestations=[
            _attestation(environment, boot_id="boot-0001"),
            _attestation(environment, boot_id="boot-0002"),
        ]
    )

    with pytest.raises(RuntimeError, match="rebooted or was replaced"):
        run_imageio_harness(
            runner=runner,
            environment=environment,
            route=ImageIOAPIRoute.FULL_DECODE,
            input_path=trigger,
        )


def test_execution_fails_if_vm_configuration_changes_between_attestations(
    tmp_path: Path,
) -> None:
    trigger = tmp_path / "opaque.bin"
    trigger.write_bytes(b"opaque")
    environment = _environment()
    before = _attestation(environment)
    runner = FakeVMRunner(
        attestations=[
            before,
            before.model_copy(
                update={
                    "runtime_configuration_sha256": "sha256:" + "d" * 64,
                }
            ),
        ]
    )

    with pytest.raises(RuntimeError, match="runtime configuration changed"):
        run_imageio_harness(
            runner=runner,
            environment=environment,
            route=ImageIOAPIRoute.FULL_DECODE,
            input_path=trigger,
        )


def test_execution_rejects_backend_that_stages_different_input(
    tmp_path: Path,
) -> None:
    trigger = tmp_path / "opaque.bin"
    trigger.write_bytes(b"opaque")

    class WrongInputRunner(FakeVMRunner):
        def execute(self, command: ImageIOVMCommand) -> ImageIOVMCommandResult:
            result = super().execute(command)
            return replace(
                result,
                guest_input_sha256="sha256:" + "f" * 64,
            )

    with pytest.raises(RuntimeError, match="guest input digest"):
        run_imageio_harness(
            runner=WrongInputRunner(),
            environment=_environment(),
            route=ImageIOAPIRoute.FULL_DECODE,
            input_path=trigger,
        )


def test_signaled_run_preserves_crash_log_digest(tmp_path: Path) -> None:
    trigger = tmp_path / "opaque.bin"
    trigger.write_bytes(b"opaque")
    crash_log = b"Process: imageio-harness\nException Type: EXC_BAD_ACCESS\n"
    runner = FakeVMRunner(
        exit_code=None,
        terminating_signal=11,
        crash_log=crash_log,
    )

    run = run_imageio_harness(
        runner=runner,
        environment=_environment(),
        route=ImageIOAPIRoute.FULL_DECODE,
        input_path=trigger,
    )

    assert run.evidence.exit_reason is ImageIOVMExitReason.SIGNALED
    assert run.evidence.crash_log_sha256 == (
        "sha256:" + hashlib.sha256(crash_log).hexdigest()
    )
    assert run.evidence.evidence_complete is True
    assert run.crash_log == crash_log


def test_signaled_run_without_crash_log_is_retained_but_incomplete(
    tmp_path: Path,
) -> None:
    trigger = tmp_path / "opaque.bin"
    trigger.write_bytes(b"opaque")
    runner = FakeVMRunner(exit_code=None, terminating_signal=6)

    run = run_imageio_harness(
        runner=runner,
        environment=_environment(),
        route=ImageIOAPIRoute.IMAGE_PROPERTIES,
        input_path=trigger,
    )

    assert run.evidence.evidence_complete is False
    assert run.evidence.evidence_gaps == (
        "signaled process has no captured crash log",
    )


def test_memory_limit_termination_is_distinct_from_a_crash(tmp_path: Path) -> None:
    trigger = tmp_path / "opaque.bin"
    trigger.write_bytes(b"opaque")
    runner = FakeVMRunner(
        exit_code=None,
        terminating_signal=9,
        memory_limit_exceeded=True,
    )

    run = run_imageio_harness(
        runner=runner,
        environment=_environment(),
        route=ImageIOAPIRoute.FULL_DECODE,
        input_path=trigger,
    )

    assert run.evidence.exit_reason is ImageIOVMExitReason.RESOURCE_LIMIT
    assert run.evidence.memory_limit_exceeded is True
    assert run.evidence.evidence_complete is True


def test_truncated_crash_log_is_preserved_as_an_explicit_evidence_gap(
    tmp_path: Path,
) -> None:
    trigger = tmp_path / "opaque.bin"
    trigger.write_bytes(b"opaque")
    runner = FakeVMRunner(
        exit_code=None,
        terminating_signal=11,
        crash_log_truncated=True,
    )

    run = run_imageio_harness(
        runner=runner,
        environment=_environment(),
        route=ImageIOAPIRoute.FULL_DECODE,
        input_path=trigger,
    )

    assert run.evidence.crash_log_truncated is True
    assert run.evidence.evidence_complete is False
    assert run.evidence.evidence_gaps == (
        "signaled process has no captured crash log",
        "crash log exceeded the capture limit",
    )


def test_input_limit_and_symlink_are_rejected_before_vm_execution(
    tmp_path: Path,
) -> None:
    trigger = tmp_path / "opaque.bin"
    trigger.write_bytes(b"0123456789")
    runner = FakeVMRunner()
    with pytest.raises(ValueError, match="limit is 5"):
        run_imageio_harness(
            runner=runner,
            environment=_environment(),
            route=ImageIOAPIRoute.DATA_PROPERTIES,
            input_path=trigger,
            limits=ImageIOHarnessLimits(max_input_bytes=5),
        )

    symlink = tmp_path / "link.bin"
    symlink.symlink_to(trigger)
    with pytest.raises(ValueError, match="symbolic link"):
        run_imageio_harness(
            runner=runner,
            environment=_environment(),
            route=ImageIOAPIRoute.DATA_PROPERTIES,
            input_path=symlink,
        )
    assert runner.commands == []


def test_private_writer_preserves_raw_artifacts_once_outside_git(
    tmp_path: Path,
) -> None:
    trigger = tmp_path / "opaque.bin"
    trigger.write_bytes(b"opaque")
    crash_log = b"synthetic crash log"
    run = run_imageio_harness(
        runner=FakeVMRunner(
            exit_code=None,
            terminating_signal=11,
            stderr=b"synthetic stderr",
            crash_log=crash_log,
        ),
        environment=_environment(),
        route=ImageIOAPIRoute.INCREMENTAL_DECODE,
        input_path=trigger,
    )
    target = tmp_path / "private-run"

    write_private_harness_run(target, run)

    payload = json.loads((target / "evidence.json").read_text())
    assert payload["argv"] == list(run.evidence.argv)
    assert payload["input_sha256"] == run.evidence.input_sha256
    assert (target / "input.bin").read_bytes() == b"opaque"
    assert (target / "crash.log").read_bytes() == crash_log
    for name in ("evidence.json", "input.bin", "stdout.bin", "stderr.bin", "crash.log"):
        assert stat.S_IMODE((target / name).stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        write_private_harness_run(target, run)


def test_private_writer_rejects_repository_path(tmp_path: Path) -> None:
    trigger = tmp_path / "opaque.bin"
    trigger.write_bytes(b"opaque")
    run = run_imageio_harness(
        runner=FakeVMRunner(),
        environment=_environment(),
        route=ImageIOAPIRoute.DATA_PROPERTIES,
        input_path=trigger,
    )
    repository_target = Path.cwd() / "private-imageio-candidate"

    with pytest.raises(ValueError, match="Git worktree"):
        write_private_harness_run(repository_target, run)
    assert not repository_target.exists()


def test_native_harness_covers_declared_apis_without_network_calls() -> None:
    source = (Path.cwd() / "tools/macos/imageio_harness.swift").read_text()
    required_calls = (
        "CGImageSourceCopyProperties(",
        "CGImageSourceCopyPropertiesAtIndex(",
        "CGImageSourceCreateThumbnailAtIndex(",
        "CGImageSourceCreateImageAtIndex(",
        "CGImageSourceCreateIncremental(",
        "CGImageSourceUpdateData(",
        "context.draw(",
    )
    assert all(call in source for call in required_calls)
    assert "dataTask" not in source
    assert "URLSession" not in source
    assert "http://" not in source
    assert "https://" not in source
