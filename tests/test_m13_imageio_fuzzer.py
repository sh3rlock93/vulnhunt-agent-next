from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnhunt_agent.macos.imageio_fuzzer import (
    ImageIOFuzzBudget,
    ImageIOFuzzClassification,
    ImageIOMutationOperator,
    PrivateImageIOFuzzStore,
    build_minimal_dicom_seed,
    generate_dicom_fuzz_cases,
    run_imageio_fuzz_campaign,
)
from vulnhunt_agent.macos.imageio_harness import (
    ImageIOVMCommand,
    ImageIOVMCommandResult,
    ImageIOVMEnvironment,
    ImageIOVMIsolationAttestation,
)

IMAGE_SHA = "sha256:" + "a" * 64
CONFIG_SHA = "sha256:" + "b" * 64
SECURITY_SHA = "sha256:" + "c" * 64


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _environment() -> ImageIOVMEnvironment:
    return ImageIOVMEnvironment(
        environment_id="imageio-vm-stable-fuzzer-01",
        manager="test-utm-runner",
        product_version="26.6",
        build_version="25G72",
        image_sha256=IMAGE_SHA,
        clean_snapshot_id="stable-clean-v1",
        disposable_clone_id="fuzz-clone-0001",
    )


def _attestation(environment: ImageIOVMEnvironment) -> ImageIOVMIsolationAttestation:
    return ImageIOVMIsolationAttestation(
        environment_id=environment.environment_id,
        manager=environment.manager,
        product_version=environment.product_version,
        build_version=environment.build_version,
        architecture="arm64",
        image_sha256=environment.image_sha256,
        snapshot_id=environment.clean_snapshot_id,
        clone_id=environment.disposable_clone_id,
        runtime_instance_id="runtime-clone-0001",
        runtime_configuration_sha256=CONFIG_SHA,
        security_configuration_sha256=SECURITY_SHA,
        boot_id="boot-0001",
        observed_at=datetime.now(UTC),
        virtualization_framework="com.apple.Virtualization",
        execution_boundary="macos_virtual_machine",
        network_device_count=0,
        outbound_network_enabled=False,
        clean_snapshot=True,
        disposable_clone=True,
        executed_on_host=False,
    )


class DeterministicFuzzRunner:
    def __init__(self, *, seed: bytes, crash_sha256: str) -> None:
        self.seed = seed
        self.crash_sha256 = crash_sha256
        self.commands: list[ImageIOVMCommand] = []

    def attest(
        self,
        environment: ImageIOVMEnvironment,
    ) -> ImageIOVMIsolationAttestation:
        return _attestation(environment)

    def execute(self, command: ImageIOVMCommand) -> ImageIOVMCommandResult:
        self.commands.append(command)
        payload = command.input_path.read_bytes()
        if command.input_sha256 == self.crash_sha256:
            exit_code = None
            signal = 11
            stdout = b""
            crash_log = b"Process: imageio-harness\nException Type: EXC_BAD_ACCESS\n"
        else:
            exit_code = 0
            signal = None
            crash_log = None
            if payload == self.seed:
                stdout = (
                    b'{"source_created":true,"type_identifier":"org.nema.dicom",'
                    b'"image_count":1,"status":0}\n'
                )
            elif len(payload) < len(self.seed):
                stdout = b'{"source_created":false,"status":-1}\n'
            else:
                stdout = (
                    b'{"source_created":true,"type_identifier":"org.nema.dicom",'
                    b'"image_count":1,"status":-4}\n'
                )
        return ImageIOVMCommandResult(
            environment_id=command.environment.environment_id,
            boot_id="boot-0001",
            argv=command.argv,
            guest_input_sha256=command.input_sha256,
            enforced_limits=command.limits,
            exit_code=exit_code,
            terminating_signal=signal,
            timed_out=False,
            launch_error=None,
            duration_ms=5,
            stdout=stdout,
            stderr=b"",
            crash_log=crash_log,
        )


def test_minimal_seed_generates_a_stable_bounded_corpus() -> None:
    seed = build_minimal_dicom_seed()

    first = generate_dicom_fuzz_cases(seed, campaign_seed="campaign-001", max_cases=80)
    second = generate_dicom_fuzz_cases(seed, campaign_seed="campaign-001", max_cases=80)

    assert seed[128:132] == b"DICM"
    assert first == second
    assert len(first) == 80
    assert len({case.manifest.case_id for case in first}) == len(first)
    assert len({case.manifest.input_sha256 for case in first}) == len(first)
    assert all(case.manifest.input_sha256 == _sha256(case.payload) for case in first)
    assert all(case.manifest.input_size_bytes == len(case.payload) for case in first)
    assert all(case.manifest.routes for case in first)
    assert any(
        case.manifest.operator is ImageIOMutationOperator.SEMANTIC_US_BOUNDARY
        for case in first
    )


def test_campaign_seed_changes_case_identity_and_bit_selection() -> None:
    seed = build_minimal_dicom_seed()
    first = generate_dicom_fuzz_cases(seed, campaign_seed="campaign-a", max_cases=80)
    second = generate_dicom_fuzz_cases(seed, campaign_seed="campaign-b", max_cases=80)

    assert [case.manifest.case_id for case in first] != [
        case.manifest.case_id for case in second
    ]
    first_flips = [
        case.payload
        for case in first
        if case.manifest.operator is ImageIOMutationOperator.VALUE_BIT_FLIP
    ]
    second_flips = [
        case.payload
        for case in second
        if case.manifest.operator is ImageIOMutationOperator.VALUE_BIT_FLIP
    ]
    assert first_flips != second_flips


@pytest.mark.parametrize(
    "invalid",
    [b"", b"\x00" * 132, b"\x00" * 128 + b"DICM" + b"truncated"],
)
def test_generator_rejects_non_dicom_or_truncated_seeds(invalid: bytes) -> None:
    with pytest.raises(ValueError):
        generate_dicom_fuzz_cases(invalid, campaign_seed="campaign-001")


def test_campaign_runs_one_vm_runner_and_retains_only_interesting_raw_artifacts(
    tmp_path: Path,
) -> None:
    seed = build_minimal_dicom_seed()
    seed_path = tmp_path / "seed.dcm"
    seed_path.write_bytes(seed)
    generated = generate_dicom_fuzz_cases(seed, campaign_seed="campaign-001", max_cases=3)
    runner = DeterministicFuzzRunner(
        seed=seed,
        crash_sha256=generated[0].manifest.input_sha256,
    )
    store = PrivateImageIOFuzzStore(tmp_path / "private-campaign")

    summary = run_imageio_fuzz_campaign(
        runner=runner,
        environment=_environment(),
        seed_path=seed_path,
        store=store,
        campaign_id="imageio-fuzz-dicom-smoke",
        campaign_seed="campaign-001",
        budget=ImageIOFuzzBudget(max_cases=3, max_executions=10),
    )

    assert summary.generated_cases == 3
    assert summary.executed_cases == 3
    assert summary.model_calls == 0
    assert summary.classification_counts[ImageIOFuzzClassification.CRASH_CANDIDATE] == 3
    assert summary.classification_counts[ImageIOFuzzClassification.NORMAL] >= 1
    assert summary.interesting_case_ids == (generated[0].manifest.case_id,)
    finding = store.root / "interesting" / generated[0].manifest.case_id
    assert (finding / "input.dcm").read_bytes() == generated[0].payload
    assert (finding / "data_properties" / "crash.log").exists()
    assert (store.root / "campaign-summary.json").exists()
    assert len(runner.commands) == summary.execution_count
    assert all(command.environment == _environment() for command in runner.commands)


def test_private_store_and_fuzzer_source_remain_outside_models_and_git(
    tmp_path: Path,
) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    with pytest.raises(ValueError, match="Git worktree"):
        PrivateImageIOFuzzStore(repository_root / "private-fuzz")

    source = (repository_root / "src/vulnhunt_agent/macos/imageio_fuzzer.py").read_text()
    assert "openai" not in source.casefold()
    assert "boto" not in source.casefold()
    store = PrivateImageIOFuzzStore(tmp_path / "private")
    assert store.root.is_dir()
