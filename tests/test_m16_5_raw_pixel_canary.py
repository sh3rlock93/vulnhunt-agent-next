from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.imageio_disclosure import (
    ImageIODisclosureOracleStatus,
    ImageIORawPixelObservation,
    assess_canary_disclosure,
    normalize_raw_pixel_observation,
)
from vulnhunt_agent.macos.imageio_harness import (
    ImageIOCanaryInterposer,
    ImageIOHarnessEvidence,
    ImageIOHarnessLimits,
    ImageIOVMEnvironment,
    ImageIOVMExitReason,
    PrivateImageIOHarnessRun,
)
from vulnhunt_agent.macos.imageio_inventory import ImageIOAPIRoute

_TARGET_BYTES = b"private target input"
_BENIGN_BYTES = b"private benign input"
_INPUT = "sha256:" + hashlib.sha256(_TARGET_BYTES).hexdigest()
_BENIGN = "sha256:" + hashlib.sha256(_BENIGN_BYTES).hexdigest()
_INTERPOSER = "sha256:" + "3" * 64
_POSITIONS = "sha256:" + "4" * 64


def _environment() -> ImageIOVMEnvironment:
    return ImageIOVMEnvironment(
        environment_id="imageio-vm-m16-raw-pixel",
        manager="UTM-Apple-Virtualization",
        product_version="26.6",
        build_version="25G84",
        image_sha256="sha256:" + "a" * 64,
        clean_snapshot_id="m16-clean-v1",
        disposable_clone_id="m16-disposable-01",
    )


def _observation(
    tmp_path: Path,
    canary: int,
    *,
    benign: bool = False,
    positions: str = _POSITIONS,
    position_count: int = 3,
    output_suffix: str | None = None,
    allocator_observed: bool = True,
    exit_reason: ImageIOVMExitReason = ImageIOVMExitReason.EXITED,
):
    input_sha256 = _BENIGN if benign else _INPUT
    interposer = ImageIOCanaryInterposer(
        binary_sha256=_INTERPOSER,
        canary_value=canary,
        maximum_allocation_bytes=16 * 1024 * 1024,
        human_review_approved=True,
    )
    suffix = output_suffix if output_suffix is not None else f"{canary:02x}"
    output_sha256 = "sha256:" + (suffix * 64)[:64]
    payload = {
        "raw_pixels_copied": True,
        "decoded_bytes": 64,
        "output_sha256": output_sha256,
        "canary_allocator_observed": allocator_observed,
        "canary_allocation_count": 4 if allocator_observed else 0,
        "canary_value": canary,
        "canary_position_count": position_count,
        "canary_position_sha256": positions,
        "canary_interposer_revision": "m16-canary-interposer-v1",
    }
    stdout = json.dumps(payload).encode()
    evidence = ImageIOHarnessEvidence(
        environment_id=_environment().environment_id,
        boot_id=f"boot-{canary:02x}",
        route=ImageIOAPIRoute.RAW_PIXEL_COPY,
        input_sha256=input_sha256,
        input_size_bytes=len(_BENIGN_BYTES if benign else _TARGET_BYTES),
        argv=("/opt/vulnhunt/bin/imageio-harness",),
        limits=ImageIOHarnessLimits(),
        exit_reason=exit_reason,
        exit_code=0 if exit_reason is ImageIOVMExitReason.EXITED else None,
        terminating_signal=11 if exit_reason is ImageIOVMExitReason.SIGNALED else None,
        duration_ms=10,
        stdout_sha256="sha256:" + hashlib.sha256(stdout).hexdigest(),
        stderr_sha256="sha256:" + hashlib.sha256(b"").hexdigest(),
        crash_log_sha256=(
            "sha256:" + hashlib.sha256(b"crash").hexdigest()
            if exit_reason is ImageIOVMExitReason.SIGNALED
            else None
        ),
        pre_attestation_sha256="sha256:" + "8" * 64,
        post_attestation_sha256="sha256:" + "9" * 64,
        canary_interposer_sha256=_INTERPOSER,
        canary_value=canary,
        evidence_complete=True,
    )
    input_path = tmp_path / f"{'benign' if benign else 'target'}-{canary}.bin"
    input_path.write_bytes(_BENIGN_BYTES if benign else _TARGET_BYTES)
    run = PrivateImageIOHarnessRun(
        evidence=evidence,
        input_path=input_path,
        stdout=stdout,
        stderr=b"",
        crash_log=b"crash" if exit_reason is ImageIOVMExitReason.SIGNALED else None,
    )
    return normalize_raw_pixel_observation(
        run=run,
        environment=_environment(),
        interposer=interposer,
        benign_control=benign,
    )


def _runs(tmp_path: Path):
    canaries = (0x5A, 0xA5, 0xC3)
    target = tuple(_observation(tmp_path, value) for value in canaries)
    benign = tuple(
        _observation(
            tmp_path,
            value,
            benign=True,
            positions="sha256:" + f"{value:02x}" * 32,
            position_count=0,
        )
        for value in canaries
    )
    return target, benign


def test_three_canaries_with_stable_positions_are_interesting_on_normal_exit(
    tmp_path: Path,
) -> None:
    target, benign = _runs(tmp_path)

    result = assess_canary_disclosure(target, benign)

    assert result.status is ImageIODisclosureOracleStatus.CORRELATED_DISCLOSURE
    assert result.interesting is True
    assert result.correlated_position_sha256 == _POSITIONS
    assert result.correlated_position_count == 3
    assert all(item.exit_reason is ImageIOVMExitReason.EXITED for item in target)


def test_random_positions_and_constant_output_are_not_disclosures(tmp_path: Path) -> None:
    _target, benign = _runs(tmp_path)
    canaries = (0x5A, 0xA5, 0xC3)
    changed_positions = tuple(
        _observation(
            tmp_path,
            value,
            positions="sha256:" + f"{index + 10:x}" * 64,
        )
        for index, value in enumerate(canaries)
    )
    assert assess_canary_disclosure(
        changed_positions, benign
    ).status is ImageIODisclosureOracleStatus.POSITIONS_NOT_CORRELATED

    constant_output = tuple(
        _observation(tmp_path, value, output_suffix="f") for value in canaries
    )
    assert assess_canary_disclosure(
        constant_output, benign
    ).status is ImageIODisclosureOracleStatus.OUTPUT_NOT_CANARY_DEPENDENT


def test_benign_canary_correlation_and_missing_allocator_fail(tmp_path: Path) -> None:
    target, benign = _runs(tmp_path)
    canaries = (0x5A, 0xA5, 0xC3)
    correlated_benign = tuple(
        _observation(
            tmp_path,
            value,
            benign=True,
            position_count=3,
            positions=_POSITIONS,
        )
        for value in canaries
    )
    assert assess_canary_disclosure(
        target, correlated_benign
    ).status is ImageIODisclosureOracleStatus.BENIGN_CONTROL_CORRELATED

    unobserved = tuple(
        _observation(
            tmp_path,
            value,
            allocator_observed=index != 0,
        )
        for index, value in enumerate(canaries)
    )
    assert assess_canary_disclosure(
        unobserved, benign
    ).status is ImageIODisclosureOracleStatus.ALLOCATOR_NOT_OBSERVED


def test_observation_and_assessment_are_digest_bound(tmp_path: Path) -> None:
    target, benign = _runs(tmp_path)
    observation = target[0].model_dump(mode="json")
    observation["decoded_bytes"] += 1
    with pytest.raises(ValidationError):
        ImageIORawPixelObservation.model_validate(observation)

    assessment = assess_canary_disclosure(target, benign)
    payload = assessment.model_dump(mode="json")
    payload["interesting"] = False
    with pytest.raises(ValidationError):
        type(assessment).model_validate(payload)


def test_interposer_requires_human_review_and_rejects_host_injection() -> None:
    with pytest.raises(ValidationError):
        ImageIOCanaryInterposer(
            binary_sha256=_INTERPOSER,
            canary_value=0x5A,
            human_review_approved=False,
        )
    with pytest.raises(ValidationError):
        ImageIOCanaryInterposer(
            binary_sha256=_INTERPOSER,
            canary_value=0x5A,
            human_review_approved=True,
            host_injection_allowed=True,
        )


def test_interposer_is_fixed_to_vm_harness_and_preserves_calloc() -> None:
    root = Path(__file__).resolve().parents[1]
    harness = (root / "tools/macos/imageio_harness.swift").read_text()
    worker = (root / "tools/macos/imageio_vm_worker.swift").read_text()
    interposer = (root / "tools/macos/imageio_canary_interposer.c").read_text()
    builder = (root / "tools/macos/build_imageio_vm_payload.sh").read_text()
    installer = (root / "tools/macos/install_imageio_vm_worker.sh").read_text()

    assert "image.dataProvider" in harness
    assert "provider.data" in harness
    assert "canary_position_sha256" in harness
    assert 'request.route == "raw_pixel_copy"' in worker
    assert "canary.guestPath == interposerURL.path" in worker
    assert "malloc_zone_calloc" in interposer
    assert "Never replace calloc" in interposer
    assert "malloc_zone_malloc" in interposer
    assert "malloc_zone_from_ptr" in interposer
    assert "hostInjectionAllowed" in worker
    assert "imageio_canary_interposer.c" in builder
    assert builder.count("imageio-canary-interposer.dylib") >= 3
    assert "imageio-canary-interposer.dylib" in installer
