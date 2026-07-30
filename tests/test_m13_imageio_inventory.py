from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.imageio_inventory import (
    ImageIOAPIRoute,
    ImageIOFormatFamily,
    assess_campaign_readiness,
    capture_imageio_inventory,
    freeze_campaign_manifest,
    write_frozen_campaign,
)
from vulnhunt_agent.reporting.apple_cve import (
    ApplePlatformBaseline,
    AppleReleaseChannel,
)

NOW = datetime(2026, 7, 29, tzinfo=UTC)
VM_STABLE = "sha256:" + "1" * 64
VM_BETA = "sha256:" + "2" * 64


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], Mapping[str, str] | None]] = []

    def __call__(
        self,
        argv: tuple[str, ...],
        env: Mapping[str, str] | None,
    ) -> str:
        self.calls.append((argv, env))
        if argv == ("sw_vers", "-productVersion"):
            return "26.6\n"
        if argv == ("sw_vers", "-buildVersion"):
            return "25G84\n"
        if argv[0] == "system_profiler":
            return json.dumps(
                {
                    "SPHardwareDataType": [
                        {"machine_model": "Mac17,8", "chip_type": "Apple M5 Pro"}
                    ]
                }
            )
        if argv[0] == "plutil":
            return "2784.6\n"
        if argv[:3] == ("xcrun", "swift", "-e"):
            return json.dumps(
                {
                    "type_identifiers": [
                        "public.tiff",
                        "public.jpeg",
                        "public.dicom",
                        "public.jpeg",
                    ]
                }
            )
        raise AssertionError(f"unexpected inventory command: {argv}")


def _baseline(
    channel: AppleReleaseChannel,
    version: str,
    build: str,
) -> ApplePlatformBaseline:
    return ApplePlatformBaseline(
        channel=channel,
        product_version=version,
        build_version=build,
        is_latest_public=True,
        observed_at=NOW,
        official_release_url="https://support.apple.com/en-us/128067",
    )


def _inventory(*, version: str = "26.6", build: str = "25G84"):
    runner = FakeRunner()
    inventory = capture_imageio_inventory(
        runner=runner,
        clock=lambda: NOW,
        platform_name="darwin",
        architecture="arm64",
    )
    if (version, build) != ("26.6", "25G84"):
        inventory = inventory.model_copy(
            update={"product_version": version, "build_version": build}
        )
    return inventory


def test_inventory_capture_is_sorted_and_never_accepts_image_input() -> None:
    runner = FakeRunner()
    inventory = capture_imageio_inventory(
        runner=runner,
        clock=lambda: NOW,
        platform_name="darwin",
        architecture="arm64",
    )

    assert inventory.type_identifiers == (
        "public.dicom",
        "public.jpeg",
        "public.tiff",
    )
    assert inventory.api_routes == tuple(ImageIOAPIRoute)
    assert inventory.accepts_image_input is False
    assert all(
        not any(value.endswith((".jpg", ".png", ".tiff", ".dcm")) for value in argv)
        for argv, _ in runner.calls
    )
    swift_call = next(call for call in runner.calls if call[0][0] == "xcrun")
    assert "CGImageSourceCopyTypeIdentifiers" in swift_call[0][3]
    assert swift_call[1] is not None


def test_inventory_capture_rejects_non_macos_host() -> None:
    with pytest.raises(RuntimeError, match="requires macOS"):
        capture_imageio_inventory(platform_name="linux")


def test_frozen_campaign_is_content_addressed_and_ready() -> None:
    stable = _inventory()
    beta = _inventory(version="27.0", build="26A5380h")
    stable_baseline = _baseline(AppleReleaseChannel.STABLE, "26.6", "25G84")
    beta_baseline = _baseline(
        AppleReleaseChannel.PUBLIC_BETA,
        "27.0",
        "26A5380h",
    )

    first = freeze_campaign_manifest(
        campaign_id="imageio-dicom-20260729",
        format_family=ImageIOFormatFamily.DICOM,
        stable_baseline=stable_baseline,
        beta_baseline=beta_baseline,
        stable_inventory=stable,
        beta_inventory=beta,
        stable_vm_image_sha256=VM_STABLE,
        beta_vm_image_sha256=VM_BETA,
        stable_vm_snapshot_id="stable-clean-1",
        beta_vm_snapshot_id="beta-clean-1",
        created_at=NOW,
    )
    second = freeze_campaign_manifest(
        campaign_id="imageio-dicom-20260729",
        format_family=ImageIOFormatFamily.DICOM,
        stable_baseline=stable_baseline,
        beta_baseline=beta_baseline,
        stable_inventory=stable,
        beta_inventory=beta,
        stable_vm_image_sha256=VM_STABLE,
        beta_vm_image_sha256=VM_BETA,
        stable_vm_snapshot_id="stable-clean-1",
        beta_vm_snapshot_id="beta-clean-1",
        created_at=NOW,
    )

    assert first.manifest_sha256 == second.manifest_sha256
    decision = assess_campaign_readiness(
        first,
        current_stable=stable_baseline,
        current_beta=beta_baseline,
    )
    assert decision.ready is True
    assert decision.reasons == ()


def test_campaign_fails_closed_after_new_beta_release() -> None:
    stable_baseline = _baseline(AppleReleaseChannel.STABLE, "26.6", "25G84")
    beta_baseline = _baseline(
        AppleReleaseChannel.PUBLIC_BETA,
        "27.0",
        "26A5380h",
    )
    frozen = freeze_campaign_manifest(
        campaign_id="imageio-dicom-20260729",
        format_family=ImageIOFormatFamily.DICOM,
        stable_baseline=stable_baseline,
        beta_baseline=beta_baseline,
        stable_inventory=_inventory(),
        beta_inventory=_inventory(version="27.0", build="26A5380h"),
        stable_vm_image_sha256=VM_STABLE,
        beta_vm_image_sha256=VM_BETA,
        stable_vm_snapshot_id="stable-clean-1",
        beta_vm_snapshot_id="beta-clean-1",
        created_at=NOW,
    )

    decision = assess_campaign_readiness(
        frozen,
        current_stable=stable_baseline,
        current_beta=_baseline(
            AppleReleaseChannel.PUBLIC_BETA,
            "27.0",
            "26A5400a",
        ),
    )

    assert decision.ready is False
    assert decision.reasons == (
        "frozen public_beta baseline is stale: 27.0 (26A5380h) != 27.0 (26A5400a)",
    )


def test_campaign_rejects_inventory_from_outdated_host() -> None:
    with pytest.raises(ValidationError, match="does not match its frozen baseline"):
        freeze_campaign_manifest(
            campaign_id="imageio-dicom-20260729",
            format_family=ImageIOFormatFamily.DICOM,
            stable_baseline=_baseline(AppleReleaseChannel.STABLE, "26.6", "25G84"),
            beta_baseline=_baseline(
                AppleReleaseChannel.PUBLIC_BETA,
                "27.0",
                "26A5380h",
            ),
            stable_inventory=_inventory(version="26.5.2", build="25F84"),
            beta_inventory=_inventory(version="27.0", build="26A5380h"),
            stable_vm_image_sha256=VM_STABLE,
            beta_vm_image_sha256=VM_BETA,
            stable_vm_snapshot_id="stable-clean-1",
            beta_vm_snapshot_id="beta-clean-1",
            created_at=NOW,
        )


def test_written_campaign_preserves_digest_vm_identity_and_private_policy(
    tmp_path: Path,
) -> None:
    frozen = freeze_campaign_manifest(
        campaign_id="imageio-dicom-20260729",
        format_family=ImageIOFormatFamily.DICOM,
        stable_baseline=_baseline(AppleReleaseChannel.STABLE, "26.6", "25G84"),
        beta_baseline=_baseline(
            AppleReleaseChannel.PUBLIC_BETA,
            "27.0",
            "26A5380h",
        ),
        stable_inventory=_inventory(),
        beta_inventory=_inventory(version="27.0", build="26A5380h"),
        stable_vm_image_sha256=VM_STABLE,
        beta_vm_image_sha256=VM_BETA,
        stable_vm_snapshot_id="stable-clean-1",
        beta_vm_snapshot_id="beta-clean-1",
        created_at=NOW,
    )
    target = tmp_path / "campaign.json"

    write_frozen_campaign(target, frozen)

    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["manifest_sha256"] == frozen.manifest_sha256
    assert payload["manifest"]["stable_vm_image_sha256"] == VM_STABLE
    assert payload["manifest"]["beta_vm_snapshot_id"] == "beta-clean-1"
    assert payload["manifest"]["network_enabled"] is False
    assert payload["manifest"]["host_execution_allowed"] is False
    assert payload["manifest"]["public_candidate_artifacts_allowed"] is False
