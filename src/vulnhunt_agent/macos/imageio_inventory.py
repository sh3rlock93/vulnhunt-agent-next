"""Safe ImageIO inventory capture and content-addressed campaign manifests.

Inventory capture never accepts or decodes an image.  It invokes only Apple
version/hardware tools and ``CGImageSourceCopyTypeIdentifiers`` so it is safe to
run on the control-plane host.  Malformed input execution belongs to the later
VM-only harness milestone.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from ..domain.schemas import DomainModel, SHA256_PATTERN
from ..reporting.apple_cve import ApplePlatformBaseline, AppleReleaseChannel

CommandRunner = Callable[[tuple[str, ...], Mapping[str, str] | None], str]
Clock = Callable[[], datetime]

_IMAGEIO_VERSION_PLIST = (
    "/System/Library/Frameworks/ImageIO.framework/Resources/version.plist"
)
_SWIFT_INVENTORY_PROBE = r"""
import Foundation
import ImageIO

let identifiers = (CGImageSourceCopyTypeIdentifiers() as NSArray)
    .compactMap { $0 as? String }
    .sorted()
let payload: [String: Any] = ["type_identifiers": identifiers]
let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
FileHandle.standardOutput.write(data)
""".strip()


class ImageIOAPIRoute(StrEnum):
    TYPE_IDENTIFIERS = "type_identifiers"
    DATA_PROPERTIES = "data_properties"
    IMAGE_PROPERTIES = "image_properties"
    THUMBNAIL_DECODE = "thumbnail_decode"
    FULL_DECODE = "full_decode"
    INCREMENTAL_DECODE = "incremental_decode"
    RAW_PIXEL_COPY = "raw_pixel_copy"


class ImageIOFormatFamily(StrEnum):
    DICOM = "dicom"
    RAW_DNG = "raw_dng"
    TEXTURE_CONTAINER = "texture_container"
    SGI = "sgi"


class ImageIOInventory(DomainModel):
    schema_version: str = "imageio-inventory-v1"
    captured_at: datetime
    product_version: str = Field(pattern=r"^[0-9]+(?:\.[0-9]+){1,2}$")
    build_version: str = Field(pattern=r"^[0-9A-Za-z]+$")
    architecture: str = Field(pattern=r"^(?:arm64|x86_64)$")
    hardware_model: str = Field(min_length=1, max_length=120)
    chip_type: str = Field(min_length=1, max_length=120)
    imageio_bundle_version: str = Field(min_length=1, max_length=80)
    type_identifiers: tuple[str, ...] = Field(min_length=1, max_length=256)
    api_routes: tuple[ImageIOAPIRoute, ...] = tuple(ImageIOAPIRoute)
    probe_sha256: str = Field(pattern=SHA256_PATTERN)
    accepts_image_input: Literal[False] = False

    @model_validator(mode="after")
    def validate_inventory(self) -> "ImageIOInventory":
        if self.captured_at.tzinfo is None:
            raise ValueError("inventory capture time must include a timezone")
        if tuple(sorted(set(self.type_identifiers))) != self.type_identifiers:
            raise ValueError("ImageIO type identifiers must be sorted and unique")
        if self.api_routes != tuple(ImageIOAPIRoute):
            raise ValueError("inventory must declare every supported API route")
        return self


class ImageIOCampaignManifest(DomainModel):
    schema_version: str = "imageio-campaign-v1"
    campaign_id: str = Field(pattern=r"^imageio-[a-z0-9][a-z0-9-]{2,80}$")
    created_at: datetime
    format_family: ImageIOFormatFamily
    stable_baseline: ApplePlatformBaseline
    beta_baseline: ApplePlatformBaseline
    stable_inventory: ImageIOInventory
    beta_inventory: ImageIOInventory
    stable_vm_image_sha256: str = Field(pattern=SHA256_PATTERN)
    beta_vm_image_sha256: str = Field(pattern=SHA256_PATTERN)
    stable_vm_snapshot_id: str = Field(min_length=1, max_length=200)
    beta_vm_snapshot_id: str = Field(min_length=1, max_length=200)
    discovery_mode: Literal["blind"] = "blind"
    network_enabled: Literal[False] = False
    host_execution_allowed: Literal[False] = False
    public_candidate_artifacts_allowed: Literal[False] = False

    @model_validator(mode="after")
    def bind_inventories_to_baselines(self) -> "ImageIOCampaignManifest":
        if self.created_at.tzinfo is None:
            raise ValueError("campaign creation time must include a timezone")
        pairs = (
            (
                AppleReleaseChannel.STABLE,
                self.stable_baseline,
                self.stable_inventory,
            ),
            (
                AppleReleaseChannel.PUBLIC_BETA,
                self.beta_baseline,
                self.beta_inventory,
            ),
        )
        for expected_channel, baseline, inventory in pairs:
            if baseline.channel is not expected_channel:
                raise ValueError(f"{expected_channel.value} baseline has the wrong channel")
            if not baseline.is_latest_public:
                raise ValueError(f"{expected_channel.value} baseline is not latest public")
            if (
                inventory.product_version != baseline.product_version
                or inventory.build_version != baseline.build_version
            ):
                raise ValueError(
                    f"{expected_channel.value} inventory does not match its frozen baseline"
                )
        return self


class FrozenImageIOCampaign(DomainModel):
    manifest: ImageIOCampaignManifest
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)


@dataclass(frozen=True)
class CampaignReadinessDecision:
    ready: bool
    reasons: tuple[str, ...]


def capture_imageio_inventory(
    *,
    runner: CommandRunner | None = None,
    clock: Clock | None = None,
    platform_name: str | None = None,
    architecture: str | None = None,
) -> ImageIOInventory:
    """Capture metadata and supported source types without decoding input."""

    active_platform = platform_name or sys.platform
    if active_platform != "darwin":
        raise RuntimeError("ImageIO inventory capture requires macOS")
    run = runner or _run_command
    now = (clock or _utc_now)()

    product_version = run(("sw_vers", "-productVersion"), None).strip()
    build_version = run(("sw_vers", "-buildVersion"), None).strip()
    hardware = json.loads(
        run(
            (
                "system_profiler",
                "SPHardwareDataType",
                "-json",
                "-detailLevel",
                "mini",
            ),
            None,
        )
    )
    overview = hardware["SPHardwareDataType"][0]
    bundle_version = run(
        (
            "plutil",
            "-extract",
            "CFBundleVersion",
            "raw",
            _IMAGEIO_VERSION_PLIST,
        ),
        None,
    ).strip()
    cache_root = str(Path(tempfile.gettempdir()) / "vulnhunt-imageio-inventory-cache")
    probe_payload = json.loads(
        run(
            ("xcrun", "swift", "-e", _SWIFT_INVENTORY_PROBE),
            {
                "CLANG_MODULE_CACHE_PATH": str(Path(cache_root) / "clang"),
                "SWIFT_MODULECACHE_PATH": str(Path(cache_root) / "swift"),
            },
        )
    )

    identifiers = tuple(sorted(set(probe_payload["type_identifiers"])))
    return ImageIOInventory(
        captured_at=now,
        product_version=product_version,
        build_version=build_version,
        architecture=architecture or platform.machine(),
        hardware_model=overview["machine_model"],
        chip_type=overview["chip_type"],
        imageio_bundle_version=bundle_version,
        type_identifiers=identifiers,
        probe_sha256=_sha256_text(_SWIFT_INVENTORY_PROBE),
    )


def freeze_campaign_manifest(
    *,
    campaign_id: str,
    format_family: ImageIOFormatFamily,
    stable_baseline: ApplePlatformBaseline,
    beta_baseline: ApplePlatformBaseline,
    stable_inventory: ImageIOInventory,
    beta_inventory: ImageIOInventory,
    stable_vm_image_sha256: str,
    beta_vm_image_sha256: str,
    stable_vm_snapshot_id: str,
    beta_vm_snapshot_id: str,
    created_at: datetime | None = None,
) -> FrozenImageIOCampaign:
    manifest = ImageIOCampaignManifest(
        campaign_id=campaign_id,
        created_at=created_at or _utc_now(),
        format_family=format_family,
        stable_baseline=stable_baseline,
        beta_baseline=beta_baseline,
        stable_inventory=stable_inventory,
        beta_inventory=beta_inventory,
        stable_vm_image_sha256=stable_vm_image_sha256,
        beta_vm_image_sha256=beta_vm_image_sha256,
        stable_vm_snapshot_id=stable_vm_snapshot_id,
        beta_vm_snapshot_id=beta_vm_snapshot_id,
    )
    return FrozenImageIOCampaign(
        manifest=manifest,
        manifest_sha256=_model_sha256(manifest),
    )


def assess_campaign_readiness(
    frozen: FrozenImageIOCampaign,
    *,
    current_stable: ApplePlatformBaseline,
    current_beta: ApplePlatformBaseline,
) -> CampaignReadinessDecision:
    """Fail closed when Apple publishes a build newer than the frozen campaign."""

    reasons: list[str] = []
    if _model_sha256(frozen.manifest) != frozen.manifest_sha256:
        reasons.append("frozen campaign manifest digest does not match its content")
    for expected_channel, frozen_baseline, current in (
        (
            AppleReleaseChannel.STABLE,
            frozen.manifest.stable_baseline,
            current_stable,
        ),
        (
            AppleReleaseChannel.PUBLIC_BETA,
            frozen.manifest.beta_baseline,
            current_beta,
        ),
    ):
        if current.channel is not expected_channel:
            reasons.append(f"current {expected_channel.value} baseline has the wrong channel")
            continue
        if not current.is_latest_public:
            reasons.append(f"current {expected_channel.value} baseline is not latest public")
        if (
            current.product_version != frozen_baseline.product_version
            or current.build_version != frozen_baseline.build_version
        ):
            reasons.append(
                f"frozen {expected_channel.value} baseline is stale: "
                f"{frozen_baseline.product_version} ({frozen_baseline.build_version}) "
                f"!= {current.product_version} ({current.build_version})"
            )
    return CampaignReadinessDecision(ready=not reasons, reasons=tuple(reasons))


def write_frozen_campaign(path: Path, frozen: FrozenImageIOCampaign) -> None:
    """Persist public campaign metadata only; candidate artifacts never enter it."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(frozen.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _run_command(argv: tuple[str, ...], env: Mapping[str, str] | None) -> str:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    completed = subprocess.run(
        argv,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
        env=merged_env,
    )
    return completed.stdout


def _model_sha256(model: DomainModel) -> str:
    payload = json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_text(payload)


def _sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(UTC)
