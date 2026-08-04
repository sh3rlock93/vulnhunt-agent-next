"""Static-only orchestration contracts for decompiler-first binary hunting."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from ...domain.schemas import DomainModel, ProviderPreflightResult, SHA256_PATTERN
from .benchmark import ImageIOPilotResult, ImageIOPilotStatus, run_imageio_ghidra_pilot

_DEFAULT_IMAGE_PATH = "/System/Library/Frameworks/ImageIO.framework/Versions/A/ImageIO"
_REQUIRED_COMPLETED_ARTIFACTS = (
    "ImageIO.macho",
    "binary-ranking.json",
    "context-plan.json",
    "imageio-ghidra-export.json",
    "input-provenance.json",
    "normalized-ir.json",
    "parser-discovery.json",
    "pilot-result.json",
    "range-analysis.json",
    "static-analysis.json",
)


class DecompilerHuntStatus(StrEnum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


class DecompilerHuntConfiguration(DomainModel):
    schema_version: Literal["m17-decompiler-plan-config-v1"] = "m17-decompiler-plan-config-v1"
    product_version: str = Field(min_length=1, max_length=80)
    build_version: str = Field(min_length=1, max_length=80)
    image_path: str = Field(pattern=r"^/System/Library/[A-Za-z0-9/_.-]{1,500}$")
    max_functions: int = Field(ge=1, le=100_000)
    max_ops_per_function: int = Field(ge=1, le=100_000)
    decompile_seconds: int = Field(ge=1, le=120)
    coverage_depth: int = Field(ge=0, le=16)
    max_evidence_functions: int = Field(ge=1, le=100_000)
    analysis_timeout_seconds: int = Field(ge=1, le=86_400)
    process_timeout_seconds: int = Field(ge=1, le=86_400)
    ghidra_heap: str = Field(pattern=r"^[1-9][0-9]*[GgMmKk]$")
    ghidra_launcher_sha256: str = Field(pattern=SHA256_PATTERN)
    extraction_script_sha256: str = Field(pattern=SHA256_PATTERN)
    export_script_sha256: str = Field(pattern=SHA256_PATTERN)
    configuration_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_configuration_digest(self) -> "DecompilerHuntConfiguration":
        expected = _model_digest(self, exclude={"configuration_sha256"})
        if self.configuration_sha256 != expected:
            raise ValueError("decompiler hunt configuration digest does not match")
        return self


class DecompilerArtifactDigest(DomainModel):
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$")
    byte_length: int = Field(ge=1)
    sha256: str = Field(pattern=SHA256_PATTERN)


class DecompilerHuntManifest(DomainModel):
    schema_version: Literal["m17-decompiler-hunt-manifest-v1"] = (
        "m17-decompiler-hunt-manifest-v1"
    )
    created_at: datetime
    status: DecompilerHuntStatus
    pilot_status: ImageIOPilotStatus
    configuration: DecompilerHuntConfiguration
    snapshot_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    image_uuid: str | None = Field(
        default=None,
        pattern=r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$",
    )
    image_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    export_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    ir_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    artifacts: tuple[DecompilerArtifactDigest, ...]
    provider_preflight: ProviderPreflightResult | None = None
    analysis_mode: Literal["decompiler_static_only"] = "decompiler_static_only"
    model_calls: Literal[0] = 0
    input_tokens: Literal[0] = 0
    output_tokens: Literal[0] = 0
    image_executions: Literal[0] = 0
    generated_inputs: Literal[0] = 0
    dynamic_experiments: Literal[0] = 0
    fuzzer_invocations: Literal[0] = 0
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_manifest(self) -> "DecompilerHuntManifest":
        if self.created_at.tzinfo is None:
            raise ValueError("decompiler hunt manifest creation time must include a timezone")
        names = tuple(item.name for item in self.artifacts)
        if tuple(sorted(set(names))) != names:
            raise ValueError("decompiler artifacts must be sorted and unique")
        if self.provider_preflight and self.provider_preflight.billable_model_calls:
            raise ValueError("M17 plan-only provider preflight must be non-billable")
        if self.status is DecompilerHuntStatus.COMPLETED:
            required = {
                self.snapshot_sha256,
                self.image_uuid,
                self.image_sha256,
                self.export_sha256,
                self.ir_sha256,
            }
            if None in required:
                raise ValueError("completed decompiler hunt requires all upstream identities")
            missing = set(_REQUIRED_COMPLETED_ARTIFACTS).difference(names)
            if missing:
                raise ValueError(
                    "completed decompiler hunt is missing artifacts: " + ", ".join(sorted(missing))
                )
        expected = _manifest_digest(self)
        if self.manifest_sha256 != expected:
            raise ValueError("decompiler hunt manifest digest does not match its evidence")
        return self


PilotRunner = Callable[..., ImageIOPilotResult]


def run_decompiler_hunt_plan(
    *,
    cache_path: Path,
    output_directory: Path,
    product_version: str,
    build_version: str,
    ghidra_headless: Path,
    script_directory: Path,
    java_home: Path,
    image_path: str = _DEFAULT_IMAGE_PATH,
    max_functions: int = 600,
    max_ops_per_function: int = 4000,
    decompile_seconds: int = 3,
    coverage_depth: int = 2,
    max_evidence_functions: int = 2000,
    analysis_timeout_seconds: int = 600,
    process_timeout_seconds: int = 900,
    ghidra_heap: str = "8G",
    provider_preflight: ProviderPreflightResult | None = None,
    resume: bool = False,
    pilot_runner: PilotRunner = run_imageio_ghidra_pilot,
) -> DecompilerHuntManifest:
    """Run or resume the zero-model M17 static evidence pipeline."""

    configuration = _configuration(
        product_version=product_version,
        build_version=build_version,
        image_path=image_path,
        max_functions=max_functions,
        max_ops_per_function=max_ops_per_function,
        decompile_seconds=decompile_seconds,
        coverage_depth=coverage_depth,
        max_evidence_functions=max_evidence_functions,
        analysis_timeout_seconds=analysis_timeout_seconds,
        process_timeout_seconds=process_timeout_seconds,
        ghidra_heap=ghidra_heap,
        ghidra_headless=ghidra_headless,
        script_directory=script_directory,
    )
    output = output_directory.expanduser()
    if output.exists():
        if not resume:
            raise FileExistsError(output)
        return _resume_manifest(
            output,
            expected_configuration=configuration,
            expected_preflight=provider_preflight,
        )

    if provider_preflight and provider_preflight.billable_model_calls:
        raise ValueError("M17 plan-only preflight cannot include a model probe")
    pilot = pilot_runner(
        cache_path=cache_path,
        output_directory=output,
        product_version=product_version,
        build_version=build_version,
        ghidra_headless=ghidra_headless,
        script_directory=script_directory,
        java_home=java_home,
        image_path=image_path,
        max_functions=max_functions,
        max_ops_per_function=max_ops_per_function,
        decompile_seconds=decompile_seconds,
        coverage_depth=coverage_depth,
        max_evidence_functions=max_evidence_functions,
        analysis_timeout_seconds=analysis_timeout_seconds,
        process_timeout_seconds=process_timeout_seconds,
        ghidra_heap=ghidra_heap,
    )
    _private_directory(output)
    artifacts = _artifact_digests(output)
    status = _hunt_status(pilot.status)
    payload = {
        "created_at": datetime.now(UTC),
        "status": status,
        "pilot_status": pilot.status,
        "configuration": configuration,
        "snapshot_sha256": pilot.snapshot_sha256,
        "image_uuid": pilot.image_uuid,
        "image_sha256": pilot.image_sha256,
        "export_sha256": pilot.export_sha256,
        "ir_sha256": pilot.ir_sha256,
        "artifacts": artifacts,
        "provider_preflight": provider_preflight,
    }
    manifest = DecompilerHuntManifest(
        **payload,
        manifest_sha256=_manifest_digest_payload(payload),
    )
    _write_private_json(output / "decompiler-hunt-manifest.json", manifest.model_dump(mode="json"))
    return manifest


def load_decompiler_hunt_manifest(output_directory: Path) -> DecompilerHuntManifest:
    output = _private_directory(output_directory.expanduser())
    path = _regular_file(output / "decompiler-hunt-manifest.json")
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("decompiler hunt manifest exceeds its byte limit")
    return DecompilerHuntManifest.model_validate_json(path.read_bytes())


def _configuration(
    *,
    product_version: str,
    build_version: str,
    image_path: str,
    max_functions: int,
    max_ops_per_function: int,
    decompile_seconds: int,
    coverage_depth: int,
    max_evidence_functions: int,
    analysis_timeout_seconds: int,
    process_timeout_seconds: int,
    ghidra_heap: str,
    ghidra_headless: Path,
    script_directory: Path,
) -> DecompilerHuntConfiguration:
    scripts = _private_or_regular_directory(script_directory.expanduser(), require_private=False)
    payload = {
        "product_version": product_version,
        "build_version": build_version,
        "image_path": image_path,
        "max_functions": max_functions,
        "max_ops_per_function": max_ops_per_function,
        "decompile_seconds": decompile_seconds,
        "coverage_depth": coverage_depth,
        "max_evidence_functions": max_evidence_functions,
        "analysis_timeout_seconds": analysis_timeout_seconds,
        "process_timeout_seconds": process_timeout_seconds,
        "ghidra_heap": ghidra_heap,
        "ghidra_launcher_sha256": _sha256_file(_regular_file(ghidra_headless.expanduser())),
        "extraction_script_sha256": _sha256_file(
            _regular_file(scripts / "ExtractDyldImage.java")
        ),
        "export_script_sha256": _sha256_file(_regular_file(scripts / "ExportImageIOIR.java")),
    }
    return DecompilerHuntConfiguration(
        **payload,
        configuration_sha256=_digest_payload(
            {"schema_version": "m17-decompiler-plan-config-v1", **payload}
        ),
    )


def _resume_manifest(
    output: Path,
    *,
    expected_configuration: DecompilerHuntConfiguration,
    expected_preflight: ProviderPreflightResult | None,
) -> DecompilerHuntManifest:
    manifest = load_decompiler_hunt_manifest(output)
    if manifest.configuration.configuration_sha256 != expected_configuration.configuration_sha256:
        raise ValueError("resume configuration does not match the frozen M17 plan")
    if manifest.provider_preflight != expected_preflight:
        raise ValueError("resume provider preflight does not match the frozen M17 plan")
    observed = _artifact_digests(output, exclude_manifest=True)
    if observed != manifest.artifacts:
        raise ValueError("resume artifacts do not match the frozen M17 manifest")
    return manifest


def _artifact_digests(
    output: Path,
    *,
    exclude_manifest: bool = True,
) -> tuple[DecompilerArtifactDigest, ...]:
    artifacts: list[DecompilerArtifactDigest] = []
    for path in sorted(output.iterdir(), key=lambda item: item.name):
        if path.name == "decompiler-hunt-manifest.json" and exclude_manifest:
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("M17 evidence directory contains a symlink")
        if not stat.S_ISREG(metadata.st_mode):
            continue
        artifacts.append(
            DecompilerArtifactDigest(
                name=path.name,
                byte_length=metadata.st_size,
                sha256=_sha256_file(path),
            )
        )
    return tuple(artifacts)


def _hunt_status(status: ImageIOPilotStatus) -> DecompilerHuntStatus:
    if status is ImageIOPilotStatus.COMPLETED:
        return DecompilerHuntStatus.COMPLETED
    if status in {
        ImageIOPilotStatus.BLOCKED_MISSING_CACHE,
        ImageIOPilotStatus.BLOCKED_MISSING_GHIDRA,
    }:
        return DecompilerHuntStatus.BLOCKED
    return DecompilerHuntStatus.FAILED


def _private_directory(path: Path) -> Path:
    source = _private_or_regular_directory(path, require_private=True)
    return source


def _private_or_regular_directory(path: Path, *, require_private: bool) -> Path:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("M17 path must be a regular non-symlink directory")
    if require_private and stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("M17 evidence directory must not grant group or other access")
    return path


def _regular_file(path: Path) -> Path:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("M17 evidence input must be a regular non-symlink file")
    return path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _manifest_digest(manifest: DecompilerHuntManifest) -> str:
    return _model_digest(manifest, exclude={"created_at", "manifest_sha256"})


def _manifest_digest_payload(payload: dict) -> str:
    normalized = {
        key: _jsonable(value)
        for key, value in payload.items()
        if key != "created_at"
    }
    normalized["schema_version"] = "m17-decompiler-hunt-manifest-v1"
    normalized.update(
        analysis_mode="decompiler_static_only",
        model_calls=0,
        input_tokens=0,
        output_tokens=0,
        image_executions=0,
        generated_inputs=0,
        dynamic_experiments=0,
        fuzzer_invocations=0,
    )
    return _digest_payload(normalized)


def _jsonable(value: object) -> object:
    if isinstance(value, DomainModel):
        return value.model_dump(mode="json")
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


def _model_digest(model: DomainModel, *, exclude: set[str]) -> str:
    return _digest_payload(model.model_dump(mode="json", exclude=exclude))


def _digest_payload(payload: object) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _write_private_json(path: Path, payload: object) -> None:
    encoded = (json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
