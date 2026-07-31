"""Digest-bound raw-pixel and allocator-canary disclosure oracle."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Sequence

from pydantic import Field, model_validator

from ..domain.schemas import DomainModel, SHA256_PATTERN
from .imageio_harness import (
    ImageIOCanaryInterposer,
    ImageIOVMEnvironment,
    ImageIOVMExitReason,
    PrivateImageIOHarnessRun,
)
from .imageio_inventory import ImageIOAPIRoute


class ImageIODisclosureOracleStatus(StrEnum):
    CORRELATED_DISCLOSURE = "correlated_disclosure"
    INSUFFICIENT_RUNS = "insufficient_runs"
    IDENTITY_MISMATCH = "identity_mismatch"
    ALLOCATOR_NOT_OBSERVED = "allocator_not_observed"
    POSITIONS_NOT_CORRELATED = "positions_not_correlated"
    OUTPUT_NOT_CANARY_DEPENDENT = "output_not_canary_dependent"
    BENIGN_CONTROL_CORRELATED = "benign_control_correlated"


class ImageIORawPixelObservation(DomainModel):
    schema_version: Literal["imageio-raw-pixel-observation-v1"] = (
        "imageio-raw-pixel-observation-v1"
    )
    observation_id: str = Field(pattern=r"^imageio-raw-[0-9a-f]{32}$")
    environment_id: str = Field(min_length=1, max_length=200)
    product_version: str = Field(pattern=r"^[0-9]+(?:\.[0-9]+){1,2}$")
    build_version: str = Field(pattern=r"^[0-9A-Za-z]+$")
    vm_image_sha256: str = Field(pattern=SHA256_PATTERN)
    boot_id: str = Field(min_length=1, max_length=200)
    route: Literal[ImageIOAPIRoute.RAW_PIXEL_COPY] = ImageIOAPIRoute.RAW_PIXEL_COPY
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    benign_control: bool
    interposer_sha256: str = Field(pattern=SHA256_PATTERN)
    interposer_revision: Literal["m16-canary-interposer-v1"]
    canary_value: int = Field(ge=0, le=255)
    allocator_observed: bool
    allocation_count: int = Field(ge=0)
    exit_reason: ImageIOVMExitReason
    decoded_bytes: int = Field(ge=0)
    output_sha256: str = Field(pattern=SHA256_PATTERN)
    canary_position_count: int = Field(ge=0)
    canary_position_sha256: str = Field(pattern=SHA256_PATTERN)
    harness_evidence_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_observation(self) -> "ImageIORawPixelObservation":
        if self.allocator_observed != (self.allocation_count > 0):
            raise ValueError("allocator observation does not match its allocation count")
        expected = _observation_id(
            self.model_dump(mode="json", exclude={"observation_id"})
        )
        if self.observation_id != expected:
            raise ValueError("raw-pixel observation id does not match its evidence")
        return self


class ImageIODisclosureAssessment(DomainModel):
    schema_version: Literal["imageio-disclosure-assessment-v1"] = (
        "imageio-disclosure-assessment-v1"
    )
    status: ImageIODisclosureOracleStatus
    interesting: bool
    target_observation_ids: tuple[str, ...] = Field(default=(), max_length=16)
    benign_observation_ids: tuple[str, ...] = Field(default=(), max_length=16)
    correlated_position_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    correlated_position_count: int = Field(default=0, ge=0)
    reasons: tuple[str, ...] = Field(min_length=1, max_length=12)
    assessment_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_assessment(self) -> "ImageIODisclosureAssessment":
        if tuple(sorted(set(self.target_observation_ids))) != self.target_observation_ids:
            raise ValueError("target observation ids must be sorted and unique")
        if tuple(sorted(set(self.benign_observation_ids))) != self.benign_observation_ids:
            raise ValueError("benign observation ids must be sorted and unique")
        if tuple(sorted(set(self.reasons))) != self.reasons:
            raise ValueError("disclosure reasons must be sorted and unique")
        positive = self.status is ImageIODisclosureOracleStatus.CORRELATED_DISCLOSURE
        if self.interesting is not positive:
            raise ValueError("only a correlated disclosure is interesting")
        if positive and (
            self.correlated_position_sha256 is None
            or self.correlated_position_count <= 0
        ):
            raise ValueError("positive disclosure is missing positional correlation")
        expected = _assessment_digest(
            self.model_dump(mode="json", exclude={"assessment_sha256"})
        )
        if self.assessment_sha256 != expected:
            raise ValueError("disclosure assessment digest does not match its evidence")
        return self


def normalize_raw_pixel_observation(
    *,
    run: PrivateImageIOHarnessRun,
    environment: ImageIOVMEnvironment,
    interposer: ImageIOCanaryInterposer,
    benign_control: bool,
) -> ImageIORawPixelObservation:
    """Parse bounded JSON evidence; raw provider bytes never leave the VM output object."""

    evidence = run.evidence
    if evidence.route is not ImageIOAPIRoute.RAW_PIXEL_COPY:
        raise ValueError("raw-pixel observation requires the raw provider route")
    if evidence.environment_id != environment.environment_id:
        raise ValueError("harness evidence is bound to a different VM environment")
    if not evidence.evidence_complete:
        raise ValueError("raw-pixel observation requires complete harness evidence")
    if run.input_path.stat().st_size != evidence.input_size_bytes:
        raise ValueError("raw-pixel input size does not match its evidence")
    if _sha256_bytes(run.stdout) != evidence.stdout_sha256:
        raise ValueError("raw-pixel stdout does not match its evidence digest")
    if _sha256_bytes(run.stderr) != evidence.stderr_sha256:
        raise ValueError("raw-pixel stderr does not match its evidence digest")
    crash_sha256 = _sha256_bytes(run.crash_log) if run.crash_log is not None else None
    if crash_sha256 != evidence.crash_log_sha256:
        raise ValueError("raw-pixel crash artifact does not match its evidence digest")
    if _sha256_file(run.input_path) != evidence.input_sha256:
        raise ValueError("raw-pixel input does not match its evidence digest")
    if (
        evidence.canary_interposer_sha256 != interposer.binary_sha256
        or evidence.canary_value != interposer.canary_value
    ):
        raise ValueError("harness evidence is bound to a different canary interposer")
    try:
        payload = json.loads(run.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("raw-pixel harness output is not bounded JSON") from exc
    if not isinstance(payload, dict) or payload.get("raw_pixels_copied") is not True:
        raise ValueError("raw-pixel harness did not copy provider bytes")
    values = _raw_values(payload)
    if values["decoded_bytes"] > evidence.limits.max_decoded_bytes:
        raise ValueError("raw-pixel output exceeds the decoded-byte limit")
    if values["canary_value"] != interposer.canary_value:
        raise ValueError("raw-pixel output reports a different canary byte")
    if values["canary_interposer_revision"] != interposer.source_revision:
        raise ValueError("raw-pixel output reports a different interposer revision")
    data = {
        "schema_version": "imageio-raw-pixel-observation-v1",
        "environment_id": environment.environment_id,
        "product_version": environment.product_version,
        "build_version": environment.build_version,
        "vm_image_sha256": environment.image_sha256,
        "boot_id": evidence.boot_id,
        "route": ImageIOAPIRoute.RAW_PIXEL_COPY.value,
        "input_sha256": evidence.input_sha256,
        "benign_control": benign_control,
        "interposer_sha256": interposer.binary_sha256,
        "interposer_revision": interposer.source_revision,
        "canary_value": interposer.canary_value,
        "allocator_observed": values["canary_allocator_observed"],
        "allocation_count": values["canary_allocation_count"],
        "exit_reason": evidence.exit_reason.value,
        "decoded_bytes": values["decoded_bytes"],
        "output_sha256": values["output_sha256"],
        "canary_position_count": values["canary_position_count"],
        "canary_position_sha256": values["canary_position_sha256"],
        "harness_evidence_sha256": _model_digest(evidence),
    }
    return ImageIORawPixelObservation(
        **data,
        observation_id=_observation_id(data),
    )


def assess_canary_disclosure(
    target: Sequence[ImageIORawPixelObservation],
    benign: Sequence[ImageIORawPixelObservation],
) -> ImageIODisclosureAssessment:
    """Require three-byte positional correlation and a same-build benign negative."""

    target_runs = tuple(
        sorted(
            (
                ImageIORawPixelObservation.model_validate(item.model_dump(mode="json"))
                for item in target
            ),
            key=lambda item: item.canary_value,
        )
    )
    benign_runs = tuple(
        sorted(
            (
                ImageIORawPixelObservation.model_validate(item.model_dump(mode="json"))
                for item in benign
            ),
            key=lambda item: item.canary_value,
        )
    )
    target_ids = tuple(sorted(item.observation_id for item in target_runs))
    benign_ids = tuple(sorted(item.observation_id for item in benign_runs))

    status: ImageIODisclosureOracleStatus
    reasons: tuple[str, ...]
    position_sha256: str | None = None
    position_count = 0
    if (
        len(target_runs) < 3
        or len(benign_runs) < 3
        or len({item.canary_value for item in target_runs}) < 3
        or {item.canary_value for item in target_runs}
        != {item.canary_value for item in benign_runs}
    ):
        status = ImageIODisclosureOracleStatus.INSUFFICIENT_RUNS
        reasons = ("three_matching_distinct_canary_runs_are_required",)
    elif not _identities_match(target_runs, benign_runs):
        status = ImageIODisclosureOracleStatus.IDENTITY_MISMATCH
        reasons = ("build_route_or_interposer_identity_mismatch",)
    elif any(
        not item.allocator_observed
        or item.exit_reason is not ImageIOVMExitReason.EXITED
        for item in (*target_runs, *benign_runs)
    ):
        status = ImageIODisclosureOracleStatus.ALLOCATOR_NOT_OBSERVED
        reasons = ("allocator_observation_or_normal_exit_is_missing",)
    elif not _positions_correlate(target_runs):
        status = ImageIODisclosureOracleStatus.POSITIONS_NOT_CORRELATED
        reasons = ("target_canary_positions_do_not_match_across_runs",)
    elif len({item.output_sha256 for item in target_runs}) < 3:
        status = ImageIODisclosureOracleStatus.OUTPUT_NOT_CANARY_DEPENDENT
        reasons = ("target_output_does_not_track_distinct_canary_bytes",)
    elif _positions_correlate(benign_runs) and len(
        {item.output_sha256 for item in benign_runs}
    ) >= 3:
        status = ImageIODisclosureOracleStatus.BENIGN_CONTROL_CORRELATED
        reasons = ("benign_control_tracks_the_same_canary_pattern",)
    else:
        status = ImageIODisclosureOracleStatus.CORRELATED_DISCLOSURE
        reasons = ("normal_exit_with_three_canary_positional_correlation",)
        position_sha256 = target_runs[0].canary_position_sha256
        position_count = target_runs[0].canary_position_count

    data = {
        "schema_version": "imageio-disclosure-assessment-v1",
        "status": status.value,
        "interesting": status is ImageIODisclosureOracleStatus.CORRELATED_DISCLOSURE,
        "target_observation_ids": target_ids,
        "benign_observation_ids": benign_ids,
        "correlated_position_sha256": position_sha256,
        "correlated_position_count": position_count,
        "reasons": tuple(sorted(reasons)),
    }
    return ImageIODisclosureAssessment(
        **data,
        assessment_sha256=_assessment_digest(data),
    )


def _raw_values(payload: dict[str, Any]) -> dict[str, Any]:
    schema = {
        "decoded_bytes": int,
        "output_sha256": str,
        "canary_allocator_observed": bool,
        "canary_allocation_count": int,
        "canary_value": int,
        "canary_position_count": int,
        "canary_position_sha256": str,
        "canary_interposer_revision": str,
    }
    selected: dict[str, Any] = {}
    for name, expected_type in schema.items():
        value = payload.get(name)
        if not isinstance(value, expected_type) or (
            expected_type is int and isinstance(value, bool)
        ):
            raise ValueError(f"raw-pixel output omitted typed field: {name}")
        selected[name] = value
    if selected["decoded_bytes"] < 0 or selected["canary_position_count"] < 0:
        raise ValueError("raw-pixel output contains a negative byte count")
    if selected["canary_position_count"] > selected["decoded_bytes"]:
        raise ValueError("canary positions exceed the copied raw-pixel bytes")
    return selected


def _identities_match(
    target: tuple[ImageIORawPixelObservation, ...],
    benign: tuple[ImageIORawPixelObservation, ...],
) -> bool:
    def identity(item: ImageIORawPixelObservation) -> tuple[object, ...]:
        return (
            item.environment_id,
            item.product_version,
            item.build_version,
            item.vm_image_sha256,
            item.route,
            item.interposer_sha256,
            item.interposer_revision,
        )

    identities = {identity(item) for item in (*target, *benign)}
    return (
        len(identities) == 1
        and len({item.input_sha256 for item in target}) == 1
        and len({item.input_sha256 for item in benign}) == 1
        and target[0].input_sha256 != benign[0].input_sha256
        and all(not item.benign_control for item in target)
        and all(item.benign_control for item in benign)
    )


def _positions_correlate(runs: tuple[ImageIORawPixelObservation, ...]) -> bool:
    return bool(
        runs
        and runs[0].canary_position_count > 0
        and len({item.canary_position_count for item in runs}) == 1
        and len({item.canary_position_sha256 for item in runs}) == 1
    )


def _observation_id(payload: dict[str, Any]) -> str:
    return "imageio-raw-" + hashlib.sha256(_canonical(payload)).hexdigest()[:32]


def _assessment_digest(payload: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


def _model_digest(model: DomainModel) -> str:
    return "sha256:" + hashlib.sha256(_canonical(model.model_dump(mode="json"))).hexdigest()


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
