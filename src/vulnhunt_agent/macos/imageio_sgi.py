"""Bounded SGI RLE parsing, relational mutation, and deep-seed qualification."""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from ..domain.schemas import DomainModel, SHA256_PATTERN
from .imageio_harness import (
    ImageIOHarnessEvidence,
    ImageIOHarnessLimits,
    ImageIOVMEnvironment,
    ImageIOVMExitReason,
    ImageIOVMRunner,
    run_imageio_harness,
)
from .imageio_inventory import ImageIOAPIRoute, ImageIOFormatFamily

_SGI_HEADER_BYTES = 512
_SGI_MAGIC = 0x01DA
_SGI_RLE_STORAGE = 1
_MAX_SGI_SEED_BYTES = 32 * 1024 * 1024
_MAX_SGI_DIMENSION = 16_384
_MAX_SGI_TABLE_ENTRIES = 65_536
_SGI_QUALIFICATION_ROUTES = (
    ImageIOAPIRoute.FULL_DECODE,
    ImageIOAPIRoute.RAW_PIXEL_COPY,
)


class ImageIOSGIRelation(StrEnum):
    INDIVIDUAL_IN_RANGE_COMBINED_OOB = "individual_in_range_combined_oob"
    EXACT_END_OF_FILE = "exact_end_of_file"
    ONE_BYTE_COMBINED_OVERRUN = "one_byte_combined_overrun"
    TRUNCATED_AVAILABLE_TAIL = "truncated_available_tail"
    PAIRED_BOUNDARY_MOVEMENT = "paired_boundary_movement"


class ImageIOSGIRowRange(DomainModel):
    table_index: int = Field(ge=0, le=_MAX_SGI_TABLE_ENTRIES - 1)
    start_table_offset: int = Field(ge=_SGI_HEADER_BYTES)
    length_table_offset: int = Field(ge=_SGI_HEADER_BYTES)
    data_offset: int = Field(ge=_SGI_HEADER_BYTES)
    byte_length: int = Field(ge=1, le=_MAX_SGI_SEED_BYTES)
    data_end_offset: int = Field(ge=_SGI_HEADER_BYTES)

    @model_validator(mode="after")
    def validate_end(self) -> "ImageIOSGIRowRange":
        if self.data_end_offset != self.data_offset + self.byte_length:
            raise ValueError("SGI row end does not match its offset and length")
        return self


class ImageIOSGISeedLayout(DomainModel):
    schema_version: Literal["imageio-sgi-layout-v1"] = "imageio-sgi-layout-v1"
    format_family: Literal[ImageIOFormatFamily.SGI] = ImageIOFormatFamily.SGI
    seed_sha256: str = Field(pattern=SHA256_PATTERN)
    file_size_bytes: int = Field(ge=_SGI_HEADER_BYTES, le=_MAX_SGI_SEED_BYTES)
    storage_mode: Literal[1] = 1
    bytes_per_channel: Literal[1, 2]
    dimension: int = Field(ge=1, le=3)
    width: int = Field(ge=1, le=_MAX_SGI_DIMENSION)
    height: int = Field(ge=1, le=_MAX_SGI_DIMENSION)
    channel_count: int = Field(ge=1, le=_MAX_SGI_DIMENSION)
    pixel_minimum: int = Field(ge=0, le=0xFFFFFFFF)
    pixel_maximum: int = Field(ge=0, le=0xFFFFFFFF)
    table_count: int = Field(ge=1, le=_MAX_SGI_TABLE_ENTRIES)
    table_data_offset: int = Field(ge=_SGI_HEADER_BYTES, le=_MAX_SGI_SEED_BYTES)
    rows: tuple[ImageIOSGIRowRange, ...] = Field(
        min_length=1,
        max_length=_MAX_SGI_TABLE_ENTRIES,
    )
    layout_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_layout(self) -> "ImageIOSGISeedLayout":
        if self.pixel_minimum > self.pixel_maximum:
            raise ValueError("SGI pixel range is inverted")
        if self.table_count != self.height * self.channel_count:
            raise ValueError("SGI table count does not match height times channels")
        if len(self.rows) != self.table_count:
            raise ValueError("SGI row table is incomplete")
        if tuple(item.table_index for item in self.rows) != tuple(range(self.table_count)):
            raise ValueError("SGI row table indexes are not contiguous")
        expected = _digest(self.model_dump(mode="json", exclude={"layout_sha256"}))
        if self.layout_sha256 != expected:
            raise ValueError("SGI layout digest does not match its fields")
        return self


class ImageIOSGIMutationCase(DomainModel):
    schema_version: Literal["imageio-sgi-mutation-v1"] = "imageio-sgi-mutation-v1"
    case_id: str = Field(pattern=r"^sgi-case-[0-9a-f]{32}$")
    format_family: Literal[ImageIOFormatFamily.SGI] = ImageIOFormatFamily.SGI
    seed_sha256: str = Field(pattern=SHA256_PATTERN)
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    original_file_size_bytes: int = Field(ge=_SGI_HEADER_BYTES)
    input_size_bytes: int = Field(ge=_SGI_HEADER_BYTES)
    table_index: int = Field(ge=0, le=_MAX_SGI_TABLE_ENTRIES - 1)
    start_table_offset: int = Field(ge=_SGI_HEADER_BYTES)
    length_table_offset: int = Field(ge=_SGI_HEADER_BYTES)
    original_start: int = Field(ge=0, le=0xFFFFFFFF)
    original_length: int = Field(ge=1, le=0xFFFFFFFF)
    mutated_start: int = Field(ge=0, le=0xFFFFFFFF)
    mutated_length: int = Field(ge=0, le=0xFFFFFFFF)
    operator: ImageIOSGIRelation
    asserted_relation: ImageIOSGIRelation
    routes: tuple[ImageIOAPIRoute, ...] = _SGI_QUALIFICATION_ROUTES
    model_calls: Literal[0] = 0

    @model_validator(mode="after")
    def validate_relation(self) -> "ImageIOSGIMutationCase":
        if self.operator is not self.asserted_relation:
            raise ValueError("SGI operator and asserted relation differ")
        if self.routes != _SGI_QUALIFICATION_ROUTES:
            raise ValueError("SGI cases are limited to rendered and raw-pixel routes")
        _require_relation(
            relation=self.asserted_relation,
            original_file_size=self.original_file_size_bytes,
            input_size=self.input_size_bytes,
            original_start=self.original_start,
            original_length=self.original_length,
            mutated_start=self.mutated_start,
            mutated_length=self.mutated_length,
        )
        expected = _case_id(self.model_dump(mode="json", exclude={"case_id"}))
        if self.case_id != expected:
            raise ValueError("SGI case id does not match its mutation provenance")
        return self


@dataclass(frozen=True)
class GeneratedImageIOSGICase:
    manifest: ImageIOSGIMutationCase
    payload: bytes


class ImageIOSGIQualificationObservation(DomainModel):
    schema_version: Literal["imageio-sgi-qualification-observation-v1"] = (
        "imageio-sgi-qualification-observation-v1"
    )
    route: ImageIOAPIRoute
    type_identifier: str = Field(min_length=1, max_length=200)
    image_created: Literal[True]
    pixels_materialized: Literal[True]
    decoded_bytes: int = Field(ge=1)
    harness_evidence_sha256: str = Field(pattern=SHA256_PATTERN)
    observation_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_observation(self) -> "ImageIOSGIQualificationObservation":
        if self.route not in _SGI_QUALIFICATION_ROUTES:
            raise ValueError("SGI qualification used an unapproved route")
        expected = _digest(
            self.model_dump(mode="json", exclude={"observation_sha256"})
        )
        if self.observation_sha256 != expected:
            raise ValueError("SGI qualification observation digest mismatch")
        return self


class ImageIOSGISeedQualification(DomainModel):
    schema_version: Literal["imageio-sgi-seed-qualification-v1"] = (
        "imageio-sgi-seed-qualification-v1"
    )
    seed_sha256: str = Field(pattern=SHA256_PATTERN)
    layout_sha256: str = Field(pattern=SHA256_PATTERN)
    environment_id: str = Field(min_length=1, max_length=200)
    product_version: str = Field(pattern=r"^[0-9]+(?:\.[0-9]+){1,2}$")
    build_version: str = Field(pattern=r"^[0-9A-Za-z]+$")
    vm_image_sha256: str = Field(pattern=SHA256_PATTERN)
    observations: tuple[ImageIOSGIQualificationObservation, ...] = Field(
        min_length=2,
        max_length=2,
    )
    deep_seed: Literal[True] = True
    model_calls: Literal[0] = 0
    qualification_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_qualification(self) -> "ImageIOSGISeedQualification":
        if tuple(item.route for item in self.observations) != _SGI_QUALIFICATION_ROUTES:
            raise ValueError("SGI seed qualification must use exactly two bounded routes")
        expected = _digest(
            self.model_dump(mode="json", exclude={"qualification_sha256"})
        )
        if self.qualification_sha256 != expected:
            raise ValueError("SGI qualification digest mismatch")
        return self


def build_minimal_sgi_rle_seed() -> bytes:
    """Build a deterministic 1x1 RGB SGI RLE seed for qualification and tests."""

    header = bytearray(_SGI_HEADER_BYTES)
    struct.pack_into(">HBBHHHH", header, 0, _SGI_MAGIC, 1, 1, 3, 1, 1, 3)
    struct.pack_into(">III", header, 12, 0, 255, 0)
    header[24:40] = b"VulnHunt SGI RLE"
    struct.pack_into(">I", header, 104, 0)
    packets = (b"\x81\xff\x00", b"\x81\x00\x00", b"\x81\x00\x00")
    table_count = len(packets)
    data_offset = _SGI_HEADER_BYTES + table_count * 8
    starts: list[int] = []
    cursor = data_offset
    for packet in packets:
        starts.append(cursor)
        cursor += len(packet)
    return (
        bytes(header)
        + b"".join(struct.pack(">I", value) for value in starts)
        + b"".join(struct.pack(">I", len(packet)) for packet in packets)
        + b"".join(packets)
    )


def parse_sgi_rle_seed(
    payload: bytes,
    *,
    maximum_seed_bytes: int = _MAX_SGI_SEED_BYTES,
) -> ImageIOSGISeedLayout:
    """Parse only the bounded SGI header and big-endian RLE range tables."""

    if not _SGI_HEADER_BYTES <= len(payload) <= maximum_seed_bytes:
        raise ValueError("SGI seed size is outside the approved bound")
    magic, storage, bytes_per_channel, dimension, width, height, channels = (
        struct.unpack_from(">HBBHHHH", payload, 0)
    )
    if magic != _SGI_MAGIC:
        raise ValueError("SGI seed has the wrong magic")
    if storage != _SGI_RLE_STORAGE:
        raise ValueError("SGI relational mutation requires RLE storage")
    if bytes_per_channel not in {1, 2}:
        raise ValueError("SGI bytes-per-channel must be one or two")
    if dimension not in {1, 2, 3}:
        raise ValueError("SGI dimension must be one, two, or three")
    if not all(1 <= value <= _MAX_SGI_DIMENSION for value in (width, height, channels)):
        raise ValueError("SGI dimensions exceed the bounded parser policy")
    if (dimension == 1 and (height != 1 or channels != 1)) or (
        dimension == 2 and channels != 1
    ):
        raise ValueError("SGI dimensions do not match the declared dimensionality")
    table_count = height * channels
    if table_count > _MAX_SGI_TABLE_ENTRIES:
        raise ValueError("SGI RLE table count exceeds the bounded parser policy")
    table_data_offset = _SGI_HEADER_BYTES + table_count * 8
    if table_data_offset > len(payload):
        raise ValueError("SGI seed ends inside its RLE tables")
    pixel_minimum, pixel_maximum = struct.unpack_from(">II", payload, 12)
    if pixel_minimum > pixel_maximum:
        raise ValueError("SGI pixel range is inverted")

    rows: list[ImageIOSGIRowRange] = []
    length_table_start = _SGI_HEADER_BYTES + table_count * 4
    for index in range(table_count):
        start_table_offset = _SGI_HEADER_BYTES + index * 4
        length_table_offset = length_table_start + index * 4
        data_offset = struct.unpack_from(">I", payload, start_table_offset)[0]
        byte_length = struct.unpack_from(">I", payload, length_table_offset)[0]
        data_end = data_offset + byte_length
        if (
            data_offset < table_data_offset
            or byte_length == 0
            or data_offset > len(payload)
            or byte_length > len(payload)
            or data_end > len(payload)
        ):
            raise ValueError("SGI seed contains an invalid RLE row range")
        rows.append(
            ImageIOSGIRowRange(
                table_index=index,
                start_table_offset=start_table_offset,
                length_table_offset=length_table_offset,
                data_offset=data_offset,
                byte_length=byte_length,
                data_end_offset=data_end,
            )
        )
    data = {
        "schema_version": "imageio-sgi-layout-v1",
        "format_family": ImageIOFormatFamily.SGI.value,
        "seed_sha256": _sha256_bytes(payload),
        "file_size_bytes": len(payload),
        "storage_mode": storage,
        "bytes_per_channel": bytes_per_channel,
        "dimension": dimension,
        "width": width,
        "height": height,
        "channel_count": channels,
        "pixel_minimum": pixel_minimum,
        "pixel_maximum": pixel_maximum,
        "table_count": table_count,
        "table_data_offset": table_data_offset,
        "rows": tuple(item.model_dump(mode="json") for item in rows),
    }
    return ImageIOSGISeedLayout(**data, layout_sha256=_digest(data))


def generate_sgi_relational_cases(
    seed: bytes,
    *,
    max_cases: int = 16,
) -> tuple[GeneratedImageIOSGICase, ...]:
    """Generate at most sixteen deterministic range-relation cases."""

    if not 1 <= max_cases <= 16:
        raise ValueError("SGI case budget must be between one and sixteen")
    layout = parse_sgi_rle_seed(seed)
    generated: list[GeneratedImageIOSGICase] = []
    seen = {layout.seed_sha256}

    def append(
        row: ImageIOSGIRowRange,
        relation: ImageIOSGIRelation,
        mutated_start: int,
        mutated_length: int,
        payload: bytes,
    ) -> None:
        if len(generated) >= max_cases:
            return
        input_sha256 = _sha256_bytes(payload)
        if input_sha256 in seen:
            return
        seen.add(input_sha256)
        data = {
            "schema_version": "imageio-sgi-mutation-v1",
            "format_family": ImageIOFormatFamily.SGI.value,
            "seed_sha256": layout.seed_sha256,
            "input_sha256": input_sha256,
            "original_file_size_bytes": len(seed),
            "input_size_bytes": len(payload),
            "table_index": row.table_index,
            "start_table_offset": row.start_table_offset,
            "length_table_offset": row.length_table_offset,
            "original_start": row.data_offset,
            "original_length": row.byte_length,
            "mutated_start": mutated_start,
            "mutated_length": mutated_length,
            "operator": relation.value,
            "asserted_relation": relation.value,
            "routes": tuple(route.value for route in _SGI_QUALIFICATION_ROUTES),
            "model_calls": 0,
        }
        generated.append(
            GeneratedImageIOSGICase(
                manifest=ImageIOSGIMutationCase(**data, case_id=_case_id(data)),
                payload=payload,
            )
        )

    for row in layout.rows:
        file_size = len(seed)
        start = file_size - 1
        length = 2
        append(
            row,
            ImageIOSGIRelation.INDIVIDUAL_IN_RANGE_COMBINED_OOB,
            start,
            length,
            _replace_row_range(seed, row, start=start, length=length),
        )
        start = layout.table_data_offset
        length = file_size - start
        append(
            row,
            ImageIOSGIRelation.EXACT_END_OF_FILE,
            start,
            length,
            _replace_row_range(seed, row, start=start, length=length),
        )
        length += 1
        append(
            row,
            ImageIOSGIRelation.ONE_BYTE_COMBINED_OVERRUN,
            start,
            length,
            _replace_row_range(seed, row, start=start, length=length),
        )
        truncated_size = row.data_end_offset - 1
        append(
            row,
            ImageIOSGIRelation.TRUNCATED_AVAILABLE_TAIL,
            row.data_offset,
            row.byte_length,
            seed[:truncated_size],
        )
        if row.byte_length > 1:
            append(
                row,
                ImageIOSGIRelation.PAIRED_BOUNDARY_MOVEMENT,
                row.data_offset + 1,
                row.byte_length - 1,
                _replace_row_range(
                    seed,
                    row,
                    start=row.data_offset + 1,
                    length=row.byte_length - 1,
                ),
            )
        if len(generated) >= max_cases:
            break
    return tuple(generated)


def qualify_sgi_seed(
    *,
    runner: ImageIOVMRunner,
    environment: ImageIOVMEnvironment,
    seed_path: Path,
    limits: ImageIOHarnessLimits | None = None,
) -> ImageIOSGISeedQualification:
    """Require SGI identification and pixel materialization on exactly two VM routes."""

    path = _validated_seed_path(seed_path)
    payload = path.read_bytes()
    layout = parse_sgi_rle_seed(payload)
    observations: list[ImageIOSGIQualificationObservation] = []
    for route in _SGI_QUALIFICATION_ROUTES:
        run = run_imageio_harness(
            runner=runner,
            environment=environment,
            route=route,
            input_path=path,
            limits=limits,
        )
        evidence = run.evidence
        if not evidence.evidence_complete or evidence.exit_reason is not ImageIOVMExitReason.EXITED:
            raise RuntimeError(f"SGI seed failed {route.value} VM qualification")
        try:
            raw = json.loads(run.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"SGI seed emitted invalid {route.value} JSON") from exc
        if not isinstance(raw, dict):
            raise RuntimeError(f"SGI seed emitted non-object {route.value} evidence")
        type_identifier = raw.get("type_identifier")
        decoded_bytes = raw.get("decoded_bytes")
        pixels_materialized = (
            raw.get("pixels_rendered") is True
            if route is ImageIOAPIRoute.FULL_DECODE
            else raw.get("raw_pixels_copied") is True
        )
        if (
            raw.get("source_created") is not True
            or not isinstance(type_identifier, str)
            or "sgi" not in type_identifier.casefold()
            or raw.get("image_created") is not True
            or not pixels_materialized
            or not isinstance(decoded_bytes, int)
            or isinstance(decoded_bytes, bool)
            or decoded_bytes <= 0
            or decoded_bytes > evidence.limits.max_decoded_bytes
        ):
            raise RuntimeError(
                f"SGI seed did not reach identified pixel materialization on {route.value}"
            )
        observation = {
            "schema_version": "imageio-sgi-qualification-observation-v1",
            "route": route.value,
            "type_identifier": type_identifier,
            "image_created": True,
            "pixels_materialized": True,
            "decoded_bytes": decoded_bytes,
            "harness_evidence_sha256": _model_digest(evidence),
        }
        observations.append(
            ImageIOSGIQualificationObservation(
                **observation,
                observation_sha256=_digest(observation),
            )
        )
    data = {
        "schema_version": "imageio-sgi-seed-qualification-v1",
        "seed_sha256": layout.seed_sha256,
        "layout_sha256": layout.layout_sha256,
        "environment_id": environment.environment_id,
        "product_version": environment.product_version,
        "build_version": environment.build_version,
        "vm_image_sha256": environment.image_sha256,
        "observations": tuple(item.model_dump(mode="json") for item in observations),
        "deep_seed": True,
        "model_calls": 0,
    }
    return ImageIOSGISeedQualification(
        **data,
        qualification_sha256=_digest(data),
    )


def _replace_row_range(
    seed: bytes,
    row: ImageIOSGIRowRange,
    *,
    start: int,
    length: int,
) -> bytes:
    payload = bytearray(seed)
    struct.pack_into(">I", payload, row.start_table_offset, start)
    struct.pack_into(">I", payload, row.length_table_offset, length)
    return bytes(payload)


def _require_relation(
    *,
    relation: ImageIOSGIRelation,
    original_file_size: int,
    input_size: int,
    original_start: int,
    original_length: int,
    mutated_start: int,
    mutated_length: int,
) -> None:
    combined = mutated_start + mutated_length
    if relation is ImageIOSGIRelation.INDIVIDUAL_IN_RANGE_COMBINED_OOB:
        valid = (
            input_size == original_file_size
            and mutated_start <= input_size
            and mutated_length <= input_size
            and combined > input_size
        )
    elif relation is ImageIOSGIRelation.EXACT_END_OF_FILE:
        valid = input_size == original_file_size and combined == input_size
    elif relation is ImageIOSGIRelation.ONE_BYTE_COMBINED_OVERRUN:
        valid = input_size == original_file_size and combined == input_size + 1
    elif relation is ImageIOSGIRelation.TRUNCATED_AVAILABLE_TAIL:
        valid = (
            mutated_start == original_start
            and mutated_length == original_length
            and input_size == original_start + original_length - 1
            and input_size < original_file_size
        )
    else:
        valid = (
            input_size == original_file_size
            and mutated_start == original_start + 1
            and mutated_length + 1 == original_length
            and combined == original_start + original_length
        )
    if not valid:
        raise ValueError(f"SGI mutation does not satisfy {relation.value}")


def _validated_seed_path(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError("SGI seed may not be a symbolic link")
    resolved = expanded.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("SGI seed must be a regular file")
    if resolved.stat().st_size > _MAX_SGI_SEED_BYTES:
        raise ValueError("SGI seed exceeds the maximum seed size")
    return resolved


def _case_id(payload: dict[str, Any]) -> str:
    return "sgi-case-" + hashlib.sha256(_canonical(payload)).hexdigest()[:32]


def _model_digest(model: ImageIOHarnessEvidence) -> str:
    return _digest(model.model_dump(mode="json"))


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _digest(payload: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
