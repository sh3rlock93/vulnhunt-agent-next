"""Deterministic, model-free ImageIO fuzzing vertical slice.

PR4 intentionally starts with one format family and behavioral feedback.  The
host parses and mutates bytes but never asks ImageIO to decode them; execution
is delegated to the already-attested VM runner from PR3.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
from collections import deque
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
    PrivateImageIOHarnessRun,
    run_imageio_harness,
)
from .imageio_inventory import ImageIOAPIRoute, ImageIOFormatFamily

_DICOM_PREAMBLE_SIZE = 128
_DICOM_MAGIC = b"DICM"
_LONG_VRS = frozenset({b"OB", b"OD", b"OF", b"OL", b"OV", b"OW", b"SQ", b"UC", b"UR", b"UT", b"UN"})
_SEMANTIC_US_TAGS = frozenset(
    {
        (0x0028, 0x0002),  # Samples per Pixel
        (0x0028, 0x0010),  # Rows
        (0x0028, 0x0011),  # Columns
        (0x0028, 0x0100),  # Bits Allocated
        (0x0028, 0x0101),  # Bits Stored
        (0x0028, 0x0102),  # High Bit
        (0x0028, 0x0103),  # Pixel Representation
    }
)
_PIXEL_DATA_TAG = (0x7FE0, 0x0010)
_PIXEL_LAYOUT_TAGS = frozenset(
    {
        *_SEMANTIC_US_TAGS,
        (0x0028, 0x0004),  # Photometric Interpretation
        (0x0028, 0x0006),  # Planar Configuration
        (0x0028, 0x0008),  # Number of Frames
        _PIXEL_DATA_TAG,
    }
)


class ImageIOMutationOperator(StrEnum):
    ELEMENT_LENGTH_DELTA = "element_length_delta"
    ELEMENT_LENGTH_BOUNDARY = "element_length_boundary"
    SEMANTIC_US_BOUNDARY = "semantic_us_boundary"
    VALUE_BIT_FLIP = "value_bit_flip"
    TRUNCATE_AT_ELEMENT = "truncate_at_element"
    PIXEL_LAYOUT_RELATION = "pixel_layout_relation"
    PIXEL_DATA_SIZE_RELATION = "pixel_data_size_relation"


class ImageIOFuzzClassification(StrEnum):
    NORMAL = "normal"
    PARSER_REJECTION = "parser_rejection"
    CRASH_CANDIDATE = "crash_candidate"
    TIMEOUT = "timeout"
    RESOURCE_LIMIT = "resource_limit"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"


class ImageIOFuzzBudget(DomainModel):
    max_cases: int = Field(default=64, ge=1, le=10_000)
    max_feedback_cases: int = Field(default=32, ge=0, le=10_000)
    max_generations: int = Field(default=2, ge=1, le=4)
    max_children_per_novel_input: int = Field(default=4, ge=1, le=64)
    max_executions: int = Field(default=256, ge=4, le=50_000)
    max_seed_bytes: int = Field(default=32 * 1024 * 1024, ge=132, le=128 * 1024 * 1024)


class ImageIOFuzzCase(DomainModel):
    schema_version: Literal["imageio-fuzz-case-v1"] = "imageio-fuzz-case-v1"
    case_id: str = Field(pattern=r"^case-[0-9a-f]{32}$")
    campaign_seed: str = Field(min_length=1, max_length=200)
    format_family: Literal[ImageIOFormatFamily.DICOM] = ImageIOFormatFamily.DICOM
    seed_sha256: str = Field(pattern=SHA256_PATTERN)
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    input_size_bytes: int = Field(ge=0)
    generation: int = Field(default=1, ge=1, le=4)
    parent_input_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    operator: ImageIOMutationOperator
    target_tag: str = Field(pattern=r"^[0-9A-F]{4},[0-9A-F]{4}$")
    target_offset: int = Field(ge=0)
    parameter: str = Field(min_length=1, max_length=120)
    related_tags: tuple[str, ...] = Field(default=(), max_length=8)
    routes: tuple[ImageIOAPIRoute, ...] = Field(min_length=1, max_length=5)

    @model_validator(mode="after")
    def validate_routes(self) -> "ImageIOFuzzCase":
        if len(set(self.routes)) != len(self.routes):
            raise ValueError("fuzz case routes must be unique")
        if ImageIOAPIRoute.TYPE_IDENTIFIERS in self.routes:
            raise ValueError("inventory-only route cannot execute a fuzz case")
        if len(set(self.related_tags)) != len(self.related_tags):
            raise ValueError("related DICOM tags must be unique")
        if self.target_tag in self.related_tags:
            raise ValueError("target DICOM tag must not be duplicated as a related tag")
        if any(not _is_dicom_tag(tag) for tag in self.related_tags):
            raise ValueError("related DICOM tag is invalid")
        if self.generation == 1 and self.parent_input_sha256 is not None:
            raise ValueError("first-generation case cannot have a parent input")
        if self.generation > 1 and self.parent_input_sha256 is None:
            raise ValueError("feedback-generated case requires a parent input")
        return self


class ImageIODecodeStage(StrEnum):
    UNRECOGNIZED = "unrecognized"
    SOURCE_CREATED = "source_created"
    TYPE_IDENTIFIED = "type_identified"
    IMAGE_INDEX_AVAILABLE = "image_index_available"
    IMAGE_PROPERTIES_AVAILABLE = "image_properties_available"
    IMAGE_CREATED = "image_created"
    PIXELS_RENDERED = "pixels_rendered"


class ImageIOBehaviorSignature(DomainModel):
    schema_version: Literal["imageio-behavior-v1"] = "imageio-behavior-v1"
    signature_sha256: str = Field(pattern=SHA256_PATTERN)
    source_created: bool | None = None
    type_identifier: str | None = None
    image_count: int | None = Field(default=None, ge=0)
    status: int | None = None
    image_created: bool | None = None
    thumbnail_created: bool | None = None
    pixels_rendered: bool | None = None
    width: int | None = Field(default=None, ge=0)
    height: int | None = Field(default=None, ge=0)
    update_count: int | None = Field(default=None, ge=0)
    incremental_statuses: tuple[int, ...] = Field(default=(), max_length=4096)
    properties_available: bool | None = None
    property_count: int | None = Field(default=None, ge=0)
    decoded_bytes: int | None = Field(default=None, ge=0)
    decode_skip_reason: str | None = Field(default=None, max_length=300)
    decode_stage: ImageIODecodeStage

    @model_validator(mode="before")
    @classmethod
    def infer_legacy_decode_stage(cls, value: Any) -> Any:
        if isinstance(value, dict) and "decode_stage" not in value:
            value = {**value, "decode_stage": _decode_stage(value)}
        return value


class ImageIOFuzzExecution(DomainModel):
    route: ImageIOAPIRoute
    classification: ImageIOFuzzClassification
    evidence: ImageIOHarnessEvidence
    behavior: ImageIOBehaviorSignature | None = None


class ImageIOSeedQualification(DomainModel):
    schema_version: Literal["imageio-seed-qualification-v1"] = "imageio-seed-qualification-v1"
    seed_sha256: str = Field(pattern=SHA256_PATTERN)
    executions: tuple[ImageIOFuzzExecution, ...] = Field(min_length=4, max_length=4)
    deepest_stage: ImageIODecodeStage
    pixel_decode_routes: tuple[ImageIOAPIRoute, ...] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def require_deep_seed(self) -> "ImageIOSeedQualification":
        expected_routes = {
            ImageIOAPIRoute.DATA_PROPERTIES,
            ImageIOAPIRoute.IMAGE_PROPERTIES,
            ImageIOAPIRoute.FULL_DECODE,
            ImageIOAPIRoute.INCREMENTAL_DECODE,
        }
        if {item.route for item in self.executions} != expected_routes:
            raise ValueError("seed qualification must exercise all four decode stages")
        if any(
            item.classification is not ImageIOFuzzClassification.NORMAL for item in self.executions
        ):
            raise ValueError("qualified seed routes must all exit normally")
        by_route = {item.route: item.behavior for item in self.executions}
        deep_routes: set[ImageIOAPIRoute] = set()
        for route in (
            ImageIOAPIRoute.FULL_DECODE,
            ImageIOAPIRoute.INCREMENTAL_DECODE,
        ):
            behavior = by_route[route]
            if behavior is not None and behavior.decode_stage is ImageIODecodeStage.PIXELS_RENDERED:
                deep_routes.add(route)
        if deep_routes != {
            ImageIOAPIRoute.FULL_DECODE,
            ImageIOAPIRoute.INCREMENTAL_DECODE,
        }:
            raise ValueError("qualified seed must render pixels on full and incremental routes")
        if set(self.pixel_decode_routes) != deep_routes:
            raise ValueError("qualified seed pixel routes do not match observed behavior")
        if self.deepest_stage is not ImageIODecodeStage.PIXELS_RENDERED:
            raise ValueError("qualified seed must reach the pixel-rendered stage")
        return self


class ImageIOFuzzCaseResult(DomainModel):
    schema_version: Literal["imageio-fuzz-result-v1"] = "imageio-fuzz-result-v1"
    case: ImageIOFuzzCase
    executions: tuple[ImageIOFuzzExecution, ...] = Field(min_length=1, max_length=5)
    interesting: bool
    novel_behavior: bool = False

    @model_validator(mode="after")
    def validate_interest(self) -> "ImageIOFuzzCaseResult":
        expected = any(
            execution.classification
            not in {
                ImageIOFuzzClassification.NORMAL,
                ImageIOFuzzClassification.PARSER_REJECTION,
            }
            for execution in self.executions
        )
        if self.interesting != expected:
            raise ValueError("interesting flag does not match execution classifications")
        return self


class ImageIOFuzzCampaignSummary(DomainModel):
    schema_version: Literal["imageio-fuzz-campaign-v1"] = "imageio-fuzz-campaign-v1"
    campaign_id: str = Field(pattern=r"^imageio-fuzz-[a-z0-9][a-z0-9-]{2,80}$")
    campaign_seed: str
    format_family: Literal[ImageIOFormatFamily.DICOM] = ImageIOFormatFamily.DICOM
    seed_sha256: str = Field(pattern=SHA256_PATTERN)
    seed_qualification: ImageIOSeedQualification | None = None
    generated_cases: int = Field(ge=0)
    executed_cases: int = Field(ge=0)
    execution_count: int = Field(ge=0)
    classification_counts: dict[ImageIOFuzzClassification, int]
    behavior_signature_count: int = Field(ge=0)
    interesting_case_ids: tuple[str, ...]
    novel_behavior_case_ids: tuple[str, ...] = ()
    corpus_input_sha256s: tuple[str, ...] = ()
    generation_counts: dict[int, int] = Field(default_factory=dict)
    max_generation_reached: int = Field(default=1, ge=1, le=4)
    duplicate_payloads_skipped: int = Field(default=0, ge=0)
    route_execution_counts: dict[ImageIOAPIRoute, int] = Field(default_factory=dict)
    model_calls: Literal[0] = 0


class ImageIOPayloadHistoryRecord(DomainModel):
    schema_version: Literal["imageio-payload-history-v1"] = "imageio-payload-history-v1"
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    campaign_id: str = Field(pattern=r"^imageio-fuzz-[a-z0-9][a-z0-9-]{2,80}$")
    case_id: str = Field(pattern=r"^case-[0-9a-f]{32}$")
    generation: int = Field(ge=1, le=4)


@dataclass(frozen=True)
class GeneratedImageIOFuzzCase:
    manifest: ImageIOFuzzCase
    payload: bytes


@dataclass(frozen=True)
class _DICOMElement:
    group: int
    element: int
    vr: bytes
    header_offset: int
    length_offset: int
    length_size: int
    value_offset: int
    value_length: int

    @property
    def tag(self) -> str:
        return f"{self.group:04X},{self.element:04X}"


class PrivateImageIOFuzzStore:
    """Private content-addressed storage; never writes inside a Git worktree."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        if _is_inside_git_worktree(self.root):
            raise ValueError("ImageIO fuzz artifacts may not be stored in a Git worktree")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)

    def write_seed(self, payload: bytes, *, seed_sha256: str) -> None:
        target = self.root / "seeds" / seed_sha256.removeprefix("sha256:")
        if target.exists():
            return
        target.mkdir(parents=True, mode=0o700)
        _write_private(target / "input.dcm", payload)

    def write_case(
        self,
        generated: GeneratedImageIOFuzzCase,
        runs: tuple[PrivateImageIOHarnessRun, ...],
        result: ImageIOFuzzCaseResult,
    ) -> None:
        cases = self.root / "cases"
        cases.mkdir(mode=0o700, exist_ok=True)
        _write_private_json(cases / f"{generated.manifest.case_id}.json", result)
        if not result.interesting:
            return
        finding = self.root / "interesting" / generated.manifest.case_id
        finding.mkdir(parents=True, mode=0o700)
        _write_private(finding / "input.dcm", generated.payload)
        for execution, run in zip(result.executions, runs, strict=True):
            route_directory = finding / execution.route.value
            route_directory.mkdir(mode=0o700)
            _write_private_json(route_directory / "evidence.json", run.evidence)
            _write_private(route_directory / "stdout.bin", run.stdout)
            _write_private(route_directory / "stderr.bin", run.stderr)
            if run.crash_log is not None:
                _write_private(route_directory / "crash.log", run.crash_log)

    def write_corpus_input(
        self,
        generated: GeneratedImageIOFuzzCase,
        result: ImageIOFuzzCaseResult,
    ) -> None:
        digest = generated.manifest.input_sha256.removeprefix("sha256:")
        target = self.root / "corpus" / digest
        if target.exists():
            return
        target.mkdir(parents=True, mode=0o700)
        _write_private(target / "input.dcm", generated.payload)
        _write_private_json(target / "source-case.json", result)

    def write_summary(self, summary: ImageIOFuzzCampaignSummary) -> None:
        _write_private_json(self.root / "campaign-summary.json", summary, replace=True)

    def write_benchmark_assessment(self, assessment: DomainModel) -> None:
        _write_private_json(
            self.root / "benchmark-assessment.json",
            assessment,
            replace=True,
        )


class PrivateImageIOPayloadHistory:
    """Shared private hash ledger used to skip payloads already executed elsewhere."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        if _is_inside_git_worktree(self.root):
            raise ValueError("ImageIO payload history may not be stored in a Git worktree")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)

    def claim(self, generated: GeneratedImageIOFuzzCase, *, campaign_id: str) -> bool:
        digest = generated.manifest.input_sha256.removeprefix("sha256:")
        records = self.root / "executed"
        records.mkdir(mode=0o700, exist_ok=True)
        target = records / digest
        try:
            target.mkdir(mode=0o700)
        except FileExistsError:
            return False
        record = ImageIOPayloadHistoryRecord(
            input_sha256=generated.manifest.input_sha256,
            campaign_id=campaign_id,
            case_id=generated.manifest.case_id,
            generation=generated.manifest.generation,
        )
        _write_private_json(target / "claim.json", record)
        return True


def build_minimal_dicom_seed() -> bytes:
    """Create a deterministic one-pixel Explicit VR Little Endian DICOM seed."""

    sop_class = "1.2.840.10008.5.1.4.1.1.7"
    sop_instance = "1.2.826.0.1.3680043.10.543.1"
    meta_body = b"".join(
        (
            _encode_element(0x0002, 0x0001, b"OB", b"\x00\x01"),
            _encode_element(0x0002, 0x0002, b"UI", _text_value(sop_class, b"\x00")),
            _encode_element(0x0002, 0x0003, b"UI", _text_value(sop_instance, b"\x00")),
            _encode_element(
                0x0002,
                0x0010,
                b"UI",
                _text_value("1.2.840.10008.1.2.1", b"\x00"),
            ),
            _encode_element(
                0x0002,
                0x0012,
                b"UI",
                _text_value("1.2.826.0.1.3680043.10.543", b"\x00"),
            ),
        )
    )
    meta = _encode_element(0x0002, 0x0000, b"UL", struct.pack("<I", len(meta_body)))
    dataset = b"".join(
        (
            _encode_element(0x0008, 0x0016, b"UI", _text_value(sop_class, b"\x00")),
            _encode_element(0x0008, 0x0018, b"UI", _text_value(sop_instance, b"\x00")),
            _encode_element(0x0008, 0x0060, b"CS", _text_value("OT", b" ")),
            _encode_element(0x0028, 0x0002, b"US", struct.pack("<H", 1)),
            _encode_element(0x0028, 0x0004, b"CS", _text_value("MONOCHROME2", b" ")),
            _encode_element(0x0028, 0x0010, b"US", struct.pack("<H", 1)),
            _encode_element(0x0028, 0x0011, b"US", struct.pack("<H", 1)),
            _encode_element(0x0028, 0x0100, b"US", struct.pack("<H", 8)),
            _encode_element(0x0028, 0x0101, b"US", struct.pack("<H", 8)),
            _encode_element(0x0028, 0x0102, b"US", struct.pack("<H", 7)),
            _encode_element(0x0028, 0x0103, b"US", struct.pack("<H", 0)),
            _encode_element(0x7FE0, 0x0010, b"OB", b"\x00\x00"),
        )
    )
    return b"\x00" * _DICOM_PREAMBLE_SIZE + _DICOM_MAGIC + meta + meta_body + dataset


def generate_dicom_fuzz_cases(
    seed: bytes,
    *,
    campaign_seed: str,
    max_cases: int = 64,
    generation: int = 1,
    root_seed_sha256: str | None = None,
    parent_input_sha256: str | None = None,
) -> tuple[GeneratedImageIOFuzzCase, ...]:
    """Generate a stable, de-duplicated initial DICOM mutation corpus."""

    if max_cases < 1:
        raise ValueError("max_cases must be positive")
    if not 1 <= generation <= 4:
        raise ValueError("generation must be between one and four")
    if generation == 1 and parent_input_sha256 is not None:
        raise ValueError("first-generation corpus cannot have a parent")
    if generation > 1 and parent_input_sha256 is None:
        raise ValueError("feedback generation requires a parent input")
    elements = _parse_explicit_vr_little_endian(seed)
    source_sha256 = _sha256_bytes(seed)
    seed_sha256 = root_seed_sha256 or source_sha256
    generated: list[GeneratedImageIOFuzzCase] = []
    seen_payloads = {source_sha256}

    def append_case(
        *,
        element: _DICOMElement,
        operator: ImageIOMutationOperator,
        parameter: str,
        payload: bytes,
        related_tags: tuple[str, ...] = (),
    ) -> None:
        if len(generated) >= max_cases:
            return
        input_sha256 = _sha256_bytes(payload)
        if input_sha256 in seen_payloads:
            return
        seen_payloads.add(input_sha256)
        identity = "\x00".join(
            (
                seed_sha256,
                source_sha256,
                campaign_seed,
                str(generation),
                operator.value,
                element.tag,
                str(element.header_offset),
                parameter,
                *related_tags,
            )
        ).encode()
        case_id = "case-" + hashlib.sha256(identity).hexdigest()[:32]
        generated.append(
            GeneratedImageIOFuzzCase(
                manifest=ImageIOFuzzCase(
                    case_id=case_id,
                    campaign_seed=campaign_seed,
                    seed_sha256=seed_sha256,
                    input_sha256=input_sha256,
                    input_size_bytes=len(payload),
                    generation=generation,
                    parent_input_sha256=parent_input_sha256,
                    operator=operator,
                    target_tag=element.tag,
                    target_offset=element.header_offset,
                    parameter=parameter,
                    related_tags=related_tags,
                    routes=_routes_for(operator, element),
                ),
                payload=payload,
            )
        )

    def append_operator_cases(
        element: _DICOMElement,
        operator: ImageIOMutationOperator,
    ) -> None:
        maximum = (1 << (element.length_size * 8)) - 1
        if operator is ImageIOMutationOperator.SEMANTIC_US_BOUNDARY:
            if not (
                (element.group, element.element) in _SEMANTIC_US_TAGS
                and element.vr == b"US"
                and element.value_length >= 2
            ):
                return
            for value in (0, 1, 0x7FFF, 0xFFFF):
                payload = bytearray(seed)
                payload[element.value_offset : element.value_offset + 2] = struct.pack(
                    "<H", value
                )
                append_case(
                    element=element,
                    operator=operator,
                    parameter=f"value:{value}",
                    payload=bytes(payload),
                )
            return
        if operator is ImageIOMutationOperator.ELEMENT_LENGTH_DELTA:
            mutations = (
                ("delta:+1", min(maximum, element.value_length + 1)),
                ("delta:-1", max(0, element.value_length - 1)),
            )
            for parameter, mutated_length in mutations:
                payload = bytearray(seed)
                payload[element.length_offset : element.length_offset + element.length_size] = (
                    mutated_length.to_bytes(element.length_size, "little")
                )
                append_case(
                    element=element,
                    operator=operator,
                    parameter=parameter,
                    payload=bytes(payload),
                )
            return
        if operator is ImageIOMutationOperator.TRUNCATE_AT_ELEMENT:
            if element.value_length > 0:
                append_case(
                    element=element,
                    operator=operator,
                    parameter="before-value-end",
                    payload=seed[
                        : max(element.value_offset, element.value_offset + element.value_length - 1)
                    ],
                )
            return
        if operator is ImageIOMutationOperator.ELEMENT_LENGTH_BOUNDARY:
            for parameter, mutated_length in (
                ("boundary:0", 0),
                (f"boundary:{maximum}", maximum),
            ):
                payload = bytearray(seed)
                payload[element.length_offset : element.length_offset + element.length_size] = (
                    mutated_length.to_bytes(element.length_size, "little")
                )
                append_case(
                    element=element,
                    operator=operator,
                    parameter=parameter,
                    payload=bytes(payload),
                )
            return
        if operator is ImageIOMutationOperator.VALUE_BIT_FLIP and element.value_length > 0:
            relative = _deterministic_index(campaign_seed, element.tag, element.value_length)
            payload = bytearray(seed)
            payload[element.value_offset + relative] ^= 0x80
            append_case(
                element=element,
                operator=operator,
                parameter=f"relative:{relative}:mask:0x80",
                payload=bytes(payload),
            )

    for target_tier in range(4):
        tier_elements = tuple(
            sorted(
                (element for element in elements if _target_tier(element) == target_tier),
                key=lambda element: (element.tag, element.header_offset),
            )
        )
        if target_tier == 0:
            _append_pixel_data_size_relation_cases(
                seed=seed,
                elements=elements,
                append_case=append_case,
            )
        if target_tier == 1:
            _append_pixel_layout_relation_cases(
                seed=seed,
                elements=elements,
                append_case=append_case,
            )
        for operator in (
            ImageIOMutationOperator.SEMANTIC_US_BOUNDARY,
            ImageIOMutationOperator.ELEMENT_LENGTH_DELTA,
            ImageIOMutationOperator.TRUNCATE_AT_ELEMENT,
            ImageIOMutationOperator.ELEMENT_LENGTH_BOUNDARY,
            ImageIOMutationOperator.VALUE_BIT_FLIP,
        ):
            for element in tier_elements:
                append_operator_cases(element, operator)
    return tuple(generated)


def _append_pixel_data_size_relation_cases(
    *,
    seed: bytes,
    elements: tuple[_DICOMElement, ...],
    append_case: Any,
) -> None:
    by_tag = {(item.group, item.element): item for item in elements}
    pixel_data = by_tag.get(_PIXEL_DATA_TAG)
    if pixel_data is None or pixel_data.value_length < 2:
        return
    maximum = (1 << (pixel_data.length_size * 8)) - 1
    original_length = pixel_data.value_length
    candidate_lengths = {
        0,
        2,
        max(0, (original_length // 2) & ~1),
        max(0, original_length - 2),
        min(maximum, original_length + 2),
        min(maximum, original_length * 2),
    }
    related_tags = tuple(
        sorted(
            by_tag[tag].tag
            for tag in (
                (0x0028, 0x0002),
                (0x0028, 0x0010),
                (0x0028, 0x0011),
                (0x0028, 0x0100),
                (0x0028, 0x0103),
            )
            if tag in by_tag
        )
    )
    original_value = seed[
        pixel_data.value_offset : pixel_data.value_offset + original_length
    ]
    suffix = seed[pixel_data.value_offset + original_length :]
    for new_length in sorted(candidate_lengths):
        if new_length == original_length:
            continue
        if new_length <= original_length:
            new_value = original_value[:new_length]
        else:
            new_value = original_value + b"\x00" * (new_length - original_length)
        payload = bytearray(seed[: pixel_data.value_offset] + new_value + suffix)
        payload[
            pixel_data.length_offset : pixel_data.length_offset + pixel_data.length_size
        ] = new_length.to_bytes(pixel_data.length_size, "little")
        append_case(
            element=pixel_data,
            operator=ImageIOMutationOperator.PIXEL_DATA_SIZE_RELATION,
            parameter=f"pixel-bytes:{new_length}:geometry=unchanged",
            payload=bytes(payload),
            related_tags=related_tags,
        )


def _append_pixel_layout_relation_cases(
    *,
    seed: bytes,
    elements: tuple[_DICOMElement, ...],
    append_case: Any,
) -> None:
    by_tag = {(item.group, item.element): item for item in elements}
    required = {
        (0x0028, 0x0002),
        (0x0028, 0x0010),
        (0x0028, 0x0011),
        (0x0028, 0x0100),
        (0x0028, 0x0101),
        (0x0028, 0x0102),
        _PIXEL_DATA_TAG,
    }
    if not required <= set(by_tag):
        return

    def relation_case(
        *,
        name: str,
        anchor_tag: tuple[int, int],
        updates: tuple[tuple[tuple[int, int], int], ...],
    ) -> None:
        payload = bytearray(seed)
        changed: list[_DICOMElement] = []
        for tag, value in updates:
            element = by_tag[tag]
            if element.vr != b"US" or element.value_length < 2:
                return
            payload[element.value_offset : element.value_offset + 2] = struct.pack(
                "<H", value
            )
            changed.append(element)
        anchor = by_tag[anchor_tag]
        related = tuple(
            sorted(
                {
                    item.tag
                    for item in changed
                    if item.tag != anchor.tag
                }
                | {by_tag[_PIXEL_DATA_TAG].tag}
            )
        )
        append_case(
            element=anchor,
            operator=ImageIOMutationOperator.PIXEL_LAYOUT_RELATION,
            parameter=name,
            payload=bytes(payload),
            related_tags=related,
        )

    relation_case(
        name="geometry:rows=2:columns=2:pixel=unchanged",
        anchor_tag=(0x0028, 0x0010),
        updates=(
            ((0x0028, 0x0010), 2),
            ((0x0028, 0x0011), 2),
        ),
    )
    relation_case(
        name="geometry:rows=32767:columns=32767:pixel=unchanged",
        anchor_tag=(0x0028, 0x0010),
        updates=(
            ((0x0028, 0x0010), 0x7FFF),
            ((0x0028, 0x0011), 0x7FFF),
        ),
    )
    relation_case(
        name="layout:samples=4:rows=2:columns=2:pixel=unchanged",
        anchor_tag=(0x0028, 0x0002),
        updates=(
            ((0x0028, 0x0002), 4),
            ((0x0028, 0x0010), 2),
            ((0x0028, 0x0011), 2),
        ),
    )
    relation_case(
        name="bit-depth:allocated=16:stored=16:high=15:geometry=2x2",
        anchor_tag=(0x0028, 0x0100),
        updates=(
            ((0x0028, 0x0010), 2),
            ((0x0028, 0x0011), 2),
            ((0x0028, 0x0100), 16),
            ((0x0028, 0x0101), 16),
            ((0x0028, 0x0102), 15),
        ),
    )
    relation_case(
        name="bit-depth:allocated=8:stored=16:high=15",
        anchor_tag=(0x0028, 0x0101),
        updates=(
            ((0x0028, 0x0100), 8),
            ((0x0028, 0x0101), 16),
            ((0x0028, 0x0102), 15),
        ),
    )


def _target_tier(element: _DICOMElement) -> int:
    tag = (element.group, element.element)
    if tag == _PIXEL_DATA_TAG:
        return 0
    if tag in _PIXEL_LAYOUT_TAGS:
        return 1
    if element.group != 0x0002:
        return 2
    return 3


def run_imageio_fuzz_campaign(
    *,
    runner: ImageIOVMRunner,
    environment: ImageIOVMEnvironment,
    seed_path: Path,
    store: PrivateImageIOFuzzStore,
    campaign_id: str,
    campaign_seed: str,
    budget: ImageIOFuzzBudget | None = None,
    limits: ImageIOHarnessLimits | None = None,
    history: PrivateImageIOPayloadHistory | None = None,
) -> ImageIOFuzzCampaignSummary:
    """Run one bounded corpus inside the caller's already-active VM clone."""

    active_budget = budget or ImageIOFuzzBudget()
    source = _read_seed(seed_path, maximum=active_budget.max_seed_bytes)
    seed_sha256 = _sha256_bytes(source)
    _parse_explicit_vr_little_endian(source)
    store.write_seed(source, seed_sha256=seed_sha256)
    initial_cases = generate_dicom_fuzz_cases(
        source,
        campaign_seed=campaign_seed,
        max_cases=active_budget.max_cases,
    )
    qualification = _qualify_seed(
        runner=runner,
        environment=environment,
        payload=source,
        seed_sha256=seed_sha256,
        store_root=store.root,
        limits=limits,
    )

    counts = {classification: 0 for classification in ImageIOFuzzClassification}
    signatures: set[str] = set()
    behavior_keys: set[tuple[ImageIOAPIRoute, str]] = set()
    route_execution_counts: dict[ImageIOAPIRoute, int] = {}
    for execution in qualification.executions:
        counts[execution.classification] += 1
        route_execution_counts[execution.route] = (
            route_execution_counts.get(execution.route, 0) + 1
        )
        if execution.behavior is not None:
            signatures.add(execution.behavior.signature_sha256)
            behavior_keys.add((execution.route, execution.behavior.signature_sha256))
    interesting: list[str] = []
    novel_behavior_cases: list[str] = []
    corpus_inputs: list[str] = []
    execution_count = len(qualification.executions)
    executed_cases = 0
    pending = deque(initial_cases)
    generated_cases = len(initial_cases)
    feedback_cases_remaining = (
        active_budget.max_feedback_cases if active_budget.max_generations > 1 else 0
    )
    known_payloads = {seed_sha256, *(case.manifest.input_sha256 for case in initial_cases)}
    generation_counts = {1: len(initial_cases)}
    max_generation_reached = 1
    duplicate_payloads_skipped = 0
    while pending:
        if execution_count >= active_budget.max_executions:
            break
        case = pending.popleft()
        if history is not None and not history.claim(case, campaign_id=campaign_id):
            duplicate_payloads_skipped += 1
            continue
        case_runs: list[PrivateImageIOHarnessRun] = []
        executions: list[ImageIOFuzzExecution] = []
        novel_behavior = False
        novel_deep_behavior = False
        for route in case.manifest.routes:
            if execution_count >= active_budget.max_executions:
                break
            run = _run_payload(
                runner=runner,
                environment=environment,
                payload=case.payload,
                route=route,
                store_root=store.root,
                limits=limits,
            )
            behavior = _behavior_from_run(run)
            classification = _classify(run, behavior)
            counts[classification] += 1
            route_execution_counts[route] = route_execution_counts.get(route, 0) + 1
            if behavior is not None:
                signatures.add(behavior.signature_sha256)
                behavior_key = (route, behavior.signature_sha256)
                if behavior_key not in behavior_keys:
                    novel_behavior = True
                    if (
                        classification is ImageIOFuzzClassification.NORMAL
                        and behavior.decode_stage is ImageIODecodeStage.PIXELS_RENDERED
                    ):
                        novel_deep_behavior = True
                    behavior_keys.add(behavior_key)
            case_runs.append(run)
            executions.append(
                ImageIOFuzzExecution(
                    route=route,
                    classification=classification,
                    evidence=run.evidence,
                    behavior=behavior,
                )
            )
            execution_count += 1
        if not executions:
            break
        result = ImageIOFuzzCaseResult(
            case=case.manifest,
            executions=tuple(executions),
            interesting=any(
                execution.classification
                not in {
                    ImageIOFuzzClassification.NORMAL,
                    ImageIOFuzzClassification.PARSER_REJECTION,
                }
                for execution in executions
            ),
            novel_behavior=novel_behavior,
        )
        store.write_case(case, tuple(case_runs), result)
        if result.interesting:
            interesting.append(case.manifest.case_id)
        if result.novel_behavior:
            novel_behavior_cases.append(case.manifest.case_id)
        if (
            novel_deep_behavior
            and feedback_cases_remaining > 0
            and case.manifest.generation < active_budget.max_generations
            and _is_structurally_mutable_dicom(case.payload)
        ):
            store.write_corpus_input(case, result)
            corpus_inputs.append(case.manifest.input_sha256)
            child_limit = min(
                active_budget.max_children_per_novel_input,
                feedback_cases_remaining,
            )
            children = generate_dicom_fuzz_cases(
                case.payload,
                campaign_seed=campaign_seed,
                max_cases=child_limit,
                generation=case.manifest.generation + 1,
                root_seed_sha256=seed_sha256,
                parent_input_sha256=case.manifest.input_sha256,
            )
            admitted_children = [
                child
                for child in children
                if child.manifest.input_sha256 not in known_payloads
            ][:feedback_cases_remaining]
            for child in admitted_children:
                known_payloads.add(child.manifest.input_sha256)
                pending.append(child)
                child_generation = child.manifest.generation
                generation_counts[child_generation] = (
                    generation_counts.get(child_generation, 0) + 1
                )
                max_generation_reached = max(max_generation_reached, child_generation)
            generated_cases += len(admitted_children)
            feedback_cases_remaining -= len(admitted_children)
        executed_cases += 1
    summary = ImageIOFuzzCampaignSummary(
        campaign_id=campaign_id,
        campaign_seed=campaign_seed,
        seed_sha256=seed_sha256,
        seed_qualification=qualification,
        generated_cases=generated_cases,
        executed_cases=executed_cases,
        execution_count=execution_count,
        classification_counts=counts,
        behavior_signature_count=len(signatures),
        interesting_case_ids=tuple(interesting),
        novel_behavior_case_ids=tuple(novel_behavior_cases),
        corpus_input_sha256s=tuple(corpus_inputs),
        generation_counts=generation_counts,
        max_generation_reached=max_generation_reached,
        duplicate_payloads_skipped=duplicate_payloads_skipped,
        route_execution_counts=route_execution_counts,
    )
    store.write_summary(summary)
    return summary


def _parse_explicit_vr_little_endian(payload: bytes) -> tuple[_DICOMElement, ...]:
    if len(payload) < _DICOM_PREAMBLE_SIZE + len(_DICOM_MAGIC):
        raise ValueError("DICOM seed is smaller than its preamble")
    if payload[_DICOM_PREAMBLE_SIZE : _DICOM_PREAMBLE_SIZE + 4] != _DICOM_MAGIC:
        raise ValueError("DICOM seed does not contain the DICM marker")
    elements: list[_DICOMElement] = []
    offset = _DICOM_PREAMBLE_SIZE + 4
    while offset < len(payload):
        if len(payload) - offset < 8:
            raise ValueError("DICOM seed ends inside an element header")
        group, element = struct.unpack_from("<HH", payload, offset)
        vr = payload[offset + 4 : offset + 6]
        if not all(65 <= byte <= 90 for byte in vr):
            raise ValueError("PR4 requires Explicit VR Little Endian seeds")
        if vr in _LONG_VRS:
            if len(payload) - offset < 12:
                raise ValueError("DICOM seed ends inside a long-VR header")
            length_offset = offset + 8
            length_size = 4
            value_offset = offset + 12
        else:
            length_offset = offset + 6
            length_size = 2
            value_offset = offset + 8
        value_length = int.from_bytes(
            payload[length_offset : length_offset + length_size],
            "little",
        )
        if value_length == 0xFFFFFFFF:
            raise ValueError("undefined-length DICOM seeds are deferred beyond the PR4 slice")
        value_end = value_offset + value_length
        if value_end > len(payload):
            raise ValueError("DICOM seed element length exceeds the file")
        elements.append(
            _DICOMElement(
                group=group,
                element=element,
                vr=vr,
                header_offset=offset,
                length_offset=length_offset,
                length_size=length_size,
                value_offset=value_offset,
                value_length=value_length,
            )
        )
        offset = value_end
    if not elements:
        raise ValueError("DICOM seed contains no elements")
    return tuple(elements)


def _encode_element(group: int, element: int, vr: bytes, value: bytes) -> bytes:
    tag = struct.pack("<HH", group, element)
    if vr in _LONG_VRS:
        return tag + vr + b"\x00\x00" + struct.pack("<I", len(value)) + value
    return tag + vr + struct.pack("<H", len(value)) + value


def _text_value(value: str, padding: bytes) -> bytes:
    encoded = value.encode("ascii")
    return encoded if len(encoded) % 2 == 0 else encoded + padding


def _routes_for(
    operator: ImageIOMutationOperator,
    element: _DICOMElement,
) -> tuple[ImageIOAPIRoute, ...]:
    tag = (element.group, element.element)
    if operator is ImageIOMutationOperator.PIXEL_DATA_SIZE_RELATION:
        return (ImageIOAPIRoute.FULL_DECODE, ImageIOAPIRoute.INCREMENTAL_DECODE)
    if operator is ImageIOMutationOperator.PIXEL_LAYOUT_RELATION:
        return (
            ImageIOAPIRoute.IMAGE_PROPERTIES,
            ImageIOAPIRoute.FULL_DECODE,
            ImageIOAPIRoute.INCREMENTAL_DECODE,
        )
    if operator is ImageIOMutationOperator.SEMANTIC_US_BOUNDARY:
        return (
            ImageIOAPIRoute.IMAGE_PROPERTIES,
            ImageIOAPIRoute.FULL_DECODE,
            ImageIOAPIRoute.INCREMENTAL_DECODE,
        )
    if operator is ImageIOMutationOperator.VALUE_BIT_FLIP:
        if tag in _PIXEL_LAYOUT_TAGS:
            return (ImageIOAPIRoute.FULL_DECODE, ImageIOAPIRoute.INCREMENTAL_DECODE)
        return (ImageIOAPIRoute.DATA_PROPERTIES,)
    if tag == _PIXEL_DATA_TAG:
        return (ImageIOAPIRoute.FULL_DECODE, ImageIOAPIRoute.INCREMENTAL_DECODE)
    if tag in _PIXEL_LAYOUT_TAGS:
        return (
            ImageIOAPIRoute.IMAGE_PROPERTIES,
            ImageIOAPIRoute.FULL_DECODE,
            ImageIOAPIRoute.INCREMENTAL_DECODE,
        )
    if element.group == 0x0002:
        return (ImageIOAPIRoute.DATA_PROPERTIES,)
    return (
        ImageIOAPIRoute.DATA_PROPERTIES,
        ImageIOAPIRoute.FULL_DECODE,
    )


def _run_payload(
    *,
    runner: ImageIOVMRunner,
    environment: ImageIOVMEnvironment,
    payload: bytes,
    route: ImageIOAPIRoute,
    store_root: Path,
    limits: ImageIOHarnessLimits | None,
) -> PrivateImageIOHarnessRun:
    work = store_root / ".work"
    work.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="case-", dir=work) as directory:
        input_path = Path(directory) / "input.dcm"
        _write_private(input_path, payload)
        return run_imageio_harness(
            runner=runner,
            environment=environment,
            route=route,
            input_path=input_path,
            limits=limits,
        )


def _behavior_from_run(run: PrivateImageIOHarnessRun) -> ImageIOBehaviorSignature | None:
    if run.evidence.exit_reason not in {
        ImageIOVMExitReason.EXITED,
        ImageIOVMExitReason.NONZERO_EXIT,
    }:
        return None
    try:
        raw = json.loads(run.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    selected: dict[str, Any] = {}
    fields = {
        "source_created": bool,
        "type_identifier": str,
        "image_count": int,
        "status": int,
        "image_created": bool,
        "thumbnail_created": bool,
        "pixels_rendered": bool,
        "width": int,
        "height": int,
        "update_count": int,
        "properties_available": bool,
        "property_count": int,
        "decoded_bytes": int,
        "decode_skip_reason": str,
    }
    for name, expected_type in fields.items():
        value = raw.get(name)
        if isinstance(value, expected_type):
            selected[name] = value
    statuses = raw.get("statuses")
    if isinstance(statuses, list) and all(isinstance(item, int) for item in statuses):
        selected["incremental_statuses"] = tuple(statuses[:4096])
    selected["decode_stage"] = _decode_stage(selected)
    canonical = json.dumps(selected, sort_keys=True, separators=(",", ":")).encode()
    return ImageIOBehaviorSignature(
        signature_sha256=_sha256_bytes(canonical),
        **selected,
    )


def _classify(
    run: PrivateImageIOHarnessRun,
    behavior: ImageIOBehaviorSignature | None,
) -> ImageIOFuzzClassification:
    reason = run.evidence.exit_reason
    if reason is ImageIOVMExitReason.SIGNALED:
        return ImageIOFuzzClassification.CRASH_CANDIDATE
    if reason is ImageIOVMExitReason.TIMEOUT:
        return ImageIOFuzzClassification.TIMEOUT
    if reason is ImageIOVMExitReason.RESOURCE_LIMIT:
        return ImageIOFuzzClassification.RESOURCE_LIMIT
    if reason is ImageIOVMExitReason.LAUNCH_ERROR:
        return ImageIOFuzzClassification.INFRASTRUCTURE_FAILURE
    if reason is ImageIOVMExitReason.NONZERO_EXIT:
        return ImageIOFuzzClassification.PARSER_REJECTION
    if behavior is not None and behavior.source_created is False:
        return ImageIOFuzzClassification.PARSER_REJECTION
    if behavior is not None:
        route = run.evidence.route
        minimum = {
            ImageIOAPIRoute.IMAGE_PROPERTIES: ImageIODecodeStage.IMAGE_INDEX_AVAILABLE,
            ImageIOAPIRoute.THUMBNAIL_DECODE: ImageIODecodeStage.IMAGE_CREATED,
            ImageIOAPIRoute.FULL_DECODE: ImageIODecodeStage.IMAGE_CREATED,
            ImageIOAPIRoute.INCREMENTAL_DECODE: ImageIODecodeStage.IMAGE_CREATED,
        }.get(route)
        if minimum is not None and _stage_rank(behavior.decode_stage) < _stage_rank(minimum):
            return ImageIOFuzzClassification.PARSER_REJECTION
    return ImageIOFuzzClassification.NORMAL


def _qualify_seed(
    *,
    runner: ImageIOVMRunner,
    environment: ImageIOVMEnvironment,
    payload: bytes,
    seed_sha256: str,
    store_root: Path,
    limits: ImageIOHarnessLimits | None,
) -> ImageIOSeedQualification:
    executions: list[ImageIOFuzzExecution] = []
    for route in (
        ImageIOAPIRoute.DATA_PROPERTIES,
        ImageIOAPIRoute.IMAGE_PROPERTIES,
        ImageIOAPIRoute.FULL_DECODE,
        ImageIOAPIRoute.INCREMENTAL_DECODE,
    ):
        run = _run_payload(
            runner=runner,
            environment=environment,
            payload=payload,
            route=route,
            store_root=store_root,
            limits=limits,
        )
        behavior = _behavior_from_run(run)
        classification = _classify(run, behavior)
        if classification is not ImageIOFuzzClassification.NORMAL:
            raise RuntimeError(
                f"DICOM seed failed {route.value} qualification: {classification.value}"
            )
        if behavior is None or behavior.type_identifier is None:
            raise RuntimeError(f"DICOM seed omitted {route.value} behavior evidence")
        if "dicom" not in behavior.type_identifier.casefold():
            raise RuntimeError(
                "DICOM seed was recognized as a different image family: "
                f"{behavior.type_identifier}"
            )
        executions.append(
            ImageIOFuzzExecution(
                route=route,
                classification=classification,
                evidence=run.evidence,
                behavior=behavior,
            )
        )
    deepest = max(
        (item.behavior.decode_stage for item in executions if item.behavior is not None),
        key=_stage_rank,
    )
    try:
        return ImageIOSeedQualification(
            seed_sha256=seed_sha256,
            executions=tuple(executions),
            deepest_stage=deepest,
            pixel_decode_routes=(
                ImageIOAPIRoute.FULL_DECODE,
                ImageIOAPIRoute.INCREMENTAL_DECODE,
            ),
        )
    except ValueError as exc:
        raise RuntimeError(
            "DICOM seed did not render pixels on full and incremental routes"
        ) from exc


def _decode_stage(fields: dict[str, Any]) -> ImageIODecodeStage:
    if fields.get("source_created") is not True:
        return ImageIODecodeStage.UNRECOGNIZED
    stage = ImageIODecodeStage.SOURCE_CREATED
    if fields.get("type_identifier"):
        stage = ImageIODecodeStage.TYPE_IDENTIFIED
    if int(fields.get("image_count") or 0) > 0:
        stage = ImageIODecodeStage.IMAGE_INDEX_AVAILABLE
        if fields.get("properties_available") is True:
            stage = ImageIODecodeStage.IMAGE_PROPERTIES_AVAILABLE
    if fields.get("image_created") is True or fields.get("thumbnail_created") is True:
        stage = ImageIODecodeStage.IMAGE_CREATED
    if fields.get("pixels_rendered") is True:
        stage = ImageIODecodeStage.PIXELS_RENDERED
    return stage


def _stage_rank(stage: ImageIODecodeStage) -> int:
    return tuple(ImageIODecodeStage).index(stage)


def _is_structurally_mutable_dicom(payload: bytes) -> bool:
    try:
        _parse_explicit_vr_little_endian(payload)
    except ValueError:
        return False
    return True


def _read_seed(path: Path, *, maximum: int) -> bytes:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError("DICOM seed may not be a symbolic link")
    resolved = expanded.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("DICOM seed must be a regular file")
    if resolved.stat().st_size > maximum:
        raise ValueError("DICOM seed exceeds the campaign byte limit")
    return resolved.read_bytes()


def _deterministic_index(campaign_seed: str, tag: str, length: int) -> int:
    digest = hashlib.sha256(f"{campaign_seed}\x00{tag}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % length


def _is_dicom_tag(value: str) -> bool:
    return (
        len(value) == 9
        and value[4] == ","
        and all(character in "0123456789ABCDEF" for character in value[:4] + value[5:])
    )


def _write_private_json(path: Path, model: DomainModel, *, replace: bool = False) -> None:
    if path.exists() and not replace:
        raise FileExistsError(f"private fuzz artifact already exists: {path}")
    _write_private(
        path,
        (json.dumps(model.model_dump(mode="json"), indent=2, sort_keys=True) + "\n").encode(),
    )


def _write_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    os.chmod(path, 0o600)


def _is_inside_git_worktree(path: Path) -> bool:
    return any((candidate / ".git").exists() for candidate in (path, *path.parents))


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()
