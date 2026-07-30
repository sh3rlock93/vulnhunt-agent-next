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


class ImageIOMutationOperator(StrEnum):
    ELEMENT_LENGTH_DELTA = "element_length_delta"
    ELEMENT_LENGTH_BOUNDARY = "element_length_boundary"
    SEMANTIC_US_BOUNDARY = "semantic_us_boundary"
    VALUE_BIT_FLIP = "value_bit_flip"
    TRUNCATE_AT_ELEMENT = "truncate_at_element"


class ImageIOFuzzClassification(StrEnum):
    NORMAL = "normal"
    PARSER_REJECTION = "parser_rejection"
    CRASH_CANDIDATE = "crash_candidate"
    TIMEOUT = "timeout"
    RESOURCE_LIMIT = "resource_limit"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"


class ImageIOFuzzBudget(DomainModel):
    max_cases: int = Field(default=64, ge=1, le=10_000)
    max_executions: int = Field(default=256, ge=1, le=50_000)
    max_seed_bytes: int = Field(default=32 * 1024 * 1024, ge=132, le=128 * 1024 * 1024)


class ImageIOFuzzCase(DomainModel):
    schema_version: Literal["imageio-fuzz-case-v1"] = "imageio-fuzz-case-v1"
    case_id: str = Field(pattern=r"^case-[0-9a-f]{32}$")
    campaign_seed: str = Field(min_length=1, max_length=200)
    format_family: Literal[ImageIOFormatFamily.DICOM] = ImageIOFormatFamily.DICOM
    seed_sha256: str = Field(pattern=SHA256_PATTERN)
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    input_size_bytes: int = Field(ge=0)
    operator: ImageIOMutationOperator
    target_tag: str = Field(pattern=r"^[0-9A-F]{4},[0-9A-F]{4}$")
    target_offset: int = Field(ge=0)
    parameter: str = Field(min_length=1, max_length=120)
    routes: tuple[ImageIOAPIRoute, ...] = Field(min_length=1, max_length=5)

    @model_validator(mode="after")
    def validate_routes(self) -> "ImageIOFuzzCase":
        if len(set(self.routes)) != len(self.routes):
            raise ValueError("fuzz case routes must be unique")
        if ImageIOAPIRoute.TYPE_IDENTIFIERS in self.routes:
            raise ValueError("inventory-only route cannot execute a fuzz case")
        return self


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


class ImageIOFuzzExecution(DomainModel):
    route: ImageIOAPIRoute
    classification: ImageIOFuzzClassification
    evidence: ImageIOHarnessEvidence
    behavior: ImageIOBehaviorSignature | None = None


class ImageIOFuzzCaseResult(DomainModel):
    schema_version: Literal["imageio-fuzz-result-v1"] = "imageio-fuzz-result-v1"
    case: ImageIOFuzzCase
    executions: tuple[ImageIOFuzzExecution, ...] = Field(min_length=1, max_length=5)
    interesting: bool

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
    generated_cases: int = Field(ge=0)
    executed_cases: int = Field(ge=0)
    execution_count: int = Field(ge=0)
    classification_counts: dict[ImageIOFuzzClassification, int]
    behavior_signature_count: int = Field(ge=0)
    interesting_case_ids: tuple[str, ...]
    model_calls: Literal[0] = 0


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

    def write_summary(self, summary: ImageIOFuzzCampaignSummary) -> None:
        _write_private_json(self.root / "campaign-summary.json", summary, replace=True)


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
) -> tuple[GeneratedImageIOFuzzCase, ...]:
    """Generate a stable, de-duplicated initial DICOM mutation corpus."""

    if max_cases < 1:
        raise ValueError("max_cases must be positive")
    elements = _parse_explicit_vr_little_endian(seed)
    seed_sha256 = _sha256_bytes(seed)
    generated: list[GeneratedImageIOFuzzCase] = []
    seen_payloads = {seed_sha256}

    def append_case(
        *,
        element: _DICOMElement,
        operator: ImageIOMutationOperator,
        parameter: str,
        payload: bytes,
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
                campaign_seed,
                operator.value,
                element.tag,
                str(element.header_offset),
                parameter,
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
                    operator=operator,
                    target_tag=element.tag,
                    target_offset=element.header_offset,
                    parameter=parameter,
                    routes=_routes_for(operator),
                ),
                payload=payload,
            )
        )

    for element in elements:
        maximum = (1 << (element.length_size * 8)) - 1
        for parameter, mutated_length in (
            ("delta:-1", max(0, element.value_length - 1)),
            ("delta:+1", min(maximum, element.value_length + 1)),
            ("boundary:0", 0),
            (f"boundary:{maximum}", maximum),
        ):
            payload = bytearray(seed)
            payload[element.length_offset : element.length_offset + element.length_size] = (
                mutated_length.to_bytes(element.length_size, "little")
            )
            append_case(
                element=element,
                operator=(
                    ImageIOMutationOperator.ELEMENT_LENGTH_DELTA
                    if parameter.startswith("delta")
                    else ImageIOMutationOperator.ELEMENT_LENGTH_BOUNDARY
                ),
                parameter=parameter,
                payload=bytes(payload),
            )
        if element.value_length > 0:
            relative = _deterministic_index(
                campaign_seed,
                element.tag,
                element.value_length,
            )
            payload = bytearray(seed)
            payload[element.value_offset + relative] ^= 0x80
            append_case(
                element=element,
                operator=ImageIOMutationOperator.VALUE_BIT_FLIP,
                parameter=f"relative:{relative}:mask:0x80",
                payload=bytes(payload),
            )
            append_case(
                element=element,
                operator=ImageIOMutationOperator.TRUNCATE_AT_ELEMENT,
                parameter="before-value-end",
                payload=seed[: max(element.value_offset, element.value_offset + element.value_length - 1)],
            )
        if (
            (element.group, element.element) in _SEMANTIC_US_TAGS
            and element.vr == b"US"
            and element.value_length >= 2
        ):
            for value in (0, 1, 0x7FFF, 0xFFFF):
                payload = bytearray(seed)
                payload[element.value_offset : element.value_offset + 2] = struct.pack("<H", value)
                append_case(
                    element=element,
                    operator=ImageIOMutationOperator.SEMANTIC_US_BOUNDARY,
                    parameter=f"value:{value}",
                    payload=bytes(payload),
                )
        if len(generated) >= max_cases:
            break
    return tuple(generated)


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
) -> ImageIOFuzzCampaignSummary:
    """Run one bounded corpus inside the caller's already-active VM clone."""

    active_budget = budget or ImageIOFuzzBudget()
    source = _read_seed(seed_path, maximum=active_budget.max_seed_bytes)
    seed_sha256 = _sha256_bytes(source)
    _parse_explicit_vr_little_endian(source)
    store.write_seed(source, seed_sha256=seed_sha256)
    generated = generate_dicom_fuzz_cases(
        source,
        campaign_seed=campaign_seed,
        max_cases=active_budget.max_cases,
    )
    seed_validation = _run_payload(
        runner=runner,
        environment=environment,
        payload=source,
        route=ImageIOAPIRoute.DATA_PROPERTIES,
        store_root=store.root,
        limits=limits,
    )
    seed_behavior = _behavior_from_run(seed_validation)
    if seed_validation.evidence.exit_reason is not ImageIOVMExitReason.EXITED:
        raise RuntimeError("valid DICOM seed did not exit normally in ImageIO")
    if seed_behavior is None or not seed_behavior.source_created:
        raise RuntimeError("valid DICOM seed was not recognized by ImageIO")
    if (
        seed_behavior.type_identifier is None
        or "dicom" not in seed_behavior.type_identifier.casefold()
    ):
        raise RuntimeError("valid DICOM seed was recognized as a different image family")

    counts = {classification: 0 for classification in ImageIOFuzzClassification}
    counts[ImageIOFuzzClassification.NORMAL] += 1
    signatures = {seed_behavior.signature_sha256}
    interesting: list[str] = []
    execution_count = 1
    executed_cases = 0
    for case in generated:
        if execution_count >= active_budget.max_executions:
            break
        case_runs: list[PrivateImageIOHarnessRun] = []
        executions: list[ImageIOFuzzExecution] = []
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
            if behavior is not None:
                signatures.add(behavior.signature_sha256)
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
        )
        store.write_case(case, tuple(case_runs), result)
        if result.interesting:
            interesting.append(case.manifest.case_id)
        executed_cases += 1
    summary = ImageIOFuzzCampaignSummary(
        campaign_id=campaign_id,
        campaign_seed=campaign_seed,
        seed_sha256=seed_sha256,
        generated_cases=len(generated),
        executed_cases=executed_cases,
        execution_count=execution_count,
        classification_counts=counts,
        behavior_signature_count=len(signatures),
        interesting_case_ids=tuple(interesting),
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


def _routes_for(operator: ImageIOMutationOperator) -> tuple[ImageIOAPIRoute, ...]:
    if operator is ImageIOMutationOperator.SEMANTIC_US_BOUNDARY:
        return (
            ImageIOAPIRoute.IMAGE_PROPERTIES,
            ImageIOAPIRoute.THUMBNAIL_DECODE,
            ImageIOAPIRoute.FULL_DECODE,
            ImageIOAPIRoute.INCREMENTAL_DECODE,
        )
    if operator is ImageIOMutationOperator.VALUE_BIT_FLIP:
        return (ImageIOAPIRoute.FULL_DECODE, ImageIOAPIRoute.INCREMENTAL_DECODE)
    return (
        ImageIOAPIRoute.DATA_PROPERTIES,
        ImageIOAPIRoute.FULL_DECODE,
        ImageIOAPIRoute.INCREMENTAL_DECODE,
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
    }
    for name, expected_type in fields.items():
        value = raw.get(name)
        if isinstance(value, expected_type):
            selected[name] = value
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
    return ImageIOFuzzClassification.NORMAL


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
