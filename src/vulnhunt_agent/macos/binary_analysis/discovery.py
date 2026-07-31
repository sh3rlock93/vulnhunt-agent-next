"""Deterministic ImageIO parser discovery over normalized binary IR."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from ...domain.schemas import DomainModel, SHA256_PATTERN
from .ir import IRFunction, IROperation, NormalizedBinaryIR


class BinaryFormatFamily(StrEnum):
    DICOM = "dicom"
    TIFF = "tiff"
    RAW_DNG = "raw_dng"
    JPEG = "jpeg"
    JPEG2000 = "jpeg2000"
    PNG = "png"
    GIF = "gif"
    HEIF = "heif"
    WEBP = "webp"
    TEXTURE = "texture"
    SGI = "sgi"


class ImageIOEntryRoute(StrEnum):
    DATA = "data"
    DATA_PROVIDER = "data_provider"
    URL = "url"
    INCREMENTAL = "incremental"
    PROPERTIES = "properties"
    THUMBNAIL = "thumbnail"
    FULL_DECODE = "full_decode"


class ParserEvidenceKind(StrEnum):
    FUNCTION_NAME = "function_name"
    FORMAT_STRING = "format_string"
    INPUT_MARKER = "input_marker"
    API_CALL = "api_call"
    MEMORY_SINK = "memory_sink"
    CALLGRAPH_PROXIMITY = "callgraph_proximity"


class ParserEvidence(DomainModel):
    kind: ParserEvidenceKind
    weight: int = Field(ge=1, le=20)
    address: int | None = Field(default=None, ge=0)
    detail: str = Field(min_length=1, max_length=500)


class ParserCandidate(DomainModel):
    candidate_id: str = Field(pattern=r"^parser_[0-9a-f]{20}$")
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    function_name: str = Field(min_length=1, max_length=500)
    start_address: int = Field(ge=0)
    format_families: tuple[BinaryFormatFamily, ...] = ()
    entry_routes: tuple[ImageIOEntryRoute, ...] = ()
    callgraph_distance: int | None = Field(default=None, ge=0, le=8)
    evidence: tuple[ParserEvidence, ...] = Field(min_length=1, max_length=256)
    discovery_score: int = Field(ge=1, le=1000)

    @model_validator(mode="after")
    def validate_candidate(self) -> "ParserCandidate":
        if tuple(sorted(set(self.format_families), key=str)) != self.format_families:
            raise ValueError("candidate format families must be sorted and unique")
        if tuple(sorted(set(self.entry_routes), key=str)) != self.entry_routes:
            raise ValueError("candidate entry routes must be sorted and unique")
        if tuple(sorted(self.evidence, key=_evidence_sort_key)) != self.evidence:
            raise ValueError("candidate evidence must be canonically ordered")
        if sum(item.weight for item in self.evidence) != self.discovery_score:
            raise ValueError("candidate discovery score does not match its evidence")
        return self


class ParserDiscoveryLimits(DomainModel):
    minimum_direct_score: int = Field(default=6, ge=1, le=100)
    maximum_callgraph_depth: int = Field(default=2, ge=0, le=8)
    maximum_candidates: int = Field(default=500, ge=1, le=10000)


class ImageIOParserDiscovery(DomainModel):
    schema_version: Literal["imageio-parser-discovery-v1"] = "imageio-parser-discovery-v1"
    ir_sha256: str = Field(pattern=SHA256_PATTERN)
    direct_seed_count: int = Field(ge=0)
    candidates: tuple[ParserCandidate, ...] = Field(max_length=10000)
    discovery_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_discovery(self) -> "ImageIOParserDiscovery":
        expected_order = tuple(
            sorted(
                self.candidates,
                key=lambda item: (-item.discovery_score, item.start_address, item.function_id),
            )
        )
        if expected_order != self.candidates:
            raise ValueError("parser candidates must use canonical discovery order")
        if len({item.function_id for item in self.candidates}) != len(self.candidates):
            raise ValueError("parser candidates must identify unique functions")
        expected = _discovery_digest(
            ir_sha256=self.ir_sha256,
            direct_seed_count=self.direct_seed_count,
            candidates=self.candidates,
        )
        if self.discovery_sha256 != expected:
            raise ValueError("parser discovery digest does not match its evidence")
        return self


_FORMAT_MARKERS: dict[BinaryFormatFamily, tuple[str, ...]] = {
    BinaryFormatFamily.DICOM: ("dicom", "dcm", "1.2.840.10008"),
    BinaryFormatFamily.TIFF: ("tiff", "ifd", "stripbytecounts", "tileoffsets"),
    BinaryFormatFamily.RAW_DNG: ("dng", "digital negative", "cameraraw"),
    BinaryFormatFamily.JPEG: ("jpeg", "jfif", "exif"),
    BinaryFormatFamily.JPEG2000: ("jpeg2000", "jpeg 2000", "jp2", "j2k"),
    BinaryFormatFamily.PNG: ("png", "ihdr", "idat"),
    BinaryFormatFamily.GIF: ("gif87a", "gif89a", "gif"),
    BinaryFormatFamily.HEIF: ("heif", "heic", "avif", "ftypheic"),
    BinaryFormatFamily.WEBP: ("webp", "vp8x", "vp8l"),
    BinaryFormatFamily.TEXTURE: ("texture", "ktx", "astc", "dds"),
    BinaryFormatFamily.SGI: ("sgi", "silicon graphics", "image/x-sgi"),
}
_INPUT_TAGS = {
    "decoder_entry",
    "input_data",
    "input_length",
    "input_offset",
    "input_state",
}
_INPUT_API_MARKERS: tuple[tuple[str, ImageIOEntryRoute], ...] = (
    ("cgdataprovider", ImageIOEntryRoute.DATA_PROVIDER),
    ("cgimageprovidergetsize", ImageIOEntryRoute.DATA_PROVIDER),
    ("cfdatagetbyteptr", ImageIOEntryRoute.DATA),
    ("cfdatagetlength", ImageIOEntryRoute.DATA),
    ("createwithdata", ImageIOEntryRoute.DATA),
    ("createwithurl", ImageIOEntryRoute.URL),
    ("incremental", ImageIOEntryRoute.INCREMENTAL),
    ("copyproperties", ImageIOEntryRoute.PROPERTIES),
    ("thumbnail", ImageIOEntryRoute.THUMBNAIL),
    ("createimageatindex", ImageIOEntryRoute.FULL_DECODE),
)
_MEMORY_SINKS = (
    "malloc",
    "calloc",
    "realloc",
    "memcpy",
    "memmove",
    "vm_allocate",
)


def discover_imageio_parsers(
    ir: NormalizedBinaryIR,
    *,
    limits: ParserDiscoveryLimits | None = None,
) -> ImageIOParserDiscovery:
    """Discover likely parser functions without asking an LLM to rank them."""

    active_limits = limits or ParserDiscoveryLimits()
    functions = {item.function_id: item for item in ir.functions}
    direct: dict[
        str, tuple[list[ParserEvidence], set[BinaryFormatFamily], set[ImageIOEntryRoute]]
    ] = {}
    for function in ir.functions:
        evidence, formats, routes = _direct_evidence(ir, function)
        direct[function.function_id] = (evidence, formats, routes)

    seeds = {
        identifier
        for identifier, (evidence, _, _) in direct.items()
        if sum(item.weight for item in evidence) >= active_limits.minimum_direct_score
    }
    graph = _internal_call_graph(ir)
    distances, nearest_seeds = _bounded_seed_distances(
        graph,
        seeds,
        maximum_depth=active_limits.maximum_callgraph_depth,
    )

    candidates: list[ParserCandidate] = []
    for identifier, function in functions.items():
        evidence, formats, routes = direct[identifier]
        candidate_evidence = list(evidence)
        distance = distances.get(identifier)
        if identifier not in seeds and distance is not None:
            weight = max(1, 6 - (distance * 2))
            seed_names = sorted(functions[seed].name for seed in nearest_seeds[identifier])
            candidate_evidence.append(
                ParserEvidence(
                    kind=ParserEvidenceKind.CALLGRAPH_PROXIMITY,
                    weight=weight,
                    address=function.start_address,
                    detail=f"distance {distance} from parser seed(s): {', '.join(seed_names[:4])}",
                )
            )
            for seed in nearest_seeds[identifier]:
                formats.update(direct[seed][1])
                routes.update(direct[seed][2])
        if identifier not in seeds and distance is None:
            continue
        ordered_evidence = tuple(sorted(candidate_evidence, key=_evidence_sort_key))
        score = sum(item.weight for item in ordered_evidence)
        candidates.append(
            ParserCandidate(
                candidate_id=_candidate_id(ir.ir_sha256, identifier),
                function_id=identifier,
                function_name=function.name,
                start_address=function.start_address,
                format_families=tuple(sorted(formats, key=str)),
                entry_routes=tuple(sorted(routes, key=str)),
                callgraph_distance=0 if identifier in seeds else distance,
                evidence=ordered_evidence,
                discovery_score=score,
            )
        )

    ordered = tuple(
        sorted(
            candidates,
            key=lambda item: (-item.discovery_score, item.start_address, item.function_id),
        )[: active_limits.maximum_candidates]
    )
    digest = _discovery_digest(
        ir_sha256=ir.ir_sha256,
        direct_seed_count=len(seeds),
        candidates=ordered,
    )
    return ImageIOParserDiscovery(
        ir_sha256=ir.ir_sha256,
        direct_seed_count=len(seeds),
        candidates=ordered,
        discovery_sha256=digest,
    )


def _direct_evidence(
    ir: NormalizedBinaryIR,
    function: IRFunction,
) -> tuple[list[ParserEvidence], set[BinaryFormatFamily], set[ImageIOEntryRoute]]:
    evidence: list[ParserEvidence] = []
    formats: set[BinaryFormatFamily] = set()
    routes: set[ImageIOEntryRoute] = set()
    lowered_name = function.name.lower()
    name_tokens = set(re.findall(r"[a-z0-9]+", lowered_name))
    parser_tokens = {"decode", "decoder", "parse", "parser", "reader", "read", "image"}
    matched_parser_tokens = sorted(name_tokens & parser_tokens)
    name_formats = _formats_for_text(lowered_name)
    formats.update(name_formats)
    if matched_parser_tokens or name_formats:
        detail_parts = matched_parser_tokens + [
            item.value for item in sorted(name_formats, key=str)
        ]
        evidence.append(
            ParserEvidence(
                kind=ParserEvidenceKind.FUNCTION_NAME,
                weight=6,
                address=function.start_address,
                detail="function markers: " + ", ".join(detail_parts),
            )
        )

    for string in ir.strings:
        references = tuple(
            address
            for address in string.referenced_at
            if function.start_address <= address < function.end_address
        )
        if not references:
            continue
        matched_formats = _formats_for_text(string.value.lower())
        if not matched_formats:
            continue
        formats.update(matched_formats)
        evidence.append(
            ParserEvidence(
                kind=ParserEvidenceKind.FORMAT_STRING,
                weight=8,
                address=references[0],
                detail=f"format string: {string.value[:120]}",
            )
        )

    seen_api_markers: set[str] = set()
    seen_sinks: set[str] = set()
    for block in function.blocks:
        for instruction in block.instructions:
            matched_tags = sorted(set(instruction.tags) & _INPUT_TAGS)
            if matched_tags:
                evidence.append(
                    ParserEvidence(
                        kind=ParserEvidenceKind.INPUT_MARKER,
                        weight=7,
                        address=instruction.address,
                        detail="input marker(s): " + ", ".join(matched_tags),
                    )
                )
            if not instruction.callee:
                continue
            lowered_callee = instruction.callee.lower()
            for marker, route in _INPUT_API_MARKERS:
                if marker in lowered_callee and marker not in seen_api_markers:
                    seen_api_markers.add(marker)
                    routes.add(route)
                    evidence.append(
                        ParserEvidence(
                            kind=ParserEvidenceKind.API_CALL,
                            weight=7,
                            address=instruction.address,
                            detail=f"input API call: {instruction.callee}",
                        )
                    )
            for sink in _MEMORY_SINKS:
                if sink in lowered_callee and sink not in seen_sinks:
                    seen_sinks.add(sink)
                    evidence.append(
                        ParserEvidence(
                            kind=ParserEvidenceKind.MEMORY_SINK,
                            weight=2,
                            address=instruction.address,
                            detail=f"memory sink: {instruction.callee}",
                        )
                    )
    return evidence, formats, routes


def _formats_for_text(value: str) -> set[BinaryFormatFamily]:
    return {
        family
        for family, markers in _FORMAT_MARKERS.items()
        if any(marker in value for marker in markers)
    }


def _internal_call_graph(ir: NormalizedBinaryIR) -> dict[str, set[str]]:
    graph: dict[str, set[str]] = {item.function_id: set() for item in ir.functions}
    by_name: dict[str, set[str]] = {}
    by_address = {item.start_address: item.function_id for item in ir.functions}
    for function in ir.functions:
        by_name.setdefault(function.name, set()).add(function.function_id)
    for function in ir.functions:
        for block in function.blocks:
            for instruction in block.instructions:
                if instruction.operation is not IROperation.CALL or not instruction.callee:
                    continue
                targets = by_name.get(instruction.callee, set())
                if instruction.callee.lower().startswith("0x"):
                    try:
                        target = by_address.get(int(instruction.callee, 16))
                    except ValueError:
                        target = None
                    if target:
                        targets = {target}
                for target in targets:
                    graph[function.function_id].add(target)
                    graph[target].add(function.function_id)
    return graph


def _bounded_seed_distances(
    graph: dict[str, set[str]],
    seeds: set[str],
    *,
    maximum_depth: int,
) -> tuple[dict[str, int], dict[str, set[str]]]:
    distances = {seed: 0 for seed in seeds}
    nearest = {seed: {seed} for seed in seeds}
    queue = deque(sorted(seeds))
    while queue:
        current = queue.popleft()
        distance = distances[current]
        if distance >= maximum_depth:
            continue
        for neighbor in sorted(graph[current]):
            next_distance = distance + 1
            if neighbor not in distances:
                distances[neighbor] = next_distance
                nearest[neighbor] = set(nearest[current])
                queue.append(neighbor)
            elif distances[neighbor] == next_distance:
                nearest[neighbor].update(nearest[current])
    return distances, nearest


def _candidate_id(ir_sha256: str, function_identifier: str) -> str:
    return (
        "parser_" + hashlib.sha256(f"{ir_sha256}:{function_identifier}".encode()).hexdigest()[:20]
    )


def _evidence_sort_key(item: ParserEvidence) -> tuple[str, int, str, int]:
    return (item.kind.value, item.address or -1, item.detail, item.weight)


def _discovery_digest(
    *,
    ir_sha256: str,
    direct_seed_count: int,
    candidates: tuple[ParserCandidate, ...],
) -> str:
    payload = {
        "candidates": [item.model_dump(mode="json") for item in candidates],
        "direct_seed_count": direct_seed_count,
        "ir_sha256": ir_sha256,
        "schema_version": "imageio-parser-discovery-v1",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
