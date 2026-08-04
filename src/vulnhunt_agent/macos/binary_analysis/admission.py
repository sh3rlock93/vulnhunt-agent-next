"""Code-first root admission for decompiler-native binary hunting."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from ...domain.schemas import DomainModel, SHA256_PATTERN
from .analyzers import BinaryAnalysisReport
from .decompiler_hunt import (
    DecompilerHuntStatus,
    load_decompiler_hunt_manifest,
)
from .discovery import (
    BinaryFormatFamily,
    ImageIOEntryRoute,
    ImageIOParserDiscovery,
    ParserCandidate,
    ParserEvidenceKind,
)
from .ir import (
    FunctionCoverageTier,
    IRFunction,
    IROperation,
    NormalizedBinaryIR,
)
from .ranking import BinaryFunctionRanking, RankedBinaryFunction

_MEMORY_OPERATIONS = frozenset(
    {
        IROperation.ALLOCATE,
        IROperation.COPY,
        IROperation.FREE,
        IROperation.LOAD,
        IROperation.STORE,
    }
)
_DIRECT_INPUT_EVIDENCE = frozenset(
    {
        ParserEvidenceKind.API_CALL,
        ParserEvidenceKind.FORMAT_STRING,
        ParserEvidenceKind.INPUT_MARKER,
    }
)


class CodeHuntAdmissionReason(StrEnum):
    RANKING_PREFIX = "ranking_prefix"
    FORMAT_DIVERSITY = "format_diversity"
    ROUTE_DIVERSITY = "route_diversity"
    PARSER_REACHABILITY = "parser_reachability"
    INPUT_EVIDENCE = "input_evidence"
    SECURITY_SINK = "security_sink"
    STATIC_FINDING_SIGNAL = "static_finding_signal"


class CodeHuntOmissionReason(StrEnum):
    BUDGET_EXHAUSTED = "budget_exhausted"
    COVERAGE_MISSING = "coverage_missing"
    COVERAGE_NOT_SELECTED = "coverage_not_selected"
    EMPTY_PSEUDOCODE = "empty_pseudocode"
    GENERIC_NON_PARSER = "generic_non_parser"
    MISSING_SECURITY_SINK = "missing_security_sink"
    THUNK_OR_IMPORT_STUB = "thunk_or_import_stub"
    UNKNOWN_IR_EXCEEDED = "unknown_ir_exceeded"


class CodeHuntAdmissionPolicy(DomainModel):
    maximum_roots: int = Field(default=24, ge=1, le=1024)
    diversity_slots: int = Field(default=8, ge=0, le=256)
    maximum_unknown_fraction: float = Field(default=0.85, ge=0.0, le=1.0)
    require_function_coverage: bool = True

    @model_validator(mode="after")
    def validate_policy(self) -> "CodeHuntAdmissionPolicy":
        if self.diversity_slots > self.maximum_roots:
            raise ValueError("diversity slots cannot exceed the root budget")
        return self


class CodeHuntRoot(DomainModel):
    root_id: str = Field(pattern=r"^coderoot_[0-9a-f]{20}$")
    admission_rank: int = Field(ge=1, le=100000)
    binary_rank: int = Field(ge=1, le=100000)
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    candidate_id: str = Field(pattern=r"^parser_[0-9a-f]{20}$")
    function_name: str = Field(min_length=1, max_length=500)
    start_address: int = Field(ge=0)
    priority_score: int = Field(ge=-1000, le=10000)
    finding_ids: tuple[str, ...] = Field(default=(), max_length=256)
    format_families: tuple[BinaryFormatFamily, ...] = ()
    entry_routes: tuple[ImageIOEntryRoute, ...] = ()
    callgraph_distance: int | None = Field(default=None, ge=0, le=8)
    instruction_count: int = Field(ge=1)
    unknown_instruction_count: int = Field(ge=0)
    input_evidence_count: int = Field(ge=0)
    security_sink_count: int = Field(ge=1)
    coverage_tier: FunctionCoverageTier | None = None
    admission_reasons: tuple[CodeHuntAdmissionReason, ...] = Field(min_length=3)

    @model_validator(mode="after")
    def validate_root(self) -> "CodeHuntRoot":
        if tuple(sorted(set(self.finding_ids))) != self.finding_ids:
            raise ValueError("code root finding ids must be sorted and unique")
        if tuple(sorted(set(self.format_families), key=str)) != self.format_families:
            raise ValueError("code root format families must be sorted and unique")
        if tuple(sorted(set(self.entry_routes), key=str)) != self.entry_routes:
            raise ValueError("code root entry routes must be sorted and unique")
        if tuple(sorted(set(self.admission_reasons), key=str)) != self.admission_reasons:
            raise ValueError("code root admission reasons must be sorted and unique")
        if self.unknown_instruction_count > self.instruction_count:
            raise ValueError("unknown instruction count exceeds the function total")
        expected = _root_id(self.function_id)
        if self.root_id != expected:
            raise ValueError("code root id does not match its function")
        return self


class CodeHuntOmission(DomainModel):
    binary_rank: int = Field(ge=1, le=100000)
    function_id: str = Field(pattern=r"^fn_[0-9a-f]{20}$")
    candidate_id: str = Field(pattern=r"^parser_[0-9a-f]{20}$")
    function_name: str = Field(min_length=1, max_length=500)
    start_address: int = Field(ge=0)
    reason: CodeHuntOmissionReason
    detail: str = Field(min_length=1, max_length=500)


class CodeHuntAdmission(DomainModel):
    schema_version: Literal["code-hunt-admission-v1"] = "code-hunt-admission-v1"
    ir_sha256: str = Field(pattern=SHA256_PATTERN)
    discovery_sha256: str = Field(pattern=SHA256_PATTERN)
    report_sha256: str = Field(pattern=SHA256_PATTERN)
    ranking_sha256: str = Field(pattern=SHA256_PATTERN)
    coverage_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    policy: CodeHuntAdmissionPolicy
    ranked_function_ids: tuple[str, ...] = Field(max_length=10000)
    roots: tuple[CodeHuntRoot, ...] = Field(max_length=1024)
    omissions: tuple[CodeHuntOmission, ...] = Field(max_length=10000)
    execution_function_ids: tuple[str, ...] = Field(max_length=1024)
    admission_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_admission(self) -> "CodeHuntAdmission":
        if len(self.roots) > self.policy.maximum_roots:
            raise ValueError("code hunt roots exceed the admission budget")
        if tuple(item.admission_rank for item in self.roots) != tuple(
            range(1, len(self.roots) + 1)
        ):
            raise ValueError("code hunt admission ranks must be contiguous")
        if tuple(sorted(item.binary_rank for item in self.roots)) != tuple(
            item.binary_rank for item in self.roots
        ):
            raise ValueError("code hunt execution must preserve binary ranking order")
        if tuple(sorted(item.binary_rank for item in self.omissions)) != tuple(
            item.binary_rank for item in self.omissions
        ):
            raise ValueError("code hunt omissions must preserve binary ranking order")
        if tuple(item.function_id for item in self.roots) != self.execution_function_ids:
            raise ValueError("execution function ids must match admitted root order")
        if len(set(self.ranked_function_ids)) != len(self.ranked_function_ids):
            raise ValueError("ranked function ids must be unique")
        decisions = tuple(
            sorted(
                (
                    *((item.binary_rank, item.function_id) for item in self.roots),
                    *((item.binary_rank, item.function_id) for item in self.omissions),
                )
            )
        )
        expected = tuple(enumerate(self.ranked_function_ids, start=1))
        if decisions != expected:
            raise ValueError("admission must decide every ranked function exactly once")
        expected_digest = _admission_digest(
            ir_sha256=self.ir_sha256,
            discovery_sha256=self.discovery_sha256,
            report_sha256=self.report_sha256,
            ranking_sha256=self.ranking_sha256,
            coverage_sha256=self.coverage_sha256,
            policy=self.policy,
            ranked_function_ids=self.ranked_function_ids,
            roots=self.roots,
            omissions=self.omissions,
            execution_function_ids=self.execution_function_ids,
        )
        if self.admission_sha256 != expected_digest:
            raise ValueError("code hunt admission digest does not match its decisions")
        return self


def admit_code_hunt_roots(
    ir: NormalizedBinaryIR,
    discovery: ImageIOParserDiscovery,
    report: BinaryAnalysisReport,
    ranking: BinaryFunctionRanking,
    *,
    policy: CodeHuntAdmissionPolicy | None = None,
) -> CodeHuntAdmission:
    """Select code-review roots without requiring a deterministic finding."""

    active_policy = policy or CodeHuntAdmissionPolicy()
    _validate_inputs(ir, discovery, report, ranking)
    functions = {item.function_id: item for item in ir.functions}
    candidates = {item.function_id: item for item in discovery.candidates}
    coverage_by_function = (
        {item.function_id: item for item in ir.function_coverage.functions}
        if ir.function_coverage is not None
        else {}
    )

    eligible: list[tuple[RankedBinaryFunction, ParserCandidate, IRFunction, _CodeSignals]] = []
    omitted: list[CodeHuntOmission] = []
    for entry in ranking.entries:
        candidate = candidates[entry.function_id]
        function = functions[entry.function_id]
        signals = _code_signals(function, candidate)
        omission = _eligibility_omission(
            entry,
            function,
            signals,
            coverage_by_function.get(entry.function_id),
            active_policy,
        )
        if omission is not None:
            omitted.append(omission)
        else:
            eligible.append((entry, candidate, function, signals))

    prefix_slots = max(0, active_policy.maximum_roots - active_policy.diversity_slots)
    selected: dict[str, tuple[set[CodeHuntAdmissionReason], ParserCandidate, IRFunction, _CodeSignals]] = {}
    for entry, candidate, function, signals in eligible[:prefix_slots]:
        selected[entry.function_id] = (
            {CodeHuntAdmissionReason.RANKING_PREFIX},
            candidate,
            function,
            signals,
        )

    selected_formats = {
        family
        for _, candidate, _, _ in eligible
        if candidate.function_id in selected
        for family in candidate.format_families
    }
    selected_routes = {
        route
        for _, candidate, _, _ in eligible
        if candidate.function_id in selected
        for route in candidate.entry_routes
    }
    for entry, candidate, function, signals in eligible:
        if len(selected) >= active_policy.maximum_roots:
            break
        if entry.function_id in selected:
            continue
        reasons: set[CodeHuntAdmissionReason] = set()
        if set(candidate.format_families).difference(selected_formats):
            reasons.add(CodeHuntAdmissionReason.FORMAT_DIVERSITY)
        if set(candidate.entry_routes).difference(selected_routes):
            reasons.add(CodeHuntAdmissionReason.ROUTE_DIVERSITY)
        if not reasons:
            continue
        selected[entry.function_id] = (reasons, candidate, function, signals)
        selected_formats.update(candidate.format_families)
        selected_routes.update(candidate.entry_routes)

    for entry, candidate, function, signals in eligible:
        if len(selected) >= active_policy.maximum_roots:
            break
        if entry.function_id not in selected:
            selected[entry.function_id] = (
                {CodeHuntAdmissionReason.RANKING_PREFIX},
                candidate,
                function,
                signals,
            )

    roots: list[CodeHuntRoot] = []
    for entry, candidate, function, signals in eligible:
        selection = selected.get(entry.function_id)
        if selection is None:
            omitted.append(
                _omission(
                    entry,
                    CodeHuntOmissionReason.BUDGET_EXHAUSTED,
                    f"eligible code root fell outside maximum_roots={active_policy.maximum_roots}",
                )
            )
            continue
        reasons, _, _, _ = selection
        reasons.update(
            {
                CodeHuntAdmissionReason.PARSER_REACHABILITY,
                CodeHuntAdmissionReason.INPUT_EVIDENCE,
                CodeHuntAdmissionReason.SECURITY_SINK,
            }
        )
        if entry.finding_ids:
            reasons.add(CodeHuntAdmissionReason.STATIC_FINDING_SIGNAL)
        coverage = coverage_by_function.get(entry.function_id)
        roots.append(
            CodeHuntRoot(
                root_id=_root_id(entry.function_id),
                admission_rank=len(roots) + 1,
                binary_rank=entry.rank,
                function_id=entry.function_id,
                candidate_id=entry.candidate_id,
                function_name=entry.function_name,
                start_address=entry.start_address,
                priority_score=entry.priority_score,
                finding_ids=entry.finding_ids,
                format_families=candidate.format_families,
                entry_routes=candidate.entry_routes,
                callgraph_distance=candidate.callgraph_distance,
                instruction_count=signals.instruction_count,
                unknown_instruction_count=signals.unknown_instruction_count,
                input_evidence_count=signals.input_evidence_count,
                security_sink_count=signals.security_sink_count,
                coverage_tier=coverage.selection_tier if coverage is not None else None,
                admission_reasons=tuple(sorted(reasons, key=str)),
            )
        )

    ordered_omissions = tuple(sorted(omitted, key=lambda item: item.binary_rank))
    ordered_roots = tuple(roots)
    ranked_ids = tuple(item.function_id for item in ranking.entries)
    execution_ids = tuple(item.function_id for item in ordered_roots)
    coverage_sha256 = (
        ir.function_coverage.coverage_sha256 if ir.function_coverage is not None else None
    )
    digest = _admission_digest(
        ir_sha256=ir.ir_sha256,
        discovery_sha256=discovery.discovery_sha256,
        report_sha256=report.report_sha256,
        ranking_sha256=ranking.ranking_sha256,
        coverage_sha256=coverage_sha256,
        policy=active_policy,
        ranked_function_ids=ranked_ids,
        roots=ordered_roots,
        omissions=ordered_omissions,
        execution_function_ids=execution_ids,
    )
    return CodeHuntAdmission(
        ir_sha256=ir.ir_sha256,
        discovery_sha256=discovery.discovery_sha256,
        report_sha256=report.report_sha256,
        ranking_sha256=ranking.ranking_sha256,
        coverage_sha256=coverage_sha256,
        policy=active_policy,
        ranked_function_ids=ranked_ids,
        roots=ordered_roots,
        omissions=ordered_omissions,
        execution_function_ids=execution_ids,
        admission_sha256=digest,
    )


def materialize_code_hunt_admission(
    output_directory: Path,
    *,
    policy: CodeHuntAdmissionPolicy | None = None,
) -> CodeHuntAdmission:
    """Build a deterministic admission artifact from a completed M17-1 run."""

    output = output_directory.expanduser()
    manifest = load_decompiler_hunt_manifest(output)
    if manifest.status is not DecompilerHuntStatus.COMPLETED:
        raise ValueError("code hunt admission requires a completed M17 manifest")
    artifacts = {item.name: item for item in manifest.artifacts}
    inputs: dict[str, bytes] = {}
    for name in (
        "normalized-ir.json",
        "parser-discovery.json",
        "static-analysis.json",
        "binary-ranking.json",
    ):
        path = _regular_file(output / name)
        payload = path.read_bytes()
        if _bytes_digest(payload) != artifacts[name].sha256:
            raise ValueError(f"M17 input artifact changed after manifest freeze: {name}")
        inputs[name] = payload

    ir = NormalizedBinaryIR.model_validate_json(inputs["normalized-ir.json"])
    discovery = ImageIOParserDiscovery.model_validate_json(inputs["parser-discovery.json"])
    report = BinaryAnalysisReport.model_validate_json(inputs["static-analysis.json"])
    ranking = BinaryFunctionRanking.model_validate_json(inputs["binary-ranking.json"])
    if manifest.ir_sha256 != ir.ir_sha256 or manifest.snapshot_sha256 != ir.snapshot_sha256:
        raise ValueError("M17 manifest identity does not match normalized IR")
    admission = admit_code_hunt_roots(
        ir,
        discovery,
        report,
        ranking,
        policy=policy,
    )

    m17 = output / "m17"
    if m17.exists():
        _private_directory(m17)
    else:
        m17.mkdir(mode=0o700)
    path = m17 / "code-hunt-admission.json"
    encoded = _encoded_json(admission.model_dump(mode="json"))
    if path.exists():
        existing = _regular_file(path).read_bytes()
        if existing != encoded:
            raise ValueError("existing code hunt admission does not match requested policy")
        return CodeHuntAdmission.model_validate_json(existing)
    _write_private_bytes(path, encoded)
    return admission


class _CodeSignals:
    def __init__(
        self,
        *,
        instruction_count: int,
        unknown_instruction_count: int,
        input_evidence_count: int,
        security_sink_count: int,
        parser_reachable: bool,
        stub_like: bool,
    ) -> None:
        self.instruction_count = instruction_count
        self.unknown_instruction_count = unknown_instruction_count
        self.input_evidence_count = input_evidence_count
        self.security_sink_count = security_sink_count
        self.parser_reachable = parser_reachable
        self.stub_like = stub_like


def _code_signals(function: IRFunction, candidate: ParserCandidate) -> _CodeSignals:
    instructions = tuple(
        instruction for block in function.blocks for instruction in block.instructions
    )
    evidence_kinds = {item.kind for item in candidate.evidence}
    input_tags = sum(
        1
        for instruction in instructions
        if any(_is_input_tag(tag) for tag in instruction.tags)
    )
    input_evidence_count = input_tags + sum(
        item.kind in _DIRECT_INPUT_EVIDENCE for item in candidate.evidence
    )
    inherited_route = (
        ParserEvidenceKind.CALLGRAPH_PROXIMITY in evidence_kinds
        and candidate.callgraph_distance is not None
        and bool(candidate.format_families or candidate.entry_routes)
    )
    parser_reachable = input_evidence_count > 0 or inherited_route
    security_sink_count = sum(
        instruction.operation in _MEMORY_OPERATIONS for instruction in instructions
    ) + sum(item.kind is ParserEvidenceKind.MEMORY_SINK for item in candidate.evidence)
    operational = {
        instruction.operation
        for instruction in instructions
        if instruction.operation not in {IROperation.PARAMETER, IROperation.RETURN}
    }
    stub_like = (
        len(instructions) <= 4
        and len(function.pseudocode.strip().encode()) < 160
        and operational.issubset({IROperation.ASSIGN, IROperation.CALL, IROperation.CAST})
    )
    return _CodeSignals(
        instruction_count=len(instructions),
        unknown_instruction_count=sum(
            instruction.operation is IROperation.UNKNOWN for instruction in instructions
        ),
        input_evidence_count=input_evidence_count,
        security_sink_count=security_sink_count,
        parser_reachable=parser_reachable,
        stub_like=stub_like,
    )


def _is_input_tag(tag: str) -> bool:
    return tag.startswith("input") or (
        tag.startswith("source") and not tag.startswith("source_op:")
    )


def _eligibility_omission(
    entry: RankedBinaryFunction,
    function: IRFunction,
    signals: _CodeSignals,
    coverage: object | None,
    policy: CodeHuntAdmissionPolicy,
) -> CodeHuntOmission | None:
    if policy.require_function_coverage:
        if coverage is None:
            return _omission(
                entry,
                CodeHuntOmissionReason.COVERAGE_MISSING,
                "function has no frozen decompiler coverage record",
            )
        if not getattr(coverage, "selected", False):
            return _omission(
                entry,
                CodeHuntOmissionReason.COVERAGE_NOT_SELECTED,
                "function was not selected in the frozen decompiler export",
            )
    if not function.pseudocode.strip():
        return _omission(
            entry,
            CodeHuntOmissionReason.EMPTY_PSEUDOCODE,
            "decompiler emitted no pseudocode for the ranked function",
        )
    if signals.stub_like:
        return _omission(
            entry,
            CodeHuntOmissionReason.THUNK_OR_IMPORT_STUB,
            "function is a bounded call/return thunk or import stub",
        )
    unknown_fraction = signals.unknown_instruction_count / signals.instruction_count
    if unknown_fraction > policy.maximum_unknown_fraction:
        return _omission(
            entry,
            CodeHuntOmissionReason.UNKNOWN_IR_EXCEEDED,
            f"unknown IR fraction {unknown_fraction:.3f} exceeds "
            f"{policy.maximum_unknown_fraction:.3f}",
        )
    if not signals.parser_reachable:
        return _omission(
            entry,
            CodeHuntOmissionReason.GENERIC_NON_PARSER,
            "no direct input evidence or inherited parser route reaches this function",
        )
    if signals.security_sink_count == 0:
        return _omission(
            entry,
            CodeHuntOmissionReason.MISSING_SECURITY_SINK,
            "no memory read, write, copy, allocation, free, or sink evidence is present",
        )
    return None


def _validate_inputs(
    ir: NormalizedBinaryIR,
    discovery: ImageIOParserDiscovery,
    report: BinaryAnalysisReport,
    ranking: BinaryFunctionRanking,
) -> None:
    if discovery.ir_sha256 != ir.ir_sha256:
        raise ValueError("parser discovery is bound to a different IR")
    if report.ir_sha256 != ir.ir_sha256 or report.discovery_sha256 != discovery.discovery_sha256:
        raise ValueError("static analysis is bound to different discovery evidence")
    if (
        ranking.ir_sha256 != ir.ir_sha256
        or ranking.discovery_sha256 != discovery.discovery_sha256
        or ranking.report_sha256 != report.report_sha256
    ):
        raise ValueError("binary ranking is bound to different static evidence")
    functions = {item.function_id for item in ir.functions}
    candidates = {item.function_id for item in discovery.candidates}
    ranked = {item.function_id for item in ranking.entries}
    if not ranked.issubset(functions) or not ranked.issubset(candidates):
        raise ValueError("binary ranking cites an unknown function or parser candidate")


def _omission(
    entry: RankedBinaryFunction,
    reason: CodeHuntOmissionReason,
    detail: str,
) -> CodeHuntOmission:
    return CodeHuntOmission(
        binary_rank=entry.rank,
        function_id=entry.function_id,
        candidate_id=entry.candidate_id,
        function_name=entry.function_name,
        start_address=entry.start_address,
        reason=reason,
        detail=detail,
    )


def _root_id(function_id: str) -> str:
    return "coderoot_" + hashlib.sha256(function_id.encode()).hexdigest()[:20]


def _admission_digest(
    *,
    ir_sha256: str,
    discovery_sha256: str,
    report_sha256: str,
    ranking_sha256: str,
    coverage_sha256: str | None,
    policy: CodeHuntAdmissionPolicy,
    ranked_function_ids: tuple[str, ...],
    roots: tuple[CodeHuntRoot, ...],
    omissions: tuple[CodeHuntOmission, ...],
    execution_function_ids: tuple[str, ...],
) -> str:
    payload = {
        "schema_version": "code-hunt-admission-v1",
        "ir_sha256": ir_sha256,
        "discovery_sha256": discovery_sha256,
        "report_sha256": report_sha256,
        "ranking_sha256": ranking_sha256,
        "coverage_sha256": coverage_sha256,
        "policy": policy.model_dump(mode="json"),
        "ranked_function_ids": ranked_function_ids,
        "roots": [item.model_dump(mode="json") for item in roots],
        "omissions": [item.model_dump(mode="json") for item in omissions],
        "execution_function_ids": execution_function_ids,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _regular_file(path: Path) -> Path:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("M17 admission input must be a regular non-symlink file")
    return path


def _private_directory(path: Path) -> Path:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("M17 admission path must be a regular non-symlink directory")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("M17 admission directory must not grant group or other access")
    return path


def _bytes_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _encoded_json(payload: object) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n").encode()


def _write_private_bytes(path: Path, payload: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
