"""Crash triage bridge from ImageIO fuzzing to the existing Hunter scheduler.

The static C pipeline ranks source files and graph signals. ImageIO has no
public source repository, so this adapter ranks dynamic crash clusters instead
and emits the same ``HunterWorkItem`` contract consumed by the durable queue,
budget ledger, and downstream review state machine.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from ..domain.schemas import (
    BudgetPolicy,
    DomainModel,
    HunterRoutingPlan,
    HunterWorkItem,
    SHA256_PATTERN,
)
from ..reporting.apple_cve import AppleCrashClass
from ..scheduling.budget import (
    AdmissionDecision,
    AdmissionRankingRecord,
    BudgetAllocation,
)
from ..scheduling.shadow import work_id_for
from .imageio_fuzzer import (
    ImageIOFuzzCaseResult,
    ImageIOFuzzClassification,
)
from .imageio_harness import ImageIOHarnessEvidence, ImageIOVMExitReason
from .imageio_inventory import ImageIOAPIRoute

IMAGEIO_CRASH_RANKING_POLICY = "imageio-crash-ranking-v1"
IMAGEIO_CRASH_HUNTER = "imageio-crash-analysis"
_MAX_JSON_BYTES = 8 * 1024 * 1024
_MAX_CRASH_LOG_BYTES = 16 * 1024 * 1024
_FRAME_LIMIT = 12
_UUID = re.compile(
    r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"
)
_ADDRESS = re.compile(r"0x[0-9A-Fa-f]+")
_FRAME = re.compile(
    r"^\s*\d+\s+(?P<image>\S+)\s+0x[0-9A-Fa-f]+\s+"
    r"(?P<symbol>.*?)(?:\s+\+\s+\d+)?\s*$"
)
_FAULT_ADDRESS = re.compile(
    r"(?:at|address(?:ed)?(?:\s+at)?)\s+(0x[0-9A-Fa-f]+)",
    re.IGNORECASE,
)


class ImageIOCrashTriageClass(StrEnum):
    STRONG_MEMORY_SAFETY = "strong_memory_safety"
    NONNULL_BAD_ACCESS = "nonnull_bad_access"
    UNDIFFERENTIATED = "undifferentiated"
    NULL_DEREFERENCE = "null_dereference"
    ASSERTION = "assertion"
    INCOMPLETE = "incomplete"


class ImageIOCrashObservation(DomainModel):
    schema_version: Literal["imageio-crash-observation-v1"] = (
        "imageio-crash-observation-v1"
    )
    observation_id: str = Field(pattern=r"^imageio-observation-[0-9a-f]{32}$")
    case_id: str = Field(pattern=r"^case-[0-9a-f]{32}$")
    route: ImageIOAPIRoute
    input_sha256: str = Field(pattern=SHA256_PATTERN)
    input_size_bytes: int = Field(ge=0)
    evidence_sha256: str = Field(pattern=SHA256_PATTERN)
    crash_log_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    exception_type: str = Field(default="", max_length=300)
    exception_subtype: str = Field(default="", max_length=500)
    fault_address: int | None = Field(default=None, ge=0)
    normalized_frames: tuple[str, ...] = Field(max_length=_FRAME_LIMIT)
    signature_sha256: str = Field(pattern=SHA256_PATTERN)
    triage_class: ImageIOCrashTriageClass
    apple_crash_class: AppleCrashClass | None = None
    evidence_complete: bool
    case_result_path: str
    input_path: str
    crash_log_path: str | None = None

    @model_validator(mode="after")
    def validate_triage_claim(self) -> "ImageIOCrashObservation":
        if (
            self.apple_crash_class is not None
            and self.triage_class is not ImageIOCrashTriageClass.STRONG_MEMORY_SAFETY
        ):
            raise ValueError("an Apple crash class requires a strong memory-safety signal")
        if self.evidence_complete != bool(self.crash_log_sha256 and self.crash_log_path):
            raise ValueError("complete crash evidence requires a retained crash log")
        for path in (self.case_result_path, self.input_path, self.crash_log_path):
            if path is not None:
                _validate_relative_path(path)
        return self


class ImageIOCrashCluster(DomainModel):
    schema_version: Literal["imageio-crash-cluster-v1"] = "imageio-crash-cluster-v1"
    cluster_id: str = Field(pattern=r"^imageio-cluster-[0-9a-f]{32}$")
    signature_sha256: str = Field(pattern=SHA256_PATTERN)
    triage_class: ImageIOCrashTriageClass
    apple_crash_class: AppleCrashClass | None = None
    observations: tuple[ImageIOCrashObservation, ...] = Field(min_length=1)
    representative_observation_id: str
    risk: int = Field(ge=1, le=5)
    ranking_score: int = Field(ge=0)
    ranking_reasons: tuple[str, ...] = Field(min_length=1)
    hunter_eligible: bool

    @model_validator(mode="after")
    def validate_cluster(self) -> "ImageIOCrashCluster":
        if {item.signature_sha256 for item in self.observations} != {
            self.signature_sha256
        }:
            raise ValueError("crash cluster contains more than one signature")
        if self.representative_observation_id not in {
            item.observation_id for item in self.observations
        }:
            raise ValueError("cluster representative is not an observation")
        expected_eligible = self.triage_class not in {
            ImageIOCrashTriageClass.ASSERTION,
            ImageIOCrashTriageClass.NULL_DEREFERENCE,
            ImageIOCrashTriageClass.INCOMPLETE,
        }
        if self.hunter_eligible != expected_eligible:
            raise ValueError("Hunter eligibility does not match triage class")
        return self

    @property
    def representative(self) -> ImageIOCrashObservation:
        return next(
            item
            for item in self.observations
            if item.observation_id == self.representative_observation_id
        )


class ImageIOCrashMinimization(DomainModel):
    schema_version: Literal["imageio-crash-minimization-v1"] = (
        "imageio-crash-minimization-v1"
    )
    target_signature_sha256: str = Field(pattern=SHA256_PATTERN)
    original_sha256: str = Field(pattern=SHA256_PATTERN)
    minimized_sha256: str = Field(pattern=SHA256_PATTERN)
    original_size_bytes: int = Field(ge=0)
    minimized_size_bytes: int = Field(ge=0)
    oracle_attempts: int = Field(ge=1)
    attempt_limit: int = Field(ge=1)
    protected_prefix_bytes: int = Field(ge=0)

    @property
    def reduction_percent(self) -> float:
        if not self.original_size_bytes:
            return 0.0
        return round(
            (1 - self.minimized_size_bytes / self.original_size_bytes) * 100,
            2,
        )


@dataclass(frozen=True)
class MinimizedImageIOCrash:
    record: ImageIOCrashMinimization
    payload: bytes


@dataclass(frozen=True)
class ImageIOCrashHunterPlan:
    clusters: tuple[ImageIOCrashCluster, ...]
    routing: HunterRoutingPlan
    allocation: BudgetAllocation
    admitted_work_items: tuple[HunterWorkItem, ...]


def load_imageio_crash_observations(root: Path) -> tuple[ImageIOCrashObservation, ...]:
    """Load only signaled fuzz results and verify their retained private artifacts."""

    store = _private_store_root(root)
    cases = store / "cases"
    if not cases.is_dir():
        return ()
    observations: list[ImageIOCrashObservation] = []
    for case_path in sorted(cases.glob("case-*.json")):
        result = ImageIOFuzzCaseResult.model_validate_json(
            _read_regular_file(case_path, maximum=_MAX_JSON_BYTES)
        )
        for execution in result.executions:
            if execution.classification is not ImageIOFuzzClassification.CRASH_CANDIDATE:
                continue
            route_root = (
                store
                / "interesting"
                / result.case.case_id
                / execution.route.value
            )
            input_path = route_root.parent / "input.dcm"
            crash_path = route_root / "crash.log"
            crash_log = (
                _read_regular_file(crash_path, maximum=_MAX_CRASH_LOG_BYTES)
                if crash_path.is_file() and not crash_path.is_symlink()
                else None
            )
            if not input_path.is_file() or input_path.is_symlink():
                raise RuntimeError(f"crash input is missing or unsafe: {input_path}")
            input_payload = _read_regular_file(
                input_path,
                maximum=execution.evidence.limits.max_input_bytes,
            )
            if _sha256_bytes(input_payload) != result.case.input_sha256:
                raise RuntimeError("retained crash input does not match its case digest")
            observations.append(
                normalize_imageio_crash(
                    case_id=result.case.case_id,
                    route=execution.route,
                    input_sha256=result.case.input_sha256,
                    input_size_bytes=result.case.input_size_bytes,
                    evidence=execution.evidence,
                    crash_log=crash_log,
                    case_result_path=case_path.relative_to(store).as_posix(),
                    input_path=input_path.relative_to(store).as_posix(),
                    crash_log_path=(
                        crash_path.relative_to(store).as_posix()
                        if crash_log is not None else None
                    ),
                )
            )
    return tuple(sorted(observations, key=lambda item: item.observation_id))


def normalize_imageio_crash(
    *,
    case_id: str,
    route: ImageIOAPIRoute,
    input_sha256: str,
    input_size_bytes: int,
    evidence: ImageIOHarnessEvidence,
    crash_log: bytes | None,
    case_result_path: str,
    input_path: str,
    crash_log_path: str | None,
) -> ImageIOCrashObservation:
    """Normalize ASLR-sensitive Apple crash text into one stable signature."""

    if evidence.exit_reason is not ImageIOVMExitReason.SIGNALED:
        raise ValueError("only signaled harness evidence can form a crash observation")
    evidence_sha256 = _sha256_json(evidence.model_dump(mode="json"))
    complete = bool(
        crash_log is not None
        and crash_log_path
        and evidence.evidence_complete
        and not evidence.crash_log_truncated
    )
    if crash_log is not None and evidence.crash_log_sha256 != _sha256_bytes(crash_log):
        raise RuntimeError("retained crash log does not match its evidence digest")
    text = crash_log.decode("utf-8", errors="replace") if crash_log is not None else ""
    exception_type = _field(text, "Exception Type")
    exception_subtype = _field(text, "Exception Subtype")
    fault_address = _fault_address(text)
    frames = _normalized_frames(text)
    triage_class, apple_crash_class = _triage(
        text=text,
        exception_type=exception_type,
        fault_address=fault_address,
        complete=complete,
    )
    signature = _sha256_json(
        {
            "exception_type": _normalize_exception(exception_type),
            "exception_subtype": _normalize_exception(exception_subtype),
            "triage_class": triage_class.value,
            "frames": frames[:8],
            "terminating_signal": evidence.terminating_signal,
        }
    )
    observation_id = "imageio-observation-" + hashlib.sha256(
        "\x00".join(
            (case_id, route.value, input_sha256, evidence_sha256)
        ).encode()
    ).hexdigest()[:32]
    return ImageIOCrashObservation(
        observation_id=observation_id,
        case_id=case_id,
        route=route,
        input_sha256=input_sha256,
        input_size_bytes=input_size_bytes,
        evidence_sha256=evidence_sha256,
        crash_log_sha256=(
            _sha256_bytes(crash_log) if crash_log is not None and complete else None
        ),
        exception_type=exception_type,
        exception_subtype=exception_subtype,
        fault_address=fault_address,
        normalized_frames=frames,
        signature_sha256=signature,
        triage_class=triage_class,
        apple_crash_class=apple_crash_class,
        evidence_complete=complete,
        case_result_path=case_result_path,
        input_path=input_path,
        crash_log_path=crash_log_path if complete else None,
    )


def cluster_imageio_crashes(
    observations: tuple[ImageIOCrashObservation, ...],
) -> tuple[ImageIOCrashCluster, ...]:
    """Deduplicate observations and rank clusters without an LLM call."""

    grouped: dict[str, list[ImageIOCrashObservation]] = {}
    for observation in observations:
        grouped.setdefault(observation.signature_sha256, []).append(observation)
    clusters: list[ImageIOCrashCluster] = []
    for signature, members in grouped.items():
        ordered = tuple(
            sorted(
                members,
                key=lambda item: (
                    not item.evidence_complete,
                    item.input_size_bytes,
                    item.input_sha256,
                    item.route.value,
                    item.observation_id,
                ),
            )
        )
        triage_class = min(
            (item.triage_class for item in ordered),
            key=_triage_priority,
        )
        apple_classes = {
            item.apple_crash_class for item in ordered if item.apple_crash_class is not None
        }
        apple_class = next(iter(apple_classes)) if len(apple_classes) == 1 else None
        risk = _risk_for(triage_class)
        route_count = len({item.route for item in ordered})
        complete_count = sum(item.evidence_complete for item in ordered)
        score = (
            risk * 100
            + min(complete_count, 3) * 20
            + min(route_count, 3) * 10
            + min(len(ordered), 5)
        )
        reasons = (
            f"triage:{triage_class.value}",
            f"complete_observations:{complete_count}",
            f"route_diversity:{route_count}",
            f"duplicate_observations:{max(0, len(ordered) - 1)}",
        )
        clusters.append(
            ImageIOCrashCluster(
                cluster_id="imageio-cluster-" + signature.removeprefix("sha256:")[:32],
                signature_sha256=signature,
                triage_class=triage_class,
                apple_crash_class=apple_class,
                observations=ordered,
                representative_observation_id=ordered[0].observation_id,
                risk=risk,
                ranking_score=score,
                ranking_reasons=reasons,
                hunter_eligible=triage_class not in {
                    ImageIOCrashTriageClass.ASSERTION,
                    ImageIOCrashTriageClass.NULL_DEREFERENCE,
                    ImageIOCrashTriageClass.INCOMPLETE,
                },
            )
        )
    return tuple(
        sorted(
            clusters,
            key=lambda item: (-item.ranking_score, item.cluster_id),
        )
    )


def build_imageio_crash_hunter_plan(
    *,
    store_root: Path,
    run_id: str,
    source_snapshot: str,
    budget: BudgetPolicy,
    hunter: str = IMAGEIO_CRASH_HUNTER,
) -> ImageIOCrashHunterPlan:
    """Create ranked existing-schema Hunter work and a private context packet."""

    if not re.fullmatch(SHA256_PATTERN, source_snapshot):
        raise ValueError("ImageIO Hunter source snapshot must be a SHA-256 digest")
    store = _private_store_root(store_root)
    observations = load_imageio_crash_observations(store)
    clusters = cluster_imageio_crashes(observations)
    work_items: list[HunterWorkItem] = []
    cluster_by_work_id: dict[str, ImageIOCrashCluster] = {}
    for cluster in clusters:
        if not cluster.hunter_eligible:
            continue
        files = _write_hunter_context(store, cluster)
        work_id = work_id_for(
            source_snapshot=source_snapshot,
            planning_policy=IMAGEIO_CRASH_RANKING_POLICY,
            slice_ids=(cluster.cluster_id,),
            files=files,
            hunter=hunter,
            scan_scope_digest=cluster.signature_sha256,
        )
        item = HunterWorkItem(
            work_id=work_id,
            run_id=run_id,
            source_snapshot=source_snapshot,
            scan_scope_digest=cluster.signature_sha256,
            planning_policy=IMAGEIO_CRASH_RANKING_POLICY,
            slice_ids=(cluster.cluster_id,),
            seed_file=files[0],
            files=files,
            hunter=hunter,
            risk=cluster.risk,
            required=(
                cluster.triage_class is ImageIOCrashTriageClass.STRONG_MEMORY_SAFETY
            ),
            routing_reasons=(
                "dynamic:imageio-crash-cluster",
                *cluster.ranking_reasons,
            ),
        )
        work_items.append(item)
        cluster_by_work_id[work_id] = cluster
    routing = HunterRoutingPlan(
        policy_version=IMAGEIO_CRASH_RANKING_POLICY,
        mode="signal",
        legacy_sessions=len(observations),
        work_items=tuple(work_items),
        scan_scope_digest=_sha256_json(
            [cluster.signature_sha256 for cluster in clusters]
        ),
    )
    allocation = _allocate_ranked_clusters(tuple(work_items), cluster_by_work_id, budget)
    by_work_id = {item.work_id: item for item in work_items}
    admitted = tuple(
        by_work_id[work_id] for work_id in allocation.admitted_work_ids
    )
    plan = ImageIOCrashHunterPlan(
        clusters=clusters,
        routing=routing,
        allocation=allocation,
        admitted_work_items=admitted,
    )
    _write_plan_manifest(store, plan)
    return plan


def minimize_imageio_crash(
    payload: bytes,
    *,
    target_signature_sha256: str,
    oracle: Callable[[bytes], str | None],
    max_attempts: int = 64,
    protected_prefix_bytes: int = 132,
) -> MinimizedImageIOCrash:
    """Deterministic bounded ddmin that accepts only the same crash signature."""

    if not re.fullmatch(SHA256_PATTERN, target_signature_sha256):
        raise ValueError("target crash signature must be a SHA-256 digest")
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    protected = min(max(0, protected_prefix_bytes), len(payload))
    attempts = 1
    if oracle(payload) != target_signature_sha256:
        raise ValueError("original payload does not reproduce the target crash signature")
    current = payload
    granularity = 2
    while len(current) > protected and attempts < max_attempts:
        mutable_size = len(current) - protected
        chunk_size = max(1, math.ceil(mutable_size / granularity))
        reduced = False
        for relative_start in range(0, mutable_size, chunk_size):
            if attempts >= max_attempts:
                break
            start = protected + relative_start
            end = min(len(current), start + chunk_size)
            candidate = current[:start] + current[end:]
            attempts += 1
            if oracle(candidate) == target_signature_sha256:
                current = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if reduced:
            continue
        if granularity >= mutable_size:
            break
        granularity = min(mutable_size, granularity * 2)
    return MinimizedImageIOCrash(
        record=ImageIOCrashMinimization(
            target_signature_sha256=target_signature_sha256,
            original_sha256=_sha256_bytes(payload),
            minimized_sha256=_sha256_bytes(current),
            original_size_bytes=len(payload),
            minimized_size_bytes=len(current),
            oracle_attempts=attempts,
            attempt_limit=max_attempts,
            protected_prefix_bytes=protected,
        ),
        payload=current,
    )


def _allocate_ranked_clusters(
    work_items: tuple[HunterWorkItem, ...],
    clusters: dict[str, ImageIOCrashCluster],
    budget: BudgetPolicy,
) -> BudgetAllocation:
    """Apply the shared session budget without re-sorting dynamic evidence."""

    remaining = budget.max_hunter_sessions
    retry_slots = (
        1
        if budget.max_retries_per_work_item > 0
        and len(work_items) > remaining
        and remaining > 1
        else 0
    )
    capacity = max(0, remaining - retry_slots)
    admitted_items = work_items[:capacity]
    admitted_ids = {item.work_id for item in admitted_items}
    deferred = {
        item.work_id: "max_hunter_sessions"
        for item in work_items
        if item.work_id not in admitted_ids
    }
    decisions: list[AdmissionDecision] = []
    ranking: list[AdmissionRankingRecord] = []
    for rank, item in enumerate(work_items, start=1):
        cluster = clusters[item.work_id]
        components = {
            "crash_class": cluster.risk * 100,
            "complete_observations": min(
                sum(observation.evidence_complete for observation in cluster.observations),
                3,
            ) * 20,
            "route_diversity": min(
                len({observation.route for observation in cluster.observations}),
                3,
            ) * 10,
            "reproduction_count": min(len(cluster.observations), 5),
        }
        disposition = "admitted" if item.work_id in admitted_ids else "budget_deferred"
        reason = (
            "dynamic crash-cluster priority"
            if disposition == "admitted" else "max_hunter_sessions"
        )
        if disposition == "admitted":
            decisions.append(
                AdmissionDecision(
                    work_id=item.work_id,
                    rank=rank,
                    quota="imageio_crash_priority",
                    component="ImageIO",
                    seed_file=item.seed_file,
                    score=cluster.ranking_score,
                    score_components=components,
                    reason=reason,
                    seed_family="dicom",
                    coverage_group=cluster.cluster_id,
                )
            )
        ranking.append(
            AdmissionRankingRecord(
                record_id="imageio-ranking-" + item.work_id.removeprefix("work_")[:24],
                work_id=item.work_id,
                pre_admission_rank=rank,
                component="ImageIO",
                seed_file=item.seed_file,
                score=cluster.ranking_score,
                score_components=components,
                chain_ids=(cluster.cluster_id,),
                missing_chain_elements=("bounded_binary_context",),
                guard_states=(),
                priority_class=cluster.triage_class.value,
                disposition=disposition,
                reason=reason,
                seed_family="dicom",
                coverage_group=cluster.cluster_id,
                logical_chain_group=cluster.signature_sha256,
                logical_chain_groups=(cluster.signature_sha256,),
            )
        )
    return BudgetAllocation(
        admitted_work_ids=tuple(item.work_id for item in admitted_items),
        deferred=deferred,
        critical_slots=sum(item.required for item in admitted_items),
        high_risk_slots=sum(not item.required and item.risk >= 4 for item in admitted_items),
        retry_slots=retry_slots,
        general_slots=sum(not item.required and item.risk < 4 for item in admitted_items),
        policy_version=IMAGEIO_CRASH_RANKING_POLICY,
        decisions=tuple(decisions),
        ranking=tuple(ranking),
    )


def _write_hunter_context(
    store: Path,
    cluster: ImageIOCrashCluster,
) -> tuple[str, ...]:
    representative = cluster.representative
    context_root = store / "hunter-context"
    if context_root.is_symlink():
        raise RuntimeError("Hunter context root may not be a symbolic link")
    context_root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(context_root, 0o700)
    directory = context_root / cluster.cluster_id
    if directory.is_symlink():
        raise RuntimeError("Hunter context directory may not be a symbolic link")
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    manifest = directory / "cluster.json"
    _write_private(
        manifest,
        (json.dumps(cluster.model_dump(mode="json"), indent=2, sort_keys=True) + "\n").encode(),
    )
    source_input = store / representative.input_path
    target_input = directory / "input.dcm"
    _copy_private(source_input, target_input)
    files = [
        manifest.relative_to(store).as_posix(),
        target_input.relative_to(store).as_posix(),
    ]
    if representative.crash_log_path is not None:
        target_crash = directory / "crash.log"
        _copy_private(store / representative.crash_log_path, target_crash)
        files.append(target_crash.relative_to(store).as_posix())
    return tuple(files)


def _write_plan_manifest(store: Path, plan: ImageIOCrashHunterPlan) -> None:
    payload = {
        "schema_version": "imageio-crash-hunter-plan-v1",
        "policy_version": IMAGEIO_CRASH_RANKING_POLICY,
        "clusters": [cluster.model_dump(mode="json") for cluster in plan.clusters],
        "routing": plan.routing.model_dump(mode="json"),
        "allocation": asdict(plan.allocation),
        "admitted_work_ids": [item.work_id for item in plan.admitted_work_items],
        "model_calls": 0,
    }
    _write_private(
        store / "hunter-plan.json",
        (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode(),
    )


def _triage(
    *,
    text: str,
    exception_type: str,
    fault_address: int | None,
    complete: bool,
) -> tuple[ImageIOCrashTriageClass, AppleCrashClass | None]:
    if not complete:
        return ImageIOCrashTriageClass.INCOMPLETE, None
    lowered = text.casefold()
    if any(
        marker in lowered
        for marker in (
            "assertion failed",
            "assertion failure",
            "precondition failed",
            "fatal error:",
        )
    ):
        return ImageIOCrashTriageClass.ASSERTION, None
    if "heap-buffer-overflow" in lowered or "stack-buffer-overflow" in lowered:
        if "write of size" in lowered:
            crash_class = AppleCrashClass.OUT_OF_BOUNDS_WRITE
        elif "read of size" in lowered:
            crash_class = AppleCrashClass.OUT_OF_BOUNDS_READ
        else:
            crash_class = AppleCrashClass.HEAP_CORRUPTION
        return ImageIOCrashTriageClass.STRONG_MEMORY_SAFETY, crash_class
    strong_markers: tuple[tuple[tuple[str, ...], AppleCrashClass], ...] = (
        (("heap-use-after-free", "use-after-free"), AppleCrashClass.USE_AFTER_FREE),
        (("out-of-bounds write", "heap-buffer-overflow write"), AppleCrashClass.OUT_OF_BOUNDS_WRITE),
        (("out-of-bounds read", "heap-buffer-overflow read"), AppleCrashClass.OUT_OF_BOUNDS_READ),
        (("integer overflow",), AppleCrashClass.INTEGER_OVERFLOW),
        (("type confusion",), AppleCrashClass.TYPE_CONFUSION),
        (
            (
                "heap-buffer-overflow",
                "stack-buffer-overflow",
                "heap corruption",
                "guard malloc",
                "double free",
                "malloc: corrupted",
            ),
            AppleCrashClass.HEAP_CORRUPTION,
        ),
    )
    for markers, crash_class in strong_markers:
        if any(marker in lowered for marker in markers):
            return ImageIOCrashTriageClass.STRONG_MEMORY_SAFETY, crash_class
    if "exc_bad_access" in exception_type.casefold() and fault_address is not None:
        if fault_address <= 0x1000:
            return ImageIOCrashTriageClass.NULL_DEREFERENCE, None
    if "exc_bad_access" in exception_type.casefold() and fault_address is not None:
        return ImageIOCrashTriageClass.NONNULL_BAD_ACCESS, None
    return ImageIOCrashTriageClass.UNDIFFERENTIATED, None


def _field(text: str, label: str) -> str:
    match = re.search(rf"^{re.escape(label)}:\s*(.*?)\s*$", text, re.MULTILINE)
    return match.group(1).strip() if match else ""


def _fault_address(text: str) -> int | None:
    match = _FAULT_ADDRESS.search(text)
    return int(match.group(1), 16) if match else None


def _normalized_frames(text: str) -> tuple[str, ...]:
    frames: list[str] = []
    in_crashed_thread = False
    for line in text.splitlines():
        if re.search(r"Thread\s+\d+\s+Crashed:", line):
            in_crashed_thread = True
            continue
        if in_crashed_thread and not line.strip():
            break
        if not in_crashed_thread:
            continue
        match = _FRAME.match(line)
        if match is None:
            continue
        image = match.group("image")
        symbol = _UUID.sub("<uuid>", match.group("symbol"))
        symbol = _ADDRESS.sub("<addr>", symbol)
        symbol = re.sub(r"\s+\+\s+\d+\s*$", "", symbol)
        frames.append(f"{image}!{' '.join(symbol.split())}")
    relevant = [
        frame
        for frame in frames
        if any(
            marker in frame.casefold()
            for marker in ("imageio", "coregraphics", "rawcamera", "dicom")
        )
    ]
    selected = relevant or frames
    return tuple(selected[:_FRAME_LIMIT])


def _normalize_exception(value: str) -> str:
    return " ".join(_ADDRESS.sub("<addr>", _UUID.sub("<uuid>", value)).split()).casefold()


def _triage_priority(value: ImageIOCrashTriageClass) -> int:
    return {
        ImageIOCrashTriageClass.STRONG_MEMORY_SAFETY: 0,
        ImageIOCrashTriageClass.NONNULL_BAD_ACCESS: 1,
        ImageIOCrashTriageClass.UNDIFFERENTIATED: 2,
        ImageIOCrashTriageClass.NULL_DEREFERENCE: 3,
        ImageIOCrashTriageClass.ASSERTION: 4,
        ImageIOCrashTriageClass.INCOMPLETE: 5,
    }[value]


def _risk_for(value: ImageIOCrashTriageClass) -> int:
    return {
        ImageIOCrashTriageClass.STRONG_MEMORY_SAFETY: 5,
        ImageIOCrashTriageClass.NONNULL_BAD_ACCESS: 4,
        ImageIOCrashTriageClass.UNDIFFERENTIATED: 2,
        ImageIOCrashTriageClass.NULL_DEREFERENCE: 1,
        ImageIOCrashTriageClass.ASSERTION: 1,
        ImageIOCrashTriageClass.INCOMPLETE: 1,
    }[value]


def _private_store_root(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError("ImageIO crash store may not be a symbolic link")
    resolved = expanded.resolve(strict=True)
    if _is_inside_git_worktree(resolved):
        raise ValueError("ImageIO crash artifacts may not be read or written in Git")
    if not resolved.is_dir() or resolved.is_symlink():
        raise ValueError("ImageIO crash store must be a regular directory")
    return resolved


def _read_regular_file(path: Path, *, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"private crash artifact is missing or unsafe: {path}")
    if path.stat().st_size > maximum:
        raise RuntimeError(f"private crash artifact exceeds its limit: {path}")
    return path.read_bytes()


def _copy_private(source: Path, target: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise RuntimeError(f"private crash artifact is missing or unsafe: {source}")
    if target.is_symlink():
        raise RuntimeError(f"private crash output may not be a symbolic link: {target}")
    shutil.copyfile(source, target)
    os.chmod(target, 0o600)


def _write_private(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise RuntimeError(f"private crash output may not be a symbolic link: {path}")
    path.write_bytes(payload)
    os.chmod(path, 0o600)


def _validate_relative_path(path: str) -> None:
    candidate = Path(path)
    if candidate.is_absolute() or ".." in candidate.parts or not path:
        raise ValueError("private crash artifact path must be relative and contained")


def _is_inside_git_worktree(path: Path) -> bool:
    return any((candidate / ".git").exists() for candidate in (path, *path.parents))


def _sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _sha256_json(payload: object) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return _sha256_bytes(canonical)
