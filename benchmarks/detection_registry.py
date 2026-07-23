"""Strict historical-detection registry used by M11.5 regression gates."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmarks.run_libtiff_blind_benchmark import BenchmarkContractError

REGISTRY_POLICY = "historical-detection-registry-v1"
VALID_STATUSES = frozenset({"must_detect", "recovery_target", "known_gap"})


@dataclass(frozen=True)
class DetectionBaseline:
    baseline_id: str
    status: str
    source_repository: str
    source_commit: str
    source_tree: str
    expected_hunter: str
    required_paths: tuple[str, ...]
    weakness_terms: tuple[str, ...]
    scan_manifest: str = ""
    oracle: str = ""
    last_known_good_scanner_commit: str = ""
    maximum_admission_rank: int = 0


def load_detection_registry(path: Path) -> tuple[DetectionBaseline, ...]:
    """Load a closed registry and reject silent weakening of release entries."""
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    registry = payload.get("registry") or {}
    if registry.get("schema_version") != 1:
        raise BenchmarkContractError("unsupported detection registry schema")
    if registry.get("policy_version") != REGISTRY_POLICY:
        raise BenchmarkContractError("unsupported detection registry policy")
    raw_entries = payload.get("detection")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise BenchmarkContractError("detection registry must not be empty")

    root = path.resolve().parents[1]
    entries: list[DetectionBaseline] = []
    seen: set[str] = set()
    for raw in raw_entries:
        if not isinstance(raw, dict):
            raise BenchmarkContractError("detection registry entry must be a table")
        entry = _parse_entry(raw)
        if entry.baseline_id in seen:
            raise BenchmarkContractError(
                f"duplicate detection baseline: {entry.baseline_id}"
            )
        seen.add(entry.baseline_id)
        for reference in (entry.scan_manifest, entry.oracle):
            if reference and not (root / reference).is_file():
                raise BenchmarkContractError(
                    f"detection baseline reference does not exist: {reference}"
                )
        entries.append(entry)

    if not any(entry.status == "must_detect" for entry in entries):
        raise BenchmarkContractError("registry must protect at least one detection")
    return tuple(entries)


def protected_detection_ids(
    entries: tuple[DetectionBaseline, ...],
) -> tuple[str, ...]:
    return tuple(
        entry.baseline_id for entry in entries if entry.status == "must_detect"
    )


def assert_no_status_demotion(
    before: tuple[DetectionBaseline, ...],
    after: tuple[DetectionBaseline, ...],
) -> None:
    """A protected detection cannot be removed or demoted without a policy change."""
    after_by_id = {entry.baseline_id: entry for entry in after}
    for entry in before:
        if entry.status != "must_detect":
            continue
        current = after_by_id.get(entry.baseline_id)
        if current is None:
            raise BenchmarkContractError(
                f"protected detection was removed: {entry.baseline_id}"
            )
        if current.status != "must_detect":
            raise BenchmarkContractError(
                f"protected detection was demoted: {entry.baseline_id}"
            )


def _parse_entry(raw: dict[str, Any]) -> DetectionBaseline:
    required_strings = (
        "id",
        "status",
        "source_repository",
        "source_commit",
        "source_tree",
        "expected_hunter",
    )
    values: dict[str, str] = {}
    for key in required_strings:
        value = raw.get(key)
        if not isinstance(value, str) or not value.strip():
            raise BenchmarkContractError(
                f"detection baseline requires non-empty {key}"
            )
        values[key] = value.strip()
    if values["status"] not in VALID_STATUSES:
        raise BenchmarkContractError(
            f"unsupported detection status: {values['status']}"
        )
    required_paths = _string_tuple(raw, "required_paths")
    weakness_terms = _string_tuple(raw, "weakness_terms")
    maximum_rank = raw.get("maximum_admission_rank", 0)
    if not isinstance(maximum_rank, int) or isinstance(maximum_rank, bool):
        raise BenchmarkContractError("maximum_admission_rank must be an integer")
    if values["status"] == "must_detect" and maximum_rank < 1:
        raise BenchmarkContractError(
            "must_detect entry requires a positive maximum_admission_rank"
        )
    return DetectionBaseline(
        baseline_id=values["id"],
        status=values["status"],
        source_repository=values["source_repository"],
        source_commit=values["source_commit"],
        source_tree=values["source_tree"],
        expected_hunter=values["expected_hunter"],
        required_paths=required_paths,
        weakness_terms=weakness_terms,
        scan_manifest=str(raw.get("scan_manifest") or ""),
        oracle=str(raw.get("oracle") or ""),
        last_known_good_scanner_commit=str(
            raw.get("last_known_good_scanner_commit") or ""
        ),
        maximum_admission_rank=maximum_rank,
    )


def _string_tuple(raw: dict[str, Any], key: str) -> tuple[str, ...]:
    value = raw.get(key)
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise BenchmarkContractError(
            f"detection baseline requires a non-empty string list for {key}"
        )
    return tuple(item.strip() for item in value)
