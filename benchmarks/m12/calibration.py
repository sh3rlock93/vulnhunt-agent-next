"""Closed M12.2 calibration catalog and oracle-isolation checks."""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from jsonschema import Draft202012Validator

from benchmarks.m12.benchmark_case import BenchmarkCase, load_benchmark_case
from benchmarks.run_libtiff_blind_benchmark import (
    BenchmarkContractError,
    load_scan_manifest,
)

CALIBRATION_CATALOG_POLICY = "calibration-catalog-v1"
CALIBRATION_ORACLE_POLICY = "calibration-oracle-v1"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CATALOG = PROJECT_ROOT / "benchmarks/m12/calibration/catalog.toml"
ORACLE_ROOT = PROJECT_ROOT / "benchmarks/oracles/m12-calibration"
ORACLE_SCHEMA = Path(__file__).with_name("schemas") / "calibration-oracle-v1.schema.json"
REQUIRED_FAMILIES = frozenset({
    "bounded-write-capacity",
    "parser-cursor-oob-read",
    "integer-signedness-memory",
})


@dataclass(frozen=True)
class CalibrationDefinition:
    case: BenchmarkCase
    manifest: str
    manifest_sha256: str
    oracle: dict[str, Any]


@dataclass(frozen=True)
class CalibrationCatalog:
    path: Path
    sha256: str
    repetitions_per_case: int
    selection_registry_sha256: str
    definitions: tuple[CalibrationDefinition, ...]

    def discovery_envelope(self) -> dict[str, Any]:
        """Return the only data allowed to cross into discovery workers."""
        return {
            "schema_version": 1,
            "policy_version": CALIBRATION_CATALOG_POLICY,
            "catalog_sha256": self.sha256,
            "repetitions_per_case": self.repetitions_per_case,
            "cases": [
                definition.case.discovery_payload()
                for definition in sorted(
                    self.definitions, key=lambda item: item.case.case_id
                )
            ],
        }

    def discovery_bytes(self) -> bytes:
        return (
            json.dumps(
                self.discovery_envelope(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")


def load_calibration_catalog(
    path: Path = DEFAULT_CATALOG,
    *,
    repository_root: Path = PROJECT_ROOT,
) -> CalibrationCatalog:
    """Validate the four-case calibration corpus and its sealed controls."""
    root = repository_root.resolve()
    catalog_path = path.resolve()
    payload = _load_toml(catalog_path, label="calibration catalog")
    header = payload.get("catalog")
    entries = payload.get("case")
    if not isinstance(header, dict) or not isinstance(entries, list):
        raise BenchmarkContractError("calibration catalog is missing sections")
    if set(header) != {
        "schema_version",
        "policy_version",
        "partition",
        "repetitions_per_case",
        "selection_registry_sha256",
    }:
        raise BenchmarkContractError("calibration catalog header is not closed")
    if (
        header.get("schema_version") != 1
        or header.get("policy_version") != CALIBRATION_CATALOG_POLICY
        or header.get("partition") != "calibration"
        or header.get("repetitions_per_case") != 3
    ):
        raise BenchmarkContractError("unsupported calibration catalog contract")
    selection_registry_sha256 = str(header.get("selection_registry_sha256") or "")
    if not _valid_sha256(selection_registry_sha256):
        raise BenchmarkContractError("calibration selection registry hash is invalid")
    if len(entries) != 4:
        raise BenchmarkContractError("M12.2 calibration catalog requires exactly four cases")

    definitions = tuple(
        _load_definition(entry, root)
        for entry in entries
    )
    _validate_catalog_semantics(definitions)
    catalog = CalibrationCatalog(
        path=catalog_path,
        sha256=_sha256(catalog_path),
        repetitions_per_case=3,
        selection_registry_sha256=selection_registry_sha256,
        definitions=tuple(sorted(definitions, key=lambda item: item.case.case_id)),
    )
    _validate_blind_projection(catalog)
    return catalog


def _load_definition(entry: Any, root: Path) -> CalibrationDefinition:
    if not isinstance(entry, dict) or set(entry) != {"manifest", "sha256"}:
        raise BenchmarkContractError("calibration case reference is not closed")
    manifest = _resolve_reference(root, entry["manifest"], file=True)
    claimed_sha = str(entry["sha256"])
    if _sha256(manifest) != claimed_sha:
        raise BenchmarkContractError("calibration case manifest hash mismatch")
    case = load_benchmark_case(manifest, repository_root=root)
    if case.partition != "calibration" or case.repetition_index != 1:
        raise BenchmarkContractError("calibration base case identity is invalid")

    scan_path = _resolve_reference(root, case.discovery.scan_manifest, file=True)
    scan = load_scan_manifest(scan_path)
    if scan["source"] != {
        "repository": case.source.repository,
        "commit": case.source.commit,
        "tree": case.source.tree,
    }:
        raise BenchmarkContractError("calibration scan source differs from its case")
    if scan["benchmark"].get("oracle_policy") != "blind-oracle-v1":
        raise BenchmarkContractError("calibration scan is not oracle-isolated")

    oracle_path = _resolve_reference(root, case.evaluation.reference, file=True)
    try:
        oracle_path.relative_to((root / ORACLE_ROOT.relative_to(PROJECT_ROOT)).resolve())
    except ValueError as exc:
        raise BenchmarkContractError("calibration oracle is outside the sealed root") from exc
    oracle = _load_oracle(oracle_path)
    oracle_header = oracle["oracle"]
    if (
        oracle_header["case_id"] != case.case_id
        or oracle_header["supported_family"] != case.supported_family
        or oracle_header["required_hunter"] != case.required_hunter
    ):
        raise BenchmarkContractError("calibration oracle identity differs from its case")
    fixed = oracle["fixed_source"]
    if (
        fixed["repository"] != case.source.repository
        or fixed["commit"] == case.source.commit
        or fixed["tree"] == case.source.tree
    ):
        raise BenchmarkContractError("calibration fixed control is invalid")
    location = oracle["location"]
    if location["sink_file"] not in location["required_paths"]:
        raise BenchmarkContractError("calibration sink is absent from required paths")
    if location.get("entry_file") not in location["required_paths"]:
        raise BenchmarkContractError("calibration entry is absent from required paths")
    for prefix in ("entry", "sink"):
        if int(location[f"{prefix}_line_min"]) > int(location[f"{prefix}_line_max"]):
            raise BenchmarkContractError("calibration source range is inverted")
    return CalibrationDefinition(
        case=case,
        manifest=manifest.relative_to(root).as_posix(),
        manifest_sha256=claimed_sha,
        oracle=oracle,
    )


def _load_oracle(path: Path) -> dict[str, Any]:
    payload = _load_toml(path, label="calibration oracle")
    schema = json.loads(ORACLE_SCHEMA.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "root"
        raise BenchmarkContractError(
            f"calibration-oracle-v1 validation failed at {location}: {error.message}"
        )
    return payload


def _validate_catalog_semantics(
    definitions: Iterable[CalibrationDefinition],
) -> None:
    items = tuple(definitions)
    case_ids = [item.case.case_id for item in items]
    repositories = [_normalize_repository(item.case.source.repository) for item in items]
    sources = [(item.case.source.commit, item.case.source.tree) for item in items]
    if len(case_ids) != len(set(case_ids)):
        raise BenchmarkContractError("calibration case IDs are not unique")
    if len(repositories) != len(set(repositories)):
        raise BenchmarkContractError("calibration repositories are not unique")
    if len(sources) != len(set(sources)):
        raise BenchmarkContractError("calibration vulnerable sources are not unique")
    families = {item.case.supported_family for item in items}
    if not REQUIRED_FAMILIES.issubset(families):
        raise BenchmarkContractError("calibration corpus does not cover all supported families")


def _validate_blind_projection(catalog: CalibrationCatalog) -> None:
    encoded = catalog.discovery_bytes().decode("utf-8")
    structural_tokens = (
        '"evaluation"',
        '"partition"',
        '"supported_family"',
        '"required_hunter"',
        "benchmarks/oracles/",
        "fixed_source",
        "upstream_reference",
        "weakness",
        "reproduction",
    )
    if any(token in encoded for token in structural_tokens):
        raise BenchmarkContractError("calibration discovery projection exposes evaluator data")
    for definition in catalog.definitions:
        oracle = definition.oracle
        forbidden = {
            oracle["oracle"]["upstream_reference"],
            oracle["oracle"]["weakness"],
            oracle["oracle"]["supported_family"],
            oracle["oracle"]["required_hunter"],
            oracle["fixed_source"]["commit"],
            oracle["fixed_source"]["tree"],
            *oracle["location"]["required_paths"],
        }
        if any(str(value) in encoded for value in forbidden):
            raise BenchmarkContractError("calibration discovery projection leaks oracle values")


def _resolve_reference(root: Path, raw: Any, *, file: bool) -> Path:
    value = str(raw)
    reference = PurePosixPath(value)
    if reference.is_absolute() or ".." in reference.parts or "\\" in value:
        raise BenchmarkContractError("calibration reference must be repository-relative")
    resolved = (root / Path(*reference.parts)).resolve()
    if not resolved.is_relative_to(root):
        raise BenchmarkContractError("calibration reference escapes repository root")
    if file and not resolved.is_file():
        raise BenchmarkContractError(f"calibration reference does not exist: {value}")
    return resolved


def _load_toml(path: Path, *, label: str) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise BenchmarkContractError(f"{label} is unreadable") from exc


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _valid_sha256(value: str) -> bool:
    return len(value) == 71 and value.startswith("sha256:") and all(
        character in "0123456789abcdef" for character in value[7:]
    )


def _normalize_repository(value: str) -> str:
    return value.rstrip("/").removesuffix(".git").lower()
