"""Versioned M12 benchmark-case manifest and oracle-free projection."""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator

from benchmarks.run_libtiff_blind_benchmark import BenchmarkContractError

BENCHMARK_CASE_POLICY = "benchmark-case-v1"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = Path(__file__).with_name("schemas") / "benchmark-case-v1.schema.json"


@dataclass(frozen=True)
class BenchmarkSource:
    repository: str
    commit: str
    tree: str


@dataclass(frozen=True)
class DiscoveryInput:
    scan_manifest: str
    scan_manifest_sha256: str


@dataclass(frozen=True)
class BenchmarkBudget:
    max_hunter_sessions: int
    max_input_tokens: int
    max_output_tokens: int
    max_wall_clock_minutes: int
    max_context_bytes: int
    max_retries_per_work_item: int
    max_format_repairs_per_work_item: int
    max_parallel_hunters: int


@dataclass(frozen=True)
class BenchmarkEvaluation:
    kind: str
    reference: str
    sha256: str


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    partition: str
    supported_family: str
    required_hunter: str
    repetition_index: int
    source: BenchmarkSource
    discovery: DiscoveryInput
    budget: BenchmarkBudget
    evaluation: BenchmarkEvaluation
    manifest_sha256: str

    def discovery_payload(self) -> dict[str, Any]:
        """Return the closed allowlist passed to discovery workers."""
        return {
            "case": {
                "schema_version": 1,
                "policy_version": BENCHMARK_CASE_POLICY,
                "id": self.case_id,
                "repetition_index": self.repetition_index,
            },
            "source": asdict(self.source),
            "discovery": asdict(self.discovery),
            "budget": asdict(self.budget),
        }

    def discovery_bytes(self) -> bytes:
        """Canonical bytes used for hashing and process-boundary transfer."""
        return (
            json.dumps(
                self.discovery_payload(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

    @property
    def discovery_sha256(self) -> str:
        return "sha256:" + hashlib.sha256(self.discovery_bytes()).hexdigest()


def load_benchmark_case(
    path: Path,
    *,
    repository_root: Path = PROJECT_ROOT,
) -> BenchmarkCase:
    """Load one case, validate its references, and keep evaluator data sealed."""
    manifest_path = path.resolve()
    root = repository_root.resolve()
    try:
        raw_bytes = manifest_path.read_bytes()
        payload = tomllib.loads(raw_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise BenchmarkContractError("benchmark case manifest is unreadable") from exc

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "root"
        raise BenchmarkContractError(
            f"benchmark-case-v1 validation failed at {location}: {error.message}"
        )

    case = payload["case"]
    source = payload["source"]
    discovery = payload["discovery"]
    budget = payload["budget"]
    evaluation = payload["evaluation"]

    scan_reference = _verified_reference(
        root,
        discovery["scan_manifest"],
        discovery["scan_manifest_sha256"],
        kind="scan manifest",
    )
    evaluator_reference = _verified_reference(
        root,
        evaluation["reference"],
        evaluation["sha256"],
        kind="evaluator",
    )

    return BenchmarkCase(
        case_id=case["id"],
        partition=case["partition"],
        supported_family=case["supported_family"],
        required_hunter=case["required_hunter"],
        repetition_index=case["repetition_index"],
        source=BenchmarkSource(**source),
        discovery=DiscoveryInput(
            scan_manifest=scan_reference,
            scan_manifest_sha256=discovery["scan_manifest_sha256"],
        ),
        budget=BenchmarkBudget(**budget),
        evaluation=BenchmarkEvaluation(
            kind=evaluation["kind"],
            reference=evaluator_reference,
            sha256=evaluation["sha256"],
        ),
        manifest_sha256="sha256:" + hashlib.sha256(raw_bytes).hexdigest(),
    )


def _verified_reference(
    root: Path,
    value: str,
    expected_sha256: str,
    *,
    kind: str,
) -> str:
    reference = PurePosixPath(value)
    if reference.is_absolute() or ".." in reference.parts or "\\" in value:
        raise BenchmarkContractError(f"{kind} reference must be repository-relative")
    resolved = (root / Path(*reference.parts)).resolve()
    if not resolved.is_relative_to(root):
        raise BenchmarkContractError(f"{kind} reference escapes repository root")
    if not resolved.is_file():
        raise BenchmarkContractError(f"{kind} reference does not exist: {value}")
    actual = "sha256:" + _sha256_file(resolved)
    if actual != expected_sha256:
        raise BenchmarkContractError(f"{kind} reference hash mismatch: {value}")
    return reference.as_posix()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
