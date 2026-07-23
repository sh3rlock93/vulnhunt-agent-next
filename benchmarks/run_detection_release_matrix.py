"""Validate and evaluate the closed M11.5 no-regression release matrix."""
from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.detection_registry import (
    DetectionBaseline,
    load_detection_registry,
)
from benchmarks.run_libtiff_blind_benchmark import BenchmarkContractError

MATRIX_POLICY = "detection-release-matrix-v1"
RECEIPT_POLICY = "authenticated-detection-receipt-v1"


@dataclass(frozen=True)
class ReleaseGate:
    baseline_id: str
    ci_job: str
    authenticated_receipt: str = ""
    require_differential_reproduction: bool = False


def validate_release_contract(
    registry_path: Path,
    matrix_path: Path,
    receipts_path: Path,
) -> tuple[ReleaseGate, ...]:
    baselines = load_detection_registry(registry_path)
    protected = {
        item.baseline_id: item
        for item in baselines
        if item.status == "must_detect"
    }
    matrix = tomllib.loads(matrix_path.read_text(encoding="utf-8"))
    metadata = matrix.get("matrix") or {}
    if metadata.get("schema_version") != 1:
        raise BenchmarkContractError("unsupported release matrix schema")
    if metadata.get("policy_version") != MATRIX_POLICY:
        raise BenchmarkContractError("unsupported release matrix policy")

    raw_gates = matrix.get("gate")
    if not isinstance(raw_gates, list) or not raw_gates:
        raise BenchmarkContractError("release matrix must not be empty")
    gates = tuple(_parse_gate(item) for item in raw_gates)
    gate_ids = [item.baseline_id for item in gates]
    if len(gate_ids) != len(set(gate_ids)):
        raise BenchmarkContractError("release matrix contains duplicate baselines")
    if set(gate_ids) != set(protected):
        missing = sorted(set(protected) - set(gate_ids))
        extra = sorted(set(gate_ids) - set(protected))
        raise BenchmarkContractError(
            f"release matrix coverage mismatch: missing={missing}, extra={extra}"
        )

    receipts = _load_receipts(receipts_path)
    for gate in gates:
        baseline = protected[gate.baseline_id]
        _validate_baseline_gate(baseline, gate, receipts)
    return gates


def evaluate_release_matrix(
    gates: tuple[ReleaseGate, ...],
    statuses: dict[str, str],
) -> dict[str, Any]:
    expected_jobs = {gate.ci_job for gate in gates}
    unknown = sorted(set(statuses) - expected_jobs)
    if unknown:
        raise BenchmarkContractError(f"unknown release job statuses: {unknown}")
    results = []
    for gate in gates:
        status = statuses.get(gate.ci_job, "missing")
        results.append({
            "baseline_id": gate.baseline_id,
            "ci_job": gate.ci_job,
            "status": status,
            "passed": status == "success",
            "authenticated_receipt": gate.authenticated_receipt,
        })
    return {
        "schema_version": 1,
        "policy_version": MATRIX_POLICY,
        "passed": all(item["passed"] for item in results),
        "protected_detection_ids": [gate.baseline_id for gate in gates],
        "results": results,
    }


def _parse_gate(raw: Any) -> ReleaseGate:
    if not isinstance(raw, dict):
        raise BenchmarkContractError("release gate must be a table")
    baseline_id = str(raw.get("baseline_id") or "").strip()
    ci_job = str(raw.get("ci_job") or "").strip()
    if not baseline_id or not ci_job:
        raise BenchmarkContractError("release gate requires baseline_id and ci_job")
    require_differential = raw.get("require_differential_reproduction", False)
    if not isinstance(require_differential, bool):
        raise BenchmarkContractError(
            "require_differential_reproduction must be a boolean"
        )
    return ReleaseGate(
        baseline_id=baseline_id,
        ci_job=ci_job,
        authenticated_receipt=str(raw.get("authenticated_receipt") or "").strip(),
        require_differential_reproduction=require_differential,
    )


def _load_receipts(path: Path) -> dict[str, dict[str, Any]]:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    metadata = payload.get("receipts") or {}
    if metadata.get("schema_version") != 1:
        raise BenchmarkContractError("unsupported authenticated receipt schema")
    if metadata.get("policy_version") != RECEIPT_POLICY:
        raise BenchmarkContractError("unsupported authenticated receipt policy")
    runs = payload.get("run")
    if not isinstance(runs, list):
        raise BenchmarkContractError("authenticated receipt runs must be a list")
    by_id: dict[str, dict[str, Any]] = {}
    for run in runs:
        if not isinstance(run, dict) or not str(run.get("id") or ""):
            raise BenchmarkContractError("authenticated receipt requires an id")
        run_id = str(run["id"])
        if run_id in by_id:
            raise BenchmarkContractError(f"duplicate authenticated receipt: {run_id}")
        if run.get("complete") is not True or run.get("oracle_isolated") is not True:
            raise BenchmarkContractError(f"untrusted authenticated receipt: {run_id}")
        root = str(run.get("frozen_root_sha256") or "")
        if re.fullmatch(r"[0-9a-f]{64}", root) is None:
            raise BenchmarkContractError(f"invalid frozen root in receipt: {run_id}")
        by_id[run_id] = run
    return by_id


def _validate_baseline_gate(
    baseline: DetectionBaseline,
    gate: ReleaseGate,
    receipts: dict[str, dict[str, Any]],
) -> None:
    if gate.require_differential_reproduction and not gate.authenticated_receipt:
        raise BenchmarkContractError(
            "differential reproduction requires an authenticated receipt: "
            f"{baseline.baseline_id}"
        )
    if not gate.authenticated_receipt:
        return
    receipt = receipts.get(gate.authenticated_receipt)
    if receipt is None:
        raise BenchmarkContractError(
            f"missing authenticated receipt: {gate.authenticated_receipt}"
        )
    if (
        receipt.get("source_repository") != baseline.source_repository
        or receipt.get("source_commit") != baseline.source_commit
        or receipt.get("source_tree") != baseline.source_tree
    ):
        raise BenchmarkContractError(
            f"authenticated receipt source mismatch: {baseline.baseline_id}"
        )
    detections = receipt.get("detection") or []
    match = next((
        item for item in detections
        if isinstance(item, dict)
        and item.get("baseline_id") == baseline.baseline_id
    ), None)
    if match is None or match.get("candidate_present") is not True:
        raise BenchmarkContractError(
            f"authenticated receipt lacks detection: {baseline.baseline_id}"
        )
    if match.get("hunter") != baseline.expected_hunter:
        raise BenchmarkContractError(
            f"authenticated receipt Hunter mismatch: {baseline.baseline_id}"
        )
    if not set(baseline.required_paths).issubset(match.get("paths") or []):
        raise BenchmarkContractError(
            f"authenticated receipt path mismatch: {baseline.baseline_id}"
        )
    if (
        gate.require_differential_reproduction
        and match.get("differential_reproduction") is not True
    ):
        raise BenchmarkContractError(
            f"authenticated receipt lacks differential proof: {baseline.baseline_id}"
        )


def _parse_statuses(values: list[str]) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for value in values:
        job, separator, status = value.partition("=")
        if not separator or not job or not status:
            raise BenchmarkContractError(f"invalid job status: {value}")
        if job in statuses:
            raise BenchmarkContractError(f"duplicate job status: {job}")
        statuses[job] = status
    return statuses


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def _default_registry() -> Path:
    return _root() / "benchmarks" / "historical-detections.toml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("validate", "evaluate"))
    parser.add_argument("--registry", type=Path, default=_default_registry())
    parser.add_argument(
        "--matrix",
        type=Path,
        default=_root() / "benchmarks" / "detection-release-matrix.toml",
    )
    parser.add_argument(
        "--receipts",
        type=Path,
        default=_root() / "benchmarks" / "authenticated-detection-receipts.toml",
    )
    parser.add_argument("--status", action="append", default=[])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        gates = validate_release_contract(
            args.registry.resolve(),
            args.matrix.resolve(),
            args.receipts.resolve(),
        )
        result = {
            "schema_version": 1,
            "policy_version": MATRIX_POLICY,
            "passed": True,
            "protected_detection_ids": [gate.baseline_id for gate in gates],
        }
        if args.command == "evaluate":
            result = evaluate_release_matrix(gates, _parse_statuses(args.status))
    except (BenchmarkContractError, FileNotFoundError, ValueError) as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, indent=2))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
