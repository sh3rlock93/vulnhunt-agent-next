"""Deterministic M12 benchmark metrics over frozen, authenticated artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Sequence

from jsonschema import Draft202012Validator

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.m12.benchmark_case import BenchmarkCase, load_benchmark_case
from benchmarks.run_libtiff_blind_benchmark import (
    BenchmarkContractError,
    verify_frozen,
)

METRICS_INPUT_POLICY = "benchmark-metrics-input-v1"
METRICS_POLICY = "benchmark-metrics-v1"
SCHEMA_ROOT = Path(__file__).with_name("schemas")
K_VALUES = (3, 6, 12)
VALID_OUTCOMES = frozenset({"completed", "budget_limited"})


@dataclass(frozen=True)
class VerifiedRun:
    run_id: str
    case: BenchmarkCase
    freeze_root_sha256: str
    case_manifest_sha256: str
    receipt_sha256: str
    candidates_sha256: str
    adjudications_sha256: str
    receipt: dict[str, Any]
    candidates: tuple[dict[str, Any], ...]
    admission_adjudications: tuple[dict[str, Any], ...]
    adjudications: tuple[dict[str, Any], ...]

    @property
    def valid(self) -> bool:
        return self.receipt["outcome"] in VALID_OUTCOMES

    @property
    def usage(self) -> dict[str, int]:
        return self.receipt["usage"]

    @property
    def model_tokens(self) -> int:
        usage = self.usage
        return sum(
            int(usage[key])
            for key in (
                "input_tokens",
                "output_tokens",
                "cache_read_tokens",
                "cache_write_tokens",
            )
        )

    @property
    def input_tokens(self) -> int:
        usage = self.usage
        return sum(
            int(usage[key])
            for key in ("input_tokens", "cache_read_tokens", "cache_write_tokens")
        )


@dataclass(frozen=True)
class InvalidRun:
    run_id: str
    reason: str


def reduce_metrics(
    input_path: Path,
    *,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    """Reduce one immutable cohort into exact, order-independent metrics."""
    root = (repository_root or input_path.resolve().parent).resolve()
    payload = _load_toml(input_path, "benchmark-metrics-input-v1.schema.json")
    raw_runs = payload["run"]
    run_ids = [str(item["run_id"]) for item in raw_runs]
    if len(run_ids) != len(set(run_ids)):
        raise BenchmarkContractError("benchmark metrics input contains duplicate run IDs")

    verified: list[VerifiedRun] = []
    invalid: list[InvalidRun] = []
    for raw_run in sorted(raw_runs, key=lambda item: str(item["run_id"])):
        try:
            verified.append(_load_verified_run(raw_run, root))
        except (BenchmarkContractError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            invalid.append(InvalidRun(str(raw_run["run_id"]), str(exc)))

    _validate_cohort_consistency(verified)

    valid = [run for run in verified if run.valid]
    invalid_execution = [run for run in verified if not run.valid]
    all_invalid_ids = sorted(
        [item.run_id for item in invalid]
        + [run.run_id for run in invalid_execution]
    )
    requested_ids = sorted(run_ids)
    valid_ids = sorted(run.run_id for run in valid)

    detection_metrics = {
        "admission_at_k": _run_rates_at_k(valid, _admitted),
        "hunter_detection_at_k": _run_rates_at_k(valid, _hunter_detected),
        "reportable_detection_at_k": _run_rates_at_k(valid, _reportable_detected),
    }
    precision = _precision(valid)
    costs = _cost_metrics(
        verified,
        valid,
        precision["real_candidate_keys"],
        [item.run_id for item in invalid],
    )
    negative = _negative_metrics(valid)

    result = {
        "schema_version": 1,
        "policy_version": METRICS_POLICY,
        "cohort": {
            "id": payload["cohort"]["id"],
            "snapshot_sha256": payload["cohort"]["snapshot_sha256"],
        },
        "run_accounting": {
            "requested_run_ids": requested_ids,
            "valid_run_ids": valid_ids,
            "invalid_run_ids": all_invalid_ids,
            "valid_run_rate": _id_rate(requested_ids, valid_ids),
            "artifact_failures": [asdict(item) for item in sorted(invalid, key=lambda item: item.run_id)],
            "execution_failures": [
                {"run_id": run.run_id, "outcome": run.receipt["outcome"]}
                for run in sorted(invalid_execution, key=lambda item: item.run_id)
            ],
        },
        "detection": detection_metrics,
        "case_results": _case_results(valid),
        "precision": precision,
        "negative": negative,
        "cost": costs,
        "provenance": {
            "runs": [_run_provenance(run) for run in sorted(verified, key=lambda item: item.run_id)],
            "unverified_run_ids": sorted(item.run_id for item in invalid),
        },
    }
    return result


def canonical_json_bytes(metrics: dict[str, Any]) -> bytes:
    return (json.dumps(metrics, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def render_markdown(metrics: dict[str, Any]) -> str:
    """Render a compact table without changing metric semantics."""
    lines = [
        "# M12 benchmark metrics",
        "",
        f"- Policy: `{metrics['policy_version']}`",
        f"- Cohort: `{metrics['cohort']['id']}`",
        f"- Snapshot: `{metrics['cohort']['snapshot_sha256']}`",
        "",
        "| Metric | k | Numerator | Denominator | Rate |",
        "|---|---:|---:|---:|---:|",
    ]
    valid_rate = metrics["run_accounting"]["valid_run_rate"]
    lines.append(_metric_row("valid_run_rate", "—", valid_rate))
    for name in ("admission_at_k", "hunter_detection_at_k", "reportable_detection_at_k"):
        for k in ("3", "6", "12"):
            lines.append(_metric_row(name, k, metrics["detection"][name][k]))
    lines.append(_metric_row("reportable_precision", "—", metrics["precision"]["reportable_precision"]))
    lines.append(
        _metric_row(
            "fixed_target_false_positive_rate",
            "—",
            metrics["negative"]["fixed_target_false_positive_rate"],
        )
    )
    lines.append(
        _metric_row(
            "false_escalation_rate",
            "—",
            metrics["negative"]["false_escalation_rate"],
        )
    )
    cost = metrics["cost"]
    lines.extend([
        "",
        "| Cost | Value | Numerator | Denominator |",
        "|---|---:|---:|---:|",
        (
            "| tokens_per_reportable | "
            f"{_display_cost(cost['tokens_per_reportable'])} | "
            f"{cost['tokens_per_reportable']['numerator']} | "
            f"{cost['tokens_per_reportable']['denominator']} |"
        ),
        (
            "| median_input_tokens_per_valid_run | "
            f"{_display(cost['tokens_per_valid_run']['median'])} | "
            f"{cost['tokens_per_valid_run']['total']} | "
            f"{cost['tokens_per_valid_run']['denominator']} |"
        ),
        "",
    ])
    return "\n".join(lines)


def _load_verified_run(raw: dict[str, Any], root: Path) -> VerifiedRun:
    run_id = str(raw["run_id"])
    freeze_root = _resolve_reference(root, str(raw["freeze_root"]), directory=True)
    freeze_manifest = verify_frozen(freeze_root)
    freeze_sha = "sha256:" + str(freeze_manifest["root_sha256"])
    if freeze_sha != raw["freeze_root_sha256"]:
        raise BenchmarkContractError(f"freeze root hash mismatch: {run_id}")

    case_path = _verified_file(root, raw["case_manifest"], raw["case_manifest_sha256"])
    receipt = _verified_json(
        root,
        raw["receipt"],
        raw["receipt_sha256"],
        "authenticated-benchmark-receipt-v1.schema.json",
    )
    candidates = _verified_json(
        root,
        raw["candidates"],
        raw["candidates_sha256"],
        "benchmark-candidates-v1.schema.json",
    )
    adjudications = _verified_json(
        root,
        raw["adjudications"],
        raw["adjudications_sha256"],
        "benchmark-adjudications-v1.schema.json",
    )
    case = load_benchmark_case(case_path, repository_root=root)
    _validate_run_links(run_id, raw, case, freeze_sha, receipt, candidates, adjudications)
    return VerifiedRun(
        run_id=run_id,
        case=case,
        freeze_root_sha256=freeze_sha,
        case_manifest_sha256=str(raw["case_manifest_sha256"]),
        receipt_sha256=str(raw["receipt_sha256"]),
        candidates_sha256=str(raw["candidates_sha256"]),
        adjudications_sha256=str(raw["adjudications_sha256"]),
        receipt=receipt,
        candidates=tuple(candidates["candidate"]),
        admission_adjudications=tuple(adjudications["admission"]),
        adjudications=tuple(adjudications["adjudication"]),
    )


def _validate_run_links(
    run_id: str,
    raw: dict[str, Any],
    case: BenchmarkCase,
    freeze_sha: str,
    receipt: dict[str, Any],
    candidates: dict[str, Any],
    adjudications: dict[str, Any],
) -> None:
    if any(item["run_id"] != run_id for item in (receipt, candidates, adjudications)):
        raise BenchmarkContractError(f"artifact run ID mismatch: {run_id}")
    if receipt["case_id"] != case.case_id or receipt["repetition_index"] != case.repetition_index:
        raise BenchmarkContractError(f"case identity mismatch: {run_id}")
    if receipt["case_discovery_sha256"] != case.discovery_sha256:
        raise BenchmarkContractError(f"discovery projection hash mismatch: {run_id}")
    if receipt["freeze_root_sha256"] != freeze_sha:
        raise BenchmarkContractError(f"receipt freeze root mismatch: {run_id}")
    if receipt["source"] != asdict(case.source):
        raise BenchmarkContractError(f"receipt source mismatch: {run_id}")
    if (
        raw["adjudications"] != case.evaluation.reference
        or raw["adjudications_sha256"] != case.evaluation.sha256
    ):
        raise BenchmarkContractError(f"case evaluator reference mismatch: {run_id}")

    candidate_ids = [str(item["canonical_candidate_id"]) for item in candidates["candidate"]]
    adjudication_ids = [
        str(item["canonical_candidate_id"])
        for item in adjudications["adjudication"]
    ]
    finding_ids = [str(item["finding_id"]) for item in receipt["hunter_findings"]]
    evaluated_target_ids = [str(item["target_id"]) for item in adjudications["admission"]]
    admitted_target_ids = [str(item["target_id"]) for item in receipt["admission"]]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise BenchmarkContractError(f"duplicate canonical candidate: {run_id}")
    if len(adjudication_ids) != len(set(adjudication_ids)):
        raise BenchmarkContractError(f"duplicate adjudication: {run_id}")
    if len(finding_ids) != len(set(finding_ids)):
        raise BenchmarkContractError(f"duplicate Hunter finding ID: {run_id}")
    if len(evaluated_target_ids) != len(set(evaluated_target_ids)):
        raise BenchmarkContractError(f"duplicate target admission adjudication: {run_id}")
    if not set(admitted_target_ids).issubset(evaluated_target_ids):
        raise BenchmarkContractError(f"admission references an unevaluated target: {run_id}")
    if not set(adjudication_ids).issubset(candidate_ids):
        raise BenchmarkContractError(f"adjudication references an unknown candidate: {run_id}")
    if any(
        item["canonical_candidate_id"] not in candidate_ids
        for item in receipt["hunter_findings"]
    ):
        raise BenchmarkContractError(f"Hunter finding references an unknown candidate: {run_id}")

    usage = receipt["usage"]
    sessions = int(usage["sessions"])
    if sessions > case.budget.max_hunter_sessions:
        raise BenchmarkContractError(f"session budget exceeded: {run_id}")
    input_tokens = sum(
        int(usage[key])
        for key in ("input_tokens", "cache_read_tokens", "cache_write_tokens")
    )
    if input_tokens > case.budget.max_input_tokens:
        raise BenchmarkContractError(f"input token budget exceeded: {run_id}")
    if int(usage["output_tokens"]) > case.budget.max_output_tokens:
        raise BenchmarkContractError(f"output token budget exceeded: {run_id}")
    if int(usage["wall_time_ms"]) > case.budget.max_wall_clock_minutes * 60_000:
        raise BenchmarkContractError(f"wall-clock budget exceeded: {run_id}")
    session_records = [
        int(item["session_index"])
        for item in receipt["admission"] + receipt["hunter_findings"]
    ]
    session_records.extend(
        int(item["first_session_index"])
        for item in candidates["candidate"]
    )
    if session_records and max(session_records) > sessions:
        raise BenchmarkContractError(f"artifact session exceeds receipt usage: {run_id}")
    if any(int(item["first_observed_ms"]) > int(usage["wall_time_ms"]) for item in candidates["candidate"]):
        raise BenchmarkContractError(f"candidate time exceeds receipt wall time: {run_id}")


def _admitted(run: VerifiedRun, k: int) -> bool:
    target_ids = {
        str(item["target_id"])
        for item in run.admission_adjudications
        if item["target_match"] is True
    }
    return any(
        item["target_id"] in target_ids
        and item["hunter"] == run.case.required_hunter
        and int(item["session_index"]) <= k
        for item in run.receipt["admission"]
    )


def _hunter_detected(run: VerifiedRun, k: int) -> bool:
    target_ids = _target_candidate_ids(run)
    return any(
        item["hunter"] == run.case.required_hunter
        and int(item["session_index"]) <= k
        and item["canonical_candidate_id"] in target_ids
        for item in run.receipt["hunter_findings"]
    )


def _reportable_detected(run: VerifiedRun, k: int) -> bool:
    target_ids = _target_candidate_ids(run)
    return any(
        item["state"] == "reportable"
        and int(item["first_session_index"]) <= k
        and item["canonical_candidate_id"] in target_ids
        for item in run.candidates
    )


def _target_candidate_ids(run: VerifiedRun) -> set[str]:
    return {
        str(item["canonical_candidate_id"])
        for item in run.adjudications
        if item["target_match"] is True
    }


def _run_rate(
    runs: Sequence[VerifiedRun],
    predicate: Callable[[VerifiedRun], bool],
) -> dict[str, Any]:
    denominator_ids = sorted(run.run_id for run in runs)
    success_ids = sorted(run.run_id for run in runs if predicate(run))
    return _id_rate(denominator_ids, success_ids)


def _run_rates_at_k(
    runs: Sequence[VerifiedRun],
    predicate: Callable[[VerifiedRun, int], bool],
) -> dict[str, dict[str, Any]]:
    return {
        str(k): _id_rate(
            sorted(run.run_id for run in runs),
            sorted(run.run_id for run in runs if predicate(run, k)),
        )
        for k in K_VALUES
    }


def _id_rate(denominator_ids: Sequence[str], numerator_ids: Sequence[str]) -> dict[str, Any]:
    denominator = len(denominator_ids)
    numerator = len(numerator_ids)
    interval = _wilson(numerator, denominator)
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": _ratio(numerator, denominator),
        "confidence_interval": interval,
        "source_run_ids": sorted(denominator_ids),
        "successful_run_ids": sorted(numerator_ids),
    }


def _wilson(numerator: int, denominator: int) -> dict[str, Any] | None:
    if denominator == 0:
        return None
    z = 1.959963984540054
    rate = numerator / denominator
    z2 = z * z
    center = (rate + z2 / (2 * denominator)) / (1 + z2 / denominator)
    margin = (
        z
        * ((rate * (1 - rate) / denominator + z2 / (4 * denominator * denominator)) ** 0.5)
        / (1 + z2 / denominator)
    )
    return {
        "method": "wilson",
        "level": 0.95,
        "lower": round(max(0.0, center - margin), 6),
        "upper": round(min(1.0, center + margin), 6),
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _case_results(runs: Sequence[VerifiedRun]) -> list[dict[str, Any]]:
    by_case: dict[str, list[VerifiedRun]] = {}
    for run in runs:
        by_case.setdefault(run.case.case_id, []).append(run)
    results = []
    for case_id, case_runs in sorted(by_case.items()):
        results.append({
            "case_id": case_id,
            "partition": case_runs[0].case.partition,
            "supported_family": case_runs[0].case.supported_family,
            "required_hunter": case_runs[0].case.required_hunter,
            "valid_run_ids": sorted(run.run_id for run in case_runs),
            "hunter_case_success_rate": _run_rate(case_runs, lambda run: _hunter_detected(run, 12)),
            "reportable_case_success_rate": _run_rate(
                case_runs, lambda run: _reportable_detected(run, 12)
            ),
        })
    return results


def _validate_cohort_consistency(runs: Sequence[VerifiedRun]) -> None:
    identities: dict[str, tuple[Any, ...]] = {}
    repetitions: set[tuple[str, int]] = set()
    for run in runs:
        identity = (
            run.case.partition,
            run.case.supported_family,
            run.case.required_hunter,
            run.case.source,
        )
        existing = identities.setdefault(run.case.case_id, identity)
        if existing != identity:
            raise BenchmarkContractError(
                f"case identity changes between repetitions: {run.case.case_id}"
            )
        repetition = (run.case.case_id, run.case.repetition_index)
        if repetition in repetitions:
            raise BenchmarkContractError(
                f"duplicate case repetition: {run.case.case_id}/{run.case.repetition_index}"
            )
        repetitions.add(repetition)


def _precision(runs: Sequence[VerifiedRun]) -> dict[str, Any]:
    verdicts: dict[str, set[str]] = {}
    source_runs: dict[str, set[str]] = {}
    reportable_keys: set[str] = set()
    for run in runs:
        reportable_ids = {
            str(item["canonical_candidate_id"])
            for item in run.candidates
            if item["state"] == "reportable"
        }
        adjudications = {
            str(item["canonical_candidate_id"]): str(item["validity"])
            for item in run.adjudications
        }
        for candidate_id in reportable_ids:
            key = f"{run.case.source.tree}:{candidate_id}"
            reportable_keys.add(key)
            source_runs.setdefault(key, set()).add(run.run_id)
            if candidate_id in adjudications:
                verdicts.setdefault(key, set()).add(adjudications[candidate_id])
    conflicts = sorted(key for key, values in verdicts.items() if len(values) > 1)
    real = sorted(key for key, values in verdicts.items() if values == {"real"})
    false = sorted(key for key, values in verdicts.items() if values == {"false"})
    unknown = sorted(
        reportable_keys - set(real) - set(false)
    )
    adjudicated = real + false
    run_ids = sorted({run_id for key in adjudicated for run_id in source_runs[key]})
    rate = _id_rate(adjudicated, real)
    rate["source_run_ids"] = run_ids
    rate["successful_run_ids"] = sorted(
        {run_id for key in real for run_id in source_runs[key]}
    )
    return {
        "reportable_precision": rate,
        "unique_reportable_candidates": len(reportable_keys),
        "adjudicated_candidate_keys": sorted(adjudicated),
        "unadjudicated_candidate_keys": unknown,
        "adjudication_conflicts": conflicts,
        "real_candidate_keys": real,
        "false_candidate_keys": false,
    }


def _negative_metrics(runs: Sequence[VerifiedRun]) -> dict[str, Any]:
    fixed = [
        run
        for run in runs
        if run.case.partition == "negative" and run.case.evaluation.kind == "absence_oracle"
    ]
    negative = [run for run in runs if run.case.partition == "negative"]
    fixed_matches = [run.run_id for run in fixed if _target_candidate_ids(run)]
    false_escalations = [
        run.run_id
        for run in negative
        if _has_false_reportable(run)
    ]
    return {
        "fixed_target_false_positive_rate": _id_rate(
            sorted(run.run_id for run in fixed), sorted(fixed_matches)
        ),
        "false_escalation_rate": _id_rate(
            sorted(run.run_id for run in negative), sorted(false_escalations)
        ),
    }


def _has_false_reportable(run: VerifiedRun) -> bool:
    false_ids = {
        str(item["canonical_candidate_id"])
        for item in run.adjudications
        if item["validity"] == "false"
    }
    return any(
        item["state"] == "reportable" and item["canonical_candidate_id"] in false_ids
        for item in run.candidates
    )


def _cost_metrics(
    verified: Sequence[VerifiedRun],
    valid: Sequence[VerifiedRun],
    real_candidate_keys: Sequence[str],
    missing_usage_run_ids: Sequence[str],
) -> dict[str, Any]:
    all_model_tokens = sum(run.model_tokens for run in verified)
    valid_input = [run.input_tokens for run in valid]
    valid_output = [int(run.usage["output_tokens"]) for run in valid]
    first_times = [time for run in valid if (time := _first_reportable_ms(run)) is not None]
    real_count = len(real_candidate_keys)
    usage_complete = not missing_usage_run_ids
    if not usage_complete:
        cost_value: float | None = None
        cost_status = "incomplete"
    elif real_count:
        cost_value = round(all_model_tokens / real_count, 6)
        cost_status = "defined"
    else:
        cost_value = None
        cost_status = "undefined"
    return {
        "usage_complete": usage_complete,
        "missing_usage_run_ids": sorted(missing_usage_run_ids),
        "source_run_ids": sorted(run.run_id for run in verified),
        "tokens_per_valid_run": {
            "total": sum(valid_input),
            "denominator": len(valid_input),
            "mean": _ratio(sum(valid_input), len(valid_input)),
            "median": _median(valid_input),
        },
        "output_tokens_per_valid_run": {
            "total": sum(valid_output),
            "denominator": len(valid_output),
            "mean": _ratio(sum(valid_output), len(valid_output)),
            "median": _median(valid_output),
        },
        "tokens_per_reportable": {
            "numerator": all_model_tokens,
            "denominator": real_count,
            "value": cost_value,
            "status": cost_status,
        },
        "time_to_first_reportable_ms": {
            "values": sorted(first_times),
            "median": _median(first_times),
            "source_run_ids": sorted(
                run.run_id for run in valid if _first_reportable_ms(run) is not None
            ),
        },
    }


def _first_reportable_ms(run: VerifiedRun) -> int | None:
    values = [
        int(item["first_observed_ms"])
        for item in run.candidates
        if item["state"] == "reportable"
    ]
    return min(values) if values else None


def _median(values: Sequence[int]) -> float | int | None:
    if not values:
        return None
    value = statistics.median(values)
    return int(value) if float(value).is_integer() else float(value)


def _run_provenance(run: VerifiedRun) -> dict[str, Any]:
    return {
        "run_id": run.run_id,
        "case_id": run.case.case_id,
        "repetition_index": run.case.repetition_index,
        "partition": run.case.partition,
        "supported_family": run.case.supported_family,
        "required_hunter": run.case.required_hunter,
        "outcome": run.receipt["outcome"],
        "source": asdict(run.case.source),
        "model": run.receipt["model"],
        "policies": dict(sorted(run.receipt["policies"].items())),
        "case_manifest_sha256": run.case_manifest_sha256,
        "case_discovery_sha256": run.case.discovery_sha256,
        "freeze_root_sha256": run.freeze_root_sha256,
        "receipt_sha256": run.receipt_sha256,
        "candidates_sha256": run.candidates_sha256,
        "adjudications_sha256": run.adjudications_sha256,
    }


def _metric_row(name: str, k: str, metric: dict[str, Any]) -> str:
    return (
        f"| {name} | {k} | {metric['numerator']} | {metric['denominator']} | "
        f"{_display(metric['rate'])} |"
    )


def _display(value: Any) -> str:
    return "undefined" if value is None else str(value)


def _display_cost(metric: dict[str, Any]) -> str:
    return str(metric["status"]) if metric["value"] is None else str(metric["value"])


def _load_toml(path: Path, schema_name: str) -> dict[str, Any]:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise BenchmarkContractError("benchmark metrics input is unreadable") from exc
    _validate_payload(payload, schema_name)
    return payload


def _verified_json(root: Path, reference: str, expected: str, schema_name: str) -> dict[str, Any]:
    path = _verified_file(root, reference, expected)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkContractError(f"invalid JSON artifact: {reference}") from exc
    _validate_payload(payload, schema_name)
    return payload


def _validate_payload(payload: Any, schema_name: str) -> None:
    schema = json.loads((SCHEMA_ROOT / schema_name).read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "root"
        raise BenchmarkContractError(
            f"{schema_name} validation failed at {location}: {error.message}"
        )


def _verified_file(root: Path, reference: str, expected: str) -> Path:
    path = _resolve_reference(root, str(reference), directory=False)
    actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise BenchmarkContractError(f"artifact hash mismatch: {reference}")
    return path


def _resolve_reference(root: Path, value: str, *, directory: bool) -> Path:
    reference = PurePosixPath(value)
    if reference.is_absolute() or ".." in reference.parts or "\\" in value:
        raise BenchmarkContractError("artifact reference must be repository-relative")
    resolved = (root / Path(*reference.parts)).resolve()
    if not resolved.is_relative_to(root):
        raise BenchmarkContractError("artifact reference escapes repository root")
    exists = resolved.is_dir() if directory else resolved.is_file()
    if not exists:
        kind = "directory" if directory else "file"
        raise BenchmarkContractError(f"artifact {kind} does not exist: {value}")
    return resolved


def write_outputs(metrics: dict[str, Any], json_output: Path, markdown_output: Path) -> None:
    json_output.parent.mkdir(parents=True, exist_ok=True)
    markdown_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_bytes(canonical_json_bytes(metrics))
    markdown_output.write_text(render_markdown(metrics), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--markdown-output", required=True, type=Path)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    metrics = reduce_metrics(args.input, repository_root=args.repository_root)
    write_outputs(metrics, args.json_output, args.markdown_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
