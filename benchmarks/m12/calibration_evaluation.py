"""Post-freeze M12.2 calibration adjudication and release reporting."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.m12.benchmark_case import load_benchmark_case
from benchmarks.m12.calibration import (
    DEFAULT_CATALOG,
    PROJECT_ROOT,
    CalibrationCatalog,
    CalibrationDefinition,
)
from benchmarks.m12.calibration_cohort import open_evaluation, verify_cohort_plan
from benchmarks.m12.calibration_controls import (
    assess_differential_controls,
    load_differential_controls,
)
from benchmarks.m12.calibration_quality import reduce_knowledge_quality
from benchmarks.m12.metrics import canonical_json_bytes, reduce_metrics, render_markdown
from benchmarks.run_libtiff_blind_benchmark import BenchmarkContractError, verify_frozen

EVALUATION_POLICY = "calibration-evaluation-v2"
ADJUDICATOR = "calibration-oracle-v1"


def evaluate_calibration_cohort(
    plan_path: Path,
    *,
    catalog_path: Path = DEFAULT_CATALOG,
    repository_root: Path = PROJECT_ROOT,
    output: Path | None = None,
    controls_path: Path | None = None,
) -> dict[str, Any]:
    """Open sealed oracles, build run-local adjudications, and reduce metrics."""
    plan_path = plan_path.resolve()
    cohort_root = plan_path.parent
    plan = verify_cohort_plan(plan_path, repository_root=repository_root)
    catalog = open_evaluation(
        plan_path,
        catalog_path,
        repository_root=repository_root,
    )
    definitions = {item.case.case_id: item for item in catalog.definitions}
    _copy_case_dependencies(cohort_root, catalog, repository_root.resolve())

    requested_output = output or Path("evaluation")
    evaluation_root = (
        requested_output
        if requested_output.is_absolute()
        else cohort_root / requested_output
    ).resolve()
    if not evaluation_root.is_relative_to(cohort_root) or evaluation_root == cohort_root:
        raise BenchmarkContractError("calibration evaluation output must be inside the cohort")
    runs: list[dict[str, str]] = []
    for raw in plan["run"]:
        case_id = str(raw["case_id"])
        definition = definitions.get(case_id)
        if definition is None:
            raise BenchmarkContractError(f"calibration definition is missing: {case_id}")
        runs.append(
            _evaluate_run(
                cohort_root,
                raw,
                definition,
                evaluation_root=evaluation_root,
                repository_root=repository_root.resolve(),
            )
        )

    metrics_input = evaluation_root / "metrics-input.toml"
    _write_immutable(metrics_input, _metrics_input_bytes(plan, runs))
    metrics = reduce_metrics(metrics_input, repository_root=cohort_root)
    metrics_json = evaluation_root / "metrics.json"
    metrics_markdown = evaluation_root / "metrics.md"
    _write_immutable(metrics_json, canonical_json_bytes(metrics))
    _write_immutable(metrics_markdown, render_markdown(metrics).encode("utf-8"))

    knowledge_metrics = reduce_knowledge_quality(
        cohort_root,
        plan["run"],
        ledger_path=(
            repository_root.resolve() / "knowledge" / "finding-ledger-v1.json"
        ),
    )
    knowledge_metrics_json = evaluation_root / "knowledge-metrics.json"
    _write_immutable(
        knowledge_metrics_json,
        canonical_json_bytes(knowledge_metrics),
    )
    controls = None
    controls_sha256 = None
    if controls_path is not None:
        resolved_controls = controls_path.resolve()
        if not resolved_controls.is_relative_to(cohort_root):
            raise BenchmarkContractError(
                "differential controls must be stored inside the cohort root"
            )
        controls = load_differential_controls(
            resolved_controls,
            cohort_id=str(plan["cohort_id"]),
            plan_path=plan_path,
            catalog=catalog,
        )
        controls_sha256 = _sha256(resolved_controls)

    assessment = assess_calibration_gates(
        metrics,
        knowledge_metrics=knowledge_metrics,
        controls=controls,
    )
    report = {
        "schema_version": 1,
        "policy_version": EVALUATION_POLICY,
        "cohort_id": plan["cohort_id"],
        "snapshot_sha256": plan["snapshot_sha256"],
        "catalog_sha256": catalog.sha256,
        "metrics_sha256": _sha256(metrics_json),
        "knowledge_metrics_sha256": _sha256(knowledge_metrics_json),
        "differential_controls_sha256": controls_sha256,
        "assessment": assessment,
    }
    report_json = evaluation_root / "release-report.json"
    report_markdown = evaluation_root / "release-report.md"
    _write_json_immutable(report_json, report)
    _write_immutable(report_markdown, render_release_report(metrics, report).encode("utf-8"))
    return report


def assess_calibration_gates(
    metrics: Mapping[str, Any],
    *,
    knowledge_metrics: Mapping[str, Any] | None = None,
    controls: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply only the measurable M12.2 gates to immutable metrics."""
    case_results = list(metrics["case_results"])
    admitted_cases = sorted(
        str(item["case_id"])
        for item in case_results
        if int(item["admission_case_success_rate"]["numerator"]) >= 2
    )
    detected_families = sorted({
        str(item["supported_family"])
        for item in case_results
        if int(item["hunter_case_success_rate"]["numerator"]) > 0
    })
    supported_families = sorted({str(item["supported_family"]) for item in case_results})
    median_input = metrics["cost"]["tokens_per_valid_run"]["median"]
    per_run_input = {
        str(item["run_id"]): sum(
            int(item["usage"][key])
            for key in ("input_tokens", "cache_read_tokens", "cache_write_tokens")
        )
        for item in metrics["provenance"]["runs"]
        if item["outcome"] in {"completed", "budget_limited"}
    }
    max_input = max(per_run_input.values(), default=None)
    valid_rate = metrics["run_accounting"]["valid_run_rate"]
    hunter_rate = metrics["detection"]["hunter_detection_at_k"]["12"]
    reportable_rate = metrics["detection"]["reportable_detection_at_k"]["12"]
    recovered_cases = sorted(
        str(item["case_id"])
        for item in case_results
        if int(item["hunter_case_success_rate"]["numerator"]) >= 2
    )
    case_ids = sorted(str(item["case_id"]) for item in case_results)
    control_assessment = assess_differential_controls(controls, case_ids=case_ids)
    knowledge = knowledge_metrics or {}
    recorded_model_tokens = sum(
        sum(
            int(item["usage"][key])
            for key in (
                "input_tokens",
                "output_tokens",
                "cache_read_tokens",
                "cache_write_tokens",
            )
        )
        for item in metrics["provenance"]["runs"]
    )
    retained_model_tokens = int(
        metrics["cost"]["tokens_per_reportable"]["numerator"]
    )
    gates = {
        "valid_run_rate": {
            "passed": valid_rate["rate"] == 1.0,
            "actual": valid_rate["rate"],
            "required": 1.0,
        },
        "target_hunters_admitted": {
            "passed": len(admitted_cases) >= 3,
            "actual": len(admitted_cases),
            "required": 3,
            "case_ids": admitted_cases,
            "case_rule": "admitted in at least two of three repetitions",
        },
        "hunter_detection_at_12": {
            "passed": hunter_rate["rate"] is not None and hunter_rate["rate"] >= 0.75,
            "actual": hunter_rate["rate"],
            "required": 0.75,
        },
        "reportable_detection_at_12": {
            "passed": (
                reportable_rate["rate"] is not None
                and reportable_rate["rate"] >= 0.5
            ),
            "actual": reportable_rate["rate"],
            "required": 0.5,
        },
        "supported_family_coverage": {
            "passed": detected_families == supported_families,
            "actual": detected_families,
            "required": supported_families,
            "missing": sorted(set(supported_families) - set(detected_families)),
        },
        "per_case_hunter_recovery": {
            "passed": recovered_cases == case_ids,
            "actual": recovered_cases,
            "required": case_ids,
            "case_rule": (
                "target Hunter detection in at least two of three repetitions"
            ),
        },
        "paired_differential_controls": control_assessment,
        "current_source_evidence": {
            "passed": (
                knowledge.get("findings_without_current_source_evidence") == 0
                and knowledge.get(
                    "reportable_without_current_source_evidence"
                ) == 0
            ),
            "actual": {
                "all_findings": knowledge.get(
                    "findings_without_current_source_evidence"
                ),
                "reportable": knowledge.get(
                    "reportable_without_current_source_evidence"
                ),
            },
            "required": 0,
        },
        "ledger_identity_isolation": {
            "passed": knowledge.get("ledger_identity_leaks") == [],
            "actual": knowledge.get("ledger_identity_leaks"),
            "required": [],
        },
        "duplicate_and_cost_accounting": {
            "passed": (
                bool(
                    (knowledge.get("duplicate_accounting") or {}).get(
                        "logical_findings_count_once"
                    )
                )
                and retained_model_tokens == recorded_model_tokens
            ),
            "actual": {
                "logical_findings_count_once": (
                    knowledge.get("duplicate_accounting") or {}
                ).get("logical_findings_count_once"),
                "retained_model_tokens": retained_model_tokens,
                "recorded_model_tokens": recorded_model_tokens,
            },
            "required": (
                "logical candidates deduplicated; all execution cost retained"
            ),
        },
        "median_input_tokens": {
            "passed": median_input is not None and median_input <= 1_500_000,
            "actual": median_input,
            "required_maximum": 1_500_000,
        },
        "maximum_input_tokens": {
            "passed": max_input is not None and max_input <= 2_000_000,
            "actual": max_input,
            "required_maximum": 2_000_000,
            "by_run": dict(sorted(per_run_input.items())),
        },
    }
    failed = sorted(name for name, gate in gates.items() if gate["passed"] is not True)
    return {
        "decision": "stop_and_design_m12_2_x" if failed else "pending_protected_regression",
        "failed_gates": failed,
        "gates": gates,
        "protected_regression": "external_required",
    }


def render_release_report(metrics: Mapping[str, Any], report: Mapping[str, Any]) -> str:
    assessment = report["assessment"]
    lines = [
        "# M12.2 calibration pilot release report",
        "",
        f"- Cohort: `{report['cohort_id']}`",
        f"- Snapshot: `{report['snapshot_sha256']}`",
        f"- Metrics: `{report['metrics_sha256']}`",
        f"- Knowledge metrics: `{report['knowledge_metrics_sha256']}`",
        f"- Differential controls: `{report['differential_controls_sha256']}`",
        f"- Decision: `{assessment['decision']}`",
        "- Protected regression: external validation required",
        "",
        "| Gate | Actual | Required | Result |",
        "|---|---:|---:|---|",
    ]
    for name, gate in assessment["gates"].items():
        actual = gate.get("actual")
        required = gate.get("required", gate.get("required_maximum"))
        lines.append(
            f"| {name} | `{_compact(actual)}` | `{_compact(required)}` | "
            f"{'PASS' if gate['passed'] else 'FAIL'} |"
        )
    lines.extend([
        "",
        "| Case | Family | Hunter | Admission | Hunter detection | Reportable |",
        "|---|---|---|---:|---:|---:|",
    ])
    for item in metrics["case_results"]:
        lines.append(
            f"| `{item['case_id']}` | {item['supported_family']} | "
            f"`{item['required_hunter']}` | "
            f"{_rate_count(item['admission_case_success_rate'])} | "
            f"{_rate_count(item['hunter_case_success_rate'])} | "
            f"{_rate_count(item['reportable_case_success_rate'])} |"
        )
    if assessment["failed_gates"]:
        lines.extend([
            "",
            "M12.3 is blocked. The milestone contract requires a focused M12.2.x "
            "recovery design before any sealed-holdout spend.",
        ])
    lines.append("")
    return "\n".join(lines)


def _evaluate_run(
    cohort_root: Path,
    raw: Mapping[str, Any],
    definition: CalibrationDefinition,
    *,
    evaluation_root: Path,
    repository_root: Path,
) -> dict[str, str]:
    run_id = str(raw["run_id"])
    case_path = _resolve(cohort_root, str(raw["case_manifest"]), file=True)
    case = load_benchmark_case(case_path, repository_root=repository_root)
    if case.case_id != definition.case.case_id:
        raise BenchmarkContractError(f"calibration evaluation case mismatch: {run_id}")
    frozen = _resolve(cohort_root, str(raw["freeze_root"]), file=False)
    freeze = verify_frozen(frozen)
    freeze_sha = "sha256:" + str(freeze["root_sha256"])
    receipt_path = _resolve(cohort_root, str(raw["receipt"]), file=True)
    receipt = _load_json(receipt_path, "calibration receipt")
    if receipt.get("run_id") != run_id or receipt.get("freeze_root_sha256") != freeze_sha:
        raise BenchmarkContractError(f"calibration receipt linkage mismatch: {run_id}")

    findings = _load_json(frozen / "findings.json", "frozen findings")
    analysis = _load_json(frozen / "analysis.json", "frozen analysis")
    hunt_plan = _load_json(frozen / "plan.json", "frozen hunt plan")
    if (
        not isinstance(findings, list)
        or not isinstance(analysis, dict)
        or not isinstance(hunt_plan, dict)
    ):
        raise BenchmarkContractError(f"calibration evaluation artifacts are invalid: {run_id}")
    oracle_sha = case.evaluation.sha256
    candidates = _build_candidates(run_id, findings, receipt, frozen)
    adjudications = _build_adjudications(
        run_id,
        findings,
        receipt,
        analysis,
        hunt_plan,
        definition.oracle,
        oracle_sha,
    )
    run_root = evaluation_root / "runs" / run_id
    candidates_path = run_root / "candidates.json"
    adjudications_path = run_root / "adjudications.json"
    _write_json_immutable(candidates_path, candidates)
    _write_json_immutable(adjudications_path, adjudications)
    return {
        "run_id": run_id,
        "case_manifest": str(raw["case_manifest"]),
        "case_manifest_sha256": str(raw["case_manifest_sha256"]),
        "freeze_root": str(raw["freeze_root"]),
        "freeze_root_sha256": freeze_sha,
        "receipt": str(raw["receipt"]),
        "receipt_sha256": _sha256(receipt_path),
        "candidates": _relative(cohort_root, candidates_path),
        "candidates_sha256": _sha256(candidates_path),
        "adjudications": _relative(cohort_root, adjudications_path),
        "adjudications_sha256": _sha256(adjudications_path),
        "evaluation_reference": case.evaluation.reference,
        "evaluation_sha256": oracle_sha,
    }


def _build_candidates(
    run_id: str,
    findings: Sequence[Mapping[str, Any]],
    receipt: Mapping[str, Any],
    frozen: Path,
) -> dict[str, Any]:
    session_by_candidate: dict[str, int] = {}
    for item in receipt["hunter_findings"]:
        candidate_id = str(item["canonical_candidate_id"])
        session = int(item["session_index"])
        session_by_candidate[candidate_id] = min(
            session,
            session_by_candidate.get(candidate_id, session),
        )
    wall_time = int(receipt["usage"]["wall_time_ms"])
    started = _first_event_time(frozen)
    candidates = []
    for finding in findings:
        candidate_id = str(finding.get("candidate_id") or "")
        if not candidate_id or candidate_id not in session_by_candidate:
            raise BenchmarkContractError(f"unlinked calibration candidate: {run_id}")
        candidates.append({
            "canonical_candidate_id": candidate_id,
            "state": _benchmark_state(str(finding.get("state") or "")),
            "first_session_index": session_by_candidate[candidate_id],
            "first_observed_ms": _observed_ms(finding.get("created_at"), started, wall_time),
        })
    return {
        "schema_version": 1,
        "policy_version": "benchmark-candidates-v1",
        "run_id": run_id,
        "candidate": sorted(candidates, key=lambda item: item["canonical_candidate_id"]),
    }


def _build_adjudications(
    run_id: str,
    findings: Sequence[Mapping[str, Any]],
    receipt: Mapping[str, Any],
    analysis: Mapping[str, Any],
    hunt_plan: Mapping[str, Any],
    oracle: Mapping[str, Any],
    oracle_sha: str,
) -> dict[str, Any]:
    admission = []
    for target_id in sorted({str(item["target_id"]) for item in receipt["admission"]}):
        admission.append({
            "target_id": target_id,
            "target_match": _target_matches_oracle(
                target_id,
                analysis,
                oracle,
                hunt_plan=hunt_plan,
            ),
            "evidence_sha256": oracle_sha,
        })
    adjudication = []
    for finding in sorted(findings, key=lambda item: str(item.get("candidate_id") or "")):
        candidate_id = str(finding.get("candidate_id") or "")
        target_match = _finding_matches_oracle(finding, oracle)
        adjudication.append({
            "canonical_candidate_id": candidate_id,
            "target_match": target_match,
            "validity": "real" if target_match else "unknown",
            "adjudicator": ADJUDICATOR,
            "evidence_sha256": oracle_sha,
        })
    return {
        "schema_version": 1,
        "policy_version": "benchmark-adjudications-v1",
        "run_id": run_id,
        "admission": admission,
        "adjudication": adjudication,
    }


def _finding_matches_oracle(finding: Mapping[str, Any], oracle: Mapping[str, Any]) -> bool:
    location = oracle["location"]
    sink = finding.get("sink")
    if not isinstance(sink, Mapping) or not _point_matches(sink, location, "sink"):
        return False
    entry_locations: list[Mapping[str, Any]] = []
    entrypoint = finding.get("entrypoint")
    if isinstance(entrypoint, Mapping):
        entry_locations.append(entrypoint)
    dataflow = finding.get("dataflow")
    if isinstance(dataflow, list):
        entry_locations.extend(item for item in dataflow if isinstance(item, Mapping))
    return any(_point_matches(item, location, "entry") for item in entry_locations)


def _target_matches_oracle(
    target_id: str,
    analysis: Mapping[str, Any],
    oracle: Mapping[str, Any],
    *,
    hunt_plan: Mapping[str, Any] | None = None,
) -> bool:
    graph = analysis.get("graph")
    if not isinstance(graph, Mapping):
        return False
    locations: list[Mapping[str, Any]] = []
    for key, identity in (("signals", "signal_id"), ("nodes", "node_id")):
        values = graph.get(key)
        if not isinstance(values, list):
            continue
        locations.extend(
            item
            for item in values
            if isinstance(item, Mapping) and str(item.get(identity) or "") == target_id
        )
    location = oracle["location"]
    exact_location = any(
        _point_matches(item, location, prefix)
        for item in locations
        for prefix in ("entry", "sink")
    )
    if exact_location or hunt_plan is None:
        return exact_location
    required_paths = {str(item) for item in location["required_paths"]}
    work_items = hunt_plan.get("work_items")
    if not isinstance(work_items, list):
        return False
    for item in work_items:
        if not isinstance(item, Mapping):
            continue
        targets = {
            str(value)
            for key in ("target_signal_ids", "target_node_ids")
            for value in (item.get(key) or [])
        }
        files = {str(value) for value in (item.get("files") or [])}
        if target_id in targets and required_paths.issubset(files):
            return True
    return False


def _point_matches(
    point: Mapping[str, Any],
    location: Mapping[str, Any],
    prefix: str,
) -> bool:
    if str(point.get("path") or "") != str(location[f"{prefix}_file"]):
        return False
    try:
        start = int(point["line"])
        end = int(point.get("end_line") or start)
    except (KeyError, TypeError, ValueError):
        return False
    expected_start = int(location[f"{prefix}_line_min"])
    expected_end = int(location[f"{prefix}_line_max"])
    return start <= expected_end and end >= expected_start


def _benchmark_state(value: str) -> str:
    if value == "reportable":
        return "reportable"
    if value == "rejected":
        return "rejected"
    if value in {"reviewer_verified", "reproduced", "poc_ready", "poc_attempted", "raw"}:
        return value
    return "review_inconclusive"


def _first_event_time(frozen: Path) -> datetime | None:
    event_paths = sorted(frozen.glob("*/events.jsonl"))
    if not event_paths:
        return None
    try:
        with event_paths[0].open(encoding="utf-8") as handle:
            first = json.loads(handle.readline())
        return _timestamp(first.get("ts"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _observed_ms(value: Any, started: datetime | None, wall_time: int) -> int:
    observed = _timestamp(value)
    if started is None or observed is None:
        return 0
    elapsed = max(0, round((observed - started).total_seconds() * 1000))
    return min(elapsed, wall_time)


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _copy_case_dependencies(
    cohort_root: Path,
    catalog: CalibrationCatalog,
    repository_root: Path,
) -> None:
    references = {
        definition.case.discovery.scan_manifest: definition.case.discovery.scan_manifest_sha256
        for definition in catalog.definitions
    }
    references.update({
        definition.case.evaluation.reference: definition.case.evaluation.sha256
        for definition in catalog.definitions
    })
    for reference, expected in sorted(references.items()):
        source = _resolve(repository_root, reference, file=True)
        if _sha256(source) != expected:
            raise BenchmarkContractError(f"calibration dependency hash mismatch: {reference}")
        destination = _resolve_output(cohort_root, reference)
        _write_immutable(destination, source.read_bytes())


def _metrics_input_bytes(plan: Mapping[str, Any], runs: Sequence[Mapping[str, str]]) -> bytes:
    lines = [
        "[cohort]",
        "schema_version = 1",
        'policy_version = "benchmark-metrics-input-v1"',
        f"id = {_toml_string(str(plan['cohort_id']))}",
        f"snapshot_sha256 = {_toml_string(str(plan['snapshot_sha256']))}",
        "",
    ]
    for run in runs:
        lines.append("[[run]]")
        lines.extend(f"{key} = {_toml_string(value)}" for key, value in run.items())
        lines.append("")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _compact(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) or "none"
    return str(value)


def _rate_count(metric: Mapping[str, Any]) -> str:
    return f"{metric['numerator']}/{metric['denominator']} ({metric['rate']})"


def _resolve(root: Path, value: str, *, file: bool) -> Path:
    reference = PurePosixPath(value)
    if reference.is_absolute() or ".." in reference.parts or "\\" in value:
        raise BenchmarkContractError("calibration evaluation reference is unsafe")
    resolved = (root / Path(*reference.parts)).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise BenchmarkContractError("calibration evaluation reference escapes its root")
    exists = resolved.is_file() if file else resolved.is_dir()
    if not exists:
        kind = "file" if file else "directory"
        raise BenchmarkContractError(f"calibration evaluation {kind} is missing: {value}")
    return resolved


def _resolve_output(root: Path, value: str) -> Path:
    reference = PurePosixPath(value)
    if reference.is_absolute() or ".." in reference.parts or "\\" in value:
        raise BenchmarkContractError("calibration evaluation output is unsafe")
    resolved = (root / Path(*reference.parts)).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise BenchmarkContractError("calibration evaluation output escapes its root")
    return resolved


def _relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkContractError(f"{label} is unreadable") from exc


def _write_json_immutable(path: Path, value: Any) -> None:
    _write_immutable(
        path,
        (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
            "utf-8"
        ),
    )


def _write_immutable(path: Path, value: bytes) -> None:
    if path.exists():
        if not path.is_file() or path.read_bytes() != value:
            raise BenchmarkContractError(f"calibration evaluation artifact changed: {path.name}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate a frozen M12.2 calibration cohort")
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--controls",
        type=Path,
        help="immutable calibration-differential-controls-v1 artifact",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = evaluate_calibration_cohort(
            args.plan,
            catalog_path=args.catalog,
            output=args.output,
            controls_path=args.controls,
        )
    except (BenchmarkContractError, OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
