"""M12.2 authenticated calibration cohort planning and freeze control."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import uuid
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence

from jsonschema import Draft202012Validator

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from benchmarks.m12.benchmark_case import BenchmarkCase, load_benchmark_case
from benchmarks.m12.calibration import (
    DEFAULT_CATALOG,
    CalibrationCatalog,
    load_calibration_catalog,
)
from benchmarks.m12.prepared_build import load_verified_prepared_run
from benchmarks.run_libtiff_blind_benchmark import (
    BenchmarkContractError,
    freeze_discovery,
    run_discover_parent,
    verify_frozen,
)
from vulnhunt_agent.domain.compat import candidate_from_legacy

COHORT_PLAN_POLICY = "calibration-cohort-plan-v1"
COHORT_FREEZE_POLICY = "calibration-cohort-freeze-v1"
RECEIPT_POLICY = "authenticated-benchmark-receipt-v1"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = Path(__file__).with_name("schemas")
RUN_COUNT = 12

DiscoverRunner = Callable[[BenchmarkCase, Path, Path, str, str | None], dict[str, Any]]
EvaluationLoader = Callable[[Path], CalibrationCatalog]
PreparedImageLoader = Callable[[Path], str]


def create_cohort_plan(
    catalog_path: Path,
    output_root: Path,
    *,
    repository_root: Path = PROJECT_ROOT,
    id_factory: Callable[[], str] | None = None,
) -> dict[str, Any]:
    """Freeze 4 x 3 independent run identities without executing a Hunter."""
    root = output_root.resolve()
    if root.exists() and any(root.iterdir()):
        raise BenchmarkContractError("calibration cohort output is not empty")
    root.mkdir(parents=True, exist_ok=True)
    cases_root = root / "cases"
    cases_root.mkdir()
    catalog = load_calibration_catalog(
        catalog_path.resolve(), repository_root=repository_root.resolve()
    )
    make_id = id_factory or (lambda: uuid.uuid4().hex[:16])
    cohort_id = _typed_id("cohort", make_id())
    seen_run_ids: set[str] = set()
    runs: list[dict[str, Any]] = []
    for definition in catalog.definitions:
        source_manifest = (repository_root / definition.manifest).resolve()
        source_text = source_manifest.read_text(encoding="utf-8")
        for repetition in range(1, catalog.repetitions_per_case + 1):
            run_id = _typed_id("run", make_id())
            if run_id in seen_run_ids:
                raise BenchmarkContractError("cohort ID factory produced a duplicate run ID")
            seen_run_ids.add(run_id)
            manifest_path = cases_root / f"{definition.case.case_id}-r{repetition}.toml"
            manifest_path.write_text(
                _replace_repetition(source_text, repetition), encoding="utf-8"
            )
            case = load_benchmark_case(manifest_path, repository_root=repository_root)
            if case.case_id != definition.case.case_id:
                raise BenchmarkContractError("generated cohort case identity changed")
            runs.append({
                "run_id": run_id,
                "case_id": case.case_id,
                "repetition_index": repetition,
                "case_manifest": _relative(root, manifest_path),
                "case_manifest_sha256": _sha256_file(manifest_path),
                "discovery_root": f"working/{run_id}",
                "freeze_root": f"frozen/{run_id}",
                "receipt": f"receipts/{run_id}.json",
            })
    snapshot = _sha256_json({
        "catalog_sha256": catalog.sha256,
        "runs": runs,
    })
    plan = {
        "schema_version": 1,
        "policy_version": COHORT_PLAN_POLICY,
        "cohort_id": cohort_id,
        "catalog_sha256": catalog.sha256,
        "snapshot_sha256": snapshot,
        "repetitions_per_case": catalog.repetitions_per_case,
        "run": runs,
    }
    plan_path = root / "cohort-plan.json"
    _write_json(plan_path, plan)
    (root / "cohort-plan.sha256").write_text(
        _sha256_file(plan_path) + "\n", encoding="ascii"
    )
    verify_cohort_plan(plan_path, repository_root=repository_root)
    return plan


def verify_cohort_plan(
    plan_path: Path,
    *,
    repository_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    root = plan_path.resolve().parent
    lock_path = root / "cohort-plan.sha256"
    if not lock_path.is_file() or lock_path.read_text(encoding="ascii").strip() != _sha256_file(plan_path):
        raise BenchmarkContractError("calibration cohort plan hash mismatch")
    plan = _load_json(plan_path, "calibration cohort plan")
    if set(plan) != {
        "schema_version",
        "policy_version",
        "cohort_id",
        "catalog_sha256",
        "snapshot_sha256",
        "repetitions_per_case",
        "run",
    }:
        raise BenchmarkContractError("calibration cohort plan is not closed")
    if (
        plan["schema_version"] != 1
        or plan["policy_version"] != COHORT_PLAN_POLICY
        or not re.fullmatch(r"cohort_[0-9a-f]{16}", str(plan["cohort_id"]))
        or plan["repetitions_per_case"] != 3
        or not _valid_sha256(str(plan["catalog_sha256"]))
        or not _valid_sha256(str(plan["snapshot_sha256"]))
    ):
        raise BenchmarkContractError("unsupported calibration cohort plan")
    raw_runs = plan["run"]
    if not isinstance(raw_runs, list) or len(raw_runs) != RUN_COUNT:
        raise BenchmarkContractError("calibration cohort requires exactly 12 runs")
    run_ids: set[str] = set()
    repetitions: set[tuple[str, int]] = set()
    cases: dict[str, set[int]] = {}
    for raw in raw_runs:
        _validate_run_spec(raw)
        run_id = str(raw["run_id"])
        repetition = (str(raw["case_id"]), int(raw["repetition_index"]))
        if run_id in run_ids or repetition in repetitions:
            raise BenchmarkContractError("calibration cohort run identity is duplicated")
        run_ids.add(run_id)
        repetitions.add(repetition)
        cases.setdefault(repetition[0], set()).add(repetition[1])
        manifest = _resolve(root, raw["case_manifest"], file=True)
        if _sha256_file(manifest) != raw["case_manifest_sha256"]:
            raise BenchmarkContractError("calibration cohort case hash mismatch")
        case = load_benchmark_case(manifest, repository_root=repository_root)
        if (
            case.case_id != repetition[0]
            or case.repetition_index != repetition[1]
            or case.partition != "calibration"
        ):
            raise BenchmarkContractError("calibration cohort case linkage is invalid")
    if len(cases) != 4 or any(value != {1, 2, 3} for value in cases.values()):
        raise BenchmarkContractError("calibration cohort repetition matrix is incomplete")
    if plan["snapshot_sha256"] != _sha256_json({
        "catalog_sha256": plan["catalog_sha256"],
        "runs": raw_runs,
    }):
        raise BenchmarkContractError("calibration cohort snapshot hash mismatch")
    return plan


def execute_cohort(
    plan_path: Path,
    *,
    repositories: Mapping[str, Path],
    prepared_runs: Mapping[str, Path],
    repository_root: Path = PROJECT_ROOT,
    model_id: str | None = None,
    discover_runner: DiscoverRunner | None = None,
    prepared_image_loader: PreparedImageLoader | None = None,
) -> dict[str, Any]:
    """Run and immediately freeze each repetition; valid artifacts are never retried."""
    root = plan_path.resolve().parent
    plan = verify_cohort_plan(plan_path, repository_root=repository_root)
    case_ids = {str(item["case_id"]) for item in plan["run"]}
    if set(repositories) != case_ids or set(prepared_runs) != case_ids:
        raise BenchmarkContractError("repository and prepared-run maps must cover the cohort exactly")
    image_loader = prepared_image_loader or _prepared_image
    images = {
        case_id: image_loader(prepared_runs[case_id]) for case_id in sorted(case_ids)
    }
    runner = discover_runner or _discover
    for raw in plan["run"]:
        case = load_benchmark_case(
            _resolve(root, raw["case_manifest"], file=True),
            repository_root=repository_root,
        )
        discovery = _resolve(root, raw["discovery_root"], file=False)
        frozen = _resolve(root, raw["freeze_root"], file=False)
        receipt_path = _resolve(root, raw["receipt"], file=False)
        if frozen.exists() and not receipt_path.exists():
            if not frozen.is_dir() or not discovery.is_dir():
                raise BenchmarkContractError(
                    f"partial immutable run cannot be retried: {raw['run_id']}"
                )
            _require_discovery_complete(discovery)
            verify_frozen(frozen)
            receipt = _build_receipt(str(raw["run_id"]), case, frozen)
            _write_json(receipt_path, receipt)
            _validate_schema(receipt, "authenticated-benchmark-receipt-v1.schema.json")
            _verify_run_artifacts(raw, case, frozen, receipt_path)
            continue
        if receipt_path.exists() or frozen.exists():
            if not (receipt_path.is_file() and frozen.is_dir()):
                raise BenchmarkContractError(
                    f"partial immutable run cannot be retried: {raw['run_id']}"
                )
            _verify_run_artifacts(raw, case, frozen, receipt_path)
            continue
        if discovery.exists():
            try:
                _require_discovery_complete(discovery)
            except BenchmarkContractError as exc:
                raise BenchmarkContractError(
                    f"incomplete run cannot be retried under {raw['run_id']}"
                ) from exc
        else:
            result = runner(
                case,
                repositories[case.case_id].resolve(),
                discovery,
                images[case.case_id],
                model_id,
            )
            if result.get("phase") != "discover" or result.get("complete") is not True:
                raise BenchmarkContractError(
                    f"authenticated discovery did not complete: {raw['run_id']}"
                )
            _require_discovery_complete(discovery)
        freeze_discovery(discovery, frozen)
        receipt = _build_receipt(str(raw["run_id"]), case, frozen)
        _write_json(receipt_path, receipt)
        _validate_schema(receipt, "authenticated-benchmark-receipt-v1.schema.json")
        _verify_run_artifacts(raw, case, frozen, receipt_path)
    return freeze_cohort(plan_path, repository_root=repository_root)


def freeze_cohort(
    plan_path: Path,
    *,
    repository_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    """Seal the complete 12-run receipt index used to unlock evaluation."""
    root = plan_path.resolve().parent
    plan = verify_cohort_plan(plan_path, repository_root=repository_root)
    records = []
    for raw in plan["run"]:
        case = load_benchmark_case(
            _resolve(root, raw["case_manifest"], file=True),
            repository_root=repository_root,
        )
        frozen = _resolve(root, raw["freeze_root"], file=False)
        receipt = _resolve(root, raw["receipt"], file=False)
        freeze_manifest = _verify_run_artifacts(raw, case, frozen, receipt)
        records.append({
            "run_id": raw["run_id"],
            "freeze_root_sha256": "sha256:" + freeze_manifest["root_sha256"],
            "receipt_sha256": _sha256_file(receipt),
        })
    index = {
        "schema_version": 1,
        "policy_version": COHORT_FREEZE_POLICY,
        "cohort_id": plan["cohort_id"],
        "plan_sha256": _sha256_file(plan_path),
        "run": records,
        "closed": True,
    }
    index_path = root / "cohort-freeze.json"
    if index_path.exists():
        existing = _load_json(index_path, "calibration cohort freeze")
        if existing != index:
            raise BenchmarkContractError("calibration cohort freeze is immutable")
    else:
        _write_json(index_path, index)
    return index


def open_evaluation(
    plan_path: Path,
    catalog_path: Path,
    *,
    repository_root: Path = PROJECT_ROOT,
    loader: EvaluationLoader = load_calibration_catalog,
) -> CalibrationCatalog:
    """Load sealed oracles only after every discovery freeze and receipt verifies."""
    root = plan_path.resolve().parent
    freeze_cohort(plan_path, repository_root=repository_root)
    index_path = root / "cohort-freeze.json"
    before = _sha256_file(index_path)
    catalog = loader(catalog_path.resolve())
    plan = verify_cohort_plan(plan_path, repository_root=repository_root)
    if catalog.sha256 != plan["catalog_sha256"]:
        raise BenchmarkContractError("evaluation catalog differs from the planned cohort")
    if _sha256_file(index_path) != before:
        raise BenchmarkContractError("cohort freeze changed while opening evaluation")
    return catalog


def _discover(
    case: BenchmarkCase,
    repo: Path,
    output: Path,
    image: str,
    model_id: str | None,
) -> dict[str, Any]:
    return run_discover_parent(argparse.Namespace(
        repo=repo,
        scan_manifest=(PROJECT_ROOT / case.discovery.scan_manifest),
        output=output,
        mode="authenticated",
        image=image,
        model_id=model_id,
        skip_verify=False,
    ))


def _prepared_image(run_dir: Path) -> str:
    return str(load_verified_prepared_run(run_dir)["image"])


def _build_receipt(run_id: str, case: BenchmarkCase, frozen: Path) -> dict[str, Any]:
    freeze_manifest = verify_frozen(frozen)
    discovery = _load_json(frozen / "discovery.json", "frozen discovery")
    if discovery.get("mode") != "authenticated":
        raise BenchmarkContractError("calibration receipt requires authenticated discovery")
    audit = discovery.get("oracle_access_audit") or {}
    if (
        audit.get("oracle_received") is not False
        or audit.get("fixed_tree_received") is not False
        or audit.get("denied_attempts")
    ):
        raise BenchmarkContractError("calibration discovery was not oracle isolated")
    discovered_source = (discovery.get("run_identity") or {}).get("source") or {}
    normalized_source = {
        "repository": discovered_source.get("repository")
        or discovered_source.get("origin"),
        "commit": discovered_source.get("commit"),
        "tree": discovered_source.get("tree"),
    }
    if normalized_source != asdict(case.source):
        raise BenchmarkContractError("calibration discovery source differs from its case")
    plan = _load_json(frozen / "plan.json", "frozen hunt plan")
    work = {str(item["work_id"]): item for item in plan.get("work_items") or []}
    start_order = _provider_start_order(plan)
    admission: list[dict[str, Any]] = []
    for work_id, session_index in start_order.items():
        item = work.get(work_id)
        if item is None:
            raise BenchmarkContractError("provider start references unknown work")
        targets = item.get("target_signal_ids") or item.get("target_node_ids") or [work_id]
        admission.extend({
            "target_id": str(target),
            "hunter": str(item["hunter"]),
            "session_index": session_index,
        } for target in targets)
    findings = _load_json(frozen / "findings.json", "frozen findings")
    if not isinstance(findings, list):
        raise BenchmarkContractError("frozen findings are not a list")
    hunter_findings: list[dict[str, Any]] = []
    for finding in findings:
        candidate_id = str(finding.get("candidate_id") or "")
        if not candidate_id:
            raise BenchmarkContractError("Hunter finding has no candidate identity")
        work_ids = _finding_work_ids(finding, frozen, discovery, work, start_order)
        for index, work_id in enumerate(work_ids, start=1):
            item = work[work_id]
            hunter_findings.append({
                "finding_id": (
                    candidate_id
                    if len(work_ids) == 1
                    else f"{candidate_id}:{index}:{work_id}"
                ),
                "hunter": str(item["hunter"]),
                "session_index": start_order[work_id],
                "canonical_candidate_id": candidate_id,
            })
    usage = discovery.get("usage") or {}
    sessions = int(usage.get("sessions", 0))
    if start_order and sessions < max(start_order.values()):
        raise BenchmarkContractError("receipt session usage is below executed work count")
    adapter = (discovery.get("model") or {}).get("adapter")
    if isinstance(adapter, list):
        adapter = "+".join(str(item) for item in adapter)
    summary = discovery.get("summary") or {}
    outcome = (
        "budget_limited"
        if int(summary.get("deferred_sessions", 0)) > 0
        else "completed"
    )
    return {
        "schema_version": 1,
        "policy_version": RECEIPT_POLICY,
        "run_id": run_id,
        "case_id": case.case_id,
        "repetition_index": case.repetition_index,
        "case_discovery_sha256": case.discovery_sha256,
        "freeze_root_sha256": "sha256:" + freeze_manifest["root_sha256"],
        "source": asdict(case.source),
        "model": {
            "adapter": str(adapter or "unknown"),
            "model_id": str((discovery.get("model") or {}).get("model_id") or "unknown"),
        },
        "policies": {
            str(key): str(value) for key, value in (discovery.get("policies") or {}).items()
        },
        "outcome": outcome,
        "authenticated": True,
        "oracle_isolated": True,
        "usage": {
            "sessions": sessions,
            "input_tokens": int(usage.get("input_tokens", 0)),
            "output_tokens": int(usage.get("output_tokens", 0)),
            "cache_read_tokens": int(usage.get("cache_read_tokens", 0)),
            "cache_write_tokens": int(usage.get("cache_write_tokens", 0)),
            "wall_time_ms": int(usage.get("wall_time_ms", 0)),
        },
        "admission": admission,
        "hunter_findings": hunter_findings,
    }


def _finding_work_ids(
    finding: dict[str, Any],
    frozen: Path,
    discovery: dict[str, Any],
    work: Mapping[str, dict[str, Any]],
    start_order: Mapping[str, int],
) -> list[str]:
    """Resolve verified V2 candidates back to immutable Hunter work artifacts."""
    task_key = str(finding.get("task_key") or "")
    if task_key in work and task_key in start_order:
        return [task_key]
    match = re.fullmatch(r"verified:([0-9a-f]{64})", task_key)
    run_id = str((discovery.get("run_identity") or {}).get("run_id") or "")
    if match is None or not run_id:
        raise BenchmarkContractError("Hunter finding has no executed work provenance")
    run_root = (frozen / run_id).resolve()
    if not run_root.is_relative_to(frozen.resolve()) or not run_root.is_dir():
        raise BenchmarkContractError("verified Hunter artifact root is missing")

    fingerprint = match.group(1)
    matched: set[str] = set()
    for path in sorted(run_root.glob("hunters/*/hunts/*/findings.json")):
        relative = path.relative_to(run_root).as_posix()
        parts = PurePosixPath(relative).parts
        if len(parts) != 5 or parts[0] != "hunters" or parts[2] != "hunts":
            raise BenchmarkContractError("verified Hunter artifact path is invalid")
        work_id = parts[1]
        payload = _load_json(path, "verified Hunter findings")
        raw_findings = payload.get("findings") if isinstance(payload, dict) else None
        if not isinstance(raw_findings, list):
            raise BenchmarkContractError("verified Hunter findings are invalid")
        for raw in raw_findings:
            if not isinstance(raw, dict):
                raise BenchmarkContractError("verified Hunter finding is invalid")
            seed = candidate_from_legacy(raw, run_id=run_id, task_key=relative)
            if seed.fingerprint == fingerprint:
                if work_id not in work or work_id not in start_order:
                    raise BenchmarkContractError(
                        "verified Hunter finding references unexecuted work"
                    )
                matched.add(work_id)
    if not matched:
        raise BenchmarkContractError("verified Hunter finding provenance is missing")
    return sorted(matched, key=lambda work_id: (start_order[work_id], work_id))


def _provider_start_order(plan: dict[str, Any]) -> dict[str, int]:
    allocation = plan.get("budget_allocation") or plan.get("allocation") or {}
    events = (allocation.get("admission_ledger") or {}).get("events") or []
    ordered = []
    for event in events:
        work_id = str(event.get("work_id") or "")
        if event.get("event") == "provider_started" and work_id and work_id not in ordered:
            ordered.append(work_id)
    if not ordered:
        ordered = [
            str(item["work_id"])
            for item in sorted(
                allocation.get("decisions") or [], key=lambda item: int(item["rank"])
            )
        ]
    return {work_id: index for index, work_id in enumerate(ordered, start=1)}


def _verify_run_artifacts(
    raw: dict[str, Any],
    case: BenchmarkCase,
    frozen: Path,
    receipt_path: Path,
) -> dict[str, Any]:
    freeze_manifest = verify_frozen(frozen)
    receipt = _load_json(receipt_path, "authenticated receipt")
    _validate_schema(receipt, "authenticated-benchmark-receipt-v1.schema.json")
    expected_freeze = "sha256:" + freeze_manifest["root_sha256"]
    if (
        receipt["run_id"] != raw["run_id"]
        or receipt["case_id"] != case.case_id
        or receipt["repetition_index"] != case.repetition_index
        or receipt["case_discovery_sha256"] != case.discovery_sha256
        or receipt["freeze_root_sha256"] != expected_freeze
        or receipt["source"] != asdict(case.source)
        or receipt["oracle_isolated"] is not True
    ):
        raise BenchmarkContractError("authenticated receipt linkage is invalid")
    return freeze_manifest


def _require_discovery_complete(path: Path) -> None:
    discovery = _load_json(path / "discovery.json", "discovery")
    if discovery.get("phase") != "discover" or discovery.get("complete") is not True:
        raise BenchmarkContractError("discovery is incomplete")


def _replace_repetition(source: str, repetition: int) -> str:
    result, count = re.subn(
        r"(?m)^repetition_index = [0-9]+$",
        f"repetition_index = {repetition}",
        source,
    )
    if count != 1:
        raise BenchmarkContractError("base case has no unique repetition index")
    return result


def _typed_id(prefix: str, value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{16}", value):
        raise BenchmarkContractError(f"invalid {prefix} ID material")
    return f"{prefix}_{value}"


def _validate_run_spec(raw: Any) -> None:
    if not isinstance(raw, dict) or set(raw) != {
        "run_id",
        "case_id",
        "repetition_index",
        "case_manifest",
        "case_manifest_sha256",
        "discovery_root",
        "freeze_root",
        "receipt",
    }:
        raise BenchmarkContractError("calibration cohort run spec is not closed")
    if (
        re.fullmatch(r"run_[0-9a-f]{16}", str(raw["run_id"])) is None
        or re.fullmatch(r"case_[0-9a-f]{16}", str(raw["case_id"])) is None
        or int(raw["repetition_index"]) not in {1, 2, 3}
        or not _valid_sha256(str(raw["case_manifest_sha256"]))
    ):
        raise BenchmarkContractError("calibration cohort run spec is invalid")
    for key in ("case_manifest", "discovery_root", "freeze_root", "receipt"):
        _validate_reference(str(raw[key]))


def _resolve(root: Path, raw: Any, *, file: bool) -> Path:
    value = str(raw)
    _validate_reference(value)
    path = (root / Path(*PurePosixPath(value).parts)).resolve()
    if not path.is_relative_to(root):
        raise BenchmarkContractError("calibration cohort reference escapes its root")
    if file and not path.is_file():
        raise BenchmarkContractError(f"calibration cohort file is missing: {value}")
    return path


def _validate_reference(value: str) -> None:
    reference = PurePosixPath(value)
    if reference.is_absolute() or ".." in reference.parts or "\\" in value:
        raise BenchmarkContractError("calibration cohort reference is unsafe")


def _relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _validate_schema(value: Any, name: str) -> None:
    schema = json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(value),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "root"
        raise BenchmarkContractError(f"{name} validation failed at {location}: {error.message}")


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkContractError(f"{label} is unreadable") from exc


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _valid_sha256(value: str) -> bool:
    return re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _mapping(values: Iterable[str], *, label: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        case_id, separator, raw_path = value.partition("=")
        if not separator or case_id in result:
            raise BenchmarkContractError(f"invalid or duplicate {label} mapping")
        result[case_id] = Path(raw_path)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the M12.2 calibration cohort")
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan = subparsers.add_parser("plan")
    plan.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    plan.add_argument("--output", type=Path, required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--plan", type=Path, required=True)
    run.add_argument("--repository", action="append", default=[])
    run.add_argument("--prepared-run", action="append", default=[])
    run.add_argument("--model-id")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--plan", type=Path, required=True)
    ready = subparsers.add_parser("evaluation-ready")
    ready.add_argument("--plan", type=Path, required=True)
    ready.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            result: Any = create_cohort_plan(args.catalog, args.output)
        elif args.command == "run":
            result = execute_cohort(
                args.plan,
                repositories=_mapping(args.repository, label="repository"),
                prepared_runs=_mapping(args.prepared_run, label="prepared-run"),
                model_id=args.model_id,
            )
        elif args.command == "verify":
            result = freeze_cohort(args.plan)
        else:
            catalog = open_evaluation(args.plan, args.catalog)
            result = {
                "evaluation_ready": True,
                "catalog_sha256": catalog.sha256,
                "cases": len(catalog.definitions),
            }
    except (BenchmarkContractError, OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
