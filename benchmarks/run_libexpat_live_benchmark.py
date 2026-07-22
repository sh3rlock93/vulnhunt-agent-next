"""Pinned libexpat operational benchmark without vulnerability or patch oracles."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

if __package__ in {None, ""}:  # direct ``python benchmarks/...`` execution
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.run_libtiff_blind_benchmark import (
    BenchmarkContractError,
    load_scan_manifest,
    run_discover_parent,
    verify_source_pin,
)
from vulnhunt_agent.analysis import (
    SharedContextCache,
    build_c_analysis_graph,
    build_coverage_plan,
    build_scan_scope,
)
from vulnhunt_agent.domain.schemas import BudgetPolicy
from vulnhunt_agent.infrastructure.artifacts import ArtifactStore
from vulnhunt_agent.intake.snapshot import SnapshotBuilder
from vulnhunt_agent.pipeline.outcome import classify_run_outcome
from vulnhunt_agent.pipeline.filter_files import collect_source_files
from vulnhunt_agent.scheduling import (
    allocate_work_items,
    build_routing_plan,
    build_slice_work_items,
)
from vulnhunt_agent.verification.feasibility import (
    discover_counter_feasibility_assessments,
)

BENCHMARK_SCHEMA = "libexpat-operational-v1"
FREEZE_SCHEMA = "operational-freeze-v1"


def run_deterministic(repo: Path, manifest_path: Path, output: Path) -> dict[str, Any]:
    manifest = _load_manifest(manifest_path)
    identity = verify_source_pin(repo, manifest["source"])
    _new_output(output)
    output.mkdir(parents=True)

    artifact_store = ArtifactStore(output / "snapshot-artifacts")
    snapshot = SnapshotBuilder(artifact_store).create(
        repo,
        source_url=str(manifest["source"]["repository"]),
        resolved_ref=str(manifest["source"]["commit"]),
    )
    source_manifest = json.loads(
        artifact_store.read_bytes(snapshot.manifest_artifact)
    )
    files, _test_files = collect_source_files(repo, "c")
    graph = build_c_analysis_graph(repo, files)
    coverage = build_coverage_plan(graph)
    scope_spec = manifest.get("scope") or {"mode": "full"}
    scope = build_scan_scope(
        repo,
        source_files=files,
        graph=graph,
        coverage=coverage,
        mode=str(scope_spec.get("mode") or "full"),
        include_paths=scope_spec.get("include_paths") or (),
        exclude_paths=scope_spec.get("exclude_paths") or (),
    )
    analysis = {
        "language": "c",
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": coverage.model_dump(mode="json"),
        "incremental_scope": {"mode": "full"},
        "scan_scope": scope.model_dump(mode="json"),
    }
    routing = build_routing_plan(
        run_id=str(manifest["benchmark"]["id"]),
        source_snapshot=snapshot.snapshot_artifact,
        selected_files=list(scope.selected_files),
        enabled_hunters=list(manifest["scan"]["hunters"]),
        analysis=analysis,
    )
    work = build_slice_work_items(routing, analysis)
    budget = BudgetPolicy(
        max_hunter_sessions=int(manifest["budget"]["max_hunter_sessions"]),
        max_input_tokens=int(manifest["budget"]["max_input_tokens"]),
        max_output_tokens=int(manifest["budget"]["max_output_tokens"]),
        max_wall_clock_minutes=int(
            manifest["budget"]["max_wall_clock_minutes"]
        ),
        max_retries_per_work_item=int(
            manifest["budget"]["max_retries_per_work_item"]
        ),
    )
    allocation = allocate_work_items(
        work,
        budget,
        risk_chains=graph.risk_chains,
        entrypoint_ids=graph.entrypoint_ids,
        native_full_scan=True,
    )
    admitted_ids = set(allocation.admitted_work_ids)
    admitted = [item for item in work if item.work_id in admitted_ids]
    contexts = SharedContextCache(
        output / "contexts",
        repo,
        source_snapshot=snapshot.snapshot_artifact,
        analysis=analysis,
    )
    context_records: list[dict[str, Any]] = []
    for item in admitted:
        packet = contexts.get(item)
        path = output / "contexts" / f"{packet['cache_key']}.json"
        context_records.append({
            "work_id": item.work_id,
            "bytes": path.stat().st_size,
            "related_nodes": len(packet.get("related_nodes") or ()),
            "constraints": len(packet.get("constraint_facts") or ()),
        })

    assessments = discover_counter_feasibility_assessments(
        source_root=repo,
        source_snapshot=snapshot.snapshot_artifact,
        analysis=analysis,
        run_id=str(manifest["benchmark"]["id"]),
    )
    terminal_routes = _terminal_routes(graph.critical_sink_ids, work, allocation)
    seed_counts = Counter(item.seed_file for item in admitted)
    critical_seed_files = {
        item.seed_file for item in admitted if item.required
    }
    result = {
        "schema_version": BENCHMARK_SCHEMA,
        "mode": "deterministic",
        "passed": False,
        "source": identity,
        "digests": {
            "scan_manifest": _sha256_file(manifest_path),
            "full_snapshot": snapshot.snapshot_artifact,
            "source_manifest": snapshot.manifest_artifact,
            "scope_manifest": scope.digest,
        },
        "provider": {
            "calls": 0,
            "credentials_required": False,
            "network_required": False,
        },
        "scope": scope.model_dump(mode="json"),
        "planning": {
            "source_files": len(files),
            "selected_files": len(scope.selected_files),
            "scope_deferred_targets": len(scope.scope_deferred_critical_sink_ids),
            "work_items": len(work),
            "admitted": len(admitted),
            "budget_deferred": len(allocation.deferred),
            "distinct_seed_files": len(seed_counts),
            "distinct_critical_seed_files": len(critical_seed_files),
            "maximum_seed_session_share": (
                max(seed_counts.values(), default=0) / len(admitted)
                if admitted else 0.0
            ),
            "allocation": {
                **asdict(allocation),
                "decisions": [asdict(item) for item in allocation.decisions],
            },
            "terminal_routes": terminal_routes,
        },
        "context": {
            "records": context_records,
            "maximum_bytes": max(
                (int(item["bytes"]) for item in context_records), default=0
            ),
            "hydrated_with_related_constraints": any(
                item["related_nodes"] and item["constraints"]
                for item in context_records
            ),
        },
        "feasibility": {
            "assessments": [
                item.model_dump(mode="json") for item in assessments
            ],
            "status_counts": dict(sorted(Counter(
                item.status.value for item in assessments
            ).items())),
        },
        "intake": {
            "files": snapshot.file_count,
            "bytes": snapshot.total_bytes,
            "safe_internal_symlinks": len(source_manifest.get("symlinks") or ()),
        },
        "outcome_contract": _outcome_contract_fixture(scope.model_dump(mode="json")),
        "policies": manifest["policies"],
        "budget": manifest["budget"],
    }
    checks = {
        "pinned_source": bool(identity),
        "safe_internal_symlink_intake": result["intake"]["safe_internal_symlinks"] > 0,
        "full_scope_complete": scope.repository_complete and not scope.scope_deferred_critical_sink_ids,
        "critical_routes_terminal": terminal_routes["unrouted"] == 0,
        "twelve_session_ceiling": len(admitted) <= 12,
        "three_critical_seed_files": len(critical_seed_files) >= 3,
        "dense_file_not_monopolizing": max(seed_counts.values(), default=0) < len(admitted),
        "context_bounded": result["context"]["maximum_bytes"] <= 24_000,
        "full_snapshot_context_hydrated": result["context"]["hydrated_with_related_constraints"],
        "source_cited_feasibility_refutation": any(
            item.status.value == "logically_infeasible"
            and item.bounds
            and item.arithmetic
            for item in assessments
        ),
        "run_outcomes_distinct": result["outcome_contract"]["passed"],
        "provider_free": result["provider"]["calls"] == 0,
    }
    result["checks"] = checks
    result["failed_checks"] = [key for key, passed in checks.items() if not passed]
    result["passed"] = all(checks.values())
    _write_json(output / "analysis.json", analysis)
    _write_json(output / "operational.json", result)
    _write_json(output / "metrics.json", _metrics(result))
    _write_freeze_manifest(output)
    return result


def run_authenticated(args: argparse.Namespace) -> dict[str, Any]:
    manifest = _load_manifest(args.manifest.resolve())
    output = args.output.resolve()
    _new_output(output)
    output.mkdir(parents=True)
    discovery_root = output / "discovery"
    discovery = run_discover_parent(argparse.Namespace(
        repo=args.repo.resolve(),
        scan_manifest=args.manifest.resolve(),
        output=discovery_root,
        mode="authenticated",
        image=args.image,
        model_id=args.model_id,
        skip_verify=False,
    ))
    run_id = str((discovery.get("run_identity") or {}).get("run_id") or "")
    run_dir = discovery_root / run_id
    hunt = _read_json(run_dir / "steps" / "hunt.json")
    plan = _read_json(run_dir / "steps" / "hunt_plan.json")
    verify = _read_json(run_dir / "steps" / "verify.json")
    preflight = _read_json(run_dir / "steps" / "provider_preflight.json")
    snapshot = _read_json(run_dir / "steps" / "source_snapshot.json")
    scope = (_read_json(run_dir / "steps" / "analysis_graph.json")).get(
        "scan_scope", {}
    )
    candidates = discovery.get("candidates") or []
    resolutions = Counter(
        str((item.get("resolution") or {}).get("disposition") or "unresolved")
        for item in candidates
    )
    candidate_outcomes = _candidate_outcome_counts(resolutions)
    usage = discovery.get("usage") or {}
    completed_work = int(hunt.get("done", 0) or 0)
    work_items = {
        str(item.get("work_id")): item
        for item in plan.get("work_items") or ()
        if isinstance(item, dict) and item.get("work_id")
    }
    allocation = plan.get("budget_allocation") or {}
    admitted_ids = {
        str(item.get("work_id"))
        for item in allocation.get("decisions") or ()
        if isinstance(item, dict) and item.get("work_id")
    }
    admitted_ids.update(
        str(item) for item in allocation.get("recycled_work_ids") or ()
    )
    seed_counts = Counter(
        str(work_items[work_id].get("seed_file") or "unknown")
        for work_id in admitted_ids
        if work_id in work_items
    )
    scope_deferred = len(scope.get("scope_deferred_critical_sink_ids") or ())
    final_budget_deferred = len(plan.get("budget_deferred_work_ids") or ())
    outcome = hunt.get("run_outcome") or {}
    targets = outcome.get("targets") or {}
    completed_targets = int(targets.get("finding", 0) or 0) + int(
        targets.get("no_finding", 0) or 0
    )
    admitted_targets = sum(
        len(
            work_items[work_id].get("target_signal_ids")
            or work_items[work_id].get("target_node_ids")
            or ()
        )
        for work_id in admitted_ids
        if work_id in work_items
    )
    budget_deferred_targets = sum(
        len(
            work_items[work_id].get("target_signal_ids")
            or work_items[work_id].get("target_node_ids")
            or ()
        )
        for work_id in plan.get("budget_deferred_work_ids") or ()
        if work_id in work_items
    )
    result = {
        "schema_version": BENCHMARK_SCHEMA,
        "mode": "authenticated",
        "passed": False,
        "run_id": run_id,
        "source": discovery.get("run_identity", {}).get("source", {}),
        "digests": {
            "scan_manifest": _sha256_file(args.manifest.resolve()),
            "full_snapshot": snapshot.get("snapshot_artifact"),
            "scope_manifest": scope.get("digest"),
        },
        "provider": {
            "preflight": preflight,
            "model": discovery.get("model") or {},
        },
        "scope": scope,
        "planning": {
            "selected_files": len(scope.get("selected_files") or ()),
            "selected_targets": len(scope.get("in_scope_critical_sink_ids") or ()),
            "scope_deferred_targets": scope_deferred,
            "work_items": int(plan.get("scheduled_sessions", 0) or 0),
            "admitted": len(admitted_ids),
            "admitted_targets": admitted_targets,
            "budget_deferred": final_budget_deferred,
            "budget_deferred_targets": budget_deferred_targets,
            "admitted_deferred_work": int(
                (outcome.get("work") or {}).get("admitted_deferred", 0) or 0
            ),
            "admitted_deferred_targets": max(
                int(targets.get("deferred", 0) or 0) - budget_deferred_targets,
                0,
            ),
            "completed_work": completed_work,
            "completed_targets": completed_targets,
            "distinct_seed_files": len(seed_counts),
            "maximum_seed_session_share": (
                max(seed_counts.values(), default=0) / len(admitted_ids)
                if admitted_ids else 0.0
            ),
        },
        "usage": usage,
        "tokens_per_completed_target": (
            _model_token_usage(usage)
            / completed_targets if completed_targets else None
        ),
        "time_to_first_supported_candidate_ms": _time_to_first_supported_candidate(
            run_dir,
            candidates,
        ),
        "candidate_resolutions": dict(sorted(resolutions.items())),
        "candidate_outcomes": candidate_outcomes,
        "verification": verify,
        "run_outcome": outcome,
        "target_accounting": targets,
        "policies": manifest["policies"],
        "budget": manifest["budget"],
    }
    budget = manifest["budget"]
    outcome = result["run_outcome"]
    checks = {
        "provider_ready": preflight.get("status") == "ready",
        "session_budget": int(usage.get("sessions", 0)) <= int(
            budget["max_hunter_sessions"]
        ),
        "input_budget": _input_token_usage(usage) <= int(
            budget["max_input_tokens"]
        ),
        "output_budget": int(usage.get("output_tokens", 0)) <= int(
            budget["max_output_tokens"]
        ),
        "wall_clock_budget": int(usage.get("wall_time_ms", 0)) <= int(
            budget["max_wall_clock_minutes"]
        ) * 60_000,
        "terminal_admitted_targets": bool(
            (outcome.get("targets") or {}).get("all_admitted_terminal")
        ),
        "honest_outcome": outcome.get("outcome") in {
            "valid_complete",
            "valid_budget_limited",
            "invalid_execution",
            "interrupted",
        },
        "all_candidates_resolved": "unresolved" not in resolutions,
        "scope_accounting_exact": (
            int((outcome.get("scope") or {}).get(
                "scope_deferred_critical_targets", -1
            )) == scope_deferred
            and int((outcome.get("work") or {}).get("budget_deferred", -1))
            == int(hunt.get("budget_deferred", 0) or 0)
        ),
        "usage_dimensions_complete": all(
            key in usage
            for key in (
                "input_tokens",
                "output_tokens",
                "cache_read_tokens",
                "cache_write_tokens",
                "tool_calls",
                "wall_time_ms",
            )
        ),
    }
    result["checks"] = checks
    result["failed_checks"] = [key for key, passed in checks.items() if not passed]
    result["passed"] = all(checks.values())
    _write_json(output / "operational.json", result)
    _write_json(output / "metrics.json", _metrics(result))
    _write_freeze_manifest(output)
    return result


def verify_freeze(output: Path) -> bool:
    manifest = _read_json(output / "freeze-manifest.json")
    if manifest.get("schema_version") != FREEZE_SCHEMA:
        return False
    actual = _artifact_entries(output)
    return (
        actual == manifest.get("files")
        and _entries_digest(actual) == manifest.get("root_sha256")
    )


def _load_manifest(path: Path) -> dict[str, Any]:
    payload = load_scan_manifest(path)
    raw = path.read_text(encoding="utf-8")
    if any(token in raw.casefold() for token in ("cve-", "patch", "fixed_", "ground_truth")):
        raise BenchmarkContractError("live benchmark manifest contains withheld knowledge")
    if int(payload["budget"]["max_hunter_sessions"]) != 12:
        raise BenchmarkContractError("live benchmark requires the fixed 12-session ceiling")
    return payload


def _terminal_routes(critical_ids, work, allocation) -> dict[str, Any]:
    admitted = set(allocation.admitted_work_ids)
    deferred = set(allocation.deferred)
    by_target: dict[str, set[str]] = {}
    for item in work:
        for target_id in item.target_signal_ids:
            by_target.setdefault(target_id, set()).add(item.work_id)
    dispositions = {}
    for target_id in critical_ids:
        work_ids = by_target.get(target_id, set())
        if work_ids & admitted:
            dispositions[target_id] = "admitted"
        elif work_ids & deferred:
            dispositions[target_id] = "budget_deferred"
        else:
            dispositions[target_id] = "unrouted"
    return {
        "admitted": sum(value == "admitted" for value in dispositions.values()),
        "budget_deferred": sum(
            value == "budget_deferred" for value in dispositions.values()
        ),
        "unrouted": sum(value == "unrouted" for value in dispositions.values()),
        "dispositions": dispositions,
    }


def _outcome_contract_fixture(scope: dict[str, Any]) -> dict[str, Any]:
    target_completion: dict[str, Any] = {
        "total": 1,
        "finding": 0,
        "no_finding": 1,
        "deferred": 0,
        "missing": 0,
    }
    base: dict[str, Any] = {
        "total": 1,
        "done": 1,
        "failed": 0,
        "pending": 0,
        "budget_deferred": 0,
        "total_findings": 0,
        "target_completion": target_completion,
    }
    cases = {
        "valid_complete": classify_run_outcome(base, scan_scope=scope),
        "valid_budget_limited": classify_run_outcome(
            {
                **base,
                "done": 0,
                "budget_deferred": 1,
                "target_completion": {
                    **target_completion,
                    "no_finding": 0,
                    "deferred": 1,
                },
            },
            scan_scope=scope,
        ),
        "invalid_execution": classify_run_outcome(
            base,
            scan_scope=scope,
            invalid_reason="provider_preflight_failed",
        ),
        "interrupted": classify_run_outcome(
            {**base, "done": 0, "pending": 1},
            scan_scope=scope,
        ),
    }
    expected = set(cases)
    observed = {item["outcome"] for item in cases.values()}
    return {
        "passed": expected == observed and all(
            not item["zero_findings"]
            for key, item in cases.items()
            if key in {"invalid_execution", "interrupted"}
        ),
        "cases": cases,
    }


def _metrics(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": BENCHMARK_SCHEMA,
        "mode": result["mode"],
        "passed": result["passed"],
        "digests": result.get("digests") or {},
        "scope": result.get("scope") or {},
        "planning": result.get("planning") or {},
        "usage": result.get("usage") or {
            "sessions": 0,
            "calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
            "tool_calls": 0,
            "wall_time_ms": 0,
        },
        "candidate_resolutions": result.get("candidate_resolutions") or {},
        "candidate_outcomes": result.get("candidate_outcomes") or {
            "confirmed": 0,
            "refuted": 0,
            "rejected": 0,
            "deferred": 0,
        },
        "run_outcome": result.get("run_outcome") or {},
    }


def _candidate_outcome_counts(resolutions: Counter[str]) -> dict[str, int]:
    return {
        "confirmed": resolutions["confirmed"],
        "refuted": (
            resolutions["statically_refuted"]
            + resolutions["resource_infeasible"]
        ),
        "rejected": resolutions["reproduction_rejected"],
        "deferred": resolutions["verification_deferred"],
    }


def _input_token_usage(usage: dict[str, Any]) -> int:
    return sum(
        int(usage.get(key, 0))
        for key in (
            "input_tokens",
            "cache_read_tokens",
            "cache_write_tokens",
        )
    )


def _model_token_usage(usage: dict[str, Any]) -> int:
    return _input_token_usage(usage) + int(usage.get("output_tokens", 0))


def _time_to_first_supported_candidate(
    run_dir: Path,
    candidates: list[dict[str, Any]],
) -> int | None:
    events = run_dir / "events.jsonl"
    if not events.is_file():
        return None
    started: datetime | None = None
    for line in events.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
            timestamp = datetime.fromisoformat(str(event["ts"]))
        except (KeyError, ValueError, json.JSONDecodeError):
            continue
        started = timestamp if started is None or timestamp < started else started
    supported_times: list[datetime] = []
    for candidate in candidates:
        if not candidate.get("resolution") and candidate.get("state") not in {
            "statically_supported",
            "confirmed",
        }:
            continue
        try:
            supported_times.append(datetime.fromisoformat(str(candidate["created_at"])))
        except (KeyError, ValueError):
            continue
    first = min(supported_times, default=None)
    return int((first - started).total_seconds() * 1000) if started and first else None


def _write_freeze_manifest(output: Path) -> None:
    entries = _artifact_entries(output)
    _write_json(output / "freeze-manifest.json", {
        "schema_version": FREEZE_SCHEMA,
        "files": entries,
        "root_sha256": _entries_digest(entries),
        "closed": True,
    })


def _artifact_entries(output: Path) -> list[dict[str, Any]]:
    entries = []
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.name == "freeze-manifest.json":
            continue
        entries.append({
            "path": path.relative_to(output).as_posix(),
            "size": path.stat().st_size,
            "sha256": _sha256_file(path),
        })
    return entries


def _entries_digest(entries: list[dict[str, Any]]) -> str:
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def _sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _new_output(path: Path) -> None:
    if path.exists():
        raise BenchmarkContractError(f"output already exists: {path}")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n")


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("deterministic", "authenticated", "verify"))
    parser.add_argument("--repo", type=Path)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("benchmarks/libexpat-live-scan.toml"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default="")
    parser.add_argument("--model-id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.mode == "verify":
        passed = verify_freeze(args.output.resolve())
        print(json.dumps({"passed": passed}, indent=2))
        return 0 if passed else 1
    if args.repo is None:
        raise SystemExit("--repo is required")
    if args.mode == "authenticated":
        if not args.image:
            raise SystemExit("authenticated mode requires --image")
        result = run_authenticated(args)
    else:
        result = run_deterministic(
            args.repo.resolve(),
            args.manifest.resolve(),
            args.output.resolve(),
        )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
