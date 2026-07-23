"""M11.5 withheld-oracle libcue specialist-preservation release gate."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.run_libtiff_blind_benchmark import (
    BenchmarkContractError,
    freeze_discovery,
    load_scan_manifest,
    run_discover_parent,
    verify_frozen,
    verify_source_pin,
)
from vulnhunt_agent.analysis import CAnalysisGraph
from vulnhunt_agent.sandbox import ContainerExecutor

EVALUATION_SCHEMA = "libcue-specialist-evaluation-v1"
REQUIRED_BUDGET = {
    "max_hunter_sessions": 12,
    "max_input_tokens": 2_000_000,
    "max_output_tokens": 200_000,
    "max_wall_clock_minutes": 60,
    "max_retries_per_work_item": 1,
}
REQUIRED_LIMITS = {
    "max_target_signals_per_work": 6,
    "max_context_bytes": 24_000,
    "max_parallel_hunters": 3,
}


def evaluate_frozen(args: argparse.Namespace) -> dict[str, Any]:
    frozen = args.frozen.resolve()
    freeze_manifest = verify_frozen(frozen)
    discovery = _read_json(frozen / "discovery.json")
    if discovery.get("phase") != "discover" or discovery.get("complete") is not True:
        raise BenchmarkContractError("frozen discovery is incomplete")

    # Withheld data is opened only after the discovery root is closed and verified.
    oracle_path = args.oracle.resolve()
    oracle = tomllib.loads(oracle_path.read_text(encoding="utf-8"))
    scan = load_scan_manifest(args.scan_manifest.resolve())
    vulnerable_repo = args.vulnerable_repo.resolve()
    fixed_repo = args.fixed_repo.resolve()
    vulnerable_identity = verify_source_pin(vulnerable_repo, scan["source"])
    fixed_identity = verify_source_pin(fixed_repo, oracle["fixed_source"])

    analysis = _read_json(frozen / "analysis.json")
    plan = _read_json(frozen / "plan.json")
    graph = CAnalysisGraph.model_validate(analysis.get("graph") or {})
    target_signal_ids = _matching_target_signal_ids(graph, oracle["location"])
    specialist = _specialist_record(plan, target_signal_ids, oracle["location"])
    historical = _historical_detection_record(
        graph,
        plan,
        oracle["historical_detection"],
    )
    allocation = plan.get("allocation") or plan.get("budget_allocation") or {}
    candidates = _load_candidates(frozen, discovery)
    matching_candidates = [
        candidate
        for candidate in candidates
        if _candidate_matches_oracle(candidate, oracle)
    ]
    historical_candidates = [
        candidate
        for candidate in candidates
        if _candidate_matches_historical(
            candidate,
            oracle["historical_detection"],
        )
    ]
    audit = discovery.get("oracle_access_audit") or {}

    checks: dict[str, bool] = {
        "frozen_hashes_verified": bool(freeze_manifest.get("closed")),
        "vulnerable_tree_pinned": bool(vulnerable_identity),
        "fixed_tree_pinned": bool(fixed_identity),
        "oracle_isolated_from_discovery": (
            audit.get("oracle_received") is False
            and audit.get("fixed_tree_received") is False
            and not audit.get("denied_attempts")
        ),
        "fixed_budget_contract": _contains_exact(scan["budget"], REQUIRED_BUDGET)
        and _contains_exact(scan["limits"], REQUIRED_LIMITS),
        "target_signal_identified": bool(target_signal_ids),
        "parser_specialist_planned": specialist is not None,
        "parser_specialist_admitted": bool(
            specialist and specialist.get("admission_rank") is not None
        ),
        "parser_specialist_within_session_cap": bool(
            specialist
            and specialist.get("admission_rank") is not None
            and int(specialist["admission_rank"])
            <= REQUIRED_BUDGET["max_hunter_sessions"]
        ),
        "required_specialist_quota_recorded": bool(
            specialist and specialist.get("quota") == "required_specialist"
        ),
        "required_specialist_reserve_bounded": (
            int(allocation.get("required_specialist_slots") or 0) == 1
            and len(allocation.get("admitted_work_ids") or [])
            <= REQUIRED_BUDGET["max_hunter_sessions"]
        ),
        "cross_file_context_complete": bool(
            specialist and specialist.get("required_paths_present")
        ),
        "target_context_bounded": bool(
            specialist
            and 0 < int(specialist.get("context_bytes") or 0)
            <= REQUIRED_LIMITS["max_context_bytes"]
        ),
        "historical_detection_planned": historical is not None,
        "historical_detection_admitted": bool(
            historical and historical.get("admission_rank") is not None
        ),
        "historical_detection_rank_preserved": bool(
            historical
            and historical.get("admission_rank") is not None
            and int(historical["admission_rank"])
            <= int(oracle["historical_detection"]["maximum_admission_rank"])
        ),
        "historical_detection_context_complete": bool(
            historical and historical.get("required_paths_present")
        ),
    }
    if discovery.get("mode") == "authenticated":
        usage = discovery.get("usage") or {}
        checks["hunter_budget_respected"] = (
            int(usage.get("sessions", 0)) <= REQUIRED_BUDGET["max_hunter_sessions"]
            and sum(
                int(usage.get(key, 0))
                for key in ("input_tokens", "cache_read_tokens", "cache_write_tokens")
            )
            <= REQUIRED_BUDGET["max_input_tokens"]
            and int(usage.get("output_tokens", 0))
            <= REQUIRED_BUDGET["max_output_tokens"]
        )
        checks["matching_model_candidate"] = bool(matching_candidates)
        checks["historical_model_candidate"] = bool(historical_candidates)
    else:
        checks["deterministic_without_model_credentials"] = (
            (discovery.get("model") or {}).get("adapter") == "none"
            and int((discovery.get("usage") or {}).get("sessions", -1)) == 0
        )

    reproduction = None
    if args.run_reproduction:
        if not args.vulnerable_image or not args.fixed_image:
            raise BenchmarkContractError(
                "--run-reproduction requires both prepared images"
            )
        reproduction = asyncio.run(_run_reproduction(
            vulnerable_repo=vulnerable_repo,
            fixed_repo=fixed_repo,
            vulnerable_image=args.vulnerable_image,
            fixed_image=args.fixed_image,
            spec=oracle["reproduction"],
        ))
        checks["vulnerable_asan_reproduced_twice"] = reproduction[
            "vulnerable_passed"
        ]
        checks["fixed_negative_control_passed_twice"] = reproduction["fixed_passed"]

    result = {
        "schema_version": EVALUATION_SCHEMA,
        "phase": "evaluate",
        "passed": all(checks.values()),
        "checks": checks,
        "failed_checks": [name for name, passed in checks.items() if not passed],
        "oracle": {
            "id": oracle["oracle"]["id"],
            "cve": oracle["oracle"]["cve"],
            "loaded_after_freeze_verification": True,
            "manifest_sha256": _sha256(oracle_path),
        },
        "source": {"vulnerable": vulnerable_identity, "fixed": fixed_identity},
        "target": {
            "signal_ids": sorted(target_signal_ids),
            "specialist": specialist,
            "matching_candidates": matching_candidates,
        },
        "historical_detection": {
            "record": historical,
            "matching_candidates": historical_candidates,
        },
        "metrics": {
            "candidate_count": len(candidates),
            "matching_candidate_count": len(matching_candidates),
            "sessions": int((discovery.get("usage") or {}).get("sessions", 0)),
        },
        "reproduction": reproduction,
        "oracle_access_audit": {
            **audit,
            "evaluation_oracle_opened": str(oracle_path),
            "evaluation_started_from_verified_root": freeze_manifest["root_sha256"],
        },
    }
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    _write_json(output / "evaluation.json", result)
    return result


def _matching_target_signal_ids(
    graph: CAnalysisGraph,
    location: dict[str, Any],
) -> set[str]:
    return {
        signal.signal_id
        for signal in graph.signals
        if signal.path == location["sink_file"]
        and int(location["sink_line_min"])
        <= signal.line
        <= int(location["sink_line_max"])
        and signal.category == "array_index_write"
    }


def _specialist_record(
    plan: dict[str, Any],
    target_signal_ids: set[str],
    location: dict[str, Any],
) -> dict[str, Any] | None:
    required_hunter = str(location["required_hunter"])
    work = next((
        item
        for item in plan.get("work_items", [])
        if item.get("hunter") == required_hunter
        and target_signal_ids.intersection(item.get("target_signal_ids", []))
    ), None)
    if work is None:
        return None
    work_id = str(work["work_id"])
    allocation = plan.get("allocation") or plan.get("budget_allocation") or {}
    decision: dict[str, Any] | None = next((
        item for item in allocation.get("decisions", [])
        if item.get("work_id") == work_id
    ), None)
    ranking: dict[str, Any] = next((
        item for item in allocation.get("ranking", [])
        if item.get("work_id") == work_id
    ), {})
    context: dict[str, Any] = next((
        item for item in plan.get("contexts", [])
        if item.get("work_id") == work_id
    ), {})
    hydrated = set(context.get("hydrated_context_files", []))
    required_paths = set(location["required_paths"])
    return {
        "work_id": work_id,
        "hunter": work.get("hunter"),
        "target_signal_ids": sorted(
            target_signal_ids.intersection(work.get("target_signal_ids", []))
        ),
        "pre_admission_rank": ranking.get("pre_admission_rank"),
        "admission_rank": decision.get("rank") if decision else None,
        "quota": decision.get("quota") if decision else None,
        "disposition": ranking.get("disposition"),
        "reason": ranking.get("reason"),
        "context_bytes": int(context.get("bytes") or 0),
        "hydrated_context_files": sorted(hydrated),
        "required_paths_present": required_paths.issubset(hydrated),
    }


def _candidate_matches_oracle(
    candidate: dict[str, Any],
    oracle: dict[str, Any],
) -> bool:
    location = oracle["location"]
    sink = candidate.get("sink") or {
        "path": candidate.get("sink_file", ""),
        "line": candidate.get("sink_line", 0),
    }
    try:
        sink_line = int(sink.get("line") or 0)
    except (TypeError, ValueError):
        sink_line = 0
    locations = [candidate.get("entrypoint") or {}, sink]
    locations.extend(candidate.get("dataflow") or [])
    paths = {
        str(item.get("path", ""))
        for item in locations
        if isinstance(item, dict)
    }
    searchable = " ".join((
        str(candidate.get("title", "")),
        str(candidate.get("weakness", candidate.get("type", ""))),
        str(candidate.get("description", "")),
        *(str(item) for item in candidate.get("impact", [])),
    )).casefold()
    normalized_weakness = re.sub(r"[_-]+", " ", searchable)
    bounds = any(
        term in normalized_weakness
        for term in (
            "out of bounds",
            "negative index",
            "negative array index",
            "oob",
        )
    )
    return (
        sink.get("path") == location["sink_file"]
        and int(location["sink_line_min"]) <= sink_line <= int(location["sink_line_max"])
        and set(location["required_paths"]).issubset(paths)
        and bounds
    )


def _historical_detection_record(
    graph: CAnalysisGraph,
    plan: dict[str, Any],
    spec: dict[str, Any],
) -> dict[str, Any] | None:
    signal_ids = {
        signal.signal_id
        for signal in graph.signals
        if signal.path == spec["sink_file"]
        and int(spec["sink_line_min"])
        <= signal.line
        <= int(spec["sink_line_max"])
    }
    work = next((
        item
        for item in plan.get("work_items", [])
        if item.get("hunter") == spec["required_hunter"]
        and signal_ids.intersection(item.get("target_signal_ids", []))
    ), None)
    if work is None:
        return None
    work_id = str(work["work_id"])
    allocation = plan.get("allocation") or plan.get("budget_allocation") or {}
    decision: dict[str, Any] | None = next((
        item for item in allocation.get("decisions", [])
        if item.get("work_id") == work_id
    ), None)
    context: dict[str, Any] = next((
        item for item in plan.get("contexts", [])
        if item.get("work_id") == work_id
    ), {})
    hydrated = set(context.get("hydrated_context_files", []))
    return {
        "baseline_id": spec["id"],
        "work_id": work_id,
        "hunter": work.get("hunter"),
        "admission_rank": decision.get("rank") if decision else None,
        "quota": decision.get("quota") if decision else None,
        "context_bytes": int(context.get("bytes") or 0),
        "hydrated_context_files": sorted(hydrated),
        "required_paths_present": set(spec["required_paths"]).issubset(hydrated),
        "target_signal_ids": sorted(
            signal_ids.intersection(work.get("target_signal_ids", []))
        ),
    }


def _candidate_matches_historical(
    candidate: dict[str, Any],
    spec: dict[str, Any],
) -> bool:
    sink = candidate.get("sink") or {
        "path": candidate.get("sink_file", ""),
        "line": candidate.get("sink_line", 0),
    }
    try:
        sink_line = int(sink.get("line") or 0)
    except (TypeError, ValueError):
        sink_line = 0
    searchable = " ".join((
        str(candidate.get("title", "")),
        str(candidate.get("weakness", candidate.get("type", ""))),
        str(candidate.get("description", "")),
        *(str(item) for item in candidate.get("impact", [])),
    )).casefold()
    normalized = re.sub(r"[_-]+", " ", searchable)
    return (
        sink.get("path") == spec["sink_file"]
        and int(spec["sink_line_min"]) <= sink_line <= int(spec["sink_line_max"])
        and any(term in normalized for term in spec["weakness_terms"])
    )


async def _run_reproduction(
    *,
    vulnerable_repo: Path,
    fixed_repo: Path,
    vulnerable_image: str,
    fixed_image: str,
    spec: dict[str, Any],
) -> dict[str, Any]:
    attempts = int(spec.get("attempts", 2))
    if attempts < 2:
        raise BenchmarkContractError("actual-target evaluation requires two attempts")

    async def run(repo: Path, image: str, attempt: int) -> dict[str, Any]:
        sandbox = ContainerExecutor(
            repo=repo,
            image=image,
            network="none",
            source_baked=True,
        )
        try:
            await sandbox.start()
            await sandbox.write_file("libcue-specialist-poc.c", str(spec["source"]))
            setup = await sandbox.exec_argv((
                "cc", "-O1", "-g", "-fno-omit-frame-pointer",
                "-fsanitize=address,undefined", "-I/code",
                "/workspace/libcue-specialist-poc.c",
                "/opt/vulnhunt/build/libcue.a",
                "-o", "/workspace/exec/libcue-specialist-poc",
            ))
            if setup.exit_code != 0:
                raise BenchmarkContractError(
                    f"libcue reproduction compilation failed: {setup.stderr}"
                )
            executed = await sandbox.exec_argv((
                "env",
                "ASAN_OPTIONS=detect_leaks=0:abort_on_error=1",
                "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1",
                "/workspace/exec/libcue-specialist-poc",
            ), timeout=int(spec.get("timeout_seconds", 30)))
            evidence = (executed.stdout + "\n" + executed.stderr).strip()
            return {
                "attempt": attempt,
                "clean_environment_id": sandbox.name,
                "exit_code": executed.exit_code,
                "timed_out": executed.timed_out,
                "sanitizer_crash": (
                    executed.exit_code != 0
                    and ("AddressSanitizer" in evidence or "runtime error:" in evidence)
                ),
                "target_frame_present": str(
                    spec["expected_vulnerable_frame"]
                ) in evidence,
                "evidence": evidence[-40_000:],
            }
        finally:
            await sandbox.stop()

    vulnerable = [
        await run(vulnerable_repo, vulnerable_image, attempt)
        for attempt in range(1, attempts + 1)
    ]
    fixed = [
        await run(fixed_repo, fixed_image, attempt)
        for attempt in range(1, attempts + 1)
    ]
    return {
        "vulnerable_passed": all(
            item["sanitizer_crash"] and item["target_frame_present"]
            for item in vulnerable
        ),
        "fixed_passed": all(
            not item["sanitizer_crash"]
            and str(spec["expected_fixed_stderr"]).casefold()
            in item["evidence"].casefold()
            for item in fixed
        ),
        "vulnerable_attempts": vulnerable,
        "fixed_attempts": fixed,
    }


def _load_candidates(frozen: Path, discovery: dict[str, Any]) -> list[dict[str, Any]]:
    path = frozen / "findings.json"
    value = _read_json(path) if path.is_file() else discovery.get("candidates", [])
    return value if isinstance(value, list) else []


def _contains_exact(actual: dict[str, Any], expected: dict[str, int]) -> bool:
    return all(int(actual.get(key, -1)) == value for key, value in expected.items())


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the M11.5 libcue specialist-preservation release gate"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    discover = subparsers.add_parser("discover")
    discover.add_argument("--repo", type=Path, required=True)
    discover.add_argument("--scan-manifest", type=Path, required=True)
    discover.add_argument("--output", type=Path, required=True)
    discover.add_argument(
        "--mode", choices=("deterministic", "authenticated"), required=True
    )
    discover.add_argument("--image", default="")
    discover.add_argument("--model-id")
    discover.add_argument("--skip-verify", action="store_true")

    freeze = subparsers.add_parser("freeze")
    freeze.add_argument("--discovery", type=Path, required=True)
    freeze.add_argument("--frozen", type=Path, required=True)

    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("--frozen", type=Path, required=True)
    evaluate.add_argument("--oracle", type=Path, required=True)
    evaluate.add_argument("--scan-manifest", type=Path, required=True)
    evaluate.add_argument("--vulnerable-repo", type=Path, required=True)
    evaluate.add_argument("--fixed-repo", type=Path, required=True)
    evaluate.add_argument("--output", type=Path, required=True)
    evaluate.add_argument("--run-reproduction", action="store_true")
    evaluate.add_argument("--vulnerable-image", default="")
    evaluate.add_argument("--fixed-image", default="")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "discover":
            result = run_discover_parent(args)
        elif args.command == "freeze":
            result = freeze_discovery(args.discovery, args.frozen)
        else:
            result = evaluate_frozen(args)
    except (BenchmarkContractError, FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    if args.command == "evaluate" and not result["passed"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
