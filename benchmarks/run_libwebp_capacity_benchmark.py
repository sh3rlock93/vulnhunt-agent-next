"""M11.2 withheld-oracle libwebp capacity-ranking release gate."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
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
    source_files,
    verify_frozen,
    verify_source_pin,
)
from vulnhunt_agent.analysis import CAnalysisGraph, build_c_analysis_graph
from vulnhunt_agent.reproduction.provenance import (
    NATIVE_EVIDENCE_POLICY,
    derive_execution_provenance,
)
from vulnhunt_agent.sandbox import ContainerExecutor

EVALUATION_SCHEMA = "libwebp-capacity-evaluation-v1"
REQUIRED_ADMISSION_RANK = 6
REQUIRED_BUDGET = {
    "max_hunter_sessions": 12,
    "max_input_tokens": 1_000_000,
    "max_output_tokens": 100_000,
    "max_wall_clock_minutes": 45,
    "max_retries_per_work_item": 1,
}
REQUIRED_LIMITS = {
    "max_target_signals_per_work": 6,
    "max_context_bytes": 24_000,
    "max_parallel_hunters": 2,
}


def evaluate_frozen(args: argparse.Namespace) -> dict[str, Any]:
    frozen = args.frozen.resolve()
    freeze_manifest = verify_frozen(frozen)
    discovery = _read_json(frozen / "discovery.json")
    if discovery.get("phase") != "discover" or discovery.get("complete") is not True:
        raise BenchmarkContractError("frozen discovery is incomplete")

    # Withheld data becomes reachable only after the closed discovery hash verifies.
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
    vulnerable_chains = _matching_capacity_chains(graph, oracle["location"])
    fixed_graph = build_c_analysis_graph(fixed_repo, source_files(fixed_repo))
    fixed_chains = _matching_capacity_chains(fixed_graph, oracle["location"])
    admitted_rank = _matching_admission_rank(plan, vulnerable_chains)
    context = _matching_context(plan, vulnerable_chains, oracle["location"])
    candidates = _load_candidates(frozen, discovery)
    matching_candidates = [
        candidate
        for candidate in candidates
        if _candidate_matches_oracle(candidate, oracle)
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
        "capacity_policies_recorded": _capacity_policies_recorded(
            discovery.get("policies") or {}
        ),
        "fixed_budget_contract": _contains_exact(scan["budget"], REQUIRED_BUDGET)
        and _contains_exact(scan["limits"], REQUIRED_LIMITS),
        "full_plan_bounded": (
            int(discovery["summary"].get("max_target_signals", 7)) <= 6
            and int(discovery["summary"].get("max_context_bytes", 24_001))
            <= 24_000
        ),
        "terminal_routes_complete": bool(
            discovery["summary"].get("dispositions_complete")
        ),
        "vulnerable_complete_unchecked_chain_found": any(
            chain.priority_class.value == "complete_unchecked_capacity_path"
            and chain.guard_state.value == "absent"
            for chain in vulnerable_chains
        ),
        "target_admitted_in_top_six": (
            admitted_rank is not None and admitted_rank <= REQUIRED_ADMISSION_RANK
        ),
        "cross_file_context_complete": context is not None
        and context["required_paths_present"],
        "target_context_bounded": context is not None
        and 0 < context["bytes"] <= 24_000,
        "fixed_has_no_equivalent_unsafe_chain": not any(
            chain.priority_class.value.startswith("complete_")
            and chain.guard_state.value != "dominates"
            for chain in fixed_chains
        ),
        "native_evidence_policy_recorded": (
            discovery.get("policies", {}).get("evidence")
            == NATIVE_EVIDENCE_POLICY
        ),
    }
    if discovery.get("mode") == "authenticated":
        usage = discovery.get("usage") or {}
        model = discovery.get("model") or {}
        checks["authenticated_identity_complete"] = all((
            bool((discovery.get("run_identity") or {}).get("run_id")),
            bool(model.get("adapter")),
            bool(model.get("model_id")),
            "estimated_cost_usd" in usage,
        ))
        checks["hunter_budget_respected"] = (
            int(usage.get("sessions", 0)) <= REQUIRED_BUDGET["max_hunter_sessions"]
            and sum(
                int(usage.get(key, 0))
                for key in (
                    "input_tokens",
                    "cache_read_tokens",
                    "cache_write_tokens",
                )
            )
            <= REQUIRED_BUDGET["max_input_tokens"]
            and int(usage.get("output_tokens", 0))
            <= REQUIRED_BUDGET["max_output_tokens"]
        )
        checks["matching_model_candidate"] = bool(matching_candidates)
    else:
        checks["deterministic_without_model_credentials"] = (
            (discovery.get("model") or {}).get("adapter") == "none"
            and int((discovery.get("usage") or {}).get("sessions", -1)) == 0
        )

    reproduction = None
    if args.run_reproduction:
        if not args.poc or not args.vulnerable_image or not args.fixed_image:
            raise BenchmarkContractError(
                "--run-reproduction requires --poc and both prepared images"
            )
        reproduction = asyncio.run(_run_reproduction(
            vulnerable_repo=vulnerable_repo,
            fixed_repo=fixed_repo,
            vulnerable_image=args.vulnerable_image,
            fixed_image=args.fixed_image,
            poc=args.poc.resolve(),
            spec=oracle["reproduction"],
        ))
        checks["two_clean_vulnerable_asan_attempts"] = reproduction[
            "vulnerable_passed"
        ]
        checks["two_clean_fixed_negative_attempts"] = reproduction["fixed_passed"]

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
        "source": {
            "vulnerable": vulnerable_identity,
            "fixed": fixed_identity,
        },
        "target": {
            "vulnerable_chains": [
                chain.model_dump(mode="json") for chain in vulnerable_chains
            ],
            "fixed_chains": [
                chain.model_dump(mode="json") for chain in fixed_chains
            ],
            "admission_rank": admitted_rank,
            "context": context,
            "matching_candidates": matching_candidates,
        },
        "metrics": {
            "top_k_admission_rank": admitted_rank,
            "candidate_count": len(candidates),
            "matching_candidate_count": len(matching_candidates),
            "sessions": int((discovery.get("usage") or {}).get("sessions", 0)),
            "input_tokens": int(
                (discovery.get("usage") or {}).get("input_tokens", 0)
            ),
            "output_tokens": int(
                (discovery.get("usage") or {}).get("output_tokens", 0)
            ),
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


def _matching_capacity_chains(
    graph: CAnalysisGraph,
    location: dict[str, Any],
) -> list[Any]:
    facts = {fact.fact_id: fact for fact in graph.capacity_facts}
    required_paths = set(location["required_paths"])
    matches = []
    for chain in graph.capacity_risk_chains:
        allocation = facts.get(chain.allocation_fact_id)
        write_facts = [facts.get(fact_id) for fact_id in chain.write_fact_ids]
        allocation_match = (
            allocation is not None
            and allocation.path == location["allocation_file"]
            and int(location["allocation_line_min"])
            <= allocation.line
            <= int(location["allocation_line_max"])
        )
        write_match = any(
            fact is not None
            and fact.path == location["write_file"]
            and int(location["write_line_min"])
            <= fact.line
            <= int(location["write_line_max"])
            for fact in write_facts
        )
        if allocation_match and write_match and required_paths.issubset(chain.paths):
            matches.append(chain)
    return matches


def _matching_admission_rank(plan: dict[str, Any], chains: list[Any]) -> int | None:
    chain_ids = {chain.chain_id for chain in chains}
    allocation = plan.get("allocation") or plan.get("budget_allocation") or {}
    ranks = [
        int(record["pre_admission_rank"])
        for record in allocation.get("ranking", [])
        if record.get("disposition") == "admitted"
        and chain_ids.intersection(record.get("chain_ids", []))
    ]
    return min(ranks) if ranks else None


def _matching_context(
    plan: dict[str, Any],
    chains: list[Any],
    location: dict[str, Any],
) -> dict[str, Any] | None:
    chain_ids = {chain.chain_id for chain in chains}
    required_paths = set(location["required_paths"])
    records = [
        item
        for item in plan.get("contexts", [])
        if chain_ids.intersection(item.get("capacity_risk_chain_ids", []))
    ]
    if not records:
        return None
    records.sort(key=lambda item: (int(item["bytes"]), str(item["work_id"])))
    record = records[0]
    hydrated = set(record.get("hydrated_context_files", []))
    return {
        "work_id": record["work_id"],
        "cache_key": record["cache_key"],
        "bytes": int(record["bytes"]),
        "required_paths_present": required_paths.issubset(hydrated),
        "hydrated_context_files": sorted(hydrated),
        "chain_ids": sorted(
            chain_ids.intersection(record.get("capacity_risk_chain_ids", []))
        ),
    }


def _candidate_matches_oracle(
    candidate: dict[str, Any],
    oracle: dict[str, Any],
) -> bool:
    location = oracle["location"]
    required_paths = set(location["required_paths"])
    locations = [candidate.get("entrypoint") or {}, candidate.get("sink") or {}]
    locations.extend(candidate.get("dataflow") or [])
    paths = {
        str(item.get("path", ""))
        for item in locations
        if isinstance(item, dict)
    }
    searchable = " ".join((
        str(candidate.get("title", "")),
        str(candidate.get("weakness", "")),
        *(str(item) for item in candidate.get("impact", [])),
    )).casefold()
    capacity_match = any(
        term in searchable for term in ("capacity", "table", "allocation", "size")
    )
    bounds_match = any(
        term in searchable
        for term in ("overflow", "out-of-bounds", "out of bounds", "oob")
    )
    return required_paths.issubset(paths) and capacity_match and bounds_match


async def _run_reproduction(
    *,
    vulnerable_repo: Path,
    fixed_repo: Path,
    vulnerable_image: str,
    fixed_image: str,
    poc: Path,
    spec: dict[str, Any],
) -> dict[str, Any]:
    if not poc.is_file():
        raise BenchmarkContractError(f"PoC does not exist: {poc}")
    payload = poc.read_bytes()
    if len(payload) != int(spec["poc_size"]) or hashlib.sha256(payload).hexdigest() != str(
        spec["poc_sha256"]
    ):
        raise BenchmarkContractError("PoC size or SHA-256 does not match oracle")
    attempts = int(spec.get("attempts", 2))
    if attempts < 2:
        raise BenchmarkContractError("actual-target evaluation requires two attempts")

    async def run(repo: Path, image: str, index: int) -> dict[str, Any]:
        sandbox = ContainerExecutor(
            repo=repo,
            image=image,
            network="none",
            source_baked=True,
        )
        try:
            await sandbox.start()
            environment_id = sandbox.name
            await sandbox.write_bytes(str(spec["workspace_input"]), payload)
            argv = tuple(str(item) for item in spec["argv"])
            execution = await sandbox.exec_argv(
                argv,
                timeout=int(spec.get("timeout_seconds", 30)),
            )
            provenance = derive_execution_provenance(
                argv=argv,
                setup_argvs=(),
                stdout=execution.stdout,
                stderr=execution.stderr,
            )
            return {
                "attempt": index,
                "clean_environment_id": environment_id,
                "exit_code": execution.exit_code,
                "timed_out": execution.timed_out,
                "duration_ms": execution.duration_ms,
                "stdout": execution.stdout[-20_000:],
                "stderr": execution.stderr[-40_000:],
                "execution_subject": provenance.execution_subject.value,
                "target_binary": provenance.target_binary,
                "target_source_reached": provenance.target_source_reached,
                "sanitizer_failure_class": provenance.sanitizer_failure_class,
                "sanitizer_frames": [
                    item.model_dump(mode="json")
                    for item in provenance.sanitizer_frames
                ],
                "provenance_policy": NATIVE_EVIDENCE_POLICY,
            }
        finally:
            await sandbox.stop()

    vulnerable = [
        await run(vulnerable_repo, vulnerable_image, index)
        for index in range(1, attempts + 1)
    ]
    fixed = [
        await run(fixed_repo, fixed_image, index)
        for index in range(1, attempts + 1)
    ]
    expected_failure = str(spec["expected_vulnerable_failure"])
    vulnerable_passed = (
        len({item["clean_environment_id"] for item in vulnerable}) == attempts
        and all(
            item["execution_subject"] == "prepared_binary"
            and item["target_source_reached"]
            and item["sanitizer_failure_class"] == expected_failure
            for item in vulnerable
        )
    )
    fixed_passed = (
        len({item["clean_environment_id"] for item in fixed}) == attempts
        and all(item["sanitizer_failure_class"] is None for item in fixed)
        and all(
            str(spec["expected_fixed_stderr"]) in item["stderr"]
            for item in fixed
        )
    )
    return {
        "policy_version": NATIVE_EVIDENCE_POLICY,
        "poc": {
            "path": str(poc),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        },
        "vulnerable_passed": vulnerable_passed,
        "fixed_passed": fixed_passed,
        "vulnerable_attempts": vulnerable,
        "fixed_attempts": fixed,
    }


def _capacity_policies_recorded(policies: dict[str, Any]) -> bool:
    return all((
        policies.get("capacity_fact") == "c-capacity-fact-v2",
        policies.get("capacity_summary") == "c-capacity-summary-v2",
        policies.get("capacity_risk_chain") == "c-capacity-risk-chain-v3",
        policies.get("context") == "c-context-v6",
        policies.get("admission") == "c-budget-v7",
    ))


def _contains_exact(actual: dict[str, Any], expected: dict[str, int]) -> bool:
    return all(int(actual.get(key, -1)) == value for key, value in expected.items())


def _load_candidates(
    frozen: Path,
    discovery: dict[str, Any],
) -> list[dict[str, Any]]:
    path = frozen / "findings.json"
    value = _read_json(path) if path.is_file() else discovery.get("candidates", [])
    return value if isinstance(value, list) else []


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
        description="Run the M11.2 libwebp blind capacity-ranking release gate"
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
    evaluate.add_argument("--poc", type=Path)
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
