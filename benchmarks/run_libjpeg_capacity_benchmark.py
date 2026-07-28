"""M11.4 dual-mode withheld-oracle libjpeg-turbo capacity gate."""
from __future__ import annotations

import argparse
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
from benchmarks.run_libwebp_capacity_benchmark import (
    _contains_exact,
    _load_candidates,
    _matching_admission_rank,
    _matching_capacity_chains,
    _matching_context,
    _read_json,
    _sha256,
    _write_json,
)
from vulnhunt_agent.analysis import CAnalysisGraph, build_c_analysis_graph
from vulnhunt_agent.reproduction.provenance import NATIVE_EVIDENCE_POLICY

EVALUATION_SCHEMA = "libjpeg-capacity-alias-evaluation-v1"
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

    # The oracle and fixed source are opened only after the frozen hashes verify.
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
    pre_admission_rank = _matching_admission_rank(plan, vulnerable_chains)
    session_rank = _matching_session_rank(plan, vulnerable_chains)
    provider_start_rank = _matching_provider_start_rank(plan, vulnerable_chains)
    context = _matching_context(plan, vulnerable_chains, oracle["location"])
    candidates = _load_model_candidates(frozen, discovery)
    matching_candidates = [
        item for item in candidates if _candidate_matches_oracle(item, oracle)
    ]
    audit = discovery.get("oracle_access_audit") or {}
    dual_mode = _dual_mode_plan_parity(
        plan,
        getattr(args, "deterministic_frozen", None),
    )

    checks: dict[str, bool] = {
        "frozen_hashes_verified": bool(freeze_manifest.get("closed")),
        "vulnerable_tree_pinned": bool(vulnerable_identity),
        "fixed_tree_pinned": bool(fixed_identity),
        "oracle_isolated_from_discovery": (
            audit.get("oracle_received") is False
            and audit.get("fixed_tree_received") is False
            and not audit.get("denied_attempts")
        ),
        "capacity_alias_policies_recorded": _capacity_policies_recorded(
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
        "caller_callee_alias_chain_recovered": _alias_chain_recovered(
            graph, oracle["location"]
        ),
        "vulnerable_complete_unchecked_chain_found": any(
            chain.priority_class.value == "complete_unchecked_capacity_path"
            and chain.guard_state.value == "absent"
            for chain in vulnerable_chains
        ),
        "target_admitted_in_first_six_sessions": (
            session_rank is not None and session_rank <= REQUIRED_ADMISSION_RANK
        ),
        "cross_file_context_complete": context is not None
        and context["required_paths_present"],
        "target_context_bounded": context is not None
        and 0 < context["bytes"] <= 24_000,
        "fixed_has_no_equivalent_unchecked_chain": not any(
            chain.priority_class.value == "complete_unchecked_capacity_path"
            for chain in fixed_chains
        ),
        "fixed_sizing_derivation_is_deprioritized": any(
            chain.priority_class.value == "complete_unknown_guard_path"
            and "bounded_write_derivation=True" in chain.rationale
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
            and (
                int(usage.get("input_tokens", 0))
                + int(usage.get("cache_read_tokens", 0))
                + int(usage.get("cache_write_tokens", 0))
            ) <= REQUIRED_BUDGET["max_input_tokens"]
            and int(usage.get("output_tokens", 0))
            <= REQUIRED_BUDGET["max_output_tokens"]
        )
        checks["deterministic_authenticated_plan_parity"] = bool(
            dual_mode.get("matches")
        )
        checks["target_provider_started_in_first_six_sessions"] = (
            provider_start_rank is not None
            and provider_start_rank <= REQUIRED_ADMISSION_RANK
        )
        checks["per_work_input_fairness_enforced"] = (
            _input_fairness_enforced(plan)
        )
        checks["matching_model_candidate"] = bool(matching_candidates)
    else:
        checks["deterministic_without_model_credentials"] = (
            (discovery.get("model") or {}).get("adapter") == "none"
            and int((discovery.get("usage") or {}).get("sessions", -1)) == 0
        )

    result = {
        "schema_version": EVALUATION_SCHEMA,
        "phase": "evaluate",
        "passed": all(checks.values()),
        "checks": checks,
        "failed_checks": [name for name, passed in checks.items() if not passed],
        "oracle": {
            "id": oracle["oracle"]["id"],
            "upstream_reference": oracle["oracle"]["upstream_reference"],
            "loaded_after_freeze_verification": True,
            "manifest_sha256": _sha256(oracle_path),
        },
        "source": {"vulnerable": vulnerable_identity, "fixed": fixed_identity},
        "target": {
            "vulnerable_chains": [
                chain.model_dump(mode="json") for chain in vulnerable_chains
            ],
            "fixed_chains": [
                chain.model_dump(mode="json") for chain in fixed_chains
            ],
            "pre_admission_rank": pre_admission_rank,
            "session_rank": session_rank,
            "provider_start_rank": provider_start_rank,
            "context": context,
            "matching_candidates": matching_candidates,
        },
        "metrics": {
            "pre_admission_rank": pre_admission_rank,
            "session_rank": session_rank,
            "provider_start_rank": provider_start_rank,
            "candidate_count": len(candidates),
            "matching_candidate_count": len(matching_candidates),
            "sessions": int((discovery.get("usage") or {}).get("sessions", 0)),
        },
        "oracle_access_audit": {
            **audit,
            "evaluation_oracle_opened": str(oracle_path),
            "evaluation_started_from_verified_root": freeze_manifest["root_sha256"],
        },
        "dual_mode_plan": dual_mode,
    }
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    _write_json(output / "evaluation.json", result)
    return result


def _alias_chain_recovered(
    graph: CAnalysisGraph,
    location: dict[str, Any],
) -> bool:
    summaries = {summary.function: summary for summary in graph.capacity_summaries}
    leaf = summaries.get(str(location["leaf_function"]))
    wrapper = summaries.get(str(location["wrapper_function"]))
    return bool(
        leaf
        and wrapper
        and leaf.pointer_aliases.get("ptr") == "dstPlanes"
        and "dstPlanes" in leaf.written_parameters
        and wrapper.pointer_aliases.get("dstPlanes") == "dstBuf"
        and "dstBuf" in wrapper.written_parameters
    )


def _matching_session_rank(plan: dict[str, Any], chains: list[Any]) -> int | None:
    """Return the paid-session order, excluding deferred and duplicate records."""
    chain_ids = {chain.chain_id for chain in chains}
    allocation = plan.get("allocation") or plan.get("budget_allocation") or {}
    matching_work_ids = {
        record["work_id"]
        for record in allocation.get("ranking", [])
        if record.get("disposition") == "admitted"
        and chain_ids.intersection(record.get("chain_ids", []))
    }
    ranks = [
        int(decision["rank"])
        for decision in allocation.get("decisions", [])
        if decision.get("work_id") in matching_work_ids
    ]
    return min(ranks) if ranks else None


def _matching_provider_start_rank(
    plan: dict[str, Any],
    chains: list[Any],
) -> int | None:
    chain_ids = {chain.chain_id for chain in chains}
    allocation = plan.get("budget_allocation") or plan.get("allocation") or {}
    matching_work_ids = {
        record["work_id"]
        for record in allocation.get("ranking", [])
        if chain_ids.intersection(record.get("chain_ids", []))
    }
    ledger = allocation.get("admission_ledger") or {}
    provider_starts = [
        event.get("work_id")
        for event in ledger.get("events", [])
        if event.get("event") == "provider_started"
        and event.get("provider_started") is True
    ]
    ranks = [
        rank
        for rank, work_id in enumerate(provider_starts, start=1)
        if work_id in matching_work_ids
    ]
    return min(ranks) if ranks else None


def _dual_mode_plan_parity(
    authenticated_plan: dict[str, Any],
    deterministic_frozen: Path | None,
) -> dict[str, Any]:
    authenticated_contract = authenticated_plan.get("plan_contract") or {}
    authenticated_hash = str(
        authenticated_contract.get("normalized_semantic_sha256") or ""
    )
    if deterministic_frozen is None:
        return {
            "matches": False,
            "reason": "deterministic frozen baseline was not provided",
            "authenticated_normalized_sha256": authenticated_hash,
            "deterministic_normalized_sha256": "",
        }
    baseline_root = deterministic_frozen.resolve()
    freeze_manifest = verify_frozen(baseline_root)
    discovery = _read_json(baseline_root / "discovery.json")
    if discovery.get("mode") != "deterministic":
        raise BenchmarkContractError(
            "dual-mode baseline must be a deterministic discovery"
        )
    deterministic_plan = _read_json(baseline_root / "plan.json")
    deterministic_contract = deterministic_plan.get("plan_contract") or {}
    deterministic_hash = str(
        deterministic_contract.get("normalized_semantic_sha256") or ""
    )
    return {
        "matches": bool(
            authenticated_hash
            and deterministic_hash
            and authenticated_hash == deterministic_hash
        ),
        "reason": "normalized plan hashes compared after baseline verification",
        "authenticated_normalized_sha256": authenticated_hash,
        "deterministic_normalized_sha256": deterministic_hash,
        "deterministic_freeze_root_sha256": freeze_manifest["root_sha256"],
    }


def _input_fairness_enforced(plan: dict[str, Any]) -> bool:
    allocation = plan.get("budget_allocation") or plan.get("allocation") or {}
    fairness = allocation.get("input_fairness") or {}
    state = plan.get("budget_state") or {}
    limits = fairness.get("work_input_limits") or {}
    work_usage = state.get("work_input_tokens") or {}
    return bool(
        fairness.get("policy_version") == "work-input-fairness-v2"
        and state.get("input_fairness_policy") == "work-input-fairness-v2"
        and limits
        and work_usage
        and all(
            work_id in limits and int(value) <= int(limits[work_id])
            for work_id, value in work_usage.items()
        )
    )


def _candidate_matches_oracle(
    candidate: dict[str, Any],
    oracle: dict[str, Any],
) -> bool:
    required_paths = set(oracle["location"]["required_paths"])
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
    return required_paths.issubset(paths) and any(
        term in searchable
        for term in ("out-of-bounds", "out of bounds", "oob", "overflow")
    )


def _load_model_candidates(
    frozen: Path,
    discovery: dict[str, Any],
) -> list[dict[str, Any]]:
    """Load both verified candidates and raw Hunter findings from the freeze.

    Authenticated discovery may deliberately skip the separate verification phase
    to keep the benchmark budget focused on Hunter recall.  Those model findings
    are still valid discovery-gate inputs, but they remain explicitly unverified
    and must not be confused with repository-backed verified candidates.
    """
    candidates = list(_load_candidates(frozen, discovery))
    seen = {_candidate_identity(item) for item in candidates}
    for path in sorted(frozen.glob("*/hunters/*/hunts/*/findings.json")):
        payload = _read_json(path)
        findings = payload.get("findings") if isinstance(payload, dict) else None
        if not isinstance(findings, list):
            continue
        for raw in findings:
            if not isinstance(raw, dict):
                continue
            candidate = _normalize_raw_model_finding(raw)
            identity = _candidate_identity(candidate)
            if identity in seen:
                continue
            seen.add(identity)
            candidates.append(candidate)
    return candidates


def _normalize_raw_model_finding(raw: dict[str, Any]) -> dict[str, Any]:
    touched = raw.get("files_touched")
    dataflow = [
        {"path": str(path), "line": 0}
        for path in touched if isinstance(path, str)
    ] if isinstance(touched, list) else []
    return {
        "title": str(raw.get("title", "")),
        "weakness": str(raw.get("type", "")),
        "impact": [
            str(value)
            for value in (raw.get("description"), raw.get("attack"))
            if value
        ],
        "entrypoint": {
            "path": str(raw.get("entry_file", "")),
            "line": int(raw.get("entry_line", 0) or 0),
        },
        "sink": {
            "path": str(raw.get("sink_file", "")),
            "line": int(raw.get("sink_line", 0) or 0),
        },
        "dataflow": dataflow,
        "status": str(raw.get("status", "unverified")),
        "candidate_origin": "raw_hunter_finding",
    }


def _candidate_identity(candidate: dict[str, Any]) -> tuple[str, str, int]:
    sink = candidate.get("sink") or {}
    return (
        str(candidate.get("title", "")).casefold(),
        str(sink.get("path", "")),
        int(sink.get("line", 0) or 0),
    )


def _capacity_policies_recorded(policies: dict[str, Any]) -> bool:
    return all((
        policies.get("capacity_fact") == "c-capacity-fact-v2",
        policies.get("capacity_summary") == "c-capacity-summary-v2",
        policies.get("capacity_risk_chain") == "c-capacity-risk-chain-v3",
        policies.get("context") == "c-context-v7",
        policies.get("admission") == "c-budget-v11",
        policies.get("input_fairness") == "work-input-fairness-v2",
    ))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the M11.4 libjpeg-turbo dual-mode release gate"
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
    evaluate.add_argument("--deterministic-frozen", type=Path)
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
