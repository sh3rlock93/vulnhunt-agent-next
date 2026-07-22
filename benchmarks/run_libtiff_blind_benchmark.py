"""Withheld-oracle, three-phase LibTIFF native discovery benchmark.

``discover`` receives only the vulnerable tree and scanner manifest.  It runs in
a fresh child process with an oracle-directory access guard.  ``freeze`` copies
and hashes the closed discovery artifacts.  Only ``evaluate`` accepts an oracle
or fixed tree.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

from vulnhunt_agent.analysis import (
    CAnalysisGraph,
    SharedContextCache,
    build_c_analysis_graph,
    build_coverage_plan,
)
from vulnhunt_agent.domain.schemas import BudgetPolicy
from vulnhunt_agent.reproduction.provenance import (
    NATIVE_EVIDENCE_POLICY,
    derive_execution_provenance,
)
from vulnhunt_agent.sandbox import ContainerExecutor
from vulnhunt_agent.scheduling import (
    allocate_native_work_plan,
    build_native_work_plan,
)

BLIND_POLICY = "blind-oracle-v1"
FREEZE_SCHEMA = "blind-freeze-v1"
DISCOVERY_SCHEMA = "blind-discovery-v1"
EVALUATION_SCHEMA = "blind-evaluation-v1"
_SNAPSHOT_PREFIX = "sha256:"
_C_SUFFIXES = frozenset({".c", ".h", ".l", ".y"})
_EXCLUDED_PARTS = frozenset({"test", "tests", "vendor", "third_party"})
_FORBIDDEN_SCAN_KEY = re.compile(
    r"(?:^|_)(?:cve|fixed|ground_truth|patch|diff|poc|trigger|weakness|"
    r"sink_file|sink_function|sink_line|entry_file|entry_function)(?:_|$)",
    re.IGNORECASE,
)
_FORBIDDEN_SCAN_VALUE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
_FORBIDDEN_ENV = re.compile(
    r"(?:ORACLE|GROUND_TRUTH|CVE|FIXED_(?:TREE|REPO|COMMIT)|KNOWN_(?:POC|TRIGGER))",
    re.IGNORECASE,
)


class BenchmarkContractError(RuntimeError):
    """A phase or blindness invariant was violated."""


def source_files(repo: Path) -> list[str]:
    return sorted(
        path.relative_to(repo).as_posix()
        for path in repo.rglob("*")
        if path.is_file()
        and path.suffix.lower() in _C_SUFFIXES
        and not any(
            part.startswith(".") or part.lower() in _EXCLUDED_PARTS
            for part in path.relative_to(repo).parts
        )
    )


def load_scan_manifest(path: Path) -> dict[str, Any]:
    payload = tomllib.loads(path.read_text(encoding="utf-8"))
    _audit_scan_payload(payload)
    required = {"benchmark", "source", "scan", "policies", "budget", "limits"}
    missing = sorted(required - payload.keys())
    if missing:
        raise BenchmarkContractError(
            "scan manifest is missing sections: " + ", ".join(missing)
        )
    if payload["benchmark"].get("schema_version") != 1:
        raise BenchmarkContractError("unsupported scan manifest schema")
    return payload


def _audit_scan_payload(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key)
            if _FORBIDDEN_SCAN_KEY.search(normalized):
                raise BenchmarkContractError(
                    "withheld knowledge is forbidden in scan manifest key: "
                    + ".".join((*path, normalized))
                )
            _audit_scan_payload(child, (*path, normalized))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _audit_scan_payload(child, (*path, str(index)))
    elif isinstance(value, str) and _FORBIDDEN_SCAN_VALUE.search(value):
        raise BenchmarkContractError(
            "withheld vulnerability identifier is forbidden in scan manifest"
        )


def git_identity(repo: Path) -> dict[str, str]:
    if not (repo / ".git").exists():
        raise BenchmarkContractError(f"target is not a Git checkout: {repo}")
    return {
        "commit": _git(repo, "rev-parse", "HEAD"),
        "tree": _git(repo, "rev-parse", "HEAD^{tree}"),
        "origin": _git_optional(repo, "remote", "get-url", "origin"),
    }


def verify_source_pin(repo: Path, source: dict[str, Any]) -> dict[str, str]:
    identity = git_identity(repo)
    expected_commit = str(source["commit"])
    expected_tree = str(source["tree"])
    if identity["commit"] != expected_commit or identity["tree"] != expected_tree:
        raise BenchmarkContractError(
            "source pin mismatch: expected "
            f"{expected_commit}/{expected_tree}, got "
            f"{identity['commit']}/{identity['tree']}"
        )
    return identity


def run_discover_parent(args: argparse.Namespace) -> dict[str, Any]:
    scan_manifest = args.scan_manifest.resolve()
    repo = args.repo.resolve()
    output = args.output.resolve()
    load_scan_manifest(scan_manifest)
    _require_new_output(output)
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "_discover-worker",
        "--repo",
        str(repo),
        "--scan-manifest",
        str(scan_manifest),
        "--output",
        str(output),
        "--mode",
        args.mode,
    ]
    if args.image:
        command.extend(("--image", args.image))
    if args.model_id:
        command.extend(("--model-id", args.model_id))
    if args.skip_verify:
        command.append("--skip-verify")
    env, forwarded = _worker_environment(authenticated=args.mode == "authenticated")
    env["VULNHUNT_BLIND_FORWARDED_ENV_NAMES"] = ",".join(forwarded)
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        raise BenchmarkContractError(
            f"oracle-free discovery worker failed with exit {completed.returncode}"
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise BenchmarkContractError(
            "discovery worker did not return its structured result"
        ) from exc
    if result.get("phase") != "discover" or result.get("complete") is not True:
        raise BenchmarkContractError("discovery worker did not complete")
    return result


def _worker_environment(*, authenticated: bool) -> tuple[dict[str, str], list[str]]:
    exact = {
        "HOME",
        "PATH",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    }
    prefixes = (
        "CODEX_",
        "OPENAI_",
        "AWS_",
        "DOCKER_",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "XDG_",
        "VULNHUNT_SETTINGS_PATH",
    )
    result: dict[str, str] = {}
    forwarded: list[str] = []
    for key, value in os.environ.items():
        if _FORBIDDEN_ENV.search(key):
            continue
        operational = key in exact or key.startswith(prefixes)
        if not operational:
            continue
        credential = key.startswith(("OPENAI_", "AWS_", "CODEX_"))
        if credential and not authenticated and key != "CODEX_HOME":
            continue
        result[key] = value
        forwarded.append(key)
    result.setdefault("PATH", os.defpath)
    result["PYTHONUNBUFFERED"] = "1"
    return result, sorted(forwarded)


def run_discover_worker(args: argparse.Namespace) -> dict[str, Any]:
    repo = args.repo.resolve()
    scan_path = args.scan_manifest.resolve()
    output = args.output.resolve()
    oracle_root = (Path(__file__).resolve().parent / "oracles").resolve()
    denied_attempts: list[str] = []
    _install_oracle_access_guard(oracle_root, denied_attempts)
    manifest = load_scan_manifest(scan_path)
    source_identity = verify_source_pin(repo, manifest["source"])
    _require_new_output(output)
    output.mkdir(parents=True)
    audit = {
        "policy_version": BLIND_POLICY,
        "process_id": os.getpid(),
        "scan_manifest": str(scan_path),
        "scan_manifest_sha256": _sha256_file(scan_path),
        "source_root": str(repo),
        "source_identity": source_identity,
        "allowed_input_roots": [str(repo), str(scan_path)],
        "denied_root_kinds": ["evaluation_oracles"],
        "denied_attempts": denied_attempts,
        "forwarded_environment_names": [
            item
            for item in os.environ.get(
                "VULNHUNT_BLIND_FORWARDED_ENV_NAMES", ""
            ).split(",")
            if item
        ],
        "oracle_received": False,
        "fixed_tree_received": False,
    }
    print(
        f"[blind-discover] source pin verified: {source_identity['commit']}",
        file=sys.stderr,
        flush=True,
    )
    if args.mode == "deterministic":
        result = _run_deterministic_discovery(
            repo=repo,
            output=output,
            manifest=manifest,
            source_identity=source_identity,
            audit=audit,
        )
    else:
        if not args.image:
            raise BenchmarkContractError(
                "authenticated discovery requires a prepared --image"
            )
        result = asyncio.run(_run_authenticated_discovery(
            repo=repo,
            output=output,
            manifest=manifest,
            source_identity=source_identity,
            audit=audit,
            image=args.image,
            model_id=args.model_id,
            skip_verify=args.skip_verify,
        ))
    audit["denied_attempts"] = list(denied_attempts)
    _write_json(output / "oracle-access-audit.json", audit)
    result["oracle_access_audit"] = audit
    _write_json(output / "discovery.json", result)
    return result


def _install_oracle_access_guard(
    oracle_root: Path,
    denied_attempts: list[str],
) -> None:
    def audit(event: str, args: tuple[Any, ...]) -> None:
        if event != "open" or not args:
            return
        raw = args[0]
        if not isinstance(raw, (str, bytes, os.PathLike)):
            return
        try:
            candidate = Path(os.fsdecode(raw)).resolve()
            candidate.relative_to(oracle_root)
        except (OSError, ValueError):
            return
        denied_attempts.append(str(candidate))
        raise PermissionError("evaluation oracle access denied during discovery")

    sys.addaudithook(audit)


def _run_deterministic_discovery(
    *,
    repo: Path,
    output: Path,
    manifest: dict[str, Any],
    source_identity: dict[str, str],
    audit: dict[str, Any],
) -> dict[str, Any]:
    print("[blind-discover] building full C graph", file=sys.stderr, flush=True)
    files = source_files(repo)
    graph = build_c_analysis_graph(repo, files)
    coverage = build_coverage_plan(graph)
    snapshot = _SNAPSHOT_PREFIX + hashlib.sha256(
        f"{source_identity['commit']}:{source_identity['tree']}".encode()
    ).hexdigest()
    analysis = {
        "language": "c",
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": coverage.model_dump(mode="json"),
        "incremental_scope": {"mode": "full"},
    }
    native_work_plan = build_native_work_plan(
        run_id=manifest["benchmark"]["id"],
        source_snapshot=snapshot,
        selected_files=list(coverage.selected_files),
        enabled_hunters=list(manifest["scan"]["hunters"]),
        analysis=analysis,
    )
    routing = native_work_plan.routing
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
    admission_plan = allocate_native_work_plan(
        native_work_plan,
        budget,
        native_full_scan=True,
    )
    allocation = admission_plan.allocation
    work = admission_plan.work_items
    admitted = set(allocation.admitted_work_ids)
    cache = SharedContextCache(
        output / "contexts",
        repo,
        source_snapshot=snapshot,
        analysis=analysis,
    )
    context_records = []
    for item in work:
        if item.work_id not in admitted:
            continue
        for packet in cache.get_shards(item):
            path = output / "contexts" / f"{packet['cache_key']}.json"
            context_records.append({
                "work_id": item.work_id,
                "cache_key": packet["cache_key"],
                "bytes": path.stat().st_size,
                "target_signal_ids": list(item.target_signal_ids),
                "risk_chain_ids": [
                    chain["chain_id"] for chain in packet.get("risk_chains", [])
                ],
                "capacity_risk_chain_ids": [
                    chain["chain_id"]
                    for chain in packet.get("capacity_risk_chains", [])
                ],
                "hydrated_context_files": packet.get("hydrated_context_files", []),
            })
    terminal = _terminal_routes(graph, work, allocation)
    plan = {
        "routing": routing.model_dump(mode="json"),
        "work_items": [item.model_dump(mode="json") for item in work],
        "allocation": {
            **asdict(allocation),
            "decisions": [asdict(item) for item in allocation.decisions],
        },
        "plan_contract": admission_plan.contract,
        "contexts": context_records,
        "terminal_routes": terminal,
    }
    _write_json(output / "analysis.json", analysis)
    _write_json(output / "plan.json", plan)
    print(
        f"[blind-discover] planned {len(work)} work items; "
        f"admitted {len(admitted)}",
        file=sys.stderr,
        flush=True,
    )
    return {
        "schema_version": DISCOVERY_SCHEMA,
        "phase": "discover",
        "complete": True,
        "mode": "deterministic",
        "run_identity": {
            "run_id": manifest["benchmark"]["id"] + "-deterministic",
            "source": source_identity,
        },
        "model": {"adapter": "none", "model_id": "none"},
        "policies": manifest["policies"],
        "budget": manifest["budget"],
        "usage": {
            "sessions": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "estimated_cost_usd": 0.0,
        },
        "summary": {
            "source_files": len(files),
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "signals": len(graph.signals),
            "critical_signals": len(graph.critical_sink_ids),
            "risk_chains": len(graph.risk_chains),
            "capacity_risk_chains": len(graph.capacity_risk_chains),
            "coverage_complete": coverage.complete,
            "work_items": len(work),
            "admitted_sessions": len(admitted),
            "deferred_sessions": len(allocation.deferred),
            "max_target_signals": max(
                (len(item.target_signal_ids) for item in work), default=0
            ),
            "max_context_bytes": max(
                (item["bytes"] for item in context_records), default=0
            ),
            "dispositions_complete": terminal["complete"],
        },
        "candidates": [],
        "oracle_access_audit": audit,
    }


async def _run_authenticated_discovery(
    *,
    repo: Path,
    output: Path,
    manifest: dict[str, Any],
    source_identity: dict[str, str],
    audit: dict[str, Any],
    image: str,
    model_id: str | None,
    skip_verify: bool,
) -> dict[str, Any]:
    from vulnhunt_agent.core import settings as app_settings
    from vulnhunt_agent.core.events import EventBus
    from vulnhunt_agent.core.run_store import RunStore
    from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
    from vulnhunt_agent.pipeline.analysis_graph import run_analysis_graph
    from vulnhunt_agent.pipeline.file_selector import run_file_selector
    from vulnhunt_agent.pipeline.filter_files import run_filter
    from vulnhunt_agent.pipeline.hunt import run_hunt
    from vulnhunt_agent.pipeline.sandbox_prepare import run_prepare
    from vulnhunt_agent.pipeline.source_snapshot import run_source_snapshot
    from vulnhunt_agent.pipeline.verify import run_verify

    run_id = (
        manifest["benchmark"]["id"]
        + "-"
        + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid.uuid4().hex[:8]
    )
    # The pipeline deliberately derives its durable run identity from the
    # RunStore directory name.  Keep the benchmark ID and repository ID equal.
    run_dir = output / run_id
    store = RunStore(run_dir)
    store.save_step("hunter_selection", {
        "policy_version": "benchmark-hunter-selection-v1",
        "source": "scan_manifest",
        "hunters": list(manifest["scan"]["hunters"]),
    })
    chosen_model = model_id or app_settings.DEFAULT_MODEL.model_id
    store.save_config({
        "repo_source": manifest["source"]["repository"],
        "repo_path": str(repo),
        "environment": manifest["scan"]["environment"],
        "model_id": chosen_model,
        "model_id_ranker": chosen_model,
        "model_id_reviewer": chosen_model,
        "scan_base_ref": "",
        "scan_head_ref": "",
        "prepare_mode": "custom",
        "custom_image": image,
        "max_hunters_parallel": int(manifest["limits"]["max_parallel_hunters"]),
        "hunter_max_iterations": 40,
        "budget_max_hunter_sessions": int(
            manifest["budget"]["max_hunter_sessions"]
        ),
        "budget_max_input_tokens": int(manifest["budget"]["max_input_tokens"]),
        "budget_max_output_tokens": int(
            manifest["budget"]["max_output_tokens"]
        ),
        "budget_max_wall_clock_minutes": int(
            manifest["budget"]["max_wall_clock_minutes"]
        ),
        "budget_max_retries_per_work_item": int(
            manifest["budget"]["max_retries_per_work_item"]
        ),
    })
    bus = EventBus(run_dir / "events.jsonl")
    steps = (
        run_source_snapshot,
        run_filter,
        run_analysis_graph,
        run_file_selector,
        run_prepare,
        run_hunt,
    )
    for step in steps:
        print(
            f"[blind-discover] authenticated step: {step.__name__}",
            file=sys.stderr,
            flush=True,
        )
        await step(store, bus)
    if not skip_verify:
        print(
            "[blind-discover] authenticated step: run_verify",
            file=sys.stderr,
            flush=True,
        )
        await run_verify(store, bus)

    analysis = store.load_step("analysis_graph") or {}
    plan = store.load_step("hunt_plan") or {}
    hunt = store.load_step("hunt") or {}
    context_records = []
    context_keys = plan.get("context_cache_keys") or {}
    for work_id, cache_key in sorted(context_keys.items()):
        path = run_dir / "cache" / "context" / f"{cache_key}.json"
        if not path.is_file():
            continue
        packet = json.loads(path.read_text(encoding="utf-8"))
        context_records.append({
            "work_id": work_id,
            "cache_key": cache_key,
            "bytes": path.stat().st_size,
            "target_signal_ids": (
                packet.get("change_focus") or {}
            ).get("target_signal_ids", []),
            "risk_chain_ids": [
                item["chain_id"]
                for item in packet.get("risk_chains", [])
                if isinstance(item, dict) and isinstance(item.get("chain_id"), str)
            ],
            "capacity_risk_chain_ids": [
                item["chain_id"]
                for item in packet.get("capacity_risk_chains", [])
                if isinstance(item, dict) and isinstance(item.get("chain_id"), str)
            ],
            "hydrated_context_files": packet.get("hydrated_context_files", []),
        })
    plan["contexts"] = context_records
    _write_json(output / "analysis.json", analysis)
    _write_json(output / "plan.json", plan)
    with SqliteRepository(run_dir / "state.db", read_only=True) as repository:
        findings = [
            item.model_dump(mode="json")
            for item in repository.list_candidates(run_id)
        ]
        evidence = [
            item.model_dump(mode="json")
            for item in repository.list_evidence(run_id)
        ]
        usage_items = repository.list_budget_usage(run_id)
    _write_json(output / "findings.json", findings)
    _write_json(output / "evidence.json", evidence)
    costs = [item.estimated_cost_usd for item in usage_items]
    usage = {
        "sessions": sum(item.sessions for item in usage_items),
        "calls": sum(item.calls for item in usage_items),
        "iterations": sum(item.iterations for item in usage_items),
        "input_tokens": sum(item.input_tokens for item in usage_items),
        "output_tokens": sum(item.output_tokens for item in usage_items),
        "cache_read_tokens": sum(item.cache_read_tokens for item in usage_items),
        "cache_write_tokens": sum(item.cache_write_tokens for item in usage_items),
        "tool_calls": sum(item.tool_calls for item in usage_items),
        "repeated_reads": sum(item.repeated_reads for item in usage_items),
        "poc_writes": sum(item.poc_writes for item in usage_items),
        "exec_calls": sum(item.exec_calls for item in usage_items),
        "wall_time_ms": sum(item.wall_time_ms for item in usage_items),
        "estimated_cost_usd": (
            sum(float(cost) for cost in costs if cost is not None)
            if costs and all(cost is not None for cost in costs)
            else None
        ),
    }
    transports = sorted({item.transport for item in usage_items})
    terminal = hunt.get("target_completion") or {}
    work_items = plan.get("work_items") or []
    dispositions_complete = (
        int(terminal.get("missing", 0)) == 0
        and int(hunt.get("pending", 0)) == 0
        and int(hunt.get("failed", 0)) == 0
    )
    if int(hunt.get("failed", 0)):
        raise BenchmarkContractError(
            "authenticated Hunter execution failed for "
            f"{hunt['failed']} admitted work items"
        )
    compact_terminal = {
        key: terminal.get(key)
        for key in ("total", "finding", "no_finding", "deferred", "missing", "complete")
    }
    return {
        "schema_version": DISCOVERY_SCHEMA,
        "phase": "discover",
        "complete": True,
        "mode": "authenticated",
        "run_identity": {"run_id": run_id, "source": source_identity},
        "model": {
            "adapter": transports[0] if len(transports) == 1 else transports,
            "model_id": chosen_model,
        },
        "policies": manifest["policies"],
        "budget": manifest["budget"],
        "usage": usage,
        "summary": {
            "risk_chains": len((analysis.get("graph") or {}).get("risk_chains", [])),
            "capacity_risk_chains": len(
                (analysis.get("graph") or {}).get("capacity_risk_chains", [])
            ),
            "scheduled_sessions": plan.get("scheduled_sessions", 0),
            "admitted_sessions": (
                plan.get("budget_allocation") or {}
            ).get("admitted_sessions", 0),
            "deferred_sessions": (
                plan.get("budget_allocation") or {}
            ).get("deferred_sessions", 0),
            "deferred_critical_targets": len(
                plan.get("budget_deferred_critical_work_ids") or []
            ),
            "findings": len(findings),
            "evidence": len(evidence),
            "max_target_signals": max(
                (len(item.get("target_signal_ids", [])) for item in work_items),
                default=0,
            ),
            "max_context_bytes": max(
                (item["bytes"] for item in context_records), default=0
            ),
            "dispositions_complete": dispositions_complete,
            "target_completion": compact_terminal,
        },
        "candidates": findings,
        "oracle_access_audit": audit,
    }


def _terminal_routes(graph, work, allocation) -> dict[str, Any]:
    admitted = set(allocation.admitted_work_ids)
    deferred = set(allocation.deferred)
    by_signal: dict[str, set[str]] = {}
    for item in work:
        for signal_id in item.target_signal_ids:
            by_signal.setdefault(signal_id, set()).add(item.work_id)
    dispositions = {}
    for signal_id in graph.critical_sink_ids:
        ids = by_signal.get(signal_id, set())
        if ids & admitted:
            dispositions[signal_id] = "admitted"
        elif ids & deferred:
            dispositions[signal_id] = "budget_deferred"
        else:
            dispositions[signal_id] = "unrouted"
    counts = {
        state: sum(value == state for value in dispositions.values())
        for state in ("admitted", "budget_deferred", "unrouted")
    }
    return {
        "complete": counts["unrouted"] == 0,
        "counts": counts,
        "dispositions": dispositions,
    }


def freeze_discovery(discovery: Path, frozen: Path) -> dict[str, Any]:
    discovery = discovery.resolve()
    frozen = frozen.resolve()
    _require_discovery_complete(discovery)
    _require_new_output(frozen)
    if frozen == discovery or discovery in frozen.parents or frozen in discovery.parents:
        raise BenchmarkContractError("freeze roots must not overlap")
    _reject_non_regular_artifacts(discovery)
    shutil.copytree(discovery, frozen)
    entries = _artifact_entries(frozen)
    root_digest = _entries_digest(entries)
    manifest = {
        "schema_version": FREEZE_SCHEMA,
        "phase": "freeze",
        "discovery_root_name": discovery.name,
        "files": entries,
        "root_sha256": root_digest,
        "closed": True,
    }
    _write_json(frozen / "freeze-manifest.json", manifest)
    verify_frozen(frozen)
    return manifest


def verify_frozen(frozen: Path) -> dict[str, Any]:
    frozen = frozen.resolve()
    manifest_path = frozen / "freeze-manifest.json"
    if not manifest_path.is_file():
        raise BenchmarkContractError("frozen artifacts have no SHA-256 manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != FREEZE_SCHEMA or not manifest.get("closed"):
        raise BenchmarkContractError("invalid or open freeze manifest")
    expected = manifest.get("files")
    if not isinstance(expected, list):
        raise BenchmarkContractError("invalid freeze file list")
    actual = _artifact_entries(frozen, exclude={"freeze-manifest.json"})
    if actual != expected or _entries_digest(actual) != manifest.get("root_sha256"):
        raise BenchmarkContractError("frozen artifact SHA-256 verification failed")
    return manifest


def evaluate_frozen(args: argparse.Namespace) -> dict[str, Any]:
    frozen = args.frozen.resolve()
    freeze_manifest = verify_frozen(frozen)
    discovery = json.loads((frozen / "discovery.json").read_text(encoding="utf-8"))
    if discovery.get("phase") != "discover" or discovery.get("complete") is not True:
        raise BenchmarkContractError("frozen discovery is incomplete")
    # Oracle knowledge is deliberately loaded only after frozen hashes verify.
    oracle_path = args.oracle.resolve()
    oracle = tomllib.loads(oracle_path.read_text(encoding="utf-8"))
    vulnerable_repo = args.vulnerable_repo.resolve()
    fixed_repo = args.fixed_repo.resolve()
    scan = load_scan_manifest(args.scan_manifest.resolve())
    vulnerable_identity = verify_source_pin(vulnerable_repo, scan["source"])
    fixed_identity = verify_source_pin(fixed_repo, {
        "commit": oracle["fixed_source"]["commit"],
        "tree": oracle["fixed_source"]["tree"],
    })
    analysis = json.loads((frozen / "analysis.json").read_text(encoding="utf-8"))
    plan = json.loads((frozen / "plan.json").read_text(encoding="utf-8"))
    graph = CAnalysisGraph.model_validate(analysis.get("graph") or {})
    location = oracle["location"]
    vulnerable_chains = _oracle_matching_chains(graph, location, fixed=False)
    fixed_graph = build_c_analysis_graph(fixed_repo, source_files(fixed_repo))
    fixed_chains = _oracle_matching_chains(fixed_graph, location, fixed=True)
    admitted_rank = _matching_admission_rank(plan, vulnerable_chains)
    context_bytes = _matching_context_bytes(plan, vulnerable_chains)
    candidates = _load_candidates(frozen, discovery)
    matching_candidates = [
        item for item in candidates if _candidate_matches_oracle(item, oracle)
    ]
    audit = discovery.get("oracle_access_audit") or {}
    checks: dict[str, bool] = {
        "frozen_hashes_verified": bool(freeze_manifest.get("closed")),
        "vulnerable_tree_pinned": bool(vulnerable_identity),
        "fixed_tree_pinned": bool(fixed_identity),
        "oracle_not_received_by_discovery": (
            audit.get("oracle_received") is False
            and audit.get("fixed_tree_received") is False
            and not audit.get("denied_attempts")
        ),
        "full_plan_bounded": (
            int(discovery["summary"].get("max_target_signals", 6)) <= 6
            and int(discovery["summary"].get("max_context_bytes", 24_000)) <= 24_000
        ),
        "terminal_routes_complete": bool(
            discovery["summary"].get("dispositions_complete")
        ),
        "vulnerable_chain_found": any(
            chain.score >= 80 and chain.guard_state.value != "dominates"
            for chain in vulnerable_chains
        ),
        "target_admitted_within_budget": admitted_rank is not None and admitted_rank <= 24,
        "target_context_bounded": (
            context_bytes is not None and 0 < context_bytes <= 24_000
        ),
        "fixed_guard_lowers_chain": any(
            chain.guard_state.value == "dominates"
            and chain.score < max((item.score for item in vulnerable_chains), default=0)
            for chain in fixed_chains
        ),
        "actual_target_policy_recorded": (
            discovery.get("policies", {}).get("evidence")
            == NATIVE_EVIDENCE_POLICY
        ),
        "authenticated_identity_complete": True,
    }
    if discovery.get("mode") == "authenticated":
        model = discovery.get("model") or {}
        usage = discovery.get("usage") or {}
        checks["authenticated_identity_complete"] = all((
            bool((discovery.get("run_identity") or {}).get("run_id")),
            bool(model.get("adapter")),
            bool(model.get("model_id")),
            bool(discovery.get("policies")),
            "estimated_cost_usd" in usage,
        ))
        checks["matching_model_finding"] = bool(matching_candidates)
        checks["hunter_budget_respected"] = (
            int(usage.get("sessions", 0)) <= 24
            and sum(
                int(usage.get(key, 0))
                for key in (
                    "input_tokens",
                    "cache_read_tokens",
                    "cache_write_tokens",
                )
            ) <= 2_000_000
            and int(usage.get("output_tokens", 0)) <= 200_000
        )
    else:
        checks["deterministic_without_model_credentials"] = (
            (discovery.get("model") or {}).get("adapter") == "none"
            and int((discovery.get("usage") or {}).get("sessions", -1)) == 0
        )

    reproduction = None
    if args.run_reproduction:
        if not args.vulnerable_image or not args.fixed_image:
            raise BenchmarkContractError(
                "--run-reproduction requires both prepared image options"
            )
        reproduction = asyncio.run(_run_oracle_reproduction(
            vulnerable_repo=vulnerable_repo,
            fixed_repo=fixed_repo,
            vulnerable_image=args.vulnerable_image,
            fixed_image=args.fixed_image,
            spec=oracle["reproduction"],
        ))
        checks["two_clean_vulnerable_attempts"] = reproduction["vulnerable_passed"]
        checks["fixed_trigger_rejected"] = reproduction["fixed_passed"]
        checks["fixed_negative_control_no_equivalent_confirmed"] = (
            reproduction["fixed_passed"]
            and checks["fixed_guard_lowers_chain"]
        )

    finding_metrics = _first_valid_finding_metrics(frozen, oracle)
    if discovery.get("mode") == "authenticated":
        checks["first_valid_finding_metrics_recorded"] = all(
            finding_metrics.get(key) is not None
            for key in (
                "time_to_first_valid_finding_ms",
                "input_tokens_to_first_valid_finding",
                "output_tokens_to_first_valid_finding",
            )
        )
    reproduction_subjects = sorted({
        item["execution_subject"]
        for item in (reproduction or {}).get("vulnerable_attempts", [])
    })

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
            "manifest_sha256": _sha256_file(oracle_path),
        },
        "source": {
            "vulnerable": vulnerable_identity,
            "fixed": fixed_identity,
        },
        "target": {
            "vulnerable_chains": [
                item.model_dump(mode="json") for item in vulnerable_chains
            ],
            "fixed_chains": [
                item.model_dump(mode="json") for item in fixed_chains
            ],
            "admission_rank": admitted_rank,
            "context_bytes": context_bytes,
            "matching_candidates": matching_candidates,
        },
        "fixed_negative_control": {
            "mode": "post-freeze deterministic and actual-target replay",
            "guarded_matching_chains": sum(
                item.guard_state.value == "dominates" for item in fixed_chains
            ),
            "equivalent_confirmed_findings": 0,
            "same_candidate_confirmed": bool(
                reproduction is not None and not reproduction["fixed_passed"]
            ),
        },
        "metrics": {
            "top_k_admission_rank": admitted_rank,
            **finding_metrics,
            "dispositions_complete": bool(
                discovery["summary"].get("dispositions_complete")
            ),
            "confirmed_oracle_findings": (
                len(matching_candidates)
                if reproduction is not None and reproduction["vulnerable_passed"]
                else 0
            ),
            "unverified_findings": sum(
                item.get("state") not in {"reviewer_verified", "reportable"}
                for item in candidates
            ),
            "evidence_subjects": reproduction_subjects,
            "deferred_critical_targets": int(
                discovery["summary"].get(
                    "deferred_critical_targets",
                    len(plan.get("budget_deferred_critical_work_ids") or []),
                )
            ),
        },
        "reproduction": reproduction,
        "oracle_access_audit": {
            **audit,
            "evaluation_oracle_opened": str(oracle_path),
            "evaluation_started_from_verified_root": freeze_manifest["root_sha256"],
        },
    }
    args.output.resolve().mkdir(parents=True, exist_ok=True)
    _write_json(args.output.resolve() / "evaluation.json", result)
    return result


def _oracle_matching_chains(graph, location, *, fixed: bool):
    lower = int(
        location["fixed_sink_line_min"] if fixed else location["sink_line_min"]
    )
    upper = int(
        location["fixed_sink_line_max"] if fixed else location["sink_line_max"]
    )
    return [
        chain
        for chain in graph.risk_chains
        if chain.path == location["sink_file"]
        and chain.function == location["sink_function"]
        and any(lower <= line <= upper for line in chain.sink_lines)
        and chain.transform_steps
        and chain.allocation_signal_ids
    ]


def _matching_admission_rank(plan, chains) -> int | None:
    signals = {
        signal_id
        for chain in chains
        for signal_id in (*chain.allocation_signal_ids, *chain.sink_signal_ids)
    }
    work_ids = {
        item["work_id"]
        for item in plan.get("work_items", [])
        if signals.intersection(item.get("target_signal_ids", []))
    }
    decisions = (
        plan.get("allocation", {}).get("decisions")
        or plan.get("budget_allocation", {}).get("decisions")
        or []
    )
    ranks = [
        int(item["rank"]) for item in decisions if item.get("work_id") in work_ids
    ]
    return min(ranks) if ranks else None


def _matching_context_bytes(plan, chains) -> int | None:
    chain_ids = {chain.chain_id for chain in chains}
    sizes = [
        int(item["bytes"])
        for item in plan.get("contexts", [])
        if chain_ids.intersection(item.get("risk_chain_ids", []))
    ]
    if sizes:
        return max(sizes)
    return None


def _load_candidates(frozen: Path, discovery: dict[str, Any]) -> list[dict[str, Any]]:
    path = frozen / "findings.json"
    if path.is_file():
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, list) else []
    value = discovery.get("candidates")
    return value if isinstance(value, list) else []


def _candidate_matches_oracle(candidate: dict[str, Any], oracle: dict[str, Any]) -> bool:
    location = oracle["location"]
    locations = [candidate.get("entrypoint") or {}, candidate.get("sink") or {}]
    locations.extend(candidate.get("dataflow") or [])
    location_match = any(
        item.get("path") == location["sink_file"]
        and int(item.get("line", 0)) >= int(location["source_line_min"])
        and int(item.get("line", 0)) <= int(location["sink_line_max"])
        for item in locations
    )
    searchable = " ".join((
        str(candidate.get("title", "")),
        str(candidate.get("weakness", "")),
        *(str(item) for item in candidate.get("impact", [])),
    )).casefold()
    weakness_match = (
        any(term in searchable for term in ("integer", "size", "overflow", "wrap"))
        and any(term in searchable for term in ("buffer", "memory", "heap", "bounds"))
    )
    return location_match and weakness_match


def _first_valid_finding_metrics(
    frozen: Path,
    oracle: dict[str, Any],
) -> dict[str, int | None]:
    location = oracle["location"]
    first_event: datetime | None = None
    run_started: datetime | None = None
    for events_path in sorted(frozen.glob("*/events.jsonl")):
        for line in events_path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
                timestamp = datetime.fromisoformat(str(event["ts"]))
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                continue
            if run_started is None or timestamp < run_started:
                run_started = timestamp
            if (
                event.get("file") == location["sink_file"]
                and int(event.get("findings", 0)) > 0
                and event.get("type") in {"hunter_done", "hunter_deferred"}
                and (first_event is None or timestamp < first_event)
            ):
                first_event = timestamp

    checkpoint: dict[str, Any] = {}
    for findings_path in sorted(frozen.glob("*/hunters/*/hunts/*/findings.json")):
        try:
            payload = json.loads(findings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        raw_findings = payload.get("findings") if isinstance(payload, dict) else None
        if not isinstance(raw_findings, list) or not any(
            _raw_candidate_matches_oracle(item, oracle)
            for item in raw_findings
            if isinstance(item, dict)
        ):
            continue
        usage_path = findings_path.with_name("usage-checkpoint.json")
        if usage_path.is_file():
            checkpoint = json.loads(usage_path.read_text(encoding="utf-8"))
        break

    elapsed = (
        int((first_event - run_started).total_seconds() * 1000)
        if first_event is not None and run_started is not None
        else None
    )
    return {
        "time_to_first_valid_finding_ms": elapsed,
        "input_tokens_to_first_valid_finding": _optional_int(
            checkpoint.get("input_tokens")
        ),
        "output_tokens_to_first_valid_finding": _optional_int(
            checkpoint.get("output_tokens")
        ),
        "cache_tokens_to_first_valid_finding": (
            _optional_int(checkpoint.get("cache_read_tokens"))
            if checkpoint
            else None
        ),
    }


def _raw_candidate_matches_oracle(
    candidate: dict[str, Any],
    oracle: dict[str, Any],
) -> bool:
    location = oracle["location"]
    line = candidate.get("sink_line")
    return (
        candidate.get("sink_file") == location["sink_file"]
        and isinstance(line, int)
        and int(location["sink_line_min"]) <= line <= int(location["sink_line_max"])
        and _candidate_matches_oracle({
            "entrypoint": {
                "path": candidate.get("entry_file", ""),
                "line": candidate.get("entry_line", 0),
            },
            "sink": {"path": candidate.get("sink_file", ""), "line": line},
            "title": candidate.get("title", ""),
            "weakness": candidate.get("type", ""),
            "impact": [candidate.get("description", "")],
        }, oracle)
    )


def _optional_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


async def _run_oracle_reproduction(
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
            await sandbox.write_file(
                str(spec["workspace_input"]),
                str(spec["workspace_input_text"]),
            )
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
        "vulnerable_passed": vulnerable_passed,
        "fixed_passed": fixed_passed,
        "vulnerable_attempts": vulnerable,
        "fixed_attempts": fixed,
    }


def _artifact_entries(
    root: Path,
    *,
    exclude: set[str] | None = None,
) -> list[dict[str, Any]]:
    excluded = exclude or set()
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "size": path.stat().st_size,
            "sha256": _sha256_file(path),
        }
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.relative_to(root).as_posix() not in excluded
    ]


def _entries_digest(entries: list[dict[str, Any]]) -> str:
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _reject_non_regular_artifacts(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise BenchmarkContractError(
                f"discovery artifact is not a regular file or directory: {path}"
            )


def _require_discovery_complete(root: Path) -> None:
    path = root / "discovery.json"
    if not path.is_file():
        raise BenchmarkContractError("discovery output is missing")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("phase") != "discover" or payload.get("complete") is not True:
        raise BenchmarkContractError("discovery output is not complete")


def _require_new_output(path: Path) -> None:
    if path.exists():
        raise BenchmarkContractError(f"output already exists: {path}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise BenchmarkContractError(
            f"git {' '.join(args)} failed for {repo}: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _git_optional(repo: Path, *args: str) -> str:
    try:
        return _git(repo, *args)
    except BenchmarkContractError:
        return ""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the three-phase withheld-oracle LibTIFF benchmark"
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

    worker = subparsers.add_parser("_discover-worker", help=argparse.SUPPRESS)
    worker.add_argument("--repo", type=Path, required=True)
    worker.add_argument("--scan-manifest", type=Path, required=True)
    worker.add_argument("--output", type=Path, required=True)
    worker.add_argument(
        "--mode", choices=("deterministic", "authenticated"), required=True
    )
    worker.add_argument("--image", default="")
    worker.add_argument("--model-id")
    worker.add_argument("--skip-verify", action="store_true")

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
        elif args.command == "_discover-worker":
            result = run_discover_worker(args)
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
