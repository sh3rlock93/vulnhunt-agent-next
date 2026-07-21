"""Pinned deterministic regression for zlib MiniZip CVE-2023-45853."""
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Sequence

from vulnhunt_agent.analysis import (
    SharedContextCache,
    build_c_analysis_graph,
    build_coverage_plan,
    build_incremental_scope,
)
from vulnhunt_agent.scheduling import build_routing_plan, build_slice_work_items

_C_SUFFIXES = frozenset({".c", ".h", ".l", ".y"})
_EXCLUDED_PARTS = frozenset({"test", "tests", "vendor", "third_party"})
_HUNTERS = (
    "c-bounds-integers",
    "c-memory-lifetime",
    "c-parser-state",
    "c-injection-format",
    "c-concurrency-state",
    "c-error-contracts",
)
_SNAPSHOT = "sha256:" + "0" * 64


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


def evaluate(
    repo: Path,
    spec_path: Path,
    expect: str,
    *,
    base_ref: str = "",
    head_ref: str = "HEAD",
) -> dict:
    spec = tomllib.loads(spec_path.read_text())
    truth = spec["ground_truth"]
    limits = spec["limits"]
    graph = build_c_analysis_graph(repo, source_files(repo))
    coverage = build_coverage_plan(graph)
    target_node = next(
        (
            item for item in graph.nodes
            if item.path == truth["sink_file"]
            and item.symbol == truth["sink_function"]
        ),
        None,
    )
    target_signals = [
        item for item in graph.signals
        if target_node is not None
        and item.node_id == target_node.node_id
        and item.operation == truth["operation"]
    ]
    source_matches_pin = _source_matches_pin(repo, spec, expect)

    result: dict = {
        "expect": expect,
        "source_matches_pin": source_matches_pin,
        "target_node": target_node.model_dump(mode="json") if target_node else None,
        "target_signals": [item.model_dump(mode="json") for item in target_signals],
        "summary": {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "critical_sinks": len(graph.critical_sink_ids),
            "slices": len(coverage.slices),
            "coverage_complete": coverage.complete,
        },
    }
    if expect == "fixed":
        checks = {
            "source_matches_pin": source_matches_pin,
            "target_node_found": target_node is not None,
            "target_signals_found": bool(target_signals),
            "target_signals_guarded": all(
                item.category == "allocation_size_guarded" for item in target_signals
            ),
            "target_risk_lowered": all(item.risk < 4 for item in target_signals),
            "target_not_critical": all(
                item.signal_id not in graph.critical_sink_ids for item in target_signals
            ),
            "three_reject_guards_found": all(
                "16-bit reject guards=3" in item.detail for item in target_signals
            ),
        }
        result["checks"] = checks
        result["failed_checks"] = [
            name for name, passed in checks.items() if not passed
        ]
        result["passed"] = all(checks.values())
        return result

    scope = build_incremental_scope(
        repo,
        base_ref=base_ref or spec["fixed_commit"],
        head_ref=head_ref,
        graph=graph,
        coverage=coverage,
    )
    analysis = {
        "language": "c",
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": coverage.model_dump(mode="json"),
        "incremental_scope": scope.model_dump(mode="json"),
    }
    routing = build_routing_plan(
        run_id="zlib-cve-2023-45853",
        source_snapshot=_SNAPSHOT,
        selected_files=list(scope.selected_files),
        enabled_hunters=list(_HUNTERS),
        analysis=analysis,
    )
    work = build_slice_work_items(routing, analysis)
    primary = work[0] if work else None
    with tempfile.TemporaryDirectory(prefix="vulnhunt-zlib-context-") as temp:
        cache_root = Path(temp) / "cache"
        packet = (
            SharedContextCache(
                cache_root,
                repo,
                source_snapshot=_SNAPSHOT,
                analysis=analysis,
            ).get(primary)
            if primary is not None
            else {}
        )
        packet_bytes = (
            next(cache_root.glob("context_*.json")).stat().st_size
            if packet else 0
        )
    first_excerpt = next(iter(packet.get("source_excerpts", [])), {}).get("path")

    target_signal_ids = {item.signal_id for item in target_signals}
    checks = {
        "source_matches_pin": source_matches_pin,
        "target_node_found": target_node is not None,
        "target_signals_found": bool(target_signals),
        "target_signals_unguarded": all(
            item.category == "allocation_size" for item in target_signals
        ),
        "target_risk_high": all(item.risk >= 4 for item in target_signals),
        "incremental_scope": scope.mode == "incremental" and not scope.fallback_reason,
        "target_node_changed": (
            target_node is not None and target_node.node_id in scope.changed_node_ids
        ),
        "target_is_critical": bool(target_signal_ids & set(scope.critical_sink_ids)),
        "critical_sinks_covered": not routing.uncovered_critical_sink_ids,
        "primary_work_found": primary is not None,
        "primary_seed_is_sink": (
            primary is not None and primary.seed_file == truth["sink_file"]
        ),
        "primary_targets_node": (
            target_node is not None
            and primary is not None
            and target_node.node_id in primary.target_node_ids
        ),
        "primary_targets_signal": (
            primary is not None
            and bool(target_signal_ids & set(primary.target_signal_ids))
        ),
        "work_session_limit": len(work) <= int(limits["max_work_sessions"]),
        "slice_limit": all(
            len(item.slice_ids) <= int(limits["max_slices_per_work"])
            for item in work
        ),
        "target_node_limit": all(
            len(item.target_node_ids) <= int(limits["max_target_nodes_per_work"])
            for item in work
        ),
        "target_signal_limit": all(
            len(item.target_signal_ids) <= int(limits["max_target_signals_per_work"])
            for item in work
        ),
        "context_size_limit": 0 < packet_bytes <= int(limits["max_context_bytes"]),
        "sink_excerpt_first": first_excerpt == truth["sink_file"],
    }
    result.update({
        "passed": all(checks.values()),
        "checks": checks,
        "failed_checks": [name for name, passed in checks.items() if not passed],
        "incremental_scope": {
            "mode": scope.mode,
            "fallback_reason": scope.fallback_reason,
            "changed_files": list(scope.changed_files),
            "changed_node_ids": list(scope.changed_node_ids),
            "selected_files": list(scope.selected_files),
            "critical_sinks": len(scope.critical_sink_ids),
        },
        "routing": {
            "routed_sessions": routing.scheduled_sessions,
            "work_sessions": len(work),
            "primary_seed": primary.seed_file if primary else None,
            "primary_target_nodes": list(primary.target_node_ids) if primary else [],
            "primary_target_signals": list(primary.target_signal_ids) if primary else [],
            "slice_counts": [len(item.slice_ids) for item in work],
            "packet_bytes": packet_bytes,
            "first_excerpt": first_excerpt,
        },
    })
    return result


def _source_matches_pin(
    repo: Path,
    spec: dict,
    expect: str,
) -> bool:
    pinned_commit = (
        spec["fixed_commit"] if expect == "fixed" else spec["vulnerable_commit"]
    )
    if expect == "fixed" and _git(repo, "rev-parse", "HEAD") != pinned_commit:
        return False
    return _git(repo, "rev-parse", "HEAD^{tree}") == _git(
        repo,
        "rev-parse",
        f"{pinned_commit}^{{tree}}",
    )


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument(
        "--spec",
        type=Path,
        default=Path("benchmarks/zlib-cve-2023-45853.toml"),
    )
    parser.add_argument("--expect", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--base-ref", default="")
    parser.add_argument("--head-ref", default="HEAD")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = evaluate(
        args.repo.resolve(),
        args.spec.resolve(),
        args.expect,
        base_ref=args.base_ref,
        head_ref=args.head_ref,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if not result["passed"]:
        details = json.dumps({
            "failed_checks": result.get("failed_checks", []),
            "target_signals": result.get("target_signals", []),
            "summary": result.get("summary", {}),
        }, separators=(",", ":"), ensure_ascii=True)
        print(f"::error title=zlib CVE regression failed::{details}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
