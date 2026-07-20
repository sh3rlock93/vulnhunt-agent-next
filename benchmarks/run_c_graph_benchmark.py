"""Evaluate the deterministic C graph without exposing oracle data to a model."""
from __future__ import annotations

import argparse
import json
import tomllib
from pathlib import Path
from typing import Sequence

from vulnhunt_agent.analysis import build_c_analysis_graph, build_coverage_plan
from vulnhunt_agent.scheduling import build_routing_plan

_C_SUFFIXES = frozenset({".c", ".h", ".l", ".y"})
_EXCLUDED_PARTS = frozenset({"test", "tests", "vendor", "third_party"})


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


def evaluate(repo: Path, spec_path: Path, expect: str) -> dict:
    # The graph is built from target source alone. Ground truth is loaded only
    # afterwards and is used solely as an evaluation oracle.
    graph = build_c_analysis_graph(repo, source_files(repo))
    plan = build_coverage_plan(graph)
    routing = build_routing_plan(
        run_id="benchmark",
        source_snapshot="sha256:" + "0" * 64,
        selected_files=list(plan.selected_files),
        enabled_hunters=[
            "c-bounds-integers",
            "c-memory-lifetime",
            "c-parser-state",
        ],
        analysis={
            "language": "c",
            "graph": graph.model_dump(mode="json"),
            "coverage_plan": plan.model_dump(mode="json"),
        },
    )

    spec = tomllib.loads(spec_path.read_text())
    truth = spec["ground_truth"]
    nodes = {item.node_id: item for item in graph.nodes}
    target_signals = [
        signal
        for signal in graph.signals
        if signal.path == truth["sink_file"]
        and truth["sink_line_min"] <= signal.line <= truth["sink_line_max"]
        and nodes[signal.node_id].symbol == truth["sink_function"]
        and signal.operation == "subscript assignment"
    ]
    critical = {
        signal.signal_id
        for signal in target_signals
        if signal.signal_id in graph.critical_sink_ids
    }
    trace_slices = [
        item
        for item in plan.slices
        if item.sink_signal_id in critical and truth["entry_file"] in item.files
    ]

    if expect == "vulnerable":
        passed = (
            bool(critical)
            and bool(trace_slices)
            and any("lower_guard=no" in item.detail for item in target_signals)
            and not routing.uncovered_critical_sink_ids
            and routing.session_reduction_percent >= 50
            and any(
                item.hunter == "c-bounds-integers"
                and item.seed_file == truth["sink_file"]
                for item in routing.work_items
            )
            and any(
                item.hunter == "c-parser-state"
                and item.seed_file == truth["sink_file"]
                for item in routing.work_items
            )
        )
    else:
        passed = (
            bool(target_signals)
            and not critical
            and any(
                item.risk < 4 and "lower_guard=yes" in item.detail
                for item in target_signals
            )
        )

    return {
        "expect": expect,
        "passed": passed,
        "summary": {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "entrypoints": len(graph.entrypoint_ids),
            "critical_sinks": len(graph.critical_sink_ids),
            "slices": len(plan.slices),
            "selected_files": len(plan.selected_files),
            "coverage_complete": plan.complete,
        },
        "target_signals": [
            {
                "path": item.path,
                "line": item.line,
                "category": item.category,
                "risk": item.risk,
                "detail": item.detail,
            }
            for item in target_signals
        ],
        "trace_files": [list(item.files) for item in trace_slices],
        "routing": {
            "legacy_sessions": routing.legacy_sessions,
            "scheduled_sessions": routing.scheduled_sessions,
            "session_reduction_percent": routing.session_reduction_percent,
            "critical_sinks_detected": len(
                routing.detected_critical_sink_ids
            ),
            "critical_sinks_covered": len(
                routing.covered_critical_sink_ids
            ),
            "work_items": [
                {
                    "file": item.seed_file,
                    "hunter": item.hunter,
                    "risk": item.risk,
                    "required": item.required,
                }
                for item in routing.work_items
            ],
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument(
        "--spec",
        type=Path,
        default=Path("benchmarks/libcue-cve-2023-43641.toml"),
    )
    parser.add_argument("--expect", choices=("vulnerable", "fixed"), required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = evaluate(args.repo.resolve(), args.spec.resolve(), args.expect)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
