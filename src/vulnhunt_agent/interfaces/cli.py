"""CLI over the V2 metadata repository; only `export` opens it writable."""
from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import tomllib
from pathlib import Path
from typing import Sequence

from ..domain.states import FindingState
from ..infrastructure.artifacts import ArtifactStore
from ..infrastructure.sqlite_repository import SqliteRepository
from ..reporting.service import StrictReportService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vulnhunt")
    parser.add_argument(
        "--db",
        type=Path,
        default=Path(".vulnhunt/state.db"),
        help="path to the V2 SQLite metadata database",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("runs", help="list runs")

    scan = subparsers.add_parser(
        "scan",
        help="plan or execute a full/incremental repository scan",
    )
    scan.add_argument("repo")
    scan.add_argument("--base-ref", default="")
    scan.add_argument("--head-ref", default="HEAD")
    scan.add_argument("--environment", default="c:gcc-13")
    scan.add_argument("--model-id")
    scan.add_argument("--run-id")
    scan.add_argument(
        "--run-root",
        type=Path,
        default=Path(".vulnhunt/runs"),
    )
    scan.add_argument(
        "--plan-only",
        action="store_true",
        help="stop after graph, diff scope, and file selection",
    )
    scan.add_argument("--skip-verify", action="store_true")
    scan.add_argument(
        "--prepare-mode",
        choices=("auto", "custom"),
        default="auto",
    )
    scan.add_argument("--custom-image", default="")
    scan.add_argument("--max-hunter-sessions", type=int, default=100)
    scan.add_argument(
        "--scope-mode",
        choices=("full", "files", "component"),
        default=None,
    )
    scan.add_argument(
        "--include-path",
        action="append",
        default=[],
        help="repository-relative file or component to include; repeatable",
    )
    scan.add_argument(
        "--exclude-path",
        action="append",
        default=[],
        help="repository-relative file or component to exclude; repeatable",
    )
    scan.add_argument(
        "--scope-manifest",
        type=Path,
        help="JSON or TOML file containing mode/include_paths/exclude_paths",
    )
    scan.add_argument(
        "--provider-model-probe",
        action="store_true",
        help="perform one explicit billable model call after local provider preflight",
    )

    status = subparsers.add_parser("status", help="show one run and task counts")
    status.add_argument("run_id")

    findings = subparsers.add_parser("findings", help="list validated findings")
    findings.add_argument("run_id")
    findings.add_argument("--state", choices=[state.value for state in FindingState])

    tasks = subparsers.add_parser(
        "tasks", help="list durable tasks, attempts, and lease state"
    )
    tasks.add_argument("run_id")
    tasks.add_argument("--status")

    recover = subparsers.add_parser(
        "recover", help="requeue expired task leases without changing task identity"
    )
    recover.add_argument("run_id")
    recover.add_argument("--max-attempts", type=int, default=3)

    export = subparsers.add_parser(
        "export", help="materialize consensus-verified Markdown, JSON, and SARIF"
    )
    export.add_argument("run_id")
    export.add_argument("--candidate")
    export.add_argument("--output", type=Path, required=True)
    export.add_argument(
        "--artifacts",
        type=Path,
        default=Path(".vulnhunt/artifacts"),
        help="content-addressed artifact store root",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        try:
            return asyncio.run(_run_scan(args))
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            parser.error(f"scan failed: {exc}")
    try:
        with SqliteRepository(
            args.db, read_only=args.command not in {"export", "recover"}
        ) as repository:
            if args.command == "runs":
                _print_json([run.model_dump(mode="json") for run in repository.list_runs()])
                return 0
            if args.command == "status":
                run = repository.get_run(args.run_id)
                if run is None:
                    parser.error(f"unknown run: {args.run_id}")
                tasks = repository.list_tasks(args.run_id)
                counts: dict[str, int] = {}
                for task in tasks:
                    counts[task["status"]] = counts.get(task["status"], 0) + 1
                _print_json(
                    {
                        "run": run.model_dump(mode="json"),
                        "task_counts": counts,
                        "leased_tasks": sum(
                            1 for task in tasks if task["lease_owner"] is not None
                        ),
                        "finding_count": len(repository.list_candidates(args.run_id)),
                    }
                )
                return 0
            if args.command == "findings":
                state = FindingState(args.state) if args.state else None
                findings = repository.list_candidates(args.run_id, state)
                _print_json([finding.model_dump(mode="json") for finding in findings])
                return 0
            if args.command == "tasks":
                tasks = repository.list_tasks(args.run_id)
                if args.status:
                    tasks = [
                        task for task in tasks
                        if task["status"] == args.status
                    ]
                _print_json(tasks)
                return 0
            if args.command == "recover":
                try:
                    result = repository.reclaim_expired_tasks(
                        args.run_id,
                        max_attempts=args.max_attempts,
                    )
                except (KeyError, ValueError) as exc:
                    parser.error(str(exc))
                _print_json(result)
                return 0
            service = StrictReportService(
                repository, ArtifactStore(args.artifacts)
            )
            candidates = repository.list_candidates(args.run_id)
            if args.candidate:
                candidates = [
                    item for item in candidates
                    if item.candidate_id == args.candidate
                ]
                if not candidates:
                    parser.error(
                        f"unknown candidate in run {args.run_id}: {args.candidate}"
                    )
            bundles = []
            for finding in candidates:
                if finding.state not in {
                    FindingState.REVIEWER_VERIFIED,
                    FindingState.REPORTABLE,
                }:
                    continue
                bundle = service.materialize(
                    args.output,
                    run_id=args.run_id,
                    candidate_id=finding.candidate_id,
                )
                bundles.append({
                    "candidate_id": finding.candidate_id,
                    "markdown": str(bundle.report_path),
                    "json": str(bundle.json_path),
                    "sarif": str(bundle.sarif_path),
                    "provenance": str(bundle.provenance_path),
                })
            _print_json(bundles)
            return 0
    except (FileNotFoundError, sqlite3.OperationalError) as exc:
        parser.error(f"cannot access V2 database or artifacts: {exc}")
    return 2


async def _run_scan(args) -> int:
    from ..core import settings as app_settings
    from ..core.events import EventBus
    from ..core.run_store import RunStore, new_run_id
    from ..pipeline.analysis_graph import run_analysis_graph
    from ..pipeline.file_selector import run_file_selector
    from ..pipeline.filter_files import run_filter
    from ..pipeline.hunt import run_hunt
    from ..pipeline.sandbox_prepare import run_prepare
    from ..pipeline.source_snapshot import run_source_snapshot
    from ..pipeline.verify import run_verify
    from ..repo.fetch import resolve

    repo = resolve(args.repo)
    run_id = args.run_id or new_run_id()
    store = RunStore(args.run_root.resolve() / run_id)
    model_id = args.model_id or app_settings.DEFAULT_MODEL.model_id
    scope_config = _load_scan_scope_config(args)
    store.save_config({
        "repo_source": args.repo,
        "repo_path": str(repo),
        "environment": args.environment,
        "model_id": model_id,
        "model_id_ranker": model_id,
        "model_id_reviewer": model_id,
        "scan_base_ref": args.base_ref,
        "scan_head_ref": args.head_ref if args.base_ref else "",
        "prepare_mode": args.prepare_mode,
        "custom_image": args.custom_image,
        "max_hunters_parallel": 3,
        "hunter_max_iterations": 100,
        "budget_max_hunter_sessions": args.max_hunter_sessions,
        "budget_max_input_tokens": 2_000_000,
        "budget_max_output_tokens": 200_000,
        "budget_max_wall_clock_minutes": 60,
        "budget_max_retries_per_work_item": 1,
        "provider_preflight_model_probe": args.provider_model_probe,
        **scope_config,
    })
    bus = EventBus(store.dir / "events.jsonl")
    for step in (
        run_source_snapshot,
        run_filter,
        run_analysis_graph,
        run_file_selector,
    ):
        await step(store, bus)

    analysis = store.load_step("analysis_graph") or {}
    selector = store.load_step("file_selector") or {}
    if args.plan_only:
        _print_json({
            "run_id": run_id,
            "run_dir": str(store.dir),
            "mode": "plan_only",
            "incremental_scope": analysis.get("incremental_scope") or {},
            "scan_scope": analysis.get("scan_scope") or {},
            "selected_files": selector.get("selected") or [],
        })
        return 0

    await run_prepare(store, bus)
    await run_hunt(store, bus)
    if not args.skip_verify:
        await run_verify(store, bus)
    _print_json({
        "run_id": run_id,
        "run_dir": str(store.dir),
        "mode": "complete",
        "outcome": (store.load_step("hunt") or {}).get("outcome"),
        "run_outcome": (store.load_step("hunt") or {}).get("run_outcome") or {},
        "incremental_scope": analysis.get("incremental_scope") or {},
        "scan_scope": analysis.get("scan_scope") or {},
        "hunt": store.load_step("hunt") or {},
        "verify": store.load_step("verify") or {},
    })
    return 0


def _load_scan_scope_config(args) -> dict:
    if args.scope_manifest is not None:
        if args.scope_mode is not None or args.include_path or args.exclude_path:
            raise ValueError(
                "--scope-manifest cannot be combined with inline scope options"
            )
        path = args.scope_manifest.resolve()
        if path.suffix.casefold() == ".toml":
            payload = tomllib.loads(path.read_text(encoding="utf-8"))
        else:
            payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("scope manifest must contain an object")
        allowed = {"policy_version", "mode", "include_paths", "exclude_paths"}
        unknown = set(payload) - allowed
        if unknown:
            raise ValueError(
                "scope manifest contains unknown fields: " + ", ".join(sorted(unknown))
            )
        if payload.get("policy_version", "scan-scope-v1") != "scan-scope-v1":
            raise ValueError("unsupported scope manifest policy_version")
        mode = payload.get("mode", "full")
        includes = payload.get("include_paths", [])
        excludes = payload.get("exclude_paths", [])
    else:
        mode = args.scope_mode or "full"
        includes = args.include_path
        excludes = args.exclude_path
    if mode not in {"full", "files", "component"}:
        raise ValueError(f"unsupported scope mode: {mode}")
    if not isinstance(includes, list) or not all(isinstance(p, str) for p in includes):
        raise ValueError("scope include_paths must be a list of strings")
    if not isinstance(excludes, list) or not all(isinstance(p, str) for p in excludes):
        raise ValueError("scope exclude_paths must be a list of strings")
    return {
        "scan_scope_mode": mode,
        "scan_scope_include_paths": includes,
        "scan_scope_exclude_paths": excludes,
    }


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
