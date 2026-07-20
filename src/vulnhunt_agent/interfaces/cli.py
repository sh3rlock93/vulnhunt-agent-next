"""CLI over the V2 metadata repository; only `export` opens it writable."""
from __future__ import annotations

import argparse
import json
import sqlite3
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

    status = subparsers.add_parser("status", help="show one run and task counts")
    status.add_argument("run_id")

    findings = subparsers.add_parser("findings", help="list validated findings")
    findings.add_argument("run_id")
    findings.add_argument("--state", choices=[state.value for state in FindingState])

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
    try:
        with SqliteRepository(
            args.db, read_only=args.command != "export"
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
                        "finding_count": len(repository.list_candidates(args.run_id)),
                    }
                )
                return 0
            if args.command == "findings":
                state = FindingState(args.state) if args.state else None
                findings = repository.list_candidates(args.run_id, state)
                _print_json([finding.model_dump(mode="json") for finding in findings])
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


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
