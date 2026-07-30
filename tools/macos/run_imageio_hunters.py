#!/usr/bin/env python3
"""Run admitted ImageIO crash clusters through the specialist Hunter."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from vulnhunt_agent.core import settings
from vulnhunt_agent.core.llm import LLMClient
from vulnhunt_agent.core.provider_preflight import preflight_model_client
from vulnhunt_agent.domain.schemas import BudgetPolicy, RunRecord
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.macos.imageio_crashes import build_imageio_crash_hunter_plan
from vulnhunt_agent.macos.imageio_hunter import (
    ImageIOBinaryContext,
    execute_imageio_hunter_plan,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze eligible private ImageIO crash clusters with the existing "
            "budgeted durable Hunter queue. This command never executes proposed experiments."
        )
    )
    parser.add_argument("--store", required=True, type=Path)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-snapshot", required=True)
    parser.add_argument("--model-id", default=settings.DEFAULT_MODEL.model_id)
    parser.add_argument("--binary-context", action="append", default=[], type=Path)
    parser.add_argument("--max-hunter-sessions", type=int, default=12)
    parser.add_argument("--max-input-tokens", type=int, default=2_000_000)
    parser.add_argument("--max-output-tokens", type=int, default=200_000)
    parser.add_argument("--max-wall-clock-minutes", type=int, default=60)
    parser.add_argument("--max-retries-per-work-item", type=int, default=1)
    return parser.parse_args()


def _load_binary_contexts(paths: list[Path]) -> tuple[ImageIOBinaryContext, ...]:
    contexts: list[ImageIOBinaryContext] = []
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"binary context is missing or unsafe: {path}")
        if path.stat().st_size > 128 * 1024:
            raise RuntimeError(f"binary context file exceeds its limit: {path}")
        contexts.append(ImageIOBinaryContext.model_validate_json(path.read_bytes()))
    return tuple(contexts)


def _ensure_run(database: Path, run_id: str, source_snapshot: str) -> None:
    with SqliteRepository(database) as repository:
        existing = repository.get_run(run_id)
        if existing is None:
            repository.save_run(RunRecord(run_id=run_id, source_snapshot=source_snapshot))
            return
        if existing.source_snapshot != source_snapshot:
            raise RuntimeError("existing ImageIO run uses a different source snapshot")


async def _run(arguments: argparse.Namespace) -> dict:
    budget = BudgetPolicy(
        max_hunter_sessions=arguments.max_hunter_sessions,
        max_input_tokens=arguments.max_input_tokens,
        max_output_tokens=arguments.max_output_tokens,
        max_wall_clock_minutes=arguments.max_wall_clock_minutes,
        max_retries_per_work_item=arguments.max_retries_per_work_item,
    )
    plan = build_imageio_crash_hunter_plan(
        store_root=arguments.store,
        run_id=arguments.run_id,
        source_snapshot=arguments.source_snapshot,
        budget=budget,
    )
    if not plan.admitted_work_items:
        return {
            "schema_version": "imageio-hunter-run-summary-v1",
            "run_id": arguments.run_id,
            "crash_clusters": len(plan.clusters),
            "admitted_work_items": 0,
            "completed_work_items": 0,
            "model_calls": 0,
            "experiments_executed": 0,
        }
    contexts = _load_binary_contexts(arguments.binary_context)
    if contexts and len(plan.admitted_work_items) != 1:
        raise RuntimeError(
            "bounded binary context may be attached only when exactly one cluster is admitted"
        )
    database = arguments.database or arguments.store / "state.db"
    _ensure_run(database, arguments.run_id, arguments.source_snapshot)
    client = LLMClient(model_id=arguments.model_id)
    preflight = await preflight_model_client(client)
    if not preflight.ready:
        raise RuntimeError(
            f"ImageIO Hunter provider preflight failed: {preflight.code.value}; "
            f"{preflight.remediation}"
        )
    results = await execute_imageio_hunter_plan(
        plan=plan,
        store_root=arguments.store,
        database=database,
        client=client,
        budget=budget,
        binary_contexts=contexts,
    )
    return {
        "schema_version": "imageio-hunter-run-summary-v1",
        "run_id": arguments.run_id,
        "transport": str(getattr(client, "transport", "bedrock_converse")),
        "model_id": arguments.model_id,
        "crash_clusters": len(plan.clusters),
        "admitted_work_items": len(plan.admitted_work_items),
        "completed_work_items": len(results),
        "model_calls": sum(result.usage.calls for result in results),
        "hunter_sessions": sum(result.usage.sessions for result in results),
        "hypotheses": sum(len(result.assessment.hypotheses) for result in results),
        "experiment_plans": sum(len(result.experiment_plans) for result in results),
        "experiments_executed": 0,
        "review_required": True,
    }


def main() -> int:
    arguments = parse_arguments()
    summary = asyncio.run(_run(arguments))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
