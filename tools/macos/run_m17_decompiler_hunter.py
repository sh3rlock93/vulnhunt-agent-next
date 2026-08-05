#!/usr/bin/env python3
"""Plan or run M17 decompiler-native Hunter sessions over frozen evidence."""

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
from vulnhunt_agent.macos.binary_analysis import (
    NormalizedBinaryIR,
    DecompilerHunterPolicy,
    build_decompiler_hunter_plan,
    create_binary_research_scope,
    execute_decompiler_hunter_plan,
    load_decompiler_hunt_manifest,
    materialize_binary_evidence_capsules,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run address-bound M17 Hunter sessions over an existing frozen decompiler "
            "hunt. This command never executes images, fuzzers, VMs, or experiments."
        )
    )
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--store", type=Path)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--run-id", default="m17-decompiler-hunter")
    parser.add_argument("--model", default=settings.DEFAULT_MODEL.model_id)
    parser.add_argument("--max-root-sessions", type=int, default=16)
    parser.add_argument("--max-input-tokens", type=int, default=1_000_000)
    parser.add_argument("--max-output-tokens", type=int, default=100_000)
    parser.add_argument("--max-wall-clock-minutes", type=int, default=90)
    parser.add_argument("--max-retries", type=int, default=1)
    parser.add_argument("--plan-only", action="store_true")
    return parser.parse_args()


def _read_ir(evidence: Path) -> NormalizedBinaryIR:
    path = evidence / "normalized-ir.json"
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("frozen normalized-ir.json is missing or unsafe")
    return NormalizedBinaryIR.model_validate_json(path.read_bytes())


async def _main() -> int:
    arguments = parse_arguments()
    evidence = arguments.evidence.expanduser().resolve(strict=True)
    store = (arguments.store or evidence).expanduser().resolve(strict=True)
    database = (arguments.database or (store / "m17" / "decompiler-hunter.db")).expanduser()
    manifest = load_decompiler_hunt_manifest(evidence)
    if manifest.snapshot_sha256 is None:
        raise RuntimeError("completed decompiler evidence is missing its snapshot digest")
    ir = _read_ir(evidence)
    capsules = materialize_binary_evidence_capsules(evidence)
    scope = create_binary_research_scope(
        snapshot_sha256=manifest.snapshot_sha256,
        authorization_basis="lawfully installed analyst-controlled ImageIO binary",
    )
    budget = BudgetPolicy(
        max_hunter_sessions=arguments.max_root_sessions,
        max_input_tokens=arguments.max_input_tokens,
        max_output_tokens=arguments.max_output_tokens,
        max_wall_clock_minutes=arguments.max_wall_clock_minutes,
        max_retries_per_work_item=arguments.max_retries,
    )
    client = LLMClient(arguments.model)
    preflight = await preflight_model_client(client, model_probe=False)
    if not preflight.ready:
        print(json.dumps(preflight.model_dump(mode="json"), indent=2, sort_keys=True))
        return 2
    plan = build_decompiler_hunter_plan(
        store_root=store,
        run_id=arguments.run_id,
        ir=ir,
        capsule_set=capsules,
        scope=scope,
        budget=budget,
        provider_preflight=preflight,
        policy=DecompilerHunterPolicy(
            maximum_root_sessions=arguments.max_root_sessions,
        ),
    )
    if arguments.plan_only:
        print(json.dumps(plan.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    database.parent.mkdir(parents=True, exist_ok=True)
    with SqliteRepository(database) as repository:
        existing = repository.get_run(arguments.run_id)
        if existing is None:
            repository.save_run(RunRecord(
                run_id=arguments.run_id,
                source_snapshot=manifest.snapshot_sha256,
                config={
                    "analysis_mode": "decompiler_static_only",
                    "capsule_set_sha256": capsules.capsule_set_sha256,
                    "model_id": arguments.model,
                },
            ))
        elif (
            existing.source_snapshot != manifest.snapshot_sha256
            or existing.config.get("capsule_set_sha256") != capsules.capsule_set_sha256
            or existing.config.get("model_id") != arguments.model
        ):
            raise RuntimeError("run ID is already bound to different evidence or model")
    runs = await execute_decompiler_hunter_plan(
        plan=plan,
        store_root=store,
        database=database,
        client=client,
        budget=budget,
    )
    with SqliteRepository(database, read_only=True) as repository:
        total_usage = repository.list_budget_usage(plan.run_id, scope="hunter")
        task_rows = [
            item for item in repository.list_tasks(plan.run_id)
            if item["task_type"] == "hunter"
        ]
    summary = {
        "schema_version": "decompiler-hunter-cli-result-v1",
        "run_id": plan.run_id,
        "plan_sha256": plan.plan_sha256,
        "capsule_set_sha256": plan.capsule_set_sha256,
        "admitted_root_sessions": len(plan.admitted_work_ids),
        "completed_in_this_invocation": len(runs),
        "completed_root_sessions_total": sum(
            item["status"] == "done" for item in task_rows
        ),
        "deferred_root_sessions_total": sum(
            item["status"] == "budget_deferred" for item in task_rows
        ),
        "hypotheses_in_this_invocation": sum(
            len(run.assessment.hypotheses) for run in runs
        ),
        "context_requests_in_this_invocation": sum(
            len(run.assessment.context_requests) for run in runs
        ),
        "model_calls_total": sum(item.calls for item in total_usage),
        "input_tokens_total": sum(item.input_tokens for item in total_usage),
        "output_tokens_total": sum(item.output_tokens for item in total_usage),
        "image_executions": 0,
        "generated_inputs": 0,
        "dynamic_experiments": 0,
        "fuzzer_invocations": 0,
        "vm_boots": 0,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return (
        0
        if summary["completed_root_sessions_total"] == len(plan.admitted_work_ids)
        else 3
    )


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
