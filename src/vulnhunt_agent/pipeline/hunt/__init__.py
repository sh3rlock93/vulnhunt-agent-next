"""Step 7: Hunt — Hunter and clustering pipeline per file.

  Phase A (hunters):  parallel HunterAgent per (file, hunter)
  Phase B (cluster):  ClustererAgent groups similar findings (skipped if
                      <2 findings or only 1 hunter produced findings)
Evidence-aware reproduction, review, and reporting run in the following
Verified Findings step.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from pathlib import Path

from ...analysis import context_for_file
from ...agents.queue import HuntQueueStore, HuntTask
from ...core.events import EventBus
from ...core.llm import LLMClient
from ...core.run_store import RunStore
from ...core.v2_run import advance_run, assert_source_snapshot_current
from ...domain.states import RunState
from ...infrastructure.sqlite_repository import SqliteRepository
from ...prompts import hunters_for
from ...sandbox import base_image_for, language_of
from ...scheduling import build_routing_plan, total_usage
from .. import finalize
from ..registry import Step, register
from .cluster import run_clusterer
from .hunters import flatten, run_hunters


async def run_hunt(store: RunStore, bus: EventBus) -> None:
    cfg = store.load_config() or {}
    prepare = store.load_step("sandbox_prepare") or {}
    source_snapshot = assert_source_snapshot_current(store)
    advance_run(store, RunState.HUNTING, reason="Hunter execution started")

    repo = Path(cfg["repo_path"])
    env = cfg["environment"]
    arch = {"language": language_of(env), "environment": env}
    max_parallel = int(cfg.get("max_hunters_parallel", 3))
    max_iter = int(cfg.get("hunter_max_iterations", 100))

    prepared_image = prepare.get("image")
    sandbox_enabled = prepare.get("status") == "ready" and bool(prepared_image)
    hunter_image = (
        str(prepared_image)
        if sandbox_enabled
        else base_image_for(env)
    )
    sandbox_info = finalize.sandbox_info(prepare, language_of(env))

    selector = store.load_step("file_selector") or {}
    analysis = store.load_step("analysis_graph") or {}
    files = list(selector.get("selected", []))

    hunters = _resolve_hunter_selection(
        store.dir / "steps", language_of(env)
    )
    routing_plan = build_routing_plan(
        run_id=store.dir.name,
        source_snapshot=source_snapshot,
        selected_files=files,
        enabled_hunters=hunters,
        analysis=analysis,
    )
    if routing_plan.uncovered_critical_sink_ids:
        raise RuntimeError(
            "signal router left critical sinks uncovered: "
            + ", ".join(routing_plan.uncovered_critical_sink_ids)
        )
    work_items = routing_plan.work_items
    pairs = [
        (item.seed_file, item.hunter)
        for item in work_items
    ]
    by_pair = {
        (item.seed_file, item.hunter): item
        for item in work_items
    }
    store.save_step("hunt_plan", {
        "mode": "signal",
        "policy_version": routing_plan.policy_version,
        "execution_changed": True,
        "legacy_pairs": routing_plan.legacy_sessions,
        "scheduled_sessions": routing_plan.scheduled_sessions,
        "session_reduction_percent": routing_plan.session_reduction_percent,
        "detected_critical_sink_ids": list(
            routing_plan.detected_critical_sink_ids
        ),
        "covered_critical_sink_ids": list(
            routing_plan.covered_critical_sink_ids
        ),
        "uncovered_critical_sink_ids": list(
            routing_plan.uncovered_critical_sink_ids
        ),
        "forced_files": list(routing_plan.forced_files),
        "work_items": [
            item.model_dump(mode="json")
            for item in work_items
        ],
    })

    qstore = HuntQueueStore(store.dir / "hunters")
    queue = qstore.init_from_pairs(pairs)

    bus.emit("step_start", step="hunt",
             total=len(work_items), parallel=max_parallel, max_iter=max_iter,
             image=hunter_image, hunters=hunters)

    hunter_client = LLMClient(model_id=cfg["model_id"])
    reviewer_client = _maybe_other_client(cfg, "model_id_reviewer", hunter_client, bus)
    bus.emit(
        "model_transport",
        scope="hunter",
        model_id=cfg["model_id"],
        transport=getattr(hunter_client, "transport", "bedrock_converse"),
    )
    bus.emit(
        "model_transport",
        scope="reviewer",
        model_id=cfg.get("model_id_reviewer") or cfg["model_id"],
        transport=getattr(reviewer_client, "transport", "bedrock_converse"),
    )

    hunter_sem = asyncio.Semaphore(max_parallel)

    async def run_file(task: HuntTask) -> None:
        if task.status in {"done", "failed"}:
            return
        try:
            qstore.mark_file_running(task)
            analysis_context = context_for_file(analysis, task.file)
            findings_by_cat, usage_items = await run_hunters(
                task, qstore, repo, hunter_client, hunter_image,
                arch, analysis_context, sandbox_info, max_iter, hunter_sem, bus,
                sandbox_enabled,
                {
                    sub.name: by_pair[(task.file, sub.name)]
                    for sub in task.hunters
                    if (task.file, sub.name) in by_pair
                },
            )
            if usage_items:
                with SqliteRepository(store.dir / "state.db") as repository:
                    for usage in usage_items:
                        repository.save_budget_usage(usage)
            all_findings, origins = flatten(findings_by_cat)
            if not all_findings:
                qstore.mark_file_done(task)
                return

            qstore.mark_file_phase(task, "clustering")
            await run_clusterer(
                task, qstore, reviewer_client, all_findings, origins, bus,
            )
            qstore.mark_file_done(task)
        except Exception as e:
            qstore.mark_file_failed(task, error=str(e))
            bus.emit("file_failed", file=task.file, error=str(e))

    await asyncio.gather(*[run_file(t) for t in queue.tasks])
    with SqliteRepository(store.dir / "state.db", read_only=True) as repository:
        persisted_usage = repository.list_budget_usage(
            store.dir.name, scope="hunter"
        )
    _save_summary(
        store,
        qstore,
        bus,
        hunter_image,
        total_usage(persisted_usage),
    )
    advance_run(
        store,
        RunState.REPRODUCING,
        reason="Hunter execution and clustering complete",
    )


def _resolve_hunter_selection(steps_dir: Path, language: str) -> list[str]:
    # New runs use hunter_selection.json with "hunters"; older runs used
    # category_selection.json with "categories". An existing empty selection
    # is intentional; only an absent file receives catalog defaults.
    new = steps_dir / "hunter_selection.json"
    if new.exists():
        return list(json.loads(new.read_text()).get("hunters", []))
    old = steps_dir / "category_selection.json"
    if old.exists():
        return list(json.loads(old.read_text()).get("categories", []))
    return [
        hunter.name
        for hunter in hunters_for(language)
        if hunter.default
    ]


def _maybe_other_client(cfg: dict, key: str, fallback: LLMClient, bus: EventBus) -> LLMClient:
    other = (cfg.get(key) or "").strip()
    if other and other != cfg.get("model_id"):
        bus.emit("model_picked", scope=key, model_id=other)
        return LLMClient(model_id=other)
    return fallback


def _save_summary(
    store: RunStore,
    qstore: HuntQueueStore,
    bus: EventBus,
    image: str,
    usage: dict[str, int | float | None],
) -> None:
    final = qstore.load()
    summary = {
        "total": len(final.tasks),
        "done": sum(1 for t in final.tasks if t.status == "done"),
        "failed": sum(1 for t in final.tasks if t.status == "failed"),
        "pending": sum(1 for t in final.tasks if t.status == "pending"),
        "total_findings": sum(
            sum(s.findings_count for s in t.hunters) for t in final.tasks
        ),
        "image": image,
        "usage": usage,
        "tasks": [asdict(t) for t in final.tasks],
    }
    store.save_step("hunt", summary)
    bus.emit("step_done", step="hunt", **{k: v for k, v in summary.items() if k != "tasks"})


register(Step(
    name="hunt",
    title="7. Hunter Agents",
    fn=run_hunt,
    depends_on=["file_selector", "sandbox_prepare"],
))
