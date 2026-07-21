"""Step 7: Hunt — leased Hunter execution per bounded AnalysisSlice group.

  Phase A: signal routing and overlapping-slice grouping
  Phase B: one leased HunterAgent per stable slice work item
  Phase C: deterministic finding clustering inside each work item
Evidence-aware reproduction, review, and reporting run in the following
Verified Findings step.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import asdict
from pathlib import Path

from ...analysis import CAnalysisGraph, SharedContextCache
from ...agents.hunter import TARGET_COMPLETION_POLICY
from ...agents.durable_queue import DurableHuntQueueStore
from ...agents.queue import HuntTask
from ...core.events import EventBus
from ...core.llm import LLMClient
from ...core.run_store import RunStore
from ...core.v2_run import advance_run, assert_source_snapshot_current
from ...domain.schemas import BudgetPolicy, BudgetUsage
from ...domain.states import RunState
from ...infrastructure.sqlite_repository import (
    SqliteRepository,
    TaskLeaseLostError,
)
from ...prompts import hunters_for
from ...sandbox import base_image_for, language_of
from ...scheduling import (
    BudgetController,
    BudgetedLLMClient,
    adaptive_iteration_limit,
    adaptive_output_token_limit,
    allocate_work_items,
    build_routing_plan,
    build_slice_work_items,
    total_usage,
)
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
    budget_policy = _budget_policy(cfg)

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
    if language_of(env) == "c" and any(path in {"", "."} for path in files):
        raise RuntimeError(
            "native Hunter work requires exact file targets; repository root is invalid"
        )

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
    work_items = build_slice_work_items(routing_plan, analysis)
    incremental = analysis.get("incremental_scope") or {}
    if incremental.get("mode") == "incremental":
        full_analysis = {
            **analysis,
            "incremental_scope": {
                **incremental,
                "mode": "full",
            },
        }
        full_selected = list(
            (analysis.get("coverage_plan") or {}).get("selected_files", [])
        )
        full_routing = build_routing_plan(
            run_id=store.dir.name,
            source_snapshot=source_snapshot,
            selected_files=full_selected,
            enabled_hunters=hunters,
            analysis=full_analysis,
        )
        full_work_items = build_slice_work_items(full_routing, full_analysis)
    else:
        full_routing = routing_plan
        full_work_items = work_items
    by_work_id = {item.work_id: item for item in work_items}
    hunt_plan = {
        "mode": "slice",
        "policy_version": (
            work_items[0].planning_policy
            if work_items else "c-slice-work-v1"
        ),
        "execution_changed": True,
        "target_completion_policy": TARGET_COMPLETION_POLICY,
        "completion_repair_limit": 1,
        "iteration_tiers": [6, 18, 40],
        "scan_mode": incremental.get("mode", "full"),
        "scan_base_ref": incremental.get("base_ref", ""),
        "scan_head_ref": incremental.get("head_ref", ""),
        "changed_files": len(incremental.get("changed_files", [])),
        "impacted_files": len(incremental.get("selected_files", [])),
        "full_scan_legacy_pairs": full_routing.legacy_sessions,
        "full_scan_scheduled_sessions": len(full_work_items),
        "incremental_session_reduction_percent": (
            round(
                (1 - len(work_items) / len(full_work_items)) * 100,
                2,
            )
            if full_work_items else 0.0
        ),
        "legacy_pairs": routing_plan.legacy_sessions,
        "routed_file_sessions": routing_plan.scheduled_sessions,
        "scheduled_sessions": len(work_items),
        "routed_file_reduction_percent": routing_plan.session_reduction_percent,
        "session_reduction_percent": (
            round(
                (1 - len(work_items) / routing_plan.legacy_sessions) * 100,
                2,
            )
            if routing_plan.legacy_sessions else 0.0
        ),
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
    }

    qstore = DurableHuntQueueStore(
        store.dir / "hunters",
        store.dir / "state.db",
        store.dir.name,
    )
    queue = qstore.init_from_work_items(work_items)
    with SqliteRepository(store.dir / "state.db", read_only=True) as repository:
        persisted_usage = repository.list_budget_usage(
            store.dir.name, scope="hunter"
        )
    persisted_usage.extend(_checkpoint_budget_usage(
        qstore,
        queue.tasks,
        run_id=store.dir.name,
        persisted_work_ids={item.work_id for item in persisted_usage},
    ))
    pending_ids = {
        task.work_id for task in queue.tasks if task.status == "pending"
    }
    allocation = allocate_work_items(
        tuple(item for item in work_items if item.work_id in pending_ids),
        budget_policy,
        consumed_sessions=sum(item.sessions for item in persisted_usage),
        risk_chains=CAnalysisGraph.model_validate(
            analysis.get("graph") or {}
        ).risk_chains,
        entrypoint_ids=tuple(
            (analysis.get("graph") or {}).get("entrypoint_ids", ())
        ),
        native_full_scan=(
            language_of(env) == "c"
            and incremental.get("mode", "full") == "full"
        ),
    )
    admitted_ids = set(allocation.admitted_work_ids)
    task_by_id = {task.work_id: task for task in queue.tasks}
    for work_id, reason in allocation.deferred.items():
        qstore.defer(task_by_id[work_id], reason=reason)
        bus.emit("hunter_budget_deferred", work_id=work_id, reason=reason)
    hunt_plan["budget"] = budget_policy.model_dump(mode="json")
    hunt_plan["budget_allocation"] = {
        "policy_version": allocation.policy_version,
        "admitted_sessions": len(allocation.admitted_work_ids),
        "chain_critical_slots": allocation.chain_critical_slots,
        "component_diverse_slots": allocation.component_diverse_slots,
        "high_risk_non_chain_slots": allocation.high_risk_non_chain_slots,
        "critical_slots": allocation.critical_slots,
        "high_risk_slots": allocation.high_risk_slots,
        "general_slots": allocation.general_slots,
        "retry_slots": allocation.retry_slots,
        "deferred_sessions": len(allocation.deferred),
        "decisions": [asdict(item) for item in allocation.decisions],
    }
    hunt_plan["budget_deferred_work_ids"] = sorted(allocation.deferred)
    hunt_plan["budget_deferred_critical_work_ids"] = sorted(
        work_id
        for work_id in allocation.deferred
        if by_work_id[work_id].required
    )
    context_cache = SharedContextCache(
        store.dir / "cache" / "context",
        repo,
        source_snapshot=source_snapshot,
        analysis=analysis,
    )
    analysis_contexts = {
        item.work_id: context_cache.get(item)
        for item in work_items
        if item.work_id in admitted_ids
    }
    context_cache_stats = context_cache.stats()
    hunt_plan["context_cache"] = context_cache_stats
    hunt_plan["context_cache_keys"] = {
        work_id: context["cache_key"]
        for work_id, context in sorted(analysis_contexts.items())
    }
    store.save_step("hunt_plan", hunt_plan)

    bus.emit("step_start", step="hunt",
             total=len(admitted_ids), parallel=max_parallel, max_iter=max_iter,
             image=hunter_image, hunters=hunters)

    budget_controller = BudgetController(budget_policy, persisted_usage)
    if not admitted_ids:
        _save_summary(
            store,
            qstore,
            bus,
            hunter_image,
            total_usage(persisted_usage),
            budget_policy,
            budget_controller.snapshot(),
            context_cache_stats,
        )
        advance_run(
            store,
            RunState.REPRODUCING,
            reason="No Hunter work admitted for this scan",
        )
        return

    hunter_client = LLMClient(model_id=cfg["model_id"])
    budgeted_hunter_client = BudgetedLLMClient(
        hunter_client,
        budget_controller,
    )
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
    worker_id = f"hunter-{uuid.uuid4().hex[:16]}"
    lease_seconds = int(cfg.get("hunter_lease_seconds", 900))
    max_attempts = min(
        int(cfg.get(
            "hunter_max_attempts",
            budget_policy.max_retries_per_work_item + 1,
        )),
        budget_policy.max_retries_per_work_item + 1,
    )

    async def run_work(task: HuntTask) -> None:
        if task.status in {"done", "failed", "budget_deferred"}:
            return
        item = by_work_id.get(task.work_id)
        if item is None:
            raise RuntimeError(f"durable queue returned unknown work: {task.work_id}")
        lease = qstore.acquire(
            task,
            worker_id=worker_id,
            lease_seconds=lease_seconds,
            max_attempts=max_attempts,
        )
        if lease is None:
            bus.emit("hunter_lease_unavailable", work_id=task.work_id)
            return
        heartbeat_stop = asyncio.Event()
        heartbeat_errors: list[Exception] = []
        heartbeat = asyncio.create_task(_heartbeat_lease(
            qstore,
            lease,
            lease_seconds=lease_seconds,
            stop=heartbeat_stop,
            errors=heartbeat_errors,
        ))
        try:
            qstore.mark_file_running(task)
            analysis_context = analysis_contexts[item.work_id]
            iteration_limit = adaptive_iteration_limit(
                item,
                configured_cap=max_iter,
                attempt=lease.attempt,
                has_evidence=_has_evidence(qstore, task),
            )
            output_token_limit = adaptive_output_token_limit(
                item,
                configured_cap=int(cfg.get("hunter_max_output_tokens_per_call", 4_000)),
            )
            findings_by_cat, usage_items, deferred = await run_hunters(
                task, qstore, repo, budgeted_hunter_client, hunter_image,
                arch, analysis_context, sandbox_info, iteration_limit, hunter_sem, bus,
                sandbox_enabled,
                {item.hunter: item},
                lambda: qstore.heartbeat(
                    lease,
                    lease_seconds=lease_seconds,
                ),
                max_tokens_per_call=output_token_limit,
            )
            if usage_items:
                with SqliteRepository(store.dir / "state.db") as repository:
                    for usage in usage_items:
                        repository.save_budget_usage(usage)
            if deferred:
                reason = ",".join(sorted(set(deferred.values())))
                await _stop_heartbeat(heartbeat_stop, heartbeat)
                if heartbeat_errors:
                    raise heartbeat_errors[0]
                qstore.finish(
                    lease,
                    status="budget_deferred",
                    error=reason,
                )
                qstore.mark_file_deferred(task, reason)
                bus.emit(
                    "hunter_budget_deferred",
                    work_id=task.work_id,
                    reason=reason,
                )
                return
            failed = [sub.error for sub in task.hunters if sub.status == "failed"]
            if failed:
                raise RuntimeError(failed[0] or "Hunter work failed")
            all_findings, origins = flatten(findings_by_cat)
            if not all_findings:
                await _stop_heartbeat(heartbeat_stop, heartbeat)
                if heartbeat_errors:
                    raise heartbeat_errors[0]
                qstore.finish(lease, status="done")
                qstore.mark_file_done(task)
                return

            qstore.mark_file_phase(task, "clustering")
            await run_clusterer(
                task, qstore, reviewer_client, all_findings, origins, bus,
            )
            await _stop_heartbeat(heartbeat_stop, heartbeat)
            if heartbeat_errors:
                raise heartbeat_errors[0]
            qstore.finish(lease, status="done")
            qstore.mark_file_done(task)
        except Exception as e:
            await _stop_heartbeat(heartbeat_stop, heartbeat)
            try:
                qstore.finish(lease, status="failed", error=str(e))
            except TaskLeaseLostError:
                bus.emit(
                    "hunter_lease_lost",
                    work_id=task.work_id,
                    error=str(e),
                )
                return
            qstore.mark_file_failed(task, error=str(e))
            bus.emit(
                "file_failed",
                file=task.file,
                work_id=task.work_id,
                error=str(e),
            )

    await asyncio.gather(*[
        run_work(task)
        for task in _tasks_in_admission_order(
            queue.tasks,
            allocation.admitted_work_ids,
        )
    ])
    with SqliteRepository(store.dir / "state.db", read_only=True) as repository:
        persisted_usage = repository.list_budget_usage(
            store.dir.name, scope="hunter"
        )
    persisted_usage.extend(_checkpoint_budget_usage(
        qstore,
        qstore.load().tasks,
        run_id=store.dir.name,
        persisted_work_ids={item.work_id for item in persisted_usage},
    ))
    _save_summary(
        store,
        qstore,
        bus,
        hunter_image,
        total_usage(persisted_usage),
        budget_policy,
        budget_controller.snapshot(),
        context_cache_stats,
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


def _tasks_in_admission_order(
    tasks: list[HuntTask],
    admitted_work_ids: tuple[str, ...],
) -> list[HuntTask]:
    """Launch work in the exact persisted admission-rank order."""
    by_work_id = {task.work_id: task for task in tasks}
    return [
        by_work_id[work_id]
        for work_id in admitted_work_ids
        if work_id in by_work_id
    ]


def _budget_policy(cfg: dict) -> BudgetPolicy:
    return BudgetPolicy(
        max_hunter_sessions=int(cfg.get("budget_max_hunter_sessions", 100)),
        max_input_tokens=int(cfg.get("budget_max_input_tokens", 2_000_000)),
        max_output_tokens=int(cfg.get("budget_max_output_tokens", 200_000)),
        max_wall_clock_minutes=int(
            cfg.get("budget_max_wall_clock_minutes", 60)
        ),
        max_retries_per_work_item=int(
            cfg.get("budget_max_retries_per_work_item", 1)
        ),
    )


def _has_evidence(
    qstore: DurableHuntQueueStore,
    task: HuntTask,
) -> bool:
    work_dir = qstore.task_dir(task)
    hunter_dir = work_dir / "hunts" / task.hunters[0].name
    if (hunter_dir / "findings.json").exists():
        return True
    pocs = hunter_dir / "pocs"
    return pocs.exists() and any(path.is_file() for path in pocs.rglob("*"))


def _maybe_other_client(cfg: dict, key: str, fallback: LLMClient, bus: EventBus) -> LLMClient:
    other = (cfg.get(key) or "").strip()
    if other and other != cfg.get("model_id"):
        bus.emit("model_picked", scope=key, model_id=other)
        return LLMClient(model_id=other)
    return fallback


async def _heartbeat_lease(
    qstore: DurableHuntQueueStore,
    lease,
    *,
    lease_seconds: int,
    stop: asyncio.Event,
    errors: list[Exception],
) -> None:
    interval = max(1.0, min(60.0, lease_seconds / 3))
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            try:
                qstore.heartbeat(lease, lease_seconds=lease_seconds)
            except Exception as exc:
                errors.append(exc)
                return


async def _stop_heartbeat(
    stop: asyncio.Event,
    heartbeat: asyncio.Task,
) -> None:
    stop.set()
    await heartbeat


def _save_summary(
    store: RunStore,
    qstore,
    bus: EventBus,
    image: str,
    usage: dict[str, int | float | None],
    policy: BudgetPolicy,
    budget_state: dict[str, int | float | bool],
    context_cache: dict[str, int | str],
) -> None:
    final = qstore.load()
    summary = {
        "total": len(final.tasks),
        "done": sum(1 for t in final.tasks if t.status == "done"),
        "failed": sum(1 for t in final.tasks if t.status == "failed"),
        "budget_deferred": sum(
            1 for t in final.tasks if t.status == "budget_deferred"
        ),
        "pending": sum(1 for t in final.tasks if t.status == "pending"),
        "total_findings": sum(
            sum(s.findings_count for s in t.hunters) for t in final.tasks
        ),
        "image": image,
        "usage": usage,
        "budget": policy.model_dump(mode="json"),
        "budget_state": budget_state,
        "context_cache": context_cache,
        "unanalysed_work_ids": sorted(
            task.work_id
            for task in final.tasks
            if task.status == "budget_deferred"
        ),
        "tasks": [asdict(t) for t in final.tasks],
    }
    summary["target_completion"] = _target_completion(qstore, final.tasks)
    summary["protocol_metrics"] = _protocol_metrics(qstore, final.tasks)
    store.save_step("hunt", summary)
    bus.emit("step_done", step="hunt", **{k: v for k, v in summary.items() if k != "tasks"})


def _target_completion(qstore, tasks: list[HuntTask]) -> dict:
    counts = {
        "finding": 0,
        "no_finding": 0,
        "deferred": 0,
        "missing": 0,
    }
    incomplete: list[dict[str, str]] = []
    for task in tasks:
        expected = task.target_signal_ids or task.target_node_ids
        if not expected:
            continue
        dispositions: dict[str, str] = {}
        if task.hunters:
            path = qstore.hunt_dir(task, task.hunters[0].name) / "findings.json"
            try:
                payload = json.loads(path.read_text()) if path.is_file() else {}
            except (OSError, json.JSONDecodeError):
                payload = {}
            dispositions = {
                item["target_id"]: item["status"]
                for item in payload.get("target_dispositions", [])
                if isinstance(item, dict)
                and isinstance(item.get("target_id"), str)
                and item.get("status") in counts
            }
        for target_id in expected:
            status = dispositions.get(target_id)
            if status is None:
                status = "deferred" if task.status == "budget_deferred" else "missing"
            counts[status] += 1
            if status in {"deferred", "missing"}:
                incomplete.append({
                    "work_id": task.work_id,
                    "target_id": target_id,
                    "status": status,
                })
    total = sum(counts.values())
    return {
        "total": total,
        **counts,
        "complete": not incomplete,
        "incomplete": incomplete,
    }


def _checkpoint_budget_usage(
    qstore,
    tasks: list[HuntTask],
    *,
    run_id: str,
    persisted_work_ids: set[str],
) -> list[BudgetUsage]:
    usage: list[BudgetUsage] = []
    for task in tasks:
        if task.work_id in persisted_work_ids or not task.hunters:
            continue
        path = qstore.hunt_dir(task, task.hunters[0].name) / "usage-checkpoint.json"
        try:
            payload = json.loads(path.read_text()) if path.is_file() else {}
        except (OSError, json.JSONDecodeError):
            continue
        iterations = payload.get("iterations", 0)
        if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 1:
            continue
        usage.append(BudgetUsage(
            run_id=run_id,
            work_id=task.work_id,
            scope="hunter",
            model_id=str(payload.get("model_id") or "unknown"),
            transport=str(payload.get("transport") or "unknown"),
            sessions=1,
            calls=iterations,
            iterations=iterations,
            input_tokens=_nonnegative_int(payload.get("input_tokens")),
            output_tokens=_nonnegative_int(payload.get("output_tokens")),
            cache_read_tokens=_nonnegative_int(payload.get("cache_read_tokens")),
            cache_write_tokens=_nonnegative_int(payload.get("cache_write_tokens")),
            tool_calls=_nonnegative_int(payload.get("tool_calls")),
            repeated_reads=_nonnegative_int(payload.get("repeated_reads")),
            poc_writes=_nonnegative_int(payload.get("poc_writes")),
            exec_calls=_nonnegative_int(payload.get("exec_calls")),
            wall_time_ms=_nonnegative_int(payload.get("wall_time_ms")),
        ))
    return usage


def _protocol_metrics(qstore, tasks: list[HuntTask]) -> dict:
    tool_arguments_invalid = 0
    protocol_repairs = 0
    protocol_repair_successes = 0
    transient_retries = 0
    failures: dict[str, int] = {}
    for task in tasks:
        if not task.hunters:
            continue
        path = qstore.hunt_dir(task, task.hunters[0].name) / "usage-checkpoint.json"
        try:
            payload = json.loads(path.read_text()) if path.is_file() else {}
        except (OSError, json.JSONDecodeError):
            continue
        tool_arguments_invalid += _nonnegative_int(
            payload.get("tool_argument_errors")
        )
        protocol_repairs += _nonnegative_int(payload.get("protocol_repairs"))
        protocol_repair_successes += _nonnegative_int(
            payload.get("protocol_repair_successes")
        )
        transient_retries += _nonnegative_int(payload.get("transient_retries"))
        raw_failures = payload.get("model_failures")
        if isinstance(raw_failures, dict):
            for category, count in raw_failures.items():
                failures[str(category)] = failures.get(str(category), 0) + _nonnegative_int(
                    count
                )
    return {
        "tool_arguments_invalid": tool_arguments_invalid,
        "protocol_repairs": protocol_repairs,
        "protocol_repair_successes": protocol_repair_successes,
        "transient_retries": transient_retries,
        "model_failures": failures,
    }


def _nonnegative_int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


register(Step(
    name="hunt",
    title="7. Hunter Agents",
    fn=run_hunt,
    depends_on=["file_selector", "sandbox_prepare"],
))
