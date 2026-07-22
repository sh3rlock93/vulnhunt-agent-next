"""Phase A — run all hunters for one file in parallel."""
from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path

from ...agents import HunterAgent
from ...agents.hunter import HuntResult
from ...agents.tools import HunterTools
from ...core.model_errors import ModelClientError
from ...domain.schemas import BudgetUsage, HunterWorkItem
from ...prompts import hunter_by_name
from ...sandbox import ContainerExecutor
from ...scheduling.metrics import with_estimated_cost
from .. import finalize


async def run_hunters(
    task, qstore, repo: Path, client, image: str,
    arch: dict, analysis_context: dict | tuple[dict, ...], sandbox_info: str,
    max_iter: int, sem, bus,
    sandbox_enabled: bool,
    work_items: dict[str, HunterWorkItem] | None = None,
    before_commit=None,
    max_tokens_per_call: int = 4_000,
) -> tuple[dict[str, list[dict]], list[BudgetUsage], dict[str, str]]:
    """Run all hunters for one file in parallel; return {hunter_name: findings}."""
    out: dict[str, list[dict]] = {}
    usage_items: list[BudgetUsage] = []
    deferred: dict[str, str] = {}

    async def one(name: str) -> None:
        sub = next(s for s in task.hunters if s.name == name)
        if sub.status == "done":
            existing = qstore.hunt_dir(task, name) / "findings.json"
            if existing.exists():
                out[name] = json.loads(existing.read_text()).get("findings", [])
            return
        hunter_def = hunter_by_name(name, language=arch.get("language"))
        if hunter_def is None:
            qstore.mark_hunt_failed(task, name, error=f"unknown hunter: {name}")
            return
        async with sem:
            started = time.monotonic()
            qstore.mark_hunt_running(task, name)
            bus.emit("hunter_start", file=task.file, hunter=name)
            hunt_dir = qstore.hunt_dir(task, name)
            trace = (hunt_dir / "trace.jsonl").open("a")
            checkpoint_path = hunt_dir / "usage-checkpoint.json"
            initial_metrics = _load_usage_checkpoint(checkpoint_path)
            prior_wall_time_ms = int(initial_metrics.get("wall_time_ms", 0))

            def on_event(event_type, **data):
                return trace.write(
                    json.dumps({"type": event_type, **data}, ensure_ascii=False) + "\n"
                )

            def on_checkpoint(result) -> None:
                payload = {
                    field: getattr(result, field)
                    for field in _CHECKPOINT_FIELDS
                }
                payload["wall_time_ms"] = prior_wall_time_ms + max(
                    0,
                    int((time.monotonic() - started) * 1000),
                )
                payload["model_id"] = str(getattr(client, "model_id", "unknown"))
                payload["transport"] = str(
                    getattr(client, "transport", "bedrock_converse")
                )
                _write_usage_checkpoint(checkpoint_path, payload)

            sandbox = (
                ContainerExecutor(repo=repo, image=image, source_baked=True)
                if sandbox_enabled
                else None
            )
            try:
                if sandbox is not None:
                    await sandbox.start()
                    on_event("sandbox_start", name=sandbox.name, image=image)
                tools = HunterTools(repo, sandbox=sandbox, poc_root=hunt_dir / "pocs")
                agent = HunterAgent(
                    client=client, tools=tools, arch=arch,
                    hunter_prompt=hunter_def.system_prompt,
                    sandbox_info=sandbox_info,
                    max_iterations=max_iter,
                    max_tokens_per_call=max_tokens_per_call,
                    on_event=on_event,
                    initial_metrics=initial_metrics,
                    on_checkpoint=on_checkpoint,
                )
                contexts = (
                    analysis_context
                    if isinstance(analysis_context, tuple)
                    else (analysis_context,)
                )
                result = await agent.hunt(
                    task.file,
                    contexts[0],
                    focused_retry_contexts=contexts[1:],
                )
                if result.findings:
                    finalize.rewrite_poc_paths(result.findings)
                if before_commit is not None:
                    before_commit()
                (hunt_dir / "findings.json").write_text(
                    json.dumps(asdict(result), indent=2, ensure_ascii=False)
                )
                if result.stopped == "budget_exhausted" or result.incomplete_target_ids:
                    reason = result.budget_reason or "budget_exhausted"
                    deferred[name] = reason
                    qstore.mark_hunt_deferred(task, name, reason)
                else:
                    qstore.mark_hunt_done(
                        task,
                        name,
                        findings_count=len(result.findings),
                    )
                work_item = (work_items or {}).get(name)
                if work_item is not None:
                    usage_items.append(_usage_for_result(
                        result,
                        work_item,
                        client,
                        wall_time_ms=prior_wall_time_ms + max(
                            0,
                            int((time.monotonic() - started) * 1000),
                        ),
                    ))
                bus.emit(
                    "hunter_deferred"
                    if result.stopped == "budget_exhausted" or result.incomplete_target_ids
                    else "hunter_done",
                    file=task.file,
                    hunter=name,
                    findings=len(result.findings),
                    iterations=result.iterations,
                    stopped=result.stopped,
                    reason=result.budget_reason,
                )
                out[name] = result.findings
            except Exception as e:
                if isinstance(e, ModelClientError):
                    bus.emit(
                        "hunter_model_failure",
                        file=task.file,
                        hunter=name,
                        category=e.category.value,
                        retryable=e.retryable,
                    )
                    partial = e.partial_result
                    work_item = (work_items or {}).get(name)
                    if isinstance(partial, HuntResult) and work_item is not None:
                        usage_items.append(_usage_for_result(
                            partial,
                            work_item,
                            client,
                            wall_time_ms=prior_wall_time_ms + max(
                                0,
                                int((time.monotonic() - started) * 1000),
                            ),
                        ))
                qstore.mark_hunt_failed(task, name, error=str(e))
                bus.emit("hunter_failed", file=task.file, hunter=name, error=str(e))
            finally:
                trace.close()
                try:
                    if sandbox is not None:
                        await sandbox.stop()
                except Exception:
                    pass

    import asyncio
    await asyncio.gather(*[one(s.name) for s in task.hunters])
    return out, usage_items, deferred


_CHECKPOINT_FIELDS = (
    "iterations",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "tool_calls",
    "repeated_reads",
    "poc_writes",
    "exec_calls",
    "tool_argument_errors",
    "protocol_repairs",
    "protocol_repair_successes",
    "transient_retries",
    "model_failures",
)


def _load_usage_checkpoint(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text()) if path.is_file() else {}
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_usage_checkpoint(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    temporary.replace(path)


def _usage_for_result(
    result: HuntResult,
    work_item: HunterWorkItem,
    client,
    *,
    wall_time_ms: int,
) -> BudgetUsage:
    started_calls = int(getattr(client, "started_calls", result.iterations or 1))
    return with_estimated_cost(BudgetUsage(
        run_id=work_item.run_id,
        work_id=work_item.work_id,
        scope="hunter",
        model_id=str(getattr(client, "model_id", "unknown")),
        transport=str(getattr(client, "transport", "bedrock_converse")),
        sessions=int(started_calls > 0),
        calls=max(result.iterations, started_calls),
        iterations=result.iterations,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        cache_read_tokens=result.cache_read_tokens,
        cache_write_tokens=result.cache_write_tokens,
        tool_calls=result.tool_calls,
        repeated_reads=result.repeated_reads,
        poc_writes=result.poc_writes,
        exec_calls=result.exec_calls,
        wall_time_ms=wall_time_ms,
    ))


def flatten(by_name: dict[str, list[dict]]) -> tuple[list[dict], list[str]]:
    """Return (flat findings, origin hunter names) preserving id-by-index."""
    flat, origins = [], []
    for n in sorted(by_name):
        for f in by_name[n]:
            flat.append(f)
            origins.append(n)
    return flat, origins
