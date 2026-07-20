"""Phase A — run all hunters for one file in parallel."""
from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path

from ...agents import HunterAgent
from ...agents.tools import HunterTools
from ...domain.schemas import BudgetUsage, HunterWorkItem
from ...prompts import hunter_by_name
from ...sandbox import ContainerExecutor
from ...scheduling.metrics import with_estimated_cost
from .. import finalize


async def run_hunters(
    task, qstore, repo: Path, client, image: str,
    arch: dict, analysis_context: dict, sandbox_info: str, max_iter: int, sem, bus,
    sandbox_enabled: bool,
    work_items: dict[str, HunterWorkItem] | None = None,
) -> tuple[dict[str, list[dict]], list[BudgetUsage]]:
    """Run all hunters for one file in parallel; return {hunter_name: findings}."""
    out: dict[str, list[dict]] = {}
    usage_items: list[BudgetUsage] = []

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

            def on_event(event_type, **data):
                return trace.write(
                    json.dumps({"type": event_type, **data}, ensure_ascii=False) + "\n"
                )

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
                    max_iterations=max_iter, on_event=on_event,
                )
                result = await agent.hunt(task.file, analysis_context)
                if result.findings:
                    finalize.rewrite_poc_paths(result.findings)
                (hunt_dir / "findings.json").write_text(
                    json.dumps(asdict(result), indent=2, ensure_ascii=False)
                )
                qstore.mark_hunt_done(task, name, findings_count=len(result.findings))
                work_item = (work_items or {}).get(name)
                if work_item is not None:
                    usage_items.append(with_estimated_cost(BudgetUsage(
                        run_id=work_item.run_id,
                        work_id=work_item.work_id,
                        scope="hunter",
                        model_id=str(getattr(client, "model_id", "unknown")),
                        transport=str(getattr(client, "transport", "bedrock_converse")),
                        sessions=1,
                        calls=result.iterations,
                        iterations=result.iterations,
                        input_tokens=result.input_tokens,
                        output_tokens=result.output_tokens,
                        cache_read_tokens=result.cache_read_tokens,
                        cache_write_tokens=result.cache_write_tokens,
                        tool_calls=result.tool_calls,
                        repeated_reads=result.repeated_reads,
                        poc_writes=result.poc_writes,
                        exec_calls=result.exec_calls,
                        wall_time_ms=max(0, int((time.monotonic() - started) * 1000)),
                    )))
                bus.emit("hunter_done", file=task.file, hunter=name,
                         findings=len(result.findings), iterations=result.iterations,
                         stopped=result.stopped)
                out[name] = result.findings
            except Exception as e:
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
    return out, usage_items


def flatten(by_name: dict[str, list[dict]]) -> tuple[list[dict], list[str]]:
    """Return (flat findings, origin hunter names) preserving id-by-index."""
    flat, origins = [], []
    for n in sorted(by_name):
        for f in by_name[n]:
            flat.append(f)
            origins.append(n)
    return flat, origins
