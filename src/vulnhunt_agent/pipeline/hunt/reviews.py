"""Phase C — one ReviewerAgent per cluster group, in parallel."""
from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from pathlib import Path

from ...agents import ReviewerAgent
from ...agents.queue import ReviewSubTask
from ...agents.tools import HunterTools
from .. import finalize


async def run_reviews(
    task, qstore, repo: Path, client, arch: dict, groups: list[dict],
    all_findings: list[dict], origins: list[str], sem, bus,
) -> None:
    """One reviewer per group, in parallel."""
    task.reviews = [ReviewSubTask(group_id=f"g{i+1}") for i in range(len(groups))]
    qstore.persist(task)

    async def one(idx: int, group: dict) -> None:
        gid = f"g{idx+1}"
        sub = next(r for r in task.reviews if r.group_id == gid)
        ids = group.get("finding_ids", [])
        group_findings = [all_findings[i] for i in ids]
        review_dir = qstore.review_dir(task, gid)
        finalize.write_group_input(review_dir, group, group_findings)
        used_origins = sorted({origins[i] for i in ids})
        poc_roots = [qstore.hunt_dir(task, c) / "pocs" for c in used_origins]
        async with sem:
            sub.status = "running"
            qstore.persist(task)
            bus.emit("review_start", file=task.file, group=gid, size=len(group_findings))
            trace = (review_dir / "trace.jsonl").open("a")
            on_event = lambda t, **d: trace.write(json.dumps({"type": t, **d}, ensure_ascii=False) + "\n")
            try:
                tools = HunterTools(repo, sandbox=None, poc_root=poc_roots)
                agent = ReviewerAgent(
                    client=client, tools=tools, arch=arch,
                    max_iterations=30, on_event=on_event,
                )
                result = await agent.review(task.file, group_findings, group.get("reason", ""))
                finalize.enrich_with_cvss(result)
                (review_dir / "review.json").write_text(
                    json.dumps(asdict(result), indent=2, ensure_ascii=False)
                )
                finalize.materialize_reports(review_dir, result)
                sub.status = "done"
                sub.reportable = len(result.reports)
                qstore.persist(task)
                bus.emit("review_done", file=task.file, group=gid,
                         reviewed=len(result.reviewed),
                         reportable=len(result.reports),
                         stopped=result.stopped)
            except Exception as e:
                sub.status = "failed"
                sub.error = str(e)
                qstore.persist(task)
                bus.emit("review_failed", file=task.file, group=gid, error=str(e))
            finally:
                trace.close()

    await asyncio.gather(*[one(i, g) for i, g in enumerate(groups)])
