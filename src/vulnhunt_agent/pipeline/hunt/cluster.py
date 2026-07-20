"""Phase B — cluster similar findings before review.

Skipped when there are <2 findings or only 1 hunter produced findings:
in those cases, every finding becomes its own group.
"""
from __future__ import annotations

import json
from dataclasses import asdict

from ...analysis.dedup import deterministic_partitions
from ...agents.clusterer import ClustererAgent


async def run_clusterer(
    task, qstore, client, findings: list[dict], origins: list[str], bus,
) -> list[dict]:
    """Return cluster groups (1 group per finding if cluster step is skipped)."""
    clusters_path = qstore.task_dir(task) / "clusters.json"
    if task.cluster_status == "done" and clusters_path.exists():
        return json.loads(clusters_path.read_text()).get("groups", [])

    used = set(origins)
    if len(findings) < 2 or len(used) < 2:
        task.cluster_status = "skipped"
        qstore.persist(task)
        return _one_group_per_finding(findings)

    partitions = deterministic_partitions(findings)
    if len(partitions) == 1:
        groups = [{
            "finding_ids": partitions[0],
            "reason": "deterministic fingerprint match",
        }]
        clusters_path.write_text(json.dumps(
            {"strategy": "deterministic", "groups": groups},
            indent=2,
            ensure_ascii=False,
        ))
        task.cluster_status = "done"
        qstore.persist(task)
        bus.emit(
            "cluster_done",
            file=task.file,
            n_groups=1,
            strategy="deterministic",
        )
        return groups

    task.cluster_status = "running"
    qstore.persist(task)
    bus.emit("cluster_start", file=task.file, n_findings=len(findings))

    trace = (qstore.task_dir(task) / "cluster.trace.jsonl").open("a")

    def on_event(event_type, **data):
        return trace.write(
            json.dumps({"type": event_type, **data}, ensure_ascii=False) + "\n"
        )

    try:
        agent = ClustererAgent(client=client, on_event=on_event)
        representatives = [findings[ids[0]] for ids in partitions]
        result = await agent.cluster(task.file, representatives)
        groups = _expand_groups(result.groups, partitions)
        payload = {
            **asdict(result),
            "strategy": "deterministic_then_semantic",
            "deterministic_partitions": partitions,
            "groups": groups,
        }
        clusters_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        task.cluster_status = "done"
        qstore.persist(task)
        bus.emit(
            "cluster_done",
            file=task.file,
            n_groups=len(groups),
            strategy="deterministic_then_semantic",
        )
        return groups
    except Exception as e:
        task.cluster_status = "failed"
        qstore.persist(task)
        bus.emit("cluster_failed", file=task.file, error=str(e))
        return [
            {"finding_ids": ids, "reason": "deterministic fallback"}
            for ids in partitions
        ]
    finally:
        trace.close()


def _one_group_per_finding(findings: list[dict]) -> list[dict]:
    return [{"finding_ids": [i], "reason": ""} for i in range(len(findings))]


def _expand_groups(
    semantic_groups: list[dict],
    partitions: list[list[int]],
) -> list[dict]:
    expanded = []
    seen: set[int] = set()
    for group in semantic_groups:
        representative_ids = group.get("finding_ids", [])
        finding_ids = sorted({
            finding_id
            for representative_id in representative_ids
            if isinstance(representative_id, int)
            and 0 <= representative_id < len(partitions)
            for finding_id in partitions[representative_id]
        })
        if not finding_ids:
            continue
        seen.update(finding_ids)
        expanded.append({
            "finding_ids": finding_ids,
            "reason": group.get("reason", ""),
        })
    missing = [
        finding_id
        for partition in partitions
        for finding_id in partition
        if finding_id not in seen
    ]
    if missing:
        expanded.append({
            "finding_ids": missing,
            "reason": "unassigned semantic representatives",
        })
    return expanded
