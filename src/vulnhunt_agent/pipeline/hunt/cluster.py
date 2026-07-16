"""Phase B — cluster similar findings before review.

Skipped when there are <2 findings or only 1 hunter produced findings:
in those cases, every finding becomes its own group.
"""
from __future__ import annotations

import json
from dataclasses import asdict

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
        result = await agent.cluster(task.file, findings)
        (qstore.task_dir(task) / "clusters.json").write_text(
            json.dumps(asdict(result), indent=2, ensure_ascii=False)
        )
        task.cluster_status = "done"
        qstore.persist(task)
        bus.emit("cluster_done", file=task.file, n_groups=len(result.groups))
        return result.groups
    except Exception as e:
        task.cluster_status = "failed"
        qstore.persist(task)
        bus.emit("cluster_failed", file=task.file, error=str(e))
        return _one_group_per_finding(findings)
    finally:
        trace.close()


def _one_group_per_finding(findings: list[dict]) -> list[dict]:
    return [{"finding_ids": [i], "reason": ""} for i in range(len(findings))]
