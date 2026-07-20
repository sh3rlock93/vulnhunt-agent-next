"""Persistent queue for the hunt step. Resume-on-crash.

A task is one *file*. Inside a task, the lifecycle is:
  1. hunters[]    — one HuntSubTask per (file, hunter), runs HunterAgent
  2. cluster      — runs ClustererAgent IFF >=2 findings AND >=2 hunters
  3. reviews[]    — one ReviewSubTask per cluster group, runs ReviewerAgent

Per-file dir lives at <root>/<file_hash>/. Per-hunter outputs go to
hunts/<name>/, per-group reviews to reviews/<group_id>/.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class HuntSubTask:
    name: str
    status: str = "pending"           # pending | running | done | failed
    findings_count: int = 0
    started_at: str = ""
    finished_at: str = ""
    error: str = ""


@dataclass
class ReviewSubTask:
    group_id: str                     # e.g. "g1", "g2"
    status: str = "pending"
    reportable: int = 0
    started_at: str = ""
    finished_at: str = ""
    error: str = ""


@dataclass
class HuntTask:
    file: str                         # relative path
    hash: str                         # deterministic dir name
    status: str = "pending"           # pending | hunting | clustering | reviewing | done | failed
    started_at: str = ""
    finished_at: str = ""
    error: str = ""
    hunters: list[HuntSubTask] = field(default_factory=list)
    cluster_status: str = "skipped"   # skipped | pending | running | done | failed
    reviews: list[ReviewSubTask] = field(default_factory=list)


@dataclass
class HuntQueue:
    tasks: list[HuntTask] = field(default_factory=list)


class HuntQueueStore:
    """Reads/writes the queue JSON and per-file directories."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.queue_path = self.root / "_queue.json"

    def load(self) -> HuntQueue:
        if not self.queue_path.exists():
            return HuntQueue()
        raw = json.loads(self.queue_path.read_text())
        return HuntQueue(tasks=[_task_from(t) for t in raw["tasks"]])

    def save(self, queue: HuntQueue) -> None:
        self.queue_path.write_text(json.dumps(
            {"tasks": [asdict(t) for t in queue.tasks]},
            indent=2, ensure_ascii=False,
        ))

    def init_from_pairs(self, pairs: list[tuple[str, str]]) -> HuntQueue:
        """Build queue from (file, hunter_name) pairs.

        Done/failed/running file tasks keep their existing dir to avoid
        orphaning artefacts. Each file task carries its own hunters[] list.
        """
        existing = {t.file: t for t in self.load().tasks}
        files: dict[str, list[str]] = {}
        for f, n in pairs:
            files.setdefault(f, []).append(n)

        tasks: list[HuntTask] = []
        for f, names in files.items():
            prev = existing.get(f)
            if prev and prev.status in ("done", "failed", "hunting", "clustering", "reviewing"):
                tasks.append(prev)
                continue
            tasks.append(HuntTask(
                file=f,
                hash=_task_dirname(f),
                hunters=[HuntSubTask(name=n) for n in names],
            ))
        q = HuntQueue(tasks=tasks)
        self.save(q)
        return q

    def task_dir(self, task: HuntTask) -> Path:
        d = self.root / task.hash
        d.mkdir(parents=True, exist_ok=True)
        return d

    def hunt_dir(self, task: HuntTask, name: str) -> Path:
        d = self.task_dir(task) / "hunts" / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def review_dir(self, task: HuntTask, group_id: str) -> Path:
        d = self.task_dir(task) / "reviews" / group_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    # --- transitions ---

    def mark_file_running(self, task: HuntTask) -> None:
        task.status = "hunting"
        task.started_at = _now()
        task.error = ""
        self._rewrite(task)
        self._write_task_json(task)

    def mark_file_phase(self, task: HuntTask, phase: str) -> None:
        task.status = phase
        self._rewrite(task)
        self._write_task_json(task)

    def mark_file_done(self, task: HuntTask) -> None:
        task.status = "done"
        task.finished_at = _now()
        self._rewrite(task)
        self._write_task_json(task)

    def mark_file_failed(self, task: HuntTask, error: str) -> None:
        task.status = "failed"
        task.finished_at = _now()
        task.error = error
        self._rewrite(task)
        self._write_task_json(task)

    def mark_hunt_running(self, task: HuntTask, name: str) -> None:
        sub = self._hunter(task, name)
        sub.status = "running"
        sub.started_at = _now()
        sub.error = ""
        self._rewrite(task)

    def mark_hunt_done(self, task: HuntTask, name: str, findings_count: int) -> None:
        sub = self._hunter(task, name)
        sub.status = "done"
        sub.finished_at = _now()
        sub.findings_count = findings_count
        self._rewrite(task)

    def mark_hunt_failed(self, task: HuntTask, name: str, error: str) -> None:
        sub = self._hunter(task, name)
        sub.status = "failed"
        sub.finished_at = _now()
        sub.error = error
        self._rewrite(task)

    def reset_failed(self) -> int:
        """Reset failed file tasks AND failed sub-tasks back to pending."""
        q = self.load()
        count = 0
        for t in q.tasks:
            if t.status == "failed":
                t.status = "pending"
                t.error = ""
                count += 1
            for hunt_sub in t.hunters:
                if hunt_sub.status == "failed":
                    hunt_sub.status = "pending"
                    hunt_sub.error = ""
            for review_sub in t.reviews:
                if review_sub.status == "failed":
                    review_sub.status = "pending"
                    review_sub.error = ""
        self.save(q)
        return count

    def persist(self, task: HuntTask) -> None:
        """Public wrapper around _rewrite — call after mutating sub-tasks in-place."""
        self._rewrite(task)

    def _hunter(self, task: HuntTask, name: str) -> HuntSubTask:
        for sub in task.hunters:
            if sub.name == name:
                return sub
        sub = HuntSubTask(name=name)
        task.hunters.append(sub)
        return sub

    def _write_task_json(self, task: HuntTask) -> None:
        path = self.task_dir(task) / "task.json"
        path.write_text(json.dumps(asdict(task), indent=2, ensure_ascii=False))

    def _rewrite(self, updated: HuntTask) -> None:
        q = self.load()
        for i, t in enumerate(q.tasks):
            if t.file == updated.file:
                q.tasks[i] = updated
                break
        self.save(q)


# ----- helpers -----

def _task_from(d: dict) -> HuntTask:
    return HuntTask(
        file=d["file"],
        hash=d["hash"],
        status=d.get("status", "pending"),
        started_at=d.get("started_at", ""),
        finished_at=d.get("finished_at", ""),
        error=d.get("error", ""),
        hunters=[_subtask_from(s) for s in d.get("hunters", [])],
        cluster_status=d.get("cluster_status", "skipped"),
        reviews=[ReviewSubTask(**s) for s in d.get("reviews", [])],
    )


def _subtask_from(d: dict) -> HuntSubTask:
    # Older runs stored 'category'; new runs use 'name'. Read either.
    return HuntSubTask(
        name=d.get("name") or d.get("category", ""),
        status=d.get("status", "pending"),
        findings_count=d.get("findings_count", 0),
        started_at=d.get("started_at", ""),
        finished_at=d.get("finished_at", ""),
        error=d.get("error", ""),
    )


def _task_dirname(path: str) -> str:
    """Build a readable, filesystem-safe dir name: <time>_<slug>_<hash6>."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    slug = _slugify(path)[:40]
    h = hashlib.sha1(path.encode()).hexdigest()[:6]
    return f"{ts}_{slug}_{h}"


def _slugify(path: str) -> str:
    parts = path.replace("\\", "/").split("/")
    tail = "_".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
    s = re.sub(r"[^A-Za-z0-9]+", "_", tail).strip("_")
    return s or "file"


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")
