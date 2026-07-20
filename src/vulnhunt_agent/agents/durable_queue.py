"""SQLite-leased Hunter queue for M8 slice work.

The legacy ``_queue.json`` store remains available for old runs. New work uses
the V2 task table as the status/attempt/lease authority and writes only
per-work artifact metadata below ``hunters/<work_id>/``.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..domain.schemas import HunterWorkItem, TaskLease
from ..infrastructure.sqlite_repository import (
    RepositoryConflictError,
    SqliteRepository,
)
from .queue import HuntQueue, HuntQueueStore, HuntSubTask, HuntTask, _task_from


class DurableHuntQueueStore(HuntQueueStore):
    def __init__(self, root: Path, database: Path, run_id: str):
        super().__init__(root)
        self.database = database
        self.run_id = run_id

    def init_from_work_items(
        self,
        work_items: tuple[HunterWorkItem, ...],
    ) -> HuntQueue:
        with SqliteRepository(self.database) as repository:
            for item in work_items:
                payload = item.model_dump(mode="json")
                created = repository.ensure_task(
                    self.run_id,
                    "hunter",
                    item.work_id,
                    payload=payload,
                )
                if created:
                    continue
                existing = next(
                    task for task in repository.list_tasks(self.run_id)
                    if task["task_type"] == "hunter"
                    and task["task_key"] == item.work_id
                )
                if existing["payload"] != payload:
                    raise RepositoryConflictError(
                        f"Hunter work ID is already bound to different input: {item.work_id}"
                    )
        return self.load()

    def has_durable_tasks(self) -> bool:
        if not self.database.exists():
            return False
        try:
            with SqliteRepository(self.database, read_only=True) as repository:
                return any(
                    task["task_type"] == "hunter"
                    and task["payload"].get("work_id")
                    for task in repository.list_tasks(self.run_id)
                )
        except Exception:
            return False

    def load(self) -> HuntQueue:
        if not self.database.exists():
            return HuntQueue()
        with SqliteRepository(self.database, read_only=True) as repository:
            rows = [
                task for task in repository.list_tasks(self.run_id)
                if task["task_type"] == "hunter"
                and task["payload"].get("work_id")
            ]
        return HuntQueue(tasks=[
            self._task_from_row(row)
            for row in rows
        ])

    def save(self, queue: HuntQueue) -> None:
        for task in queue.tasks:
            self._write_task_json(task)

    def task_dir(self, task: HuntTask) -> Path:
        identity = task.work_id or task.hash
        directory = self.root / identity
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def acquire(
        self,
        task: HuntTask,
        *,
        worker_id: str,
        lease_seconds: int,
        max_attempts: int,
    ) -> TaskLease | None:
        with SqliteRepository(self.database) as repository:
            return repository.acquire_task_lease(
                self.run_id,
                "hunter",
                task.work_id,
                worker_id=worker_id,
                lease_seconds=lease_seconds,
                max_attempts=max_attempts,
            )

    def heartbeat(
        self,
        lease: TaskLease,
        *,
        lease_seconds: int,
    ) -> None:
        with SqliteRepository(self.database) as repository:
            repository.heartbeat_task_lease(
                lease,
                lease_seconds=lease_seconds,
            )

    def finish(
        self,
        lease: TaskLease,
        *,
        status: str,
        error: str = "",
    ) -> None:
        with SqliteRepository(self.database) as repository:
            repository.finish_task_lease(
                lease,
                status=status,
                error=error,
            )

    def reset_failed(self) -> int:
        count = 0
        with SqliteRepository(self.database) as repository:
            for task in repository.list_tasks(self.run_id):
                if (
                    task["task_type"] == "hunter"
                    and task["payload"].get("work_id")
                    and task["status"] == "failed"
                ):
                    repository.set_task_status(
                        self.run_id,
                        "hunter",
                        task["task_key"],
                        "pending",
                    )
                    count += 1
        return count

    def _rewrite(self, updated: HuntTask) -> None:
        self._write_task_json(updated)

    def _task_from_row(self, row: dict) -> HuntTask:
        item = HunterWorkItem.model_validate(row["payload"])
        local_path = self.root / item.work_id / "task.json"
        if local_path.exists():
            task = _task_from(json.loads(local_path.read_text()))
        else:
            task = HuntTask(
                file=item.seed_file,
                hash=item.work_id,
                work_id=item.work_id,
                files=list(item.files),
                slice_ids=list(item.slice_ids),
                risk=item.risk,
                required=item.required,
                hunters=[HuntSubTask(name=item.hunter)],
            )
        task.status = _task_phase(str(row["status"]), task.status)
        if row["status"] in {"done", "failed"}:
            task.finished_at = str(row.get("completed_at") or task.finished_at)
        if row["status"] == "failed":
            task.error = str(row.get("last_error") or task.error)
            for subtask in task.hunters:
                if subtask.status != "done":
                    subtask.status = "failed"
                    subtask.error = task.error
        return task


def _task_phase(status: str, local: str) -> str:
    if status == "pending":
        return "pending"
    if status == "running":
        return local if local in {"hunting", "clustering", "reviewing"} else "hunting"
    if status == "done":
        return "done"
    if status == "failed":
        return "failed"
    return status
