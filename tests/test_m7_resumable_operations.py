from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.factories import HASH_B, candidate
from tests.test_reproducer import _prepared_candidate
from vulnhunt_agent.domain.schemas import RunRecord
from vulnhunt_agent.domain.states import FindingState, StateTransitionError
from vulnhunt_agent.infrastructure.sqlite_repository import (
    SqliteRepository,
    TaskLeaseLostError,
)
from vulnhunt_agent.interfaces.cli import main as cli_main
from vulnhunt_agent.reproduction.service import (
    ReproductionStatus,
    ReproducerService,
)
from vulnhunt_agent.sandbox.base import ExecResult, SandboxExecution, SandboxJob


def test_v1_database_migrates_tasks_in_place(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE runs (
            run_id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE TABLE tasks (
            task_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
            task_type TEXT NOT NULL,
            task_key TEXT NOT NULL,
            status TEXT NOT NULL,
            attempt INTEGER NOT NULL DEFAULT 1,
            payload_json TEXT NOT NULL,
            UNIQUE(run_id, task_type, task_key)
        );
        PRAGMA user_version=1;
        """
    )
    run = RunRecord(run_id="run-legacy")
    connection.execute(
        "INSERT INTO runs(run_id, state, payload_json) VALUES (?, ?, ?)",
        (run.run_id, run.state.value, run.model_dump_json()),
    )
    connection.execute(
        """
        INSERT INTO tasks(run_id, task_type, task_key, status, payload_json)
        VALUES ('run-legacy', 'hunter', 'target.c', 'pending', '{}')
        """
    )
    connection.commit()
    connection.close()

    with SqliteRepository(path, read_only=True) as legacy_reader:
        legacy_task = legacy_reader.list_tasks("run-legacy")[0]
        assert legacy_task["lease_owner"] is None

    with SqliteRepository(path) as repository:
        assert repository.schema_version() == 3
        task = repository.list_tasks("run-legacy")[0]
        assert task["task_key"] == "target.c"
        assert task["lease_owner"] is None
        lease = repository.acquire_task_lease(
            "run-legacy",
            "hunter",
            "target.c",
            worker_id="worker-after-migration",
        )
        assert lease is not None

    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version=99")
    connection.close()
    with pytest.raises(RuntimeError, match="newer than supported"):
        SqliteRepository(path)
    with pytest.raises(RuntimeError, match="newer than supported"):
        SqliteRepository(path, read_only=True)


def test_task_lease_is_atomic_heartbeat_guarded_and_fenced(tmp_path: Path) -> None:
    now = datetime(2026, 7, 20, 6, 0, tzinfo=UTC)
    path = tmp_path / "state.db"
    with (
        SqliteRepository(path) as repository,
        SqliteRepository(path) as contender,
    ):
        repository.save_run(RunRecord(run_id="run-1"))
        repository.ensure_task(
            "run-1", "hunter", "target.c", payload={"path": "target.c"}
        )

        first = repository.acquire_task_lease(
            "run-1",
            "hunter",
            "target.c",
            worker_id="worker-a",
            lease_seconds=30,
            now=now,
        )
        assert first is not None
        assert contender.acquire_task_lease(
            "run-1",
            "hunter",
            "target.c",
            worker_id="worker-b",
            lease_seconds=30,
            now=now + timedelta(seconds=5),
        ) is None
        visible = repository.list_tasks("run-1")[0]
        assert visible["lease_owner"] == "worker-a"
        assert "lease_token" not in visible

        first = repository.heartbeat_task_lease(
            first,
            lease_seconds=30,
            now=now + timedelta(seconds=10),
        )
        assert first.expires_at == now + timedelta(seconds=40)
        forged = first.model_copy(update={"lease_token": "x" * 32})
        with pytest.raises(TaskLeaseLostError):
            repository.finish_task_lease(
                forged,
                status="done",
                now=now + timedelta(seconds=11),
            )

        second = contender.acquire_task_lease(
            "run-1",
            "hunter",
            "target.c",
            worker_id="worker-b",
            lease_seconds=30,
            now=now + timedelta(seconds=41),
        )
        assert second is not None
        assert second.attempt == 2
        with pytest.raises(TaskLeaseLostError):
            repository.finish_task_lease(
                first,
                status="done",
                now=now + timedelta(seconds=42),
            )
        contender.finish_task_lease(
            second,
            status="done",
            now=now + timedelta(seconds=42),
        )
        finished = repository.list_tasks("run-1")[0]
        assert finished["status"] == "done"
        assert finished["completed_at"] is not None


def test_recover_requeues_expired_leases_and_caps_attempts(
    tmp_path: Path,
    capsys,
) -> None:
    old = datetime(2000, 1, 1, tzinfo=UTC)
    path = tmp_path / "state.db"
    with SqliteRepository(path) as repository:
        repository.save_run(RunRecord(run_id="run-1"))
        repository.ensure_task("run-1", "hunter", "target.c")
        lease = repository.acquire_task_lease(
            "run-1",
            "hunter",
            "target.c",
            worker_id="dead-worker",
            lease_seconds=1,
            now=old,
        )
        assert lease is not None

    assert cli_main([
        "--db",
        str(path),
        "recover",
        "run-1",
        "--max-attempts",
        "3",
    ]) == 0
    recovered = json.loads(capsys.readouterr().out)
    assert recovered["requeued"] == ["hunter:target.c"]

    with SqliteRepository(path) as repository:
        task = repository.list_tasks("run-1")[0]
        assert task["status"] == "pending"
        assert task["attempt"] == 2
        repository.acquire_task_lease(
            "run-1",
            "hunter",
            "target.c",
            worker_id="dead-again",
            lease_seconds=1,
            now=old,
        )
        exhausted = repository.reclaim_expired_tasks(
            "run-1",
            max_attempts=2,
            now=old + timedelta(seconds=2),
        )
        assert exhausted["failed"] == ["hunter:target.c"]
        assert repository.list_tasks("run-1")[0]["status"] == "failed"

    assert cli_main([
        "--db", str(path), "tasks", "run-1", "--status", "failed"
    ]) == 0
    tasks = json.loads(capsys.readouterr().out)
    assert len(tasks) == 1
    assert tasks[0]["last_error"] == "worker lease expired; attempts exhausted"


def test_task_finish_and_finding_transition_are_one_transaction(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 7, 20, 6, 0, tzinfo=UTC)
    with SqliteRepository(tmp_path / "state.db") as repository:
        repository.save_run(RunRecord(run_id="run-1"))
        repository.save_candidate(candidate())
        repository.ensure_task("run-1", "hunter", "target.c")
        lease = repository.acquire_task_lease(
            "run-1",
            "hunter",
            "target.c",
            worker_id="worker-a",
            now=now,
        )
        assert lease is not None

        with pytest.raises(StateTransitionError):
            repository.finish_task_lease_and_transition_finding(
                lease,
                status="done",
                candidate_id="cand-1",
                target=FindingState.REPORTABLE,
                idempotency_key="invalid",
                reason="must roll back",
                now=now + timedelta(seconds=1),
            )
        assert repository.list_tasks("run-1")[0]["status"] == "running"
        finding = repository.get_candidate("cand-1")
        assert finding is not None
        assert finding.state is FindingState.HYPOTHESIS

        repository.finish_task_lease_and_transition_finding(
            lease,
            status="done",
            candidate_id="cand-1",
            target=FindingState.STATICALLY_SUPPORTED,
            idempotency_key="valid",
            reason="atomic promotion",
            now=now + timedelta(seconds=1),
        )
        assert repository.list_tasks("run-1")[0]["status"] == "done"
        finding = repository.get_candidate("cand-1")
        assert finding is not None
        assert finding.state is FindingState.STATICALLY_SUPPORTED


class WorkerCrash(BaseException):
    pass


class MutableClock:
    def __init__(self, value: datetime):
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class CrashAfterFirstAttempt:
    def __init__(self) -> None:
        self.calls = 0

    async def execute(self, job: SandboxJob) -> SandboxExecution:
        self.calls += 1
        if self.calls == 2:
            raise WorkerCrash()
        return _passing_execution()


class PassingBackend:
    def __init__(self) -> None:
        self.jobs: list[SandboxJob] = []

    async def execute(self, job: SandboxJob) -> SandboxExecution:
        self.jobs.append(job)
        return _passing_execution()


async def test_reproducer_resumes_partial_evidence_after_worker_lease_expires(
    tmp_path: Path,
) -> None:
    repository, artifacts, spec = _prepared_candidate(tmp_path)
    clock = MutableClock(datetime(2026, 7, 20, 6, 0, tzinfo=UTC))
    crashed = CrashAfterFirstAttempt()
    first = ReproducerService(
        repository,
        artifacts,
        crashed,
        worker_id="worker-a",
        lease_seconds=60,
        clock=clock,
    )

    with pytest.raises(WorkerCrash):
        await first.reproduce(spec)

    assert len(repository.list_evidence("run-1")) == 1
    task = repository.list_tasks("run-1")[0]
    assert task["status"] == "running"
    assert task["attempt"] == 1

    blocked_backend = PassingBackend()
    blocked = await ReproducerService(
        repository,
        artifacts,
        blocked_backend,
        worker_id="worker-b",
        lease_seconds=60,
        clock=clock,
    ).reproduce(spec)
    assert blocked.status is ReproductionStatus.IN_PROGRESS
    assert blocked_backend.jobs == []

    clock.value += timedelta(seconds=121)
    resumed_backend = PassingBackend()
    resumed = await ReproducerService(
        repository,
        artifacts,
        resumed_backend,
        worker_id="worker-b",
        lease_seconds=60,
        clock=clock,
    ).reproduce(spec)

    assert resumed.status is ReproductionStatus.REPRODUCED
    assert len(resumed.evidence) == 2
    assert len(resumed_backend.jobs) == 1
    completed = repository.list_tasks("run-1")[0]
    assert completed["status"] == "reproduced"
    assert completed["attempt"] == 2
    repository.close()


def _passing_execution() -> SandboxExecution:
    return SandboxExecution(
        image_digest=HASH_B,
        result=ExecResult(
            exit_code=0,
            stdout="LEAKED_SECRET=1",
            stderr="",
            duration_ms=10,
        ),
    )
