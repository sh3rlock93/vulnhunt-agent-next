"""SQLite WAL repository for validated V2 domain objects."""
from __future__ import annotations

import json
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Iterator

from ..domain.schemas import (
    ArtifactRef,
    BudgetUsage,
    CandidateFinding,
    CandidateResolution,
    FeasibilityAssessment,
    Evidence,
    PocSpec,
    ReviewVerdict,
    RunRecord,
    TaskLease,
)
from ..domain.states import (
    FindingState,
    RunState,
    StateTransitionError,
    require_finding_transition,
    require_run_transition,
)


class RepositoryConflictError(RuntimeError):
    """An idempotency key or stable object ID was reused for different data."""


class TaskLeaseLostError(RuntimeError):
    """A worker attempted to mutate a task after losing its lease."""


_SCHEMA_VERSION = 3
_TASK_LEASE_COLUMNS = {
    "lease_owner": "TEXT",
    "lease_token": "TEXT",
    "lease_acquired_at": "TEXT",
    "heartbeat_at": "TEXT",
    "lease_expires_at": "TEXT",
    "last_error": "TEXT",
    "completed_at": "TEXT",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    task_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    task_type TEXT NOT NULL,
    task_key TEXT NOT NULL,
    status TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 1,
    payload_json TEXT NOT NULL,
    lease_owner TEXT,
    lease_token TEXT,
    lease_acquired_at TEXT,
    heartbeat_at TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    completed_at TEXT,
    UNIQUE(run_id, task_type, task_key)
);
CREATE TABLE IF NOT EXISTS findings (
    candidate_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    task_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    UNIQUE(run_id, task_key, fingerprint)
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
    candidate_id TEXT NOT NULL REFERENCES findings(candidate_id) ON DELETE CASCADE,
    reviewer TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY(candidate_id, reviewer)
);
CREATE TABLE IF NOT EXISTS artifacts (
    digest TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    media_type TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transitions (
    transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(entity_type, entity_id, idempotency_key)
);
CREATE TABLE IF NOT EXISTS legacy_imports (
    run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
    source_path TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    imported_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS work_usage (
    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    work_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY(run_id, work_id, scope)
);
CREATE INDEX IF NOT EXISTS findings_run_state ON findings(run_id, state);
CREATE INDEX IF NOT EXISTS tasks_run_status ON tasks(run_id, status);
CREATE INDEX IF NOT EXISTS work_usage_run_scope ON work_usage(run_id, scope);
"""


class SqliteRepository:
    def __init__(self, path: Path, *, read_only: bool = False):
        self.path = path.resolve()
        self.read_only = read_only
        if read_only:
            uri = f"file:{self.path}?mode=ro"
            self.connection = sqlite3.connect(uri, uri=True, isolation_level=None)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.connection = sqlite3.connect(self.path, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA busy_timeout=5000")
        if read_only:
            version = self.schema_version()
            if version > _SCHEMA_VERSION:
                self.connection.close()
                raise RuntimeError(
                    f"database schema {version} is newer than supported {_SCHEMA_VERSION}"
                )
        else:
            mode = self.connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).casefold() != "wal":
                self.connection.close()
                raise RuntimeError("SQLite WAL mode is required")
            version = self.schema_version()
            if version > _SCHEMA_VERSION:
                self.connection.close()
                raise RuntimeError(
                    f"database schema {version} is newer than supported {_SCHEMA_VERSION}"
                )
            try:
                self.connection.executescript(_SCHEMA)
                self._migrate_schema()
            except BaseException:
                self.connection.close()
                raise

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "SqliteRepository":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def save_run(self, run: RunRecord) -> RunRecord:
        run = RunRecord.model_validate(run)
        existing = self.get_run(run.run_id)
        if existing is not None:
            if existing != run:
                raise RepositoryConflictError(f"run ID already stores different data: {run.run_id}")
            return existing
        if run.state is not RunState.CREATED:
            raise StateTransitionError("new runs must be stored in the created state")
        self.connection.execute(
            "INSERT INTO runs(run_id, state, payload_json) VALUES (?, ?, ?)",
            (run.run_id, run.state.value, _dump(run)),
        )
        return run

    def get_run(self, run_id: str) -> RunRecord | None:
        row = self.connection.execute(
            "SELECT payload_json FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return RunRecord.model_validate_json(row["payload_json"]) if row else None

    def list_runs(self) -> list[RunRecord]:
        rows = self.connection.execute(
            "SELECT payload_json FROM runs ORDER BY run_id DESC"
        ).fetchall()
        return [RunRecord.model_validate_json(row["payload_json"]) for row in rows]

    def transition_run(
        self,
        run_id: str,
        target: RunState,
        *,
        idempotency_key: str,
        reason: str = "",
    ) -> RunRecord:
        with self._write_transaction():
            replay = self._transition_replay("run", run_id, idempotency_key, target.value)
            if replay:
                run = self._required_run(run_id)
                return run
            run = self._required_run(run_id)
            require_run_transition(run.state, target)
            updated = run.model_copy(
                update={"state": target, "updated_at": datetime.now(UTC)}
            )
            self.connection.execute(
                "UPDATE runs SET state = ?, payload_json = ? WHERE run_id = ?",
                (target.value, _dump(updated), run_id),
            )
            self._record_transition(
                "run", run_id, idempotency_key, run.state.value, target.value, reason
            )
            return updated

    def attach_run_snapshot(self, run_id: str, digest: str) -> RunRecord:
        with self._write_transaction():
            run = self._required_run(run_id)
            validated = RunRecord.model_validate(
                run.model_copy(update={"source_snapshot": digest})
            )
            if run.source_snapshot is not None:
                if run.source_snapshot != validated.source_snapshot:
                    raise RepositoryConflictError("run snapshot is immutable once attached")
                return run
            if run.state is not RunState.SNAPSHOTTING:
                raise StateTransitionError("run snapshot may only attach while snapshotting")
            updated = validated.model_copy(update={"updated_at": datetime.now(UTC)})
            self.connection.execute(
                "UPDATE runs SET payload_json = ? WHERE run_id = ?",
                (_dump(updated), run_id),
            )
            return updated

    def ensure_task(
        self,
        run_id: str,
        task_type: str,
        task_key: str,
        *,
        status: str = "pending",
        attempt: int = 1,
        payload: dict | None = None,
    ) -> bool:
        self._required_run(run_id)
        cursor = self.connection.execute(
            """
            INSERT INTO tasks(run_id, task_type, task_key, status, attempt, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id, task_type, task_key) DO NOTHING
            """,
            (run_id, task_type, task_key, status, attempt, _dump_json(payload or {})),
        )
        return cursor.rowcount == 1

    def list_tasks(self, run_id: str) -> list[dict]:
        lease_columns = (
            """
            lease_owner, heartbeat_at, lease_expires_at, last_error, completed_at
            """
            if self._task_lease_schema_available()
            else
            """
            NULL AS lease_owner, NULL AS heartbeat_at, NULL AS lease_expires_at,
            NULL AS last_error, NULL AS completed_at
            """
        )
        rows = self.connection.execute(
            f"""
            SELECT task_type, task_key, status, attempt, payload_json,
                   {lease_columns}
            FROM tasks WHERE run_id = ? ORDER BY task_type, task_key
            """,
            (run_id,),
        ).fetchall()
        return [
            {
                "task_type": row["task_type"],
                "task_key": row["task_key"],
                "status": row["status"],
                "attempt": row["attempt"],
                "payload": json.loads(row["payload_json"]),
                "lease_owner": row["lease_owner"],
                "heartbeat_at": row["heartbeat_at"],
                "lease_expires_at": row["lease_expires_at"],
                "last_error": row["last_error"],
                "completed_at": row["completed_at"],
            }
            for row in rows
        ]

    def acquire_task_lease(
        self,
        run_id: str,
        task_type: str,
        task_key: str,
        *,
        worker_id: str,
        lease_seconds: int = 60,
        max_attempts: int = 3,
        now: datetime | None = None,
    ) -> TaskLease | None:
        if not worker_id.strip():
            raise ValueError("worker_id must be non-empty")
        _validate_lease_policy(lease_seconds, max_attempts)
        current = _as_utc(now)
        with self._write_transaction():
            row = self._required_task_row(run_id, task_type, task_key)
            attempt = int(row["attempt"])
            if row["status"] == "running":
                expires_at = _parse_timestamp(row["lease_expires_at"])
                if expires_at is not None and expires_at > current:
                    return None
                if attempt >= max_attempts:
                    self._mark_task_attempts_exhausted(
                        run_id, task_type, task_key, current
                    )
                    return None
                attempt += 1
            elif row["status"] != "pending":
                return None

            token = secrets.token_urlsafe(24)
            expires_at = current + timedelta(seconds=lease_seconds)
            self.connection.execute(
                """
                UPDATE tasks
                SET status = 'running', attempt = ?, lease_owner = ?,
                    lease_token = ?, lease_acquired_at = ?, heartbeat_at = ?,
                    lease_expires_at = ?, last_error = NULL, completed_at = NULL
                WHERE run_id = ? AND task_type = ? AND task_key = ?
                """,
                (
                    attempt,
                    worker_id,
                    token,
                    current.isoformat(),
                    current.isoformat(),
                    expires_at.isoformat(),
                    run_id,
                    task_type,
                    task_key,
                ),
            )
            return TaskLease(
                run_id=run_id,
                task_type=task_type,
                task_key=task_key,
                worker_id=worker_id,
                lease_token=token,
                attempt=attempt,
                acquired_at=current,
                heartbeat_at=current,
                expires_at=expires_at,
                payload=json.loads(row["payload_json"]),
            )

    def heartbeat_task_lease(
        self,
        lease: TaskLease,
        *,
        lease_seconds: int = 60,
        now: datetime | None = None,
    ) -> TaskLease:
        lease = TaskLease.model_validate(lease)
        _validate_lease_seconds(lease_seconds)
        current = _as_utc(now)
        expires_at = current + timedelta(seconds=lease_seconds)
        with self._write_transaction():
            row = self._required_task_row(
                lease.run_id, lease.task_type, lease.task_key
            )
            self._require_live_lease(row, lease, current)
            self.connection.execute(
                """
                UPDATE tasks SET heartbeat_at = ?, lease_expires_at = ?
                WHERE run_id = ? AND task_type = ? AND task_key = ?
                """,
                (
                    current.isoformat(),
                    expires_at.isoformat(),
                    lease.run_id,
                    lease.task_type,
                    lease.task_key,
                ),
            )
        return lease.model_copy(update={
            "heartbeat_at": current,
            "expires_at": expires_at,
        })

    def finish_task_lease(
        self,
        lease: TaskLease,
        *,
        status: str,
        error: str = "",
        now: datetime | None = None,
    ) -> None:
        lease = TaskLease.model_validate(lease)
        _validate_terminal_status(status)
        current = _as_utc(now)
        with self._write_transaction():
            row = self._required_task_row(
                lease.run_id, lease.task_type, lease.task_key
            )
            self._require_live_lease(row, lease, current)
            self._finish_task_lease_locked(
                lease,
                status=status,
                error=error,
                current=current,
            )

    def finish_task_lease_and_transition_finding(
        self,
        lease: TaskLease,
        *,
        status: str,
        candidate_id: str,
        target: FindingState,
        idempotency_key: str,
        reason: str,
        error: str = "",
        now: datetime | None = None,
    ) -> CandidateFinding:
        lease = TaskLease.model_validate(lease)
        _validate_terminal_status(status)
        current = _as_utc(now)
        with self._write_transaction():
            row = self._required_task_row(
                lease.run_id, lease.task_type, lease.task_key
            )
            self._require_live_lease(row, lease, current)
            finding = self._required_candidate(candidate_id)
            if finding.run_id != lease.run_id:
                raise ValueError("task lease and candidate belong to different runs")
            updated = self._transition_finding_locked(
                candidate_id,
                target,
                idempotency_key=idempotency_key,
                reason=reason,
            )
            self._finish_task_lease_locked(
                lease,
                status=status,
                error=error,
                current=current,
            )
            return updated

    def reclaim_expired_tasks(
        self,
        run_id: str,
        *,
        max_attempts: int = 3,
        now: datetime | None = None,
    ) -> dict[str, object]:
        _validate_max_attempts(max_attempts)
        current = _as_utc(now)
        requeued: list[str] = []
        failed: list[str] = []
        with self._write_transaction():
            self._required_run(run_id)
            rows = self.connection.execute(
                """
                SELECT task_type, task_key, attempt, lease_expires_at
                FROM tasks
                WHERE run_id = ? AND status = 'running'
                ORDER BY task_type, task_key
                """,
                (run_id,),
            ).fetchall()
            for row in rows:
                expires_at = _parse_timestamp(row["lease_expires_at"])
                if expires_at is not None and expires_at > current:
                    continue
                identity = f"{row['task_type']}:{row['task_key']}"
                if int(row["attempt"]) >= max_attempts:
                    self._mark_task_attempts_exhausted(
                        run_id, row["task_type"], row["task_key"], current
                    )
                    failed.append(identity)
                    continue
                self.connection.execute(
                    """
                    UPDATE tasks
                    SET status = 'pending', attempt = attempt + 1,
                        lease_owner = NULL, lease_token = NULL,
                        lease_acquired_at = NULL, heartbeat_at = NULL,
                        lease_expires_at = NULL,
                        last_error = 'worker lease expired', completed_at = NULL
                    WHERE run_id = ? AND task_type = ? AND task_key = ?
                    """,
                    (run_id, row["task_type"], row["task_key"]),
                )
                requeued.append(identity)
        return {
            "run_id": run_id,
            "requeued": requeued,
            "failed": failed,
        }

    def set_task_status(
        self, run_id: str, task_type: str, task_key: str, status: str
    ) -> None:
        cursor = self.connection.execute(
            """
            UPDATE tasks SET status = ?
            WHERE run_id = ? AND task_type = ? AND task_key = ?
              AND lease_token IS NULL
            """,
            (status, run_id, task_type, task_key),
        )
        if cursor.rowcount != 1:
            raise KeyError(
                f"unknown or actively leased task: {run_id}/{task_type}/{task_key}"
            )

    def defer_task_for_budget(
        self,
        run_id: str,
        task_type: str,
        task_key: str,
        *,
        reason: str,
        now: datetime | None = None,
    ) -> None:
        """Finish pending, unleased work without consuming an execution attempt."""
        if not reason.strip():
            raise ValueError("budget deferral reason must be non-empty")
        current = _as_utc(now)
        cursor = self.connection.execute(
            """
            UPDATE tasks
            SET status = 'budget_deferred', last_error = ?, completed_at = ?
            WHERE run_id = ? AND task_type = ? AND task_key = ?
              AND status = 'pending' AND lease_token IS NULL
            """,
            (
                reason[:2000],
                current.isoformat(),
                run_id,
                task_type,
                task_key,
            ),
        )
        if cursor.rowcount != 1:
            raise KeyError(
                "unknown, active, or non-pending task: "
                f"{run_id}/{task_type}/{task_key}"
            )

    def requeue_budget_deferred_task(
        self,
        run_id: str,
        task_type: str,
        task_key: str,
    ) -> None:
        """Return an unstarted budget deferral to pending without adding an attempt."""
        cursor = self.connection.execute(
            """
            UPDATE tasks
            SET status = 'pending', last_error = NULL, completed_at = NULL
            WHERE run_id = ? AND task_type = ? AND task_key = ?
              AND status = 'budget_deferred' AND lease_token IS NULL
            """,
            (run_id, task_type, task_key),
        )
        if cursor.rowcount != 1:
            raise KeyError(
                "unknown, active, or non-deferred task: "
                f"{run_id}/{task_type}/{task_key}"
            )

    def save_budget_usage(self, usage: BudgetUsage) -> BudgetUsage:
        usage = BudgetUsage.model_validate(usage)
        self._required_run(usage.run_id)
        payload = _dump(usage)
        row = self.connection.execute(
            """
            SELECT payload_json FROM work_usage
            WHERE run_id = ? AND work_id = ? AND scope = ?
            """,
            (usage.run_id, usage.work_id, usage.scope),
        ).fetchone()
        if row:
            existing = BudgetUsage.model_validate_json(row["payload_json"])
            if existing != usage:
                raise RepositoryConflictError(
                    "work usage is immutable once recorded: "
                    f"{usage.run_id}/{usage.work_id}/{usage.scope}"
                )
            return existing
        self.connection.execute(
            """
            INSERT INTO work_usage(run_id, work_id, scope, payload_json)
            VALUES (?, ?, ?, ?)
            """,
            (usage.run_id, usage.work_id, usage.scope, payload),
        )
        return usage

    def list_budget_usage(
        self,
        run_id: str,
        *,
        scope: str | None = None,
    ) -> list[BudgetUsage]:
        if not self._table_available("work_usage"):
            return []
        if scope is None:
            rows = self.connection.execute(
                """
                SELECT payload_json FROM work_usage
                WHERE run_id = ? ORDER BY scope, work_id
                """,
                (run_id,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT payload_json FROM work_usage
                WHERE run_id = ? AND scope = ? ORDER BY work_id
                """,
                (run_id, scope),
            ).fetchall()
        return [
            BudgetUsage.model_validate_json(row["payload_json"])
            for row in rows
        ]

    def save_candidate(self, finding: CandidateFinding) -> tuple[CandidateFinding, bool]:
        finding = CandidateFinding.model_validate(finding)
        self._required_run(finding.run_id)
        row = self.connection.execute(
            "SELECT payload_json FROM findings WHERE candidate_id = ?",
            (finding.candidate_id,),
        ).fetchone()
        if row:
            existing = CandidateFinding.model_validate_json(row["payload_json"])
            if _candidate_seed(existing) != _candidate_seed(finding):
                raise RepositoryConflictError(
                    f"candidate ID already stores different data: {finding.candidate_id}"
                )
            return existing, False
        duplicate = self.connection.execute(
            """
            SELECT payload_json FROM findings
            WHERE run_id = ? AND task_key = ? AND fingerprint = ?
            """,
            (finding.run_id, finding.task_key, finding.fingerprint),
        ).fetchone()
        if duplicate:
            return CandidateFinding.model_validate_json(duplicate["payload_json"]), False
        if finding.state is not FindingState.HYPOTHESIS:
            raise StateTransitionError("new candidates must be stored in the hypothesis state")
        self.connection.execute(
            """
            INSERT INTO findings(candidate_id, run_id, task_key, fingerprint, state, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                finding.candidate_id,
                finding.run_id,
                finding.task_key,
                finding.fingerprint,
                finding.state.value,
                _dump(finding),
            ),
        )
        return finding, True

    def get_candidate(self, candidate_id: str) -> CandidateFinding | None:
        row = self.connection.execute(
            "SELECT payload_json FROM findings WHERE candidate_id = ?", (candidate_id,)
        ).fetchone()
        return CandidateFinding.model_validate_json(row["payload_json"]) if row else None

    def list_candidates(
        self, run_id: str, state: FindingState | None = None
    ) -> list[CandidateFinding]:
        if state is None:
            rows = self.connection.execute(
                "SELECT payload_json FROM findings WHERE run_id = ? ORDER BY candidate_id",
                (run_id,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                """
                SELECT payload_json FROM findings
                WHERE run_id = ? AND state = ? ORDER BY candidate_id
                """,
                (run_id, state.value),
            ).fetchall()
        return [CandidateFinding.model_validate_json(row["payload_json"]) for row in rows]

    def transition_finding(
        self,
        candidate_id: str,
        target: FindingState,
        *,
        idempotency_key: str,
        reason: str = "",
    ) -> CandidateFinding:
        with self._write_transaction():
            return self._transition_finding_locked(
                candidate_id,
                target,
                idempotency_key=idempotency_key,
                reason=reason,
            )

    def attach_candidate_poc(self, candidate_id: str, poc: PocSpec) -> CandidateFinding:
        poc = PocSpec.model_validate(poc)
        if self.get_artifact(poc.artifact) is None:
            raise KeyError(f"unknown PoC artifact: {poc.artifact}")
        with self._write_transaction():
            finding = self._required_candidate(candidate_id)
            if finding.poc is not None:
                if finding.poc != poc:
                    raise RepositoryConflictError("candidate PoC is immutable once attached")
                return finding
            if finding.state not in {
                FindingState.HYPOTHESIS,
                FindingState.STATICALLY_SUPPORTED,
            }:
                raise StateTransitionError("PoC must attach before poc_ready")
            updated = CandidateFinding.model_validate(
                finding.model_copy(
                    update={"poc": poc, "updated_at": datetime.now(UTC)}
                )
            )
            self.connection.execute(
                "UPDATE findings SET payload_json = ? WHERE candidate_id = ?",
                (_dump(updated), candidate_id),
            )
            return updated

    def attach_candidate_evidence(
        self, candidate_id: str, evidence_ids: tuple[str, ...]
    ) -> CandidateFinding:
        with self._write_transaction():
            finding = self._required_candidate(candidate_id)
            known = {
                item.evidence_id
                for item in self.list_evidence(finding.run_id)
                if item.candidate_id == candidate_id
            }
            missing = sorted(set(evidence_ids) - known)
            if missing:
                raise KeyError("unknown evidence: " + ", ".join(missing))
            merged = tuple(dict.fromkeys((*finding.evidence_ids, *evidence_ids)))
            if merged == finding.evidence_ids:
                return finding
            updated = CandidateFinding.model_validate(
                finding.model_copy(
                    update={"evidence_ids": merged, "updated_at": datetime.now(UTC)}
                )
            )
            self.connection.execute(
                "UPDATE findings SET payload_json = ? WHERE candidate_id = ?",
                (_dump(updated), candidate_id),
            )
            return updated

    def attach_candidate_feasibility(
        self,
        candidate_id: str,
        assessment: FeasibilityAssessment,
    ) -> CandidateFinding:
        assessment = FeasibilityAssessment.model_validate(assessment)
        with self._write_transaction():
            finding = self._required_candidate(candidate_id)
            if assessment.candidate_id != candidate_id:
                raise ValueError("feasibility assessment belongs to another candidate")
            if finding.feasibility is not None:
                if finding.feasibility != assessment:
                    raise RepositoryConflictError(
                        "candidate feasibility is immutable once attached"
                    )
                return finding
            updated = CandidateFinding.model_validate(finding.model_copy(update={
                "feasibility": assessment,
                "updated_at": datetime.now(UTC),
            }))
            self.connection.execute(
                "UPDATE findings SET payload_json = ? WHERE candidate_id = ?",
                (_dump(updated), candidate_id),
            )
            return updated

    def attach_candidate_resolution(
        self,
        candidate_id: str,
        resolution: CandidateResolution,
    ) -> CandidateFinding:
        resolution = CandidateResolution.model_validate(resolution)
        with self._write_transaction():
            finding = self._required_candidate(candidate_id)
            if finding.resolution is not None:
                if finding.resolution != resolution:
                    raise RepositoryConflictError(
                        "candidate resolution is immutable once attached"
                    )
                return finding
            updated = CandidateFinding.model_validate(finding.model_copy(update={
                "resolution": resolution,
                "updated_at": datetime.now(UTC),
            }))
            self.connection.execute(
                "UPDATE findings SET payload_json = ? WHERE candidate_id = ?",
                (_dump(updated), candidate_id),
            )
            return updated

    def save_evidence(self, evidence: Evidence) -> Evidence:
        evidence = Evidence.model_validate(evidence)
        self._required_run(evidence.run_id)
        if evidence.candidate_id is not None:
            candidate = self._required_candidate(evidence.candidate_id)
            if candidate.run_id != evidence.run_id:
                raise ValueError("evidence candidate does not belong to the run")
        row = self.connection.execute(
            "SELECT payload_json FROM evidence WHERE evidence_id = ?",
            (evidence.evidence_id,),
        ).fetchone()
        if row:
            existing = Evidence.model_validate_json(row["payload_json"])
            if existing != evidence:
                raise RepositoryConflictError(
                    f"evidence ID already stores different data: {evidence.evidence_id}"
                )
            return existing
        self.connection.execute(
            "INSERT INTO evidence(evidence_id, run_id, kind, payload_json) VALUES (?, ?, ?, ?)",
            (evidence.evidence_id, evidence.run_id, evidence.kind.value, _dump(evidence)),
        )
        return evidence

    def list_evidence(self, run_id: str) -> list[Evidence]:
        rows = self.connection.execute(
            "SELECT payload_json FROM evidence WHERE run_id = ? ORDER BY evidence_id",
            (run_id,),
        ).fetchall()
        return [Evidence.model_validate_json(row["payload_json"]) for row in rows]

    def list_candidate_evidence(self, candidate_id: str) -> list[Evidence]:
        finding = self._required_candidate(candidate_id)
        return [
            item
            for item in self.list_evidence(finding.run_id)
            if item.candidate_id == candidate_id
        ]

    def save_verdict(self, verdict: ReviewVerdict) -> ReviewVerdict:
        verdict = ReviewVerdict.model_validate(verdict)
        self._required_candidate(verdict.candidate_id)
        payload = _dump(verdict)
        row = self.connection.execute(
            """
            SELECT payload_json FROM reviews WHERE candidate_id = ? AND reviewer = ?
            """,
            (verdict.candidate_id, verdict.reviewer),
        ).fetchone()
        if row and row["payload_json"] != payload:
            raise RepositoryConflictError("reviewer verdict is immutable once recorded")
        self.connection.execute(
            """
            INSERT INTO reviews(candidate_id, reviewer, payload_json) VALUES (?, ?, ?)
            ON CONFLICT(candidate_id, reviewer) DO NOTHING
            """,
            (verdict.candidate_id, verdict.reviewer, payload),
        )
        return verdict

    def list_verdicts(self, candidate_id: str) -> list[ReviewVerdict]:
        rows = self.connection.execute(
            "SELECT payload_json FROM reviews WHERE candidate_id = ? ORDER BY reviewer",
            (candidate_id,),
        ).fetchall()
        return [ReviewVerdict.model_validate_json(row["payload_json"]) for row in rows]

    def register_artifact(self, artifact: ArtifactRef) -> None:
        artifact = ArtifactRef.model_validate(artifact)
        row = self.connection.execute(
            "SELECT size, media_type FROM artifacts WHERE digest = ?", (artifact.digest,)
        ).fetchone()
        if row and (row["size"], row["media_type"]) != (artifact.size, artifact.media_type):
            raise RepositoryConflictError("artifact metadata conflicts with existing digest")
        self.connection.execute(
            """
            INSERT INTO artifacts(digest, size, media_type) VALUES (?, ?, ?)
            ON CONFLICT(digest) DO NOTHING
            """,
            (artifact.digest, artifact.size, artifact.media_type),
        )

    def get_artifact(self, digest: str) -> ArtifactRef | None:
        row = self.connection.execute(
            "SELECT digest, size, media_type FROM artifacts WHERE digest = ?", (digest,)
        ).fetchone()
        if row is None:
            return None
        return ArtifactRef(
            digest=row["digest"], size=row["size"], media_type=row["media_type"]
        )

    def has_legacy_import(self, run_id: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM legacy_imports WHERE run_id = ?", (run_id,)
        ).fetchone()
        return row is not None

    def record_legacy_import(self, run_id: str, source_path: Path, summary: dict) -> None:
        self.connection.execute(
            """
            INSERT INTO legacy_imports(run_id, source_path, summary_json, imported_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(run_id) DO NOTHING
            """,
            (
                run_id,
                str(source_path.resolve()),
                _dump_json(summary),
                datetime.now(UTC).isoformat(),
            ),
        )

    def journal_mode(self) -> str:
        return str(self.connection.execute("PRAGMA journal_mode").fetchone()[0]).casefold()

    def foreign_keys_enabled(self) -> bool:
        return bool(self.connection.execute("PRAGMA foreign_keys").fetchone()[0])

    def schema_version(self) -> int:
        return int(self.connection.execute("PRAGMA user_version").fetchone()[0])

    def _migrate_schema(self) -> None:
        with self._write_transaction():
            version = self.schema_version()
            if version > _SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema {version} is newer than supported {_SCHEMA_VERSION}"
                )
            columns = {
                row["name"]
                for row in self.connection.execute("PRAGMA table_info(tasks)").fetchall()
            }
            for name, declaration in _TASK_LEASE_COLUMNS.items():
                if name not in columns:
                    self.connection.execute(
                        f"ALTER TABLE tasks ADD COLUMN {name} {declaration}"
                    )
            self.connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    def _task_lease_schema_available(self) -> bool:
        columns = {
            row["name"]
            for row in self.connection.execute("PRAGMA table_info(tasks)").fetchall()
        }
        return set(_TASK_LEASE_COLUMNS).issubset(columns)

    def _table_available(self, name: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (name,),
        ).fetchone()
        return row is not None

    def _required_task_row(
        self, run_id: str, task_type: str, task_key: str
    ) -> sqlite3.Row:
        row = self.connection.execute(
            """
            SELECT * FROM tasks
            WHERE run_id = ? AND task_type = ? AND task_key = ?
            """,
            (run_id, task_type, task_key),
        ).fetchone()
        if row is None:
            raise KeyError(f"unknown task: {run_id}/{task_type}/{task_key}")
        return row

    def _require_live_lease(
        self,
        row: sqlite3.Row,
        lease: TaskLease,
        current: datetime,
    ) -> None:
        expires_at = _parse_timestamp(row["lease_expires_at"])
        if (
            row["status"] != "running"
            or row["lease_owner"] != lease.worker_id
            or row["lease_token"] != lease.lease_token
            or int(row["attempt"]) != lease.attempt
            or expires_at is None
            or expires_at <= current
        ):
            raise TaskLeaseLostError(
                f"task lease is no longer active: "
                f"{lease.run_id}/{lease.task_type}/{lease.task_key}"
            )

    def _finish_task_lease_locked(
        self,
        lease: TaskLease,
        *,
        status: str,
        error: str,
        current: datetime,
    ) -> None:
        self.connection.execute(
            """
            UPDATE tasks
            SET status = ?, lease_owner = NULL, lease_token = NULL,
                lease_acquired_at = NULL, heartbeat_at = NULL,
                lease_expires_at = NULL, last_error = ?, completed_at = ?
            WHERE run_id = ? AND task_type = ? AND task_key = ?
            """,
            (
                status,
                error[:2000] or None,
                current.isoformat(),
                lease.run_id,
                lease.task_type,
                lease.task_key,
            ),
        )

    def _mark_task_attempts_exhausted(
        self,
        run_id: str,
        task_type: str,
        task_key: str,
        current: datetime,
    ) -> None:
        self.connection.execute(
            """
            UPDATE tasks
            SET status = 'failed', lease_owner = NULL, lease_token = NULL,
                lease_acquired_at = NULL, heartbeat_at = NULL,
                lease_expires_at = NULL,
                last_error = 'worker lease expired; attempts exhausted',
                completed_at = ?
            WHERE run_id = ? AND task_type = ? AND task_key = ?
            """,
            (current.isoformat(), run_id, task_type, task_key),
        )

    @contextmanager
    def _write_transaction(self) -> Iterator[None]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise
        else:
            self.connection.execute("COMMIT")

    def _required_run(self, run_id: str) -> RunRecord:
        run = self.get_run(run_id)
        if run is None:
            raise KeyError(f"unknown run: {run_id}")
        return run

    def _required_candidate(self, candidate_id: str) -> CandidateFinding:
        finding = self.get_candidate(candidate_id)
        if finding is None:
            raise KeyError(f"unknown candidate: {candidate_id}")
        return finding

    def _transition_finding_locked(
        self,
        candidate_id: str,
        target: FindingState,
        *,
        idempotency_key: str,
        reason: str,
    ) -> CandidateFinding:
        replay = self._transition_replay(
            "finding", candidate_id, idempotency_key, target.value
        )
        if replay:
            return self._required_candidate(candidate_id)
        finding = self._required_candidate(candidate_id)
        require_finding_transition(finding.state, target)
        updated = finding.model_copy(
            update={"state": target, "updated_at": datetime.now(UTC)}
        )
        self.connection.execute(
            "UPDATE findings SET state = ?, payload_json = ? WHERE candidate_id = ?",
            (target.value, _dump(updated), candidate_id),
        )
        self._record_transition(
            "finding",
            candidate_id,
            idempotency_key,
            finding.state.value,
            target.value,
            reason,
        )
        return updated

    def _transition_replay(
        self, entity_type: str, entity_id: str, idempotency_key: str, target: str
    ) -> bool:
        row = self.connection.execute(
            """
            SELECT to_state FROM transitions
            WHERE entity_type = ? AND entity_id = ? AND idempotency_key = ?
            """,
            (entity_type, entity_id, idempotency_key),
        ).fetchone()
        if row is None:
            return False
        if row["to_state"] != target:
            raise RepositoryConflictError(
                f"idempotency key already targets {row['to_state']}, not {target}"
            )
        return True

    def _record_transition(
        self,
        entity_type: str,
        entity_id: str,
        idempotency_key: str,
        current: str,
        target: str,
        reason: str,
    ) -> None:
        self.connection.execute(
            """
            INSERT INTO transitions(
                entity_type, entity_id, idempotency_key, from_state, to_state, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entity_type,
                entity_id,
                idempotency_key,
                current,
                target,
                reason,
                datetime.now(UTC).isoformat(),
            ),
        )


def _dump(model) -> str:
    return model.model_dump_json(exclude_none=False)


def _dump_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _candidate_seed(finding: CandidateFinding) -> dict:
    return finding.model_dump(exclude={
        "state",
        "evidence_ids",
        "poc",
        "feasibility",
        "resolution",
        "created_at",
        "updated_at",
    })


def _as_utc(value: datetime | None) -> datetime:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("lease timestamps must be timezone-aware")
    return current.astimezone(UTC)


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("stored lease timestamp is not timezone-aware")
    return parsed.astimezone(UTC)


def _validate_lease_policy(lease_seconds: int, max_attempts: int) -> None:
    _validate_lease_seconds(lease_seconds)
    _validate_max_attempts(max_attempts)


def _validate_lease_seconds(lease_seconds: int) -> None:
    if not 1 <= lease_seconds <= 86_400:
        raise ValueError("lease_seconds must be between 1 and 86400")


def _validate_max_attempts(max_attempts: int) -> None:
    if not 1 <= max_attempts <= 100:
        raise ValueError("max_attempts must be between 1 and 100")


def _validate_terminal_status(status: str) -> None:
    if (
        status in {"pending", "running"}
        or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", status) is None
    ):
        raise ValueError("finished task status must be terminal")
