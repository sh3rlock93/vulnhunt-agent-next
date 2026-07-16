"""SQLite WAL repository for validated V2 domain objects."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

from ..domain.schemas import ArtifactRef, CandidateFinding, Evidence, ReviewVerdict, RunRecord
from ..domain.states import (
    FindingState,
    RunState,
    StateTransitionError,
    require_finding_transition,
    require_run_transition,
)


class RepositoryConflictError(RuntimeError):
    """An idempotency key or stable object ID was reused for different data."""


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
CREATE INDEX IF NOT EXISTS findings_run_state ON findings(run_id, state);
CREATE INDEX IF NOT EXISTS tasks_run_status ON tasks(run_id, status);
PRAGMA user_version=1;
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
        if not read_only:
            mode = self.connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(mode).casefold() != "wal":
                raise RuntimeError("SQLite WAL mode is required")
            self.connection.executescript(_SCHEMA)

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
        rows = self.connection.execute(
            """
            SELECT task_type, task_key, status, attempt, payload_json
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
            }
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

    def save_evidence(self, evidence: Evidence) -> Evidence:
        evidence = Evidence.model_validate(evidence)
        self._required_run(evidence.run_id)
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

    @contextmanager
    def _write_transaction(self) -> Iterator[None]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except Exception:
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
    return finding.model_dump(exclude={"state", "created_at", "updated_at"})
