"""Shared V2 run metadata and immutable snapshot helpers for the UI pipeline."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from ..domain.schemas import ArtifactRef, RunRecord, SourceSnapshot
from ..domain.states import RUN_SEQUENCE, RunState
from ..infrastructure.artifacts import ArtifactStore
from ..infrastructure.sqlite_repository import SqliteRepository
from ..intake.snapshot import SnapshotBuilder
from .run_store import RunStore


def v2_artifact_store(store: RunStore) -> ArtifactStore:
    return ArtifactStore(store.dir / "artifacts")


def v2_database_path(store: RunStore) -> Path:
    return store.dir / "state.db"


@contextmanager
def v2_repository(store: RunStore) -> Iterator[SqliteRepository]:
    with SqliteRepository(v2_database_path(store)) as repository:
        yield repository


def ensure_source_snapshot(store: RunStore) -> SourceSnapshot:
    config = store.load_config() or {}
    repo_path = Path(config["repo_path"])
    artifacts = v2_artifact_store(store)
    with v2_repository(store) as repository:
        run = repository.get_run(store.dir.name)
        if run is None:
            run = repository.save_run(RunRecord(
                run_id=store.dir.name,
                source_url=str(config.get("repo_source") or "") or None,
                source_ref=str(config.get("ref") or "") or None,
                config=config,
            ))
        if run.state is RunState.CREATED:
            run = repository.transition_run(
                run.run_id,
                RunState.SNAPSHOTTING,
                idempotency_key="pipeline:snapshotting",
                reason="immutable source snapshot started",
            )

        snapshot = SnapshotBuilder(artifacts).create(
            repo_path,
            source_url=run.source_url,
            resolved_ref=run.source_ref,
        )
        _register_snapshot(repository, artifacts, snapshot)
        if run.source_snapshot is None:
            run = repository.attach_run_snapshot(
                run.run_id, snapshot.snapshot_artifact
            )
        elif run.source_snapshot != snapshot.snapshot_artifact:
            raise RuntimeError(
                "source tree changed after the run snapshot was created; "
                "create a new run before continuing"
            )
        if run.state is RunState.SNAPSHOTTING:
            repository.transition_run(
                run.run_id,
                RunState.INDEXING,
                idempotency_key="pipeline:indexing",
                reason="immutable source snapshot complete",
            )
        return snapshot


def assert_source_snapshot_current(store: RunStore) -> str:
    return ensure_source_snapshot(store).snapshot_artifact


def source_snapshot_path(store: RunStore) -> Path:
    digest = assert_source_snapshot_current(store)
    return v2_artifact_store(store).path_for(digest)


def advance_run(
    store: RunStore,
    target: RunState,
    *,
    reason: str,
) -> RunRecord | None:
    with v2_repository(store) as repository:
        run = repository.get_run(store.dir.name)
        if run is None:
            return None
        if run.state not in RUN_SEQUENCE or target not in RUN_SEQUENCE:
            return run
        current_index = RUN_SEQUENCE.index(run.state)
        target_index = RUN_SEQUENCE.index(target)
        if current_index >= target_index:
            return run
        for state in RUN_SEQUENCE[current_index + 1 : target_index + 1]:
            run = repository.transition_run(
                run.run_id,
                state,
                idempotency_key=f"pipeline:{state.value}",
                reason=reason,
            )
        return run


def _register_snapshot(
    repository: SqliteRepository,
    artifacts: ArtifactStore,
    snapshot: SourceSnapshot,
) -> None:
    for digest, media_type in (
        (
            snapshot.snapshot_artifact,
            "application/vnd.vulnhunt.source-tar",
        ),
        (snapshot.manifest_artifact, "application/json"),
    ):
        path = artifacts.path_for(digest)
        repository.register_artifact(ArtifactRef(
            digest=digest,
            size=path.stat().st_size,
            media_type=media_type,
        ))
