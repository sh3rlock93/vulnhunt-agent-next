from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from tests.factories import HASH_A, candidate
from vulnhunt_agent.domain.schemas import (
    ArtifactRef,
    Evidence,
    EvidenceKind,
    ReviewVerdict,
    RunRecord,
    Verdict,
)
from vulnhunt_agent.domain.states import FindingState, RunState, StateTransitionError
from vulnhunt_agent.infrastructure.artifacts import ArtifactIntegrityError, ArtifactStore
from vulnhunt_agent.infrastructure.events import JsonlEventAdapter
from vulnhunt_agent.infrastructure.sqlite_repository import (
    RepositoryConflictError,
    SqliteRepository,
)


def test_artifact_store_is_content_addressed_and_detects_tampering(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "artifacts")
    first = store.put_text("same bytes")
    second = store.put_text("same bytes")
    assert first.digest == second.digest
    assert store.read_text(first.digest) == "same bytes"
    assert store.path_for(first.digest).stat().st_mode & 0o222 == 0
    with pytest.raises(ValueError, match="invalid SHA-256"):
        store.read_bytes("../../secret")

    path = store.path_for(first.digest)
    path.chmod(0o644)
    path.write_text("tampered")
    with pytest.raises(ArtifactIntegrityError):
        store.read_bytes(first.digest)
    with pytest.raises(ArtifactIntegrityError):
        store.path_for(first.digest)


def test_jsonl_event_adapter_appends_and_validates_contract(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    events = JsonlEventAdapter(path)
    events.append("finding_transition", candidate_id="cand-1")
    assert events.read_all()[0]["candidate_id"] == "cand-1"
    with path.open("a") as stream:
        stream.write("not-json\n")
    with pytest.raises(ValueError, match="line 2"):
        events.read_all()


def test_sqlite_wal_state_transitions_and_idempotency(tmp_path) -> None:
    with SqliteRepository(tmp_path / "state.db") as repository:
        run = RunRecord(run_id="run-1", source_snapshot=HASH_A)
        repository.save_run(run)
        assert repository.journal_mode() == "wal"
        assert repository.foreign_keys_enabled()
        assert repository.schema_version() == 1
        assert repository.ensure_task("run-1", "hunter", "app.py::ssrf")
        assert not repository.ensure_task("run-1", "hunter", "app.py::ssrf")

        finding, created = repository.save_candidate(candidate())
        assert created
        duplicate, duplicate_created = repository.save_candidate(candidate(candidate_id="cand-2"))
        assert not duplicate_created
        assert duplicate.candidate_id == finding.candidate_id
        assert len(repository.list_candidates("run-1")) == 1

        transitioned = repository.transition_finding(
            "cand-1",
            FindingState.STATICALLY_SUPPORTED,
            idempotency_key="hunt:1",
        )
        assert transitioned.state is FindingState.STATICALLY_SUPPORTED
        replay = repository.transition_finding(
            "cand-1",
            FindingState.STATICALLY_SUPPORTED,
            idempotency_key="hunt:1",
        )
        assert replay.state is FindingState.STATICALLY_SUPPORTED
        with pytest.raises(RepositoryConflictError):
            repository.transition_finding(
                "cand-1",
                FindingState.POC_READY,
                idempotency_key="hunt:1",
            )
        with pytest.raises(StateTransitionError):
            repository.transition_finding(
                "cand-1",
                FindingState.REPORTABLE,
                idempotency_key="illegal",
            )

        indexing = repository.transition_run(
            "run-1",
            RunState.SNAPSHOTTING,
            idempotency_key="run:snapshot",
        )
        assert indexing.state is RunState.SNAPSHOTTING
        replayed = repository.transition_run(
            "run-1",
            RunState.SNAPSHOTTING,
            idempotency_key="run:snapshot",
        )
        assert replayed.state is RunState.SNAPSHOTTING


def test_repository_rejects_stable_id_with_different_payload(tmp_path) -> None:
    with SqliteRepository(tmp_path / "state.db") as repository:
        repository.save_run(RunRecord(run_id="run-1"))
        repository.save_candidate(candidate())
        changed = candidate().model_copy(update={"title": "Different title"})
        with pytest.raises(RepositoryConflictError, match="candidate ID"):
            repository.save_candidate(changed)


def test_repository_revalidates_domain_objects_before_storage(tmp_path) -> None:
    invalid = candidate().model_copy(update={"confidence": 2.0})
    with SqliteRepository(tmp_path / "state.db") as repository:
        repository.save_run(RunRecord(run_id="run-1"))
        with pytest.raises(ValidationError, match="less than or equal to 1"):
            repository.save_candidate(invalid)
        with pytest.raises(StateTransitionError, match="hypothesis"):
            repository.save_candidate(candidate(state=FindingState.REPORTABLE))
        with pytest.raises(StateTransitionError, match="created"):
            repository.save_run(RunRecord(run_id="run-2", state=RunState.INDEXING))
        assert repository.list_candidates("run-1") == []


def test_repository_persists_immutable_evidence_reviews_and_artifact_metadata(tmp_path) -> None:
    with SqliteRepository(tmp_path / "state.db") as repository:
        repository.save_run(RunRecord(run_id="run-1"))
        repository.save_candidate(candidate())

        evidence = Evidence(
            evidence_id="ev-source",
            run_id="run-1",
            kind=EvidenceKind.SOURCE,
            producer="indexer",
        )
        assert repository.save_evidence(evidence) == evidence
        assert repository.save_evidence(evidence) == evidence
        assert repository.list_evidence("run-1") == [evidence]
        with pytest.raises(RepositoryConflictError, match="evidence ID"):
            repository.save_evidence(evidence.model_copy(update={"producer": "hunter"}))

        verdict = ReviewVerdict(
            candidate_id="cand-1",
            verdict=Verdict.FALSE_POSITIVE,
            notes="Sanitizer blocks the flow",
            reviewer="reviewer-1",
        )
        assert repository.save_verdict(verdict) == verdict
        assert repository.list_verdicts("cand-1") == [verdict]
        with pytest.raises(RepositoryConflictError, match="immutable"):
            repository.save_verdict(verdict.model_copy(update={"notes": "Changed"}))

        artifact = ArtifactRef(digest=HASH_A, size=3, media_type="text/plain")
        repository.register_artifact(artifact)
        repository.register_artifact(artifact)
        assert repository.get_artifact(HASH_A) == artifact
        with pytest.raises(RepositoryConflictError, match="metadata"):
            repository.register_artifact(artifact.model_copy(update={"size": 4}))


def test_event_json_is_machine_readable(tmp_path) -> None:
    adapter = JsonlEventAdapter(tmp_path / "events.jsonl")
    adapter.append("run_created", run_id="run-1")
    raw = json.loads((tmp_path / "events.jsonl").read_text())
    assert raw["type"] == "run_created"
