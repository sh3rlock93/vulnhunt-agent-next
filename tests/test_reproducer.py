from __future__ import annotations

import pytest

from tests.factories import HASH_B, candidate
from vulnhunt_agent.domain.schemas import (
    OracleSpec,
    OracleType,
    PocSpec,
    ReproductionSpec,
    ReviewVerdict,
    RunRecord,
    Verdict,
)
from vulnhunt_agent.domain.states import FindingState, RunState
from vulnhunt_agent.infrastructure.artifacts import ArtifactIntegrityError, ArtifactStore
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.intake.snapshot import SnapshotBuilder
from vulnhunt_agent.reporting.service import StrictReportService
from vulnhunt_agent.reproduction.service import (
    ReproductionStatus,
    ReproducerService,
)
from vulnhunt_agent.sandbox.base import ExecResult, SandboxExecution, SandboxJob


class FakeSandboxBackend:
    def __init__(self, results: list[ExecResult]):
        self.results = list(results)
        self.jobs: list[SandboxJob] = []

    async def execute(self, job: SandboxJob) -> SandboxExecution:
        self.jobs.append(job)
        return SandboxExecution(
            image_digest=HASH_B,
            result=self.results[len(self.jobs) - 1],
        )


class BrokenSandboxBackend:
    async def execute(self, job: SandboxJob) -> SandboxExecution:
        raise RuntimeError("sandbox runtime unavailable")


async def test_reproducer_runs_twice_persists_evidence_and_unlocks_strict_report(
    tmp_path,
) -> None:
    repository, artifacts, spec = _prepared_candidate(tmp_path)
    backend = FakeSandboxBackend(
        [
            ExecResult(exit_code=0, stdout="LEAKED_SECRET=1", stderr="", duration_ms=10),
            ExecResult(exit_code=0, stdout="LEAKED_SECRET=1", stderr="", duration_ms=12),
        ]
    )
    service = ReproducerService(repository, artifacts, backend)

    outcome = await service.reproduce(spec)
    assert outcome.status is ReproductionStatus.REPRODUCED
    assert len(outcome.evidence) == 2
    assert {item.attempt for item in outcome.evidence} == {1, 2}
    assert all(item.oracle and item.oracle.result == "passed" for item in outcome.evidence)
    assert len(backend.jobs) == 2
    assert backend.jobs[0] is not backend.jobs[1]
    assert all(job.source_tar.is_file() and job.poc_file.is_file() for job in backend.jobs)

    stored = repository.get_candidate("cand-1")
    assert stored is not None
    assert stored.state is FindingState.REPRODUCED
    assert len(stored.evidence_ids) == 2

    replay = await service.reproduce(spec)
    assert replay.status is ReproductionStatus.REPRODUCED
    assert len(backend.jobs) == 2
    with pytest.raises(ValueError, match="already bound"):
        await service.reproduce(
            spec.model_copy(
                update={
                    "oracle": OracleSpec(
                        type=OracleType.STDOUT_REGEX,
                        pattern=r"DIFFERENT_RESULT=1",
                    )
                }
            )
        )

    reviewed = repository.transition_finding(
        "cand-1",
        FindingState.REVIEWER_VERIFIED,
        idempotency_key="review:verified",
    )
    verdict = repository.save_verdict(
        ReviewVerdict(
            candidate_id="cand-1",
            verdict=Verdict.REAL,
            notes="Two clean runs reached the vulnerable sink",
            reviewer="reviewer-1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )
    )
    run = repository.get_run("run-1")
    assert run is not None
    bundle = StrictReportService(repository, artifacts).materialize(
        tmp_path / "output",
        run_id=run.run_id,
        candidate_id=reviewed.candidate_id,
        reviewer=verdict.reviewer,
        markdown="# Verified SSRF\n",
    )
    assert bundle.report_path.read_text() == "# Verified SSRF\n"
    assert spec.source_snapshot in bundle.provenance_path.read_text()
    reportable = repository.get_candidate("cand-1")
    assert reportable is not None
    assert reportable.state is FindingState.REPORTABLE
    replayed_bundle = StrictReportService(repository, artifacts).materialize(
        tmp_path / "output",
        run_id=run.run_id,
        candidate_id=reviewed.candidate_id,
        reviewer=verdict.reviewer,
        markdown="# Verified SSRF\n",
    )
    assert replayed_bundle == bundle
    repository.close()


async def test_reproducer_marks_mixed_oracles_flaky(tmp_path) -> None:
    repository, artifacts, spec = _prepared_candidate(tmp_path)
    backend = FakeSandboxBackend(
        [
            ExecResult(exit_code=0, stdout="LEAKED_SECRET=1", stderr=""),
            ExecResult(exit_code=1, stdout="blocked", stderr=""),
        ]
    )
    outcome = await ReproducerService(repository, artifacts, backend).reproduce(spec)
    assert outcome.status is ReproductionStatus.FLAKY
    finding = repository.get_candidate("cand-1")
    assert finding is not None
    assert finding.state is FindingState.UNCLEAR
    repository.close()


async def test_reproducer_distinguishes_environment_failure(tmp_path) -> None:
    repository, artifacts, spec = _prepared_candidate(tmp_path)
    service = ReproducerService(
        repository, artifacts, BrokenSandboxBackend()
    )
    outcome = await service.reproduce(spec)
    assert outcome.status is ReproductionStatus.ENVIRONMENT_BLOCKED
    assert "sandbox runtime unavailable" in outcome.error
    finding = repository.get_candidate("cand-1")
    assert finding is not None
    assert finding.state is FindingState.ENVIRONMENT_BLOCKED
    with pytest.raises(ValueError, match="new reproduction_id"):
        await service.reproduce(spec)

    retry_backend = FakeSandboxBackend(
        [
            ExecResult(exit_code=0, stdout="LEAKED_SECRET=1", stderr=""),
            ExecResult(exit_code=0, stdout="LEAKED_SECRET=1", stderr=""),
        ]
    )
    retry = await ReproducerService(
        repository, artifacts, retry_backend
    ).reproduce(spec.model_copy(update={"reproduction_id": "repro-cand-1-v2"}))
    assert retry.status is ReproductionStatus.REPRODUCED
    repository.close()


def test_strict_report_never_materializes_without_reproduction_evidence(tmp_path) -> None:
    repository, artifacts, _ = _prepared_candidate(tmp_path)
    repository.transition_finding(
        "cand-1",
        FindingState.REPRODUCTION_PENDING,
        idempotency_key="bypass:pending",
    )
    repository.transition_finding(
        "cand-1",
        FindingState.REPRODUCED,
        idempotency_key="bypass:reproduced",
    )
    repository.transition_finding(
        "cand-1",
        FindingState.REVIEWER_VERIFIED,
        idempotency_key="bypass:reviewed",
    )
    repository.save_verdict(
        ReviewVerdict(
            candidate_id="cand-1",
            verdict=Verdict.REAL,
            notes="State was advanced without evidence",
            reviewer="reviewer-1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )
    )
    with pytest.raises(ValueError, match="reproduction evidence is missing"):
        StrictReportService(repository, artifacts).materialize(
            tmp_path / "output",
            run_id="run-1",
            candidate_id="cand-1",
            reviewer="reviewer-1",
            markdown="# Must not exist\n",
        )
    assert not (tmp_path / "output" / "reports").exists()
    repository.close()


async def test_strict_report_rejects_tampered_reproduction_artifact(tmp_path) -> None:
    repository, artifacts, spec = _prepared_candidate(tmp_path)
    backend = FakeSandboxBackend(
        [
            ExecResult(exit_code=0, stdout="LEAKED_SECRET=1", stderr=""),
            ExecResult(exit_code=0, stdout="LEAKED_SECRET=1", stderr=""),
        ]
    )
    outcome = await ReproducerService(repository, artifacts, backend).reproduce(spec)
    repository.transition_finding(
        "cand-1",
        FindingState.REVIEWER_VERIFIED,
        idempotency_key="tamper:reviewed",
    )
    repository.save_verdict(
        ReviewVerdict(
            candidate_id="cand-1",
            verdict=Verdict.REAL,
            notes="Evidence should be integrity checked",
            reviewer="reviewer-1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )
    )
    stdout_digest = outcome.evidence[0].stdout_artifact
    assert stdout_digest is not None
    stdout_path = artifacts.path_for(stdout_digest)
    stdout_path.chmod(0o644)
    stdout_path.write_text("tampered")

    with pytest.raises(ArtifactIntegrityError):
        StrictReportService(repository, artifacts).materialize(
            tmp_path / "output",
            run_id="run-1",
            candidate_id="cand-1",
            reviewer="reviewer-1",
            markdown="# Must not exist\n",
        )
    assert not (tmp_path / "output" / "reports").exists()
    repository.close()


def _prepared_candidate(tmp_path) -> tuple[
    SqliteRepository, ArtifactStore, ReproductionSpec
]:
    artifacts = ArtifactStore(tmp_path / "artifacts")
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('target loaded')\n")
    snapshot = SnapshotBuilder(artifacts).create(source)
    poc = artifacts.put_text("print('LEAKED_SECRET=1')\n", "text/x-python")

    repository = SqliteRepository(tmp_path / "state.db")
    repository.save_run(RunRecord(run_id="run-1"))
    repository.transition_run(
        "run-1",
        RunState.SNAPSHOTTING,
        idempotency_key="snapshot:start",
    )
    repository.attach_run_snapshot("run-1", snapshot.snapshot_artifact)
    repository.register_artifact(poc)
    repository.save_candidate(candidate())
    repository.transition_finding(
        "cand-1",
        FindingState.STATICALLY_SUPPORTED,
        idempotency_key="hunt:supported",
    )
    argv = ("python", "/workspace/poc/poc.py")
    repository.attach_candidate_poc(
        "cand-1",
        PocSpec(artifact=poc.digest, argv=argv, cwd="."),
    )
    repository.transition_finding(
        "cand-1",
        FindingState.POC_READY,
        idempotency_key="hunt:poc-ready",
    )
    return (
        repository,
        artifacts,
        ReproductionSpec(
            reproduction_id="repro-cand-1-v1",
            run_id="run-1",
            candidate_id="cand-1",
            source_snapshot=snapshot.snapshot_artifact,
            image="python:3.12-slim",
            poc_artifact=poc.digest,
            poc_path="poc.py",
            argv=argv,
            cwd=".",
            env={"PYTHONPATH": "/workspace/source"},
            oracle=OracleSpec(
                type=OracleType.STDOUT_REGEX,
                pattern=r"LEAKED_SECRET=1",
            ),
        ),
    )
