from __future__ import annotations

from tests.factories import HASH_B, HASH_C, candidate
from vulnhunt_agent.domain.schemas import (
    Evidence,
    EvidenceKind,
    ExecutionSubject,
    OracleResult,
    OracleSpec,
    OracleType,
    PocSpec,
    ReproductionSpec,
    ReviewVerdict,
    RunRecord,
    Verdict,
)
from vulnhunt_agent.domain.states import FindingState, RunState
from vulnhunt_agent.infrastructure.artifacts import ArtifactStore
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.intake.snapshot import SnapshotBuilder
from vulnhunt_agent.reporting.policy import StrictReportPolicy
from vulnhunt_agent.reproduction.provenance import derive_execution_provenance
from vulnhunt_agent.reproduction.service import ReproductionStatus, ReproducerService
from vulnhunt_agent.sandbox.base import ExecResult, SandboxExecution, SandboxJob

RAW2TIFF_ASAN = """\
==17==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123
    #0 0x123 in __interceptor_memcpy sanitizer_common_interceptors.inc:827
    #1 0x456 in main /code/tools/raw2tiff.c:328:5
    #2 0x789 in _TIFFmalloc /code/libtiff/tif_unix.c:326:12
SUMMARY: AddressSanitizer: heap-buffer-overflow /code/tools/raw2tiff.c:328:5 in main
"""


class ProvenanceSandboxBackend:
    def __init__(self, results: list[ExecResult]) -> None:
        self.results = results
        self.jobs: list[SandboxJob] = []

    async def execute(self, job: SandboxJob) -> SandboxExecution:
        self.jobs.append(job)
        index = len(self.jobs)
        return SandboxExecution(
            image_digest=HASH_B,
            result=self.results[index - 1],
            environment_id=f"clean-sandbox-{index}",
        )


def test_native_provenance_classifies_prepared_linked_and_standalone() -> None:
    direct = derive_execution_provenance(
        argv=("/opt/vulnhunt/build/tools/raw2tiff", "input.raw"),
        setup_argvs=(),
        stdout="",
        stderr=RAW2TIFF_ASAN,
    )
    assert direct.execution_subject is ExecutionSubject.PREPARED_BINARY
    assert direct.target_binary == "/opt/vulnhunt/build/tools/raw2tiff"
    assert direct.target_source_reached
    assert direct.sanitizer_failure_class == "heap-buffer-overflow"
    assert any(
        frame.path == "/code/tools/raw2tiff.c" and frame.line == 328
        for frame in direct.sanitizer_frames
    )

    linked = derive_execution_provenance(
        argv=("/workspace/exec/poc",),
        setup_argvs=(("cc", "/code/libtiff/tif_unix.c"),),
        stdout="",
        stderr=RAW2TIFF_ASAN,
    )
    assert linked.execution_subject is ExecutionSubject.LINKED_TARGET_HARNESS
    assert linked.target_source_reached
    assert "/code/libtiff/tif_unix.c" in linked.linked_target_artifacts

    standalone = derive_execution_provenance(
        argv=("/workspace/exec/poc",),
        setup_argvs=(),
        stdout="",
        stderr=(
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "#0 0x123 in main /workspace/model.c:12:3\n"
        ),
    )
    assert standalone.execution_subject is ExecutionSubject.STANDALONE_MODEL
    assert not standalone.target_source_reached


def test_prior_archive_snippet_is_downgraded_to_standalone() -> None:
    provenance = derive_execution_provenance(
        argv=("/workspace/exec/bmp_rle_oob",),
        setup_argvs=((
            "cc",
            "-fsanitize=address,undefined",
            "/workspace/bmp_rle_oob.c",
            "-o",
            "/workspace/exec/bmp_rle_oob",
        ),),
        stdout="",
        stderr=(
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "#0 0x400dec in main /workspace/bmp_rle_oob.c:27\n"
        ),
    )
    assert provenance.execution_subject is ExecutionSubject.STANDALONE_MODEL
    assert not provenance.target_source_reached


async def test_memory_safety_reproduction_requires_actual_target_twice(tmp_path) -> None:
    repository, artifacts, spec = _prepared_memory_candidate(
        tmp_path,
        argv=("/opt/vulnhunt/build/tools/raw2tiff", "/workspace/poc/input.raw"),
    )
    backend = ProvenanceSandboxBackend([
        ExecResult(exit_code=1, stdout="", stderr=RAW2TIFF_ASAN),
        ExecResult(exit_code=1, stdout="", stderr=RAW2TIFF_ASAN),
    ])
    outcome = await ReproducerService(repository, artifacts, backend).reproduce(spec)

    assert outcome.status is ReproductionStatus.REPRODUCED
    assert {item.clean_environment_id for item in outcome.evidence} == {
        "clean-sandbox-1",
        "clean-sandbox-2",
    }
    assert all(item.target_source_reached for item in outcome.evidence)
    assert all(
        item.execution_subject is ExecutionSubject.PREPARED_BINARY
        for item in outcome.evidence
    )
    finding = repository.get_candidate("cand-1")
    assert finding is not None
    assert finding.state is FindingState.REPRODUCED
    repository.close()


async def test_standalone_memory_model_remains_unverified(tmp_path) -> None:
    repository, artifacts, spec = _prepared_memory_candidate(
        tmp_path,
        argv=("/workspace/exec/poc",),
    )
    output = (
        "ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "#0 0x123 in main /workspace/model.c:12:3\n"
    )
    backend = ProvenanceSandboxBackend([
        ExecResult(exit_code=1, stdout="", stderr=output),
        ExecResult(exit_code=1, stdout="", stderr=output),
    ])
    outcome = await ReproducerService(repository, artifacts, backend).reproduce(spec)

    assert outcome.status is ReproductionStatus.UNVERIFIED
    assert all(
        item.execution_subject is ExecutionSubject.STANDALONE_MODEL
        for item in outcome.evidence
    )
    finding = repository.get_candidate("cand-1")
    assert finding is not None
    assert finding.state is FindingState.UNCLEAR
    repository.close()


def test_legacy_unknown_evidence_is_readable_but_not_target_confirmed() -> None:
    finding = candidate(
        state=FindingState.REVIEWER_VERIFIED,
        evidence_ids=("ev-repro-1", "ev-repro-2"),
    ).model_copy(update={
        "weakness": "CWE-190",
        "title": "Integer overflow reaches a memory copy",
        "impact": ("Heap buffer overflow",),
    })
    evidence = [_legacy_reproduction(1), _legacy_reproduction(2)]
    assert all(item.execution_subject is ExecutionSubject.UNKNOWN for item in evidence)
    verdict = ReviewVerdict(
        candidate_id="cand-1",
        verdict=Verdict.REAL,
        notes="Legacy evidence previously passed its text oracle",
        reviewer="reviewer-1",
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        cwe_id="CWE-190",
        evidence_ids=("ev-repro-1", "ev-repro-2"),
    )
    second = verdict.model_copy(update={
        "reviewer": "reviewer-2",
        "prompt_version": "evidence-review-v1:alternate",
    })

    decision = StrictReportPolicy().evaluate(
        finding,
        run_snapshot=HASH_C,
        evidence=evidence,
        verdicts=[verdict, second],
    )
    assert not decision.allowed
    assert (
        "memory-safety reproduction did not execute the prepared target "
        "in two clean matching attempts"
    ) in decision.reasons


def _legacy_reproduction(attempt: int) -> Evidence:
    payload = {
        "evidence_id": f"ev-repro-{attempt}",
        "run_id": "run-1",
        "candidate_id": "cand-1",
        "kind": EvidenceKind.REPRODUCTION,
        "producer": "reproducer",
        "reproduction_group": "legacy-repro",
        "attempt": attempt,
        "source_snapshot": HASH_C,
        "image_digest": HASH_B,
        "command": ("/workspace/exec/poc",),
        "exit_code": 1,
        "stdout_artifact": HASH_B,
        "stderr_artifact": HASH_C,
        "oracle": OracleResult(
            type="stderr_regex",
            expression="AddressSanitizer",
            result="passed",
        ),
    }
    return Evidence.model_validate(payload)


def _prepared_memory_candidate(
    tmp_path,
    *,
    argv: tuple[str, ...],
) -> tuple[SqliteRepository, ArtifactStore, ReproductionSpec]:
    artifacts = ArtifactStore(tmp_path / "artifacts")
    source = tmp_path / "source"
    source.mkdir()
    (source / "target.c").write_text("int main(void) { return 0; }\n")
    snapshot = SnapshotBuilder(artifacts).create(source)
    poc = artifacts.put_bytes(b"trigger", "application/octet-stream")

    repository = SqliteRepository(tmp_path / "state.db")
    repository.save_run(RunRecord(run_id="run-1"))
    repository.transition_run(
        "run-1",
        RunState.SNAPSHOTTING,
        idempotency_key="snapshot:start",
    )
    repository.attach_run_snapshot("run-1", snapshot.snapshot_artifact)
    repository.register_artifact(poc)
    finding = candidate().model_copy(update={
        "title": "Integer overflow reaches a memory copy",
        "weakness": "CWE-190",
        "impact": ("Heap buffer overflow",),
    })
    repository.save_candidate(finding)
    repository.transition_finding(
        "cand-1",
        FindingState.STATICALLY_SUPPORTED,
        idempotency_key="hunt:supported",
    )
    repository.attach_candidate_poc(
        "cand-1",
        PocSpec(artifact=poc.digest, argv=argv, cwd="."),
    )
    repository.transition_finding(
        "cand-1",
        FindingState.POC_READY,
        idempotency_key="hunt:poc-ready",
    )
    return repository, artifacts, ReproductionSpec(
        reproduction_id="repro-cand-1-native",
        run_id="run-1",
        candidate_id="cand-1",
        source_snapshot=snapshot.snapshot_artifact,
        image="vulnhunt/native-analysis:latest",
        poc_artifact=poc.digest,
        poc_path="input.raw",
        argv=argv,
        oracle=OracleSpec(
            type=OracleType.STDERR_REGEX,
            pattern="AddressSanitizer: heap-buffer-overflow",
        ),
    )
