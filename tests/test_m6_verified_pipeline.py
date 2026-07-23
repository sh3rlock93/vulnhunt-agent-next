from __future__ import annotations

import json
import re
from pathlib import Path
from typing import cast

import pytest

from tests.factories import HASH_B
from vulnhunt_agent.core.llm import LLMClient, LLMResponse
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.core.v2_run import ensure_source_snapshot, v2_artifact_store
from vulnhunt_agent.domain.schemas import OracleSpec, OracleType
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.reviewing.agent import EvidenceReviewerAgent
from vulnhunt_agent.reproduction.variants import (
    VariantExecutionPatch,
    compile_variant_spec,
)
from vulnhunt_agent.sandbox.base import ExecResult, SandboxExecution, SandboxJob
from vulnhunt_agent.verification.recipe import validate_recorded_recipe
from vulnhunt_agent.verification.service import VerifiedPipelineService

COMPILE = (
    "cc",
    "-fsanitize=address",
    "/workspace/poc.c",
    "/code/target.c",
    "-o",
    "/workspace/exec/poc",
)
TRIGGER = ("/workspace/exec/poc",)


class FakeNativeBackend:
    def __init__(self) -> None:
        self.jobs: list[SandboxJob] = []

    async def execute(self, job: SandboxJob) -> SandboxExecution:
        self.jobs.append(job)
        return SandboxExecution(
            image_digest=HASH_B,
            setup_results=(
                ExecResult(exit_code=0, stdout="", stderr="", duration_ms=20),
            ),
            result=ExecResult(
                exit_code=1,
                stdout="",
                stderr=(
                    "ERROR: AddressSanitizer: heap-buffer-overflow\n"
                    "#0 0x123 in target /code/target.c:1:28\n"
                ),
                duration_ms=30,
            ),
            environment_id=f"fake-native-clean-{len(self.jobs)}",
        )


class EvidenceCitingClient:
    async def chat(self, **kwargs) -> LLMResponse:
        prompt = kwargs["messages"][0]["content"][0]["text"]
        evidence_ids = tuple(dict.fromkeys(
            re.findall(r"ev_repro_[0-9a-f]{26}", prompt)
        ))
        payload = {
            "verdict": "real",
            "notes": "Two clean ASan attempts reproduce the out-of-bounds write.",
            "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H",
            "cwe_id": "CWE-787",
            "evidence_ids": list(evidence_ids),
            "variant_request": None,
        }
        text = json.dumps(payload)
        return LLMResponse(
            text=text,
            input_tokens=100,
            output_tokens=30,
            cache_read_tokens=0,
            cache_write_tokens=0,
            stop_reason="end_turn",
            content_blocks=[{"text": text}],
        )


class VariantThenRealClient(EvidenceCitingClient):
    def __init__(self) -> None:
        self.calls = 0

    async def chat(self, **kwargs) -> LLMResponse:
        self.calls += 1
        if self.calls == 1:
            payload = {
                "verdict": "unclear",
                "notes": "A safe control is required.",
                "cvss_vector": "",
                "cwe_id": "",
                "evidence_ids": [],
                "variant_request": {
                    "variant_type": "safe_input",
                    "rationale": "Separate the trigger from startup failure.",
                    "requested_change": "Run the PoC with its safe-control input.",
                },
            }
            text = json.dumps(payload)
            return LLMResponse(
                text=text,
                input_tokens=100,
                output_tokens=30,
                cache_read_tokens=0,
                cache_write_tokens=0,
                stop_reason="end_turn",
                content_blocks=[{"text": text}],
            )
        return await super().chat(**kwargs)


class EndToEndVariantClient(EvidenceCitingClient):
    def __init__(self) -> None:
        self.calls = 0

    async def chat(self, **kwargs) -> LLMResponse:
        self.calls += 1
        payload = {
            "verdict": "unclear",
            "notes": "An end-to-end transport control is required.",
            "cvss_vector": "",
            "cwe_id": "",
            "evidence_ids": [],
            "variant_request": {
                "variant_type": "alternate_trigger",
                "rationale": "Prove that a remote request reaches the sink.",
                "requested_change": (
                    "Run an end-to-end real TCP server with a separate client; the harness "
                    "must not call the vulnerable sink directly."
                ),
            },
        }
        text = json.dumps(payload)
        return LLMResponse(
            text=text,
            input_tokens=100,
            output_tokens=30,
            cache_read_tokens=0,
            cache_write_tokens=0,
            stop_reason="end_turn",
            content_blocks=[{"text": text}],
        )


class PipelineSafeInputCompiler:
    async def compile(self, request, base):
        return compile_variant_spec(
            request,
            base,
            VariantExecutionPatch(
                argv=(*base.argv, "--safe-control"),
                env_overrides={},
                oracle=OracleSpec(
                    type=OracleType.EXIT_CODE,
                    expected_exit_code=1,
                ),
            ),
        )


def test_recipe_must_match_tool_ledger_and_rewrites_snapshot_paths(
    tmp_path: Path,
) -> None:
    pocs = tmp_path / "pocs"
    pocs.mkdir()
    (pocs / "poc.c").write_text("int main(void) { return 0; }\n")
    finding = _finding()
    payload = _hunt_payload(finding)

    accepted = validate_recorded_recipe(finding, payload, pocs)

    assert accepted.error == ""
    assert accepted.recipe is not None
    assert accepted.recipe.setup_argvs == ((
        "cc",
        "-fsanitize=address",
        "/workspace/poc/poc.c",
        "/workspace/source/target.c",
        "-o",
        "/workspace/exec/poc",
    ),)
    assert accepted.recipe.cwd == "."

    tampered = {**finding, "reproduction": {
        **finding["reproduction"],
        "argv": ["/workspace/exec/not-recorded"],
    }}
    rejected = validate_recorded_recipe(tampered, payload, pocs)
    assert rejected.recipe is None
    assert "recorded exec tool calls" in rejected.error

    unsafe_cwd = {**finding, "reproduction": {
        **finding["reproduction"],
        "cwd": "/etc",
    }}
    unsafe_payload = _hunt_payload(unsafe_cwd)
    rejected_cwd = validate_recorded_recipe(unsafe_cwd, unsafe_payload, pocs)
    assert rejected_cwd.recipe is None
    assert "cannot be reproduced safely" in rejected_cwd.error


def test_snapshot_change_blocks_later_pipeline_steps(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "target.c").write_text("int target(void) { return 0; }\n")
    store = RunStore(tmp_path / "run-m6")
    store.save_config({"repo_path": str(source)})

    first = ensure_source_snapshot(store)
    assert ensure_source_snapshot(store) == first

    (source / "target.c").write_text("int target(void) { return 1; }\n")
    with pytest.raises(RuntimeError, match="source tree changed"):
        ensure_source_snapshot(store)


async def test_verified_pipeline_reproduces_reviews_reports_and_resumes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "target.c").write_text(
        "void target(int *values) { values[100] = 7; }\n"
    )
    store = RunStore(tmp_path / "run-m6")
    store.save_config({
        "repo_path": str(source),
        "repo_source": "https://example.test/native.git",
        "ref": "deadbeef",
    })
    ensure_source_snapshot(store)

    hunt_dir = store.dir / "hunters" / "h1" / "hunts" / "task-1"
    pocs = hunt_dir / "pocs"
    pocs.mkdir(parents=True)
    (pocs / "poc.c").write_text(
        "void target(int *); int main(void) { int v[1]; target(v); }\n"
    )
    finding = _finding()
    (hunt_dir / "findings.json").write_text(json.dumps(_hunt_payload(finding)))

    backend = FakeNativeBackend()
    client = EvidenceCitingClient()
    reviewers = [
        EvidenceReviewerAgent(
            client=cast(LLMClient, client),
            reviewer="reviewer-a",
            model_id="fake",
            prompt_variant="challenge reachability",
        ),
        EvidenceReviewerAgent(
            client=cast(LLMClient, client),
            reviewer="reviewer-b",
            model_id="fake",
            prompt_variant="challenge impact",
        ),
    ]
    repository = SqliteRepository(store.dir / "state.db")
    service = VerifiedPipelineService(
        repository,
        v2_artifact_store(store),
        backend,
        reviewers,
        output_root=store.dir / "verified",
    )

    summary = await service.verify(
        run_id=store.dir.name,
        run_dir=store.dir,
        image="scanner/prepared:m6-test",
    )

    assert summary.candidates == 1
    assert summary.recipes_accepted == 1
    assert summary.recipes_rejected == 0
    assert summary.states == {"reportable": 1}
    assert summary.reports == 1
    assert summary.errors == ()
    assert len(backend.jobs) == 2
    assert all(job.setup_argvs for job in backend.jobs)
    run = repository.get_run(store.dir.name)
    assert run is not None
    assert run.state.value == "completed"
    candidate = repository.list_candidates(store.dir.name)[0]
    evidence = repository.list_candidate_evidence(candidate.candidate_id)
    assert len([item for item in evidence if item.producer == "reproducer"]) == 2

    report_path = next((store.dir / "verified").glob("reports/*/report.json"))
    report = json.loads(report_path.read_text())
    assert report["classification"]["cwe_id"] == "CWE-787"
    assert report["verification"]["resolution"]["disposition"] == "confirmed"
    assert report["verification"]["feasibility"]["status"] == "unknown"
    assert report["reproduction"][0]["setup_commands"]
    assert list((store.dir / "verified").glob("reports/*/report.sarif"))

    replay = await service.verify(
        run_id=store.dir.name,
        run_dir=store.dir,
        image="scanner/prepared:m6-test",
    )
    assert replay.states == {"reportable": 1}
    assert replay.reports == 1
    assert len(backend.jobs) == 2
    repository.close()


async def test_verified_pipeline_executes_variant_and_automatically_rereviews(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "target.c").write_text(
        "void target(int *values) { values[100] = 7; }\n"
    )
    store = RunStore(tmp_path / "run-m9-variant")
    store.save_config({
        "repo_path": str(source),
        "repo_source": "https://example.test/native.git",
        "ref": "deadbeef",
    })
    ensure_source_snapshot(store)
    hunt_dir = store.dir / "hunters" / "h1" / "hunts" / "task-1"
    pocs = hunt_dir / "pocs"
    pocs.mkdir(parents=True)
    (pocs / "poc.c").write_text(
        "#include <string.h>\nvoid target(int *); int main(int argc, char **argv) { "
        "int v[1]; if (argc > 1 && strcmp(argv[1], \"--safe-control\") == 0) "
        "target(v); else target(v); }\n"
    )
    (hunt_dir / "findings.json").write_text(
        json.dumps(_hunt_payload(_finding()))
    )
    backend = FakeNativeBackend()
    client = VariantThenRealClient()
    reviewers = [
        EvidenceReviewerAgent(
            client=cast(LLMClient, client),
            reviewer="reviewer-a",
            model_id="fake",
            prompt_variant="challenge reachability",
        ),
        EvidenceReviewerAgent(
            client=cast(LLMClient, client),
            reviewer="reviewer-b",
            model_id="fake",
            prompt_variant="challenge impact",
        ),
    ]
    repository = SqliteRepository(store.dir / "state.db")
    summary = await VerifiedPipelineService(
        repository,
        v2_artifact_store(store),
        backend,
        reviewers,
        output_root=store.dir / "verified",
        variant_compiler=PipelineSafeInputCompiler(),
    ).verify(
        run_id=store.dir.name,
        run_dir=store.dir,
        image="scanner/prepared:m9-variant",
    )

    assert summary.variants_executed == 1
    assert summary.variants_failed == 0
    assert summary.experiment_plans == 1
    assert summary.experiment_plans_deferred == 0
    assert summary.automatic_rereviews == 1
    assert summary.states == {"reportable": 1}
    assert summary.reports == 1
    assert summary.errors == ()
    assert client.calls == 3
    assert len(backend.jobs) == 4
    assert [job.argv[-1] for job in backend.jobs[2:]] == [
        "--safe-control",
        "--safe-control",
    ]
    variant = next(
        task for task in repository.list_tasks(store.dir.name)
        if task["task_type"] == "reproduction_variant"
    )
    assert variant["status"] == "reproduced"
    candidate = repository.list_candidates(store.dir.name)[0]
    assert len(repository.list_candidate_evidence(candidate.candidate_id)) >= 5
    repository.close()


async def test_verified_pipeline_defers_unimplementable_experiment_plan(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "target.c").write_text(
        "void target(int *values) { values[100] = 7; }\n"
    )
    store = RunStore(tmp_path / "run-experiment-plan-deferred")
    store.save_config({"repo_path": str(source), "ref": "deadbeef"})
    ensure_source_snapshot(store)
    hunt_dir = store.dir / "hunters" / "h1" / "hunts" / "task-1"
    pocs = hunt_dir / "pocs"
    pocs.mkdir(parents=True)
    (pocs / "poc.c").write_text(
        "void target(int *); int main(void) { int v[1]; target(v); }\n"
    )
    (hunt_dir / "findings.json").write_text(
        json.dumps(_hunt_payload(_finding()))
    )
    backend = FakeNativeBackend()
    client = EndToEndVariantClient()
    reviewers = [
        EvidenceReviewerAgent(
            client=cast(LLMClient, client),
            reviewer="reviewer-a",
            model_id="fake",
            prompt_variant="challenge reachability",
        ),
        EvidenceReviewerAgent(
            client=cast(LLMClient, client),
            reviewer="reviewer-b",
            model_id="fake",
            prompt_variant="challenge impact",
        ),
    ]
    repository = SqliteRepository(store.dir / "state.db")

    summary = await VerifiedPipelineService(
        repository,
        v2_artifact_store(store),
        backend,
        reviewers,
        output_root=store.dir / "verified",
        variant_compiler=PipelineSafeInputCompiler(),
    ).verify(
        run_id=store.dir.name,
        run_dir=store.dir,
        image="scanner/prepared:experiment-plan",
    )

    assert summary.variants_executed == 0
    assert summary.experiment_plans == 1
    assert summary.experiment_plans_deferred == 1
    assert summary.states == {"verification_deferred": 1}
    assert summary.errors == ()
    assert client.calls == 1
    assert len(backend.jobs) == 2
    candidate = repository.list_candidates(store.dir.name)[0]
    assert candidate.resolution is not None
    assert candidate.resolution.deferred_reason is not None
    assert candidate.resolution.deferred_reason.value == "experiment_plan_unsupported"
    assert "does not consume command-line arguments" in candidate.resolution.reason
    plan_task = next(
        item for item in repository.list_tasks(store.dir.name)
        if item["task_type"] == "experiment_plan"
    )
    assert plan_task["status"] == "requires_harness"
    repository.close()


def _finding() -> dict:
    return {
        "title": "Out-of-bounds write in target",
        "type": "out_of_bounds_write",
        "description": "Attacker-controlled index corrupts memory.",
        "attack": "Invoke the parser with a crafted index.",
        "status": "confirmed",
        "entry_file": "target.c",
        "entry_line": 1,
        "sink_file": "target.c",
        "sink_line": 1,
        "files_touched": ["target.c"],
        "poc_file": "poc.c",
        "exec_output": "ERROR: AddressSanitizer: heap-buffer-overflow",
        "reproduction": {
            "setup_argvs": [list(COMPILE)],
            "argv": list(TRIGGER),
            "cwd": "/code",
            "timeout": 60,
            "oracle": {
                "type": "combined_regex",
                "pattern": "AddressSanitizer.*heap-buffer-overflow",
            },
        },
    }


def _hunt_payload(finding: dict) -> dict:
    recipe = finding["reproduction"]
    cwd = recipe["cwd"]
    timeout = recipe["timeout"]
    return {
        "findings": [finding],
        "written_pocs": ["poc.c"],
        "executions": [
            {
                "argv": list(COMPILE),
                "cwd": cwd,
                "timeout": timeout,
                "exit_code": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
                "duration_ms": 20,
            },
            {
                "argv": list(recipe["argv"]),
                "cwd": cwd,
                "timeout": timeout,
                "exit_code": 1,
                "stdout": "",
                "stderr": "ERROR: AddressSanitizer: heap-buffer-overflow",
                "timed_out": False,
                "duration_ms": 30,
            },
        ],
    }
