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
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.reviewing.agent import EvidenceReviewerAgent
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
                stderr="ERROR: AddressSanitizer: heap-buffer-overflow",
                duration_ms=30,
            ),
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
