from __future__ import annotations

import json
import os
from pathlib import Path
from typing import cast

import pytest
from jsonschema import validate

from tests.factories import HASH_B, candidate
from vulnhunt_agent.core.codex_client import CodexSubscriptionClient
from vulnhunt_agent.core.llm import LLMClient, LLMResponse
from vulnhunt_agent.core.settings import ProviderSpec
from vulnhunt_agent.domain.schemas import (
    OracleSpec,
    OracleType,
    PocSpec,
    ReproductionSpec,
    RunRecord,
)
from vulnhunt_agent.domain.states import FindingState, RunState
from vulnhunt_agent.infrastructure.artifacts import ArtifactStore
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.intake.snapshot import SnapshotBuilder
from vulnhunt_agent.interfaces.cli import main as cli_main
from vulnhunt_agent.reporting.sarif import (
    build_sarif,
    validate_sarif,
)
from vulnhunt_agent.reporting.service import StrictReportService
from vulnhunt_agent.reproduction.service import ReproducerService
from vulnhunt_agent.reviewing.agent import EvidenceReviewerAgent
from vulnhunt_agent.reviewing.packet import EvidenceReviewPacketBuilder
from vulnhunt_agent.reviewing.service import EvidenceReviewCoordinator
from vulnhunt_agent.sandbox.base import ExecResult, SandboxExecution, SandboxJob


class FakeSandboxBackend:
    def __init__(self):
        self.jobs: list[SandboxJob] = []

    async def execute(self, job: SandboxJob) -> SandboxExecution:
        self.jobs.append(job)
        return SandboxExecution(
            image_digest=HASH_B,
            result=ExecResult(
                exit_code=0,
                stdout="token=supersecret LEAKED_SECRET=1",
                stderr="",
                duration_ms=10 + len(self.jobs),
            ),
        )


class FakeReviewClient:
    def __init__(self, payload: dict):
        self.payload = payload
        self.calls = 0

    async def chat(self, **kwargs) -> LLMResponse:
        self.calls += 1
        text = json.dumps(self.payload)
        return LLMResponse(
            text=text,
            input_tokens=100,
            output_tokens=30,
            cache_read_tokens=0,
            cache_write_tokens=0,
            stop_reason="end_turn",
            content_blocks=[{"text": text}],
        )


async def test_high_finding_requires_two_evidence_citing_reviewers_and_exports(
    tmp_path, capsys,
) -> None:
    repository, artifacts, evidence_ids = await _reproduced_candidate(tmp_path)
    coordinator = EvidenceReviewCoordinator(repository, artifacts)
    first_client = FakeReviewClient(_real_proposal(evidence_ids))
    first = _agent("reviewer-a", first_client, "challenge reachability")

    pending = await coordinator.review("cand-1", [first])
    assert pending.status.value == "needs_second_review"
    pending_finding = repository.get_candidate("cand-1")
    assert pending_finding is not None
    assert pending_finding.state is FindingState.REPRODUCED

    second_client = FakeReviewClient(_real_proposal(evidence_ids))
    second = _agent("reviewer-b", second_client, "challenge impact")
    consensus = await coordinator.review("cand-1", [first, second])
    assert consensus.status.value == "verified"
    assert consensus.reviewers == ("reviewer-a", "reviewer-b")
    reviewed = repository.get_candidate("cand-1")
    assert reviewed is not None
    assert reviewed.state is FindingState.REVIEWER_VERIFIED
    assert any(item.startswith("ev_review_") for item in reviewed.evidence_ids)
    assert first_client.calls == 1
    assert second_client.calls == 1

    bundle = StrictReportService(repository, artifacts).materialize(
        tmp_path / "exports",
        run_id="run-1",
        candidate_id="cand-1",
        markdown="# ignored free-form narrative",
    )
    canonical = json.loads(bundle.json_path.read_text())
    sarif = json.loads(bundle.sarif_path.read_text())
    validate_sarif(sarif)
    assert canonical["classification"]["cwe_id"] == "CWE-918"
    assert canonical["classification"]["severity"] == "high"
    assert canonical["provenance"]["reviewers"] == ["reviewer-a", "reviewer-b"]
    assert set(evidence_ids).issubset(canonical["provenance"]["evidence_ids"])
    markdown = bundle.report_path.read_text()
    assert "# ignored free-form narrative" not in markdown
    assert all(evidence_id in markdown for evidence_id in evidence_ids)
    assert sarif["runs"][0]["results"][0]["ruleId"] == "CWE-918"
    assert sarif["runs"][0]["results"][0]["level"] == "error"

    replay = StrictReportService(repository, artifacts).materialize(
        tmp_path / "exports",
        run_id="run-1",
        candidate_id="cand-1",
    )
    assert replay == bundle
    reportable = repository.get_candidate("cand-1")
    assert reportable is not None
    assert reportable.state is FindingState.REPORTABLE

    assert cli_main([
        "--db", str(repository.path),
        "export", "run-1",
        "--candidate", "cand-1",
        "--artifacts", str(artifacts.root),
        "--output", str(tmp_path / "cli-exports"),
    ]) == 0
    cli_output = json.loads(capsys.readouterr().out)
    assert cli_output[0]["candidate_id"] == "cand-1"
    assert cli_output[0]["sarif"].endswith("report.sarif")
    repository.close()


async def test_reviewer_disagreement_transitions_to_unclear(tmp_path) -> None:
    repository, artifacts, evidence_ids = await _reproduced_candidate(tmp_path)
    coordinator = EvidenceReviewCoordinator(repository, artifacts)
    real = _agent(
        "reviewer-a",
        FakeReviewClient(_real_proposal(evidence_ids)),
        "challenge reachability",
    )
    false_positive = _agent(
        "reviewer-b",
        FakeReviewClient({
            "verdict": "false_positive",
            "notes": "The second review concludes the boundary blocks impact.",
            "cvss_vector": "",
            "cwe_id": "",
            "evidence_ids": list(evidence_ids),
            "variant_request": None,
        }),
        "challenge defenses",
    )

    decision = await coordinator.review("cand-1", [real, false_positive])

    assert decision.status.value == "disagreement"
    unclear = repository.get_candidate("cand-1")
    assert unclear is not None
    assert unclear.state is FindingState.UNCLEAR
    assert not (tmp_path / "exports").exists()
    repository.close()


async def test_two_names_with_the_same_review_configuration_do_not_pass(
    tmp_path,
) -> None:
    repository, artifacts, evidence_ids = await _reproduced_candidate(tmp_path)
    coordinator = EvidenceReviewCoordinator(repository, artifacts)
    first = _agent(
        "reviewer-a",
        FakeReviewClient(_real_proposal(evidence_ids)),
        "same challenge",
    )
    second = _agent(
        "reviewer-b",
        FakeReviewClient(_real_proposal(evidence_ids)),
        "same challenge",
    )

    decision = await coordinator.review("cand-1", [first, second])

    assert decision.status.value == "needs_second_review"
    assert "distinct model/prompt" in decision.reasons[0]
    finding = repository.get_candidate("cand-1")
    assert finding is not None and finding.state is FindingState.REPRODUCED
    repository.close()


async def test_unclear_reviewer_can_only_queue_a_reproduction_variant(tmp_path) -> None:
    repository, artifacts, evidence_ids = await _reproduced_candidate(tmp_path)
    backend_jobs_before = len(repository.list_tasks("run-1"))
    reviewer = _agent(
        "reviewer-a",
        FakeReviewClient({
            "verdict": "unclear",
            "notes": "A safe control input is needed.",
            "cvss_vector": "",
            "cwe_id": "",
            "evidence_ids": list(evidence_ids),
            "variant_request": {
                "variant_type": "safe_input",
                "rationale": "Distinguish the vulnerable path from parser failure.",
                "requested_change": "Replace the attacker URL with a loopback-safe URL.",
            },
        }),
        "request negative control",
    )

    decision = await EvidenceReviewCoordinator(
        repository, artifacts
    ).review("cand-1", [reviewer])

    assert decision.status.value == "variant_requested"
    finding = repository.get_candidate("cand-1")
    assert finding is not None and finding.state is FindingState.REPRODUCED
    tasks = repository.list_tasks("run-1")
    variants = [task for task in tasks if task["task_type"] == "reproduction_variant"]
    assert len(tasks) == backend_jobs_before + 1
    assert len(variants) == 1
    assert variants[0]["status"] == "pending"
    assert "argv" not in variants[0]["payload"]
    assert repository.list_verdicts("cand-1") == []
    repository.close()


async def test_packet_redacts_secrets_and_rejects_unapproved_cwe(tmp_path) -> None:
    repository, artifacts, evidence_ids = await _reproduced_candidate(tmp_path)
    packet = EvidenceReviewPacketBuilder(repository, artifacts).build("cand-1")
    assert "supersecret" not in packet.model_dump_json()
    assert "[REDACTED]" in packet.model_dump_json()

    reviewer = _agent(
        "reviewer-a",
        FakeReviewClient({
            **_real_proposal(evidence_ids),
            "cwe_id": "CWE-9999",
        }),
        "invalid classification",
    )
    with pytest.raises(ValueError, match="unsupported CWE"):
        await EvidenceReviewCoordinator(
            repository, artifacts
        ).review("cand-1", [reviewer])
    assert repository.list_verdicts("cand-1") == []
    repository.close()


@pytest.mark.skipif(
    os.environ.get("VULNHUNT_RUN_CODEX_TESTS") != "1",
    reason="requires an interactive Codex ChatGPT login",
)
async def test_live_codex_subscription_reviewer_returns_contract(
    tmp_path, monkeypatch,
) -> None:
    repository, artifacts, evidence_ids = await _reproduced_candidate(tmp_path)
    provider = ProviderSpec(
        name="codex-live",
        kind="openai_auto",
        reasoning_effort="medium",
        codex_timeout_seconds=180,
        codex_max_parallel=1,
    )
    monkeypatch.setattr(
        "vulnhunt_agent.core.codex_client._settings.resolve",
        lambda model_id: (None, provider),
    )
    client = CodexSubscriptionClient("gpt-5.6-sol", max_tokens=1200)
    reviewer = EvidenceReviewerAgent(
        client=cast(LLMClient, client),
        reviewer="codex-live-smoke",
        model_id="gpt-5.6-sol",
        prompt_variant="challenge whether the evidence proves the claimed root cause",
        max_attempts=2,
        max_tokens=1200,
    )

    proposal = await reviewer.review(
        EvidenceReviewPacketBuilder(repository, artifacts).build("cand-1")
    )

    assert set(proposal.evidence_ids).issubset(evidence_ids)
    repository.close()


@pytest.mark.skipif(
    not os.environ.get("VULNHUNT_SARIF_SCHEMA_PATH"),
    reason="set VULNHUNT_SARIF_SCHEMA_PATH to the downloaded OASIS schema",
)
def test_sarif_passes_complete_oasis_2_1_0_schema() -> None:
    canonical = {
        "run": {
            "run_id": "run-1",
            "source_snapshot": "sha256:" + "a" * 64,
        },
        "finding": {
            "candidate_id": "cand-1",
            "fingerprint": "f" * 64,
            "title": "Unvalidated outbound URL",
            "entrypoint": {"path": "app.py", "line": 6, "end_line": None},
            "sink": {"path": "app.py", "line": 8, "end_line": None},
            "impact": ["Read internal resources"],
        },
        "classification": {
            "cwe_id": "CWE-918",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_score": 7.5,
            "severity": "high",
        },
        "provenance": {
            "reviewers": ["reviewer-a", "reviewer-b"],
            "evidence_ids": ["ev-1", "ev-2"],
        },
    }
    sarif = build_sarif(canonical)
    schema_path = Path(os.environ["VULNHUNT_SARIF_SCHEMA_PATH"])
    schema = json.loads(schema_path.read_text())
    validate(instance=sarif, schema=schema)


def _agent(
    name: str, client: FakeReviewClient, prompt_variant: str
) -> EvidenceReviewerAgent:
    return EvidenceReviewerAgent(
        client=cast(LLMClient, client),
        reviewer=name,
        model_id="fake-review-model",
        prompt_variant=prompt_variant,
    )


def _real_proposal(evidence_ids: tuple[str, ...]) -> dict:
    return {
        "verdict": "real",
        "notes": "Two clean attempts demonstrate attacker-controlled SSRF.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-918",
        "evidence_ids": list(evidence_ids),
        "variant_request": None,
    }


async def _reproduced_candidate(
    tmp_path,
) -> tuple[SqliteRepository, ArtifactStore, tuple[str, ...]]:
    artifacts = ArtifactStore(tmp_path / "artifacts")
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('target loaded')\n")
    snapshot = SnapshotBuilder(artifacts).create(source)
    poc = artifacts.put_text("print('LEAKED_SECRET=1')\n", "text/x-python")

    repository = SqliteRepository(tmp_path / "state.db")
    repository.save_run(RunRecord(
        run_id="run-1",
        source_url="https://example.test/repo.git",
        source_ref="deadbeef",
    ))
    repository.transition_run(
        "run-1", RunState.SNAPSHOTTING, idempotency_key="snapshot:start"
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
        "cand-1", PocSpec(artifact=poc.digest, argv=argv, cwd=".")
    )
    repository.transition_finding(
        "cand-1", FindingState.POC_READY, idempotency_key="hunt:poc-ready"
    )
    outcome = await ReproducerService(
        repository, artifacts, FakeSandboxBackend()
    ).reproduce(ReproductionSpec(
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
        oracle=OracleSpec(type=OracleType.STDOUT_REGEX, pattern=r"LEAKED_SECRET=1"),
    ))
    return (
        repository,
        artifacts,
        tuple(item.evidence_id for item in outcome.evidence),
    )
