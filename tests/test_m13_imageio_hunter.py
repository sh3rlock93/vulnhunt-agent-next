from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from vulnhunt_agent.agents.durable_queue import DurableHuntQueueStore
from vulnhunt_agent.core.llm import LLMResponse
from vulnhunt_agent.domain.schemas import BudgetPolicy, RunRecord
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.macos.imageio_crashes import build_imageio_crash_hunter_plan
from vulnhunt_agent.macos.imageio_fuzzer import (
    ImageIOFuzzCase,
    ImageIOFuzzCaseResult,
    ImageIOFuzzClassification,
    ImageIOFuzzExecution,
    ImageIOMutationOperator,
    build_minimal_dicom_seed,
)
from vulnhunt_agent.macos.imageio_harness import (
    ImageIOHarnessEvidence,
    ImageIOHarnessLimits,
    ImageIOVMExitReason,
)
from vulnhunt_agent.macos.imageio_hunter import (
    ImageIOExperimentPlanStatus,
    ImageIOHunterAgent,
    ImageIOHunterAssessment,
    build_imageio_hunter_packet,
    execute_imageio_hunter_plan,
    plan_imageio_experiments,
    review_imageio_experiment,
)
from vulnhunt_agent.macos.imageio_inventory import ImageIOAPIRoute

SOURCE_SNAPSHOT = "sha256:" + "a" * 64
PRE_ATTESTATION = "sha256:" + "b" * 64
POST_ATTESTATION = "sha256:" + "c" * 64


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _write_crash_case(store: Path, *, crash_padding: int = 0) -> None:
    payload = build_minimal_dicom_seed()
    crash_log = (
        b"""Process: imageio-harness
Exception Type: EXC_BAD_ACCESS (SIGSEGV)
Exception Subtype: KERN_INVALID_ADDRESS at 0x0000000123456789
ERROR: AddressSanitizer: heap-use-after-free
Thread 0 Crashed:
0   ImageIO  0x00000001 DICOMDecodePixelData + 44
1   ImageIO  0x00000002 DICOMCreateImage + 54
2   imageio-harness 0x00000003 main + 99
"""
        + b"A" * crash_padding
    )
    route = ImageIOAPIRoute.FULL_DECODE
    case_id = "case-" + "1" * 32
    evidence = ImageIOHarnessEvidence(
        environment_id="imageio-vm-test-hunter",
        boot_id="boot-test-001",
        route=route,
        input_sha256=_sha256(payload),
        input_size_bytes=len(payload),
        argv=("/opt/vulnhunt/bin/imageio-harness", "--route", route.value),
        limits=ImageIOHarnessLimits(),
        exit_reason=ImageIOVMExitReason.SIGNALED,
        exit_code=None,
        terminating_signal=11,
        duration_ms=4,
        stdout_sha256=_sha256(b""),
        stderr_sha256=_sha256(b""),
        crash_log_sha256=_sha256(crash_log),
        pre_attestation_sha256=PRE_ATTESTATION,
        post_attestation_sha256=POST_ATTESTATION,
        evidence_complete=True,
    )
    case = ImageIOFuzzCase(
        case_id=case_id,
        campaign_seed="hunter-test-campaign",
        seed_sha256="sha256:" + "d" * 64,
        input_sha256=_sha256(payload),
        input_size_bytes=len(payload),
        operator=ImageIOMutationOperator.VALUE_BIT_FLIP,
        target_tag="0028,0010",
        target_offset=140,
        parameter="relative:0:mask:0x80",
        routes=(route,),
    )
    result = ImageIOFuzzCaseResult(
        case=case,
        executions=(
            ImageIOFuzzExecution(
                route=route,
                classification=ImageIOFuzzClassification.CRASH_CANDIDATE,
                evidence=evidence,
            ),
        ),
        interesting=True,
    )
    cases = store / "cases"
    cases.mkdir(parents=True)
    (cases / f"{case_id}.json").write_text(
        json.dumps(result.model_dump(mode="json")),
        encoding="utf-8",
    )
    route_root = store / "interesting" / case_id / route.value
    route_root.mkdir(parents=True)
    (route_root.parent / "input.dcm").write_bytes(payload)
    (route_root / "crash.log").write_bytes(crash_log)


def _assessment(packet: dict, *, evidence_id: str | None = None) -> dict:
    evidence_refs = packet["evidence_refs"]
    cited = [
        evidence_id or evidence_refs[2]["evidence_id"],
        evidence_refs[3]["evidence_id"],
    ]
    return {
        "work_id": packet["work_id"],
        "cluster_id": packet["cluster"]["cluster_id"],
        "disposition": "memory_safety_hypothesis",
        "summary": "The retained non-null bad-access evidence supports bounded replay.",
        "hypotheses": [
            {
                "hypothesis_id": "hypothesis-pixel-length",
                "title": "Pixel length may outlive its backing allocation",
                "proposed_crash_class": "use_after_free",
                "attacker_control": "The DICOM pixel-length field and encoded bytes.",
                "parser_state": "ImageIO is decoding DICOM pixel data.",
                "size_allocation_relation": "The retained stack does not expose the allocation size.",
                "root_cause_hypothesis": "Hypothesis: a mutated length reaches a stale pixel buffer.",
                "falsification_condition": "Exact replay does not reproduce the normalized signature.",
                "confidence": 0.63,
                "evidence_refs": cited,
            }
        ],
        "experiment_proposals": [
            {
                "proposal_id": "experiment-exact-replay",
                "hypothesis_id": "hypothesis-pixel-length",
                "kind": "exact_replay",
                "rationale": "Confirm that the retained input deterministically reaches the signature.",
                "route": "full_decode",
                "target_tag": None,
                "boundary_values": [],
                "incremental_chunk_sizes": [],
                "execution_limit": 3,
                "expected_observation": "Three runs reproduce the same normalized signature.",
                "falsification_condition": "The signature does not recur.",
            }
        ],
        "evidence_refs": cited,
        "unresolved_questions": ["The exact allocation site is not yet available."],
    }


class _FakeImageIOClient:
    model_id = "test-imageio-model"
    transport = "test"

    def __init__(self, responses: Callable[[dict, int], dict]) -> None:
        self._responses = responses
        self.calls = 0

    async def chat(
        self,
        messages: list[dict],
        system: str | None = None,
        tools: list[dict] | None = None,
        max_tokens: int | None = None,
        cache_system: bool = False,
        cache_tools: bool = False,
        cache_last_user: bool = False,
    ) -> LLMResponse:
        del system, tools, max_tokens, cache_system, cache_tools, cache_last_user
        self.calls += 1
        packet = json.loads(messages[0]["content"][0]["text"].split("\n", 1)[1])
        text = json.dumps(self._responses(packet, self.calls))
        return LLMResponse(
            text=text,
            input_tokens=100,
            output_tokens=50,
            cache_read_tokens=0,
            cache_write_tokens=0,
            stop_reason="end_turn",
            content_blocks=[{"text": text}],
        )


def _plan(store: Path, *, run_id: str = "imageio-hunter-run"):
    return build_imageio_crash_hunter_plan(
        store_root=store,
        run_id=run_id,
        source_snapshot=SOURCE_SNAPSHOT,
        budget=BudgetPolicy(max_hunter_sessions=4),
    )


def test_packet_verifies_artifacts_and_bounds_large_crash_log(tmp_path: Path) -> None:
    store = tmp_path / "private-campaign"
    store.mkdir()
    _write_crash_case(store, crash_padding=40 * 1024)
    plan = _plan(store)

    packet = build_imageio_hunter_packet(
        store_root=store,
        work_item=plan.admitted_work_items[0],
    )

    assert len(packet.crash_log_excerpt.encode()) == 32 * 1024
    assert {item.kind for item in packet.evidence_refs} == {
        "cluster",
        "case",
        "input",
        "crash_log",
    }
    assert packet.format_grammar.parse_complete is True
    assert packet.format_grammar.elements[-1].tag == "7FE0,0010"
    assert packet.host_execution_allowed is False
    assert packet.network_allowed is False


@pytest.mark.asyncio
async def test_hunter_repairs_an_out_of_packet_evidence_citation(tmp_path: Path) -> None:
    store = tmp_path / "private-campaign"
    store.mkdir()
    _write_crash_case(store)
    plan = _plan(store)
    item = plan.admitted_work_items[0]
    packet = build_imageio_hunter_packet(store_root=store, work_item=item)
    client = _FakeImageIOClient(
        lambda payload, call: _assessment(
            payload,
            evidence_id=("imageio-evidence-" + "f" * 20 if call == 1 else None),
        )
    )

    assessment, usage = await ImageIOHunterAgent(client).analyze(item, packet)

    assert client.calls == 2
    assert assessment.work_id == item.work_id
    assert usage.calls == 2
    assert usage.sessions == 1
    assert usage.input_tokens == 200


@pytest.mark.asyncio
async def test_existing_durable_queue_runs_hunter_and_gates_experiment(
    tmp_path: Path,
) -> None:
    store = tmp_path / "private-campaign"
    store.mkdir()
    _write_crash_case(store)
    run_id = "imageio-hunter-durable-run"
    plan = _plan(store, run_id=run_id)
    database = store / "state.db"
    with SqliteRepository(database) as repository:
        repository.save_run(RunRecord(run_id=run_id, source_snapshot=SOURCE_SNAPSHOT))

    def exact_replay_without_model_route(packet: dict, _call: int) -> dict:
        payload = _assessment(packet)
        payload["experiment_proposals"][0]["route"] = None
        return payload

    client = _FakeImageIOClient(exact_replay_without_model_route)

    results = await execute_imageio_hunter_plan(
        plan=plan,
        store_root=store,
        database=database,
        client=client,
        budget=BudgetPolicy(max_hunter_sessions=4),
    )

    assert len(results) == 1
    result = results[0]
    assert result.experiment_plans[0].status is ImageIOExperimentPlanStatus.REVIEW_REQUIRED
    assert result.experiment_plans[0].route is ImageIOAPIRoute.FULL_DECODE
    assert result.experiment_plans[0].parameters["input_sha256"] == (
        result.packet.format_grammar.input_sha256
    )
    assert result.experiment_plans[0].auto_execute is False
    output = store / "hunters" / result.packet.work_id / "imageio-analysis"
    assert (output / "assessment.json").exists()
    assert (output / "experiment-plans.json").exists()
    queue = DurableHuntQueueStore(store / "hunters", database, run_id).load()
    assert queue.tasks[0].status == "done"
    with SqliteRepository(database, read_only=True) as repository:
        usage = repository.list_budget_usage(run_id, scope="hunter")
    assert len(usage) == 1
    assert usage[0].sessions == 1

    review = review_imageio_experiment(
        result.experiment_plans[0],
        reviewer="independent-reviewer",
        approved=True,
        rationale="The replay is bounded to the retained input and signature.",
    )
    assert review.approved is True


@pytest.mark.asyncio
async def test_shared_token_budget_defers_before_model_call(tmp_path: Path) -> None:
    store = tmp_path / "private-campaign"
    store.mkdir()
    _write_crash_case(store)
    run_id = "imageio-hunter-budget-run"
    plan = _plan(store, run_id=run_id)
    database = store / "state.db"
    with SqliteRepository(database) as repository:
        repository.save_run(RunRecord(run_id=run_id, source_snapshot=SOURCE_SNAPSHOT))
    client = _FakeImageIOClient(lambda packet, _call: _assessment(packet))

    results = await execute_imageio_hunter_plan(
        plan=plan,
        store_root=store,
        database=database,
        client=client,
        budget=BudgetPolicy(
            max_hunter_sessions=4,
            max_input_tokens=1,
            max_output_tokens=1,
        ),
    )

    assert results == ()
    assert client.calls == 0
    queue = DurableHuntQueueStore(store / "hunters", database, run_id).load()
    assert queue.tasks[0].status == "budget_deferred"
    with SqliteRepository(database, read_only=True) as repository:
        assert repository.list_budget_usage(run_id, scope="hunter") == []


def test_non_runnable_experiment_cannot_be_approved(tmp_path: Path) -> None:
    store = tmp_path / "private-campaign"
    store.mkdir()
    _write_crash_case(store)
    plan = _plan(store)
    packet = build_imageio_hunter_packet(
        store_root=store,
        work_item=plan.admitted_work_items[0],
    )
    payload = _assessment(packet.model_dump(mode="json"))
    payload["experiment_proposals"][0]["kind"] = "binary_context"
    payload["experiment_proposals"][0]["route"] = None
    assessment = ImageIOHunterAssessment.model_validate(payload)

    experiment = plan_imageio_experiments(packet=packet, assessment=assessment)[0]
    assert experiment.status is ImageIOExperimentPlanStatus.REQUIRES_BINARY_CONTEXT
    assert experiment.execution_limit == 0
    with pytest.raises(ValueError, match="review-ready"):
        review_imageio_experiment(
            experiment,
            reviewer="independent-reviewer",
            approved=True,
            rationale="This still needs bounded binary context.",
        )
