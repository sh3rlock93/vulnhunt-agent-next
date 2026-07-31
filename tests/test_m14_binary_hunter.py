from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from vulnhunt_agent.agents.durable_queue import DurableHuntQueueStore
from vulnhunt_agent.core.llm import LLMResponse
from vulnhunt_agent.domain.schemas import BudgetPolicy, RunRecord
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.macos.binary_analysis import (
    AUTHORIZED_RESEARCH_SCOPE_PROMPT,
    BinaryExperimentPlanStatus,
    BinaryHunterAgent,
    BinaryHunterAssessment,
    BinaryHunterPacket,
    BinaryRankingPolicy,
    BinaryResearchScope,
    DyldArchitecture,
    GhidraJSONAdapter,
    analyze_binary_candidates,
    build_binary_hunter_plan,
    capture_dyld_shared_cache_snapshot,
    create_binary_research_scope,
    discover_imageio_parsers,
    execute_binary_hunter_plan,
    load_binary_hunter_packet,
    pack_ranked_binary_contexts,
    plan_binary_experiments,
    rank_binary_functions,
    validate_binary_hunter_assessment,
)

_CACHE_UUID = uuid.UUID("82345678-1234-5678-9abc-def012345678")
_IMAGE_UUID = "92345678-1234-5678-9ABC-DEF012345678"
_INPUT = "sha256:" + "a" * 64


def _write_cache(path: Path) -> None:
    header = bytearray(104)
    header[:16] = b"dyld_v1  arm64e\0"
    header[88:104] = _CACHE_UUID.bytes
    path.write_bytes(bytes(header) + b"m14-pr6-test-cache")


def _instruction(
    address: int,
    op: str,
    *,
    result: str | None = None,
    inputs: list[str] | None = None,
    target: str | None = None,
    tags: list[str] | None = None,
    constants: list[int] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "address": hex(address),
        "op": op,
        "inputs": inputs or [],
        "text": op,
    }
    if result is not None:
        value["result"] = result
    if target is not None:
        value["target"] = target
    if tags:
        value["tags"] = tags
    if constants:
        value["constants"] = constants
    return value


def _function(
    address: int,
    name: str,
    instructions: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "entry": hex(address),
        "size": 256,
        "name": name,
        "parameters": [],
        "pseudocode": f"static evidence for {name}; " + "A" * 380,
        "blocks": [
            {
                "name": "entry",
                "start": hex(address),
                "size": 256,
                "successors": [],
                "instructions": instructions,
            }
        ],
    }


def _pipeline(tmp_path: Path):
    primary = tmp_path / "dyld_shared_cache_arm64e"
    _write_cache(primary)
    snapshot = capture_dyld_shared_cache_snapshot(
        primary,
        product_version="26.0",
        build_version="25A123",
        architecture=DyldArchitecture.ARM64,
        captured_at=datetime(2026, 7, 31, 1, 0, tzinfo=UTC),
    )
    base = 0x100001000
    payload = {
        "schema_version": "ghidra-imageio-export-v1",
        "decompiler_version": "11.4",
        "snapshot_sha256": snapshot.snapshot_sha256,
        "image": {
            "name": "ImageIO",
            "uuid": _IMAGE_UUID,
            "architecture": "arm64",
            "base_address": "0x100000000",
        },
        "imports": ["free", "malloc"],
        "strings": [],
        "functions": [
            _function(
                base,
                "DICOMDecodeLength",
                [
                    _instruction(base, "param", result="length", tags=["input_length"]),
                    _instruction(
                        base + 4,
                        "mul",
                        result="bytes",
                        inputs=["length"],
                        constants=[16],
                    ),
                    _instruction(
                        base + 8,
                        "alloc",
                        result="buffer",
                        inputs=["bytes"],
                        target="malloc",
                    ),
                ],
            ),
            _function(
                base + 0x1000,
                "DICOMReleaseData",
                [
                    _instruction(
                        base + 0x1000,
                        "param",
                        result="pointer",
                        tags=["input_data"],
                    ),
                    _instruction(
                        base + 0x1004,
                        "free",
                        inputs=["pointer"],
                        target="free",
                    ),
                    _instruction(
                        base + 0x1008,
                        "load",
                        result="value",
                        inputs=["pointer"],
                    ),
                ],
            ),
            _function(
                base + 0x2000,
                "DICOMCheckedLength",
                [
                    _instruction(
                        base + 0x2000,
                        "param",
                        result="length",
                        tags=["input_length"],
                    ),
                    _instruction(base + 0x2004, "cmp", inputs=["length", "maximum"]),
                    _instruction(base + 0x2008, "return"),
                ],
            ),
        ],
    }
    ir = GhidraJSONAdapter().normalize(
        payload,
        expected_snapshot_sha256=snapshot.snapshot_sha256,
        created_at=datetime(2026, 7, 31, 1, 1, tzinfo=UTC),
    )
    discovery = discover_imageio_parsers(ir)
    report = analyze_binary_candidates(ir, discovery)
    policy = BinaryRankingPolicy(
        context_budget_bytes=700,
        maximum_segment_bytes=620,
        maximum_packs=8,
        maximum_pseudocode_bytes=500,
    )
    ranking = rank_binary_functions(ir, discovery, report, policy=policy)
    context_plan = pack_ranked_binary_contexts(
        ir,
        discovery,
        report,
        ranking,
        policy=policy,
    )
    scope = create_binary_research_scope(
        snapshot_sha256=snapshot.snapshot_sha256,
        authorization_basis="Analyst-owned macOS VM and locally installed ImageIO binary",
    )
    return snapshot, ir, discovery, report, ranking, context_plan, scope


def _plan(store: Path, evidence_root: Path, *, sessions: int = 8, retained: bool = True):
    snapshot, ir, discovery, report, ranking, context_plan, scope = _pipeline(evidence_root)
    plan = build_binary_hunter_plan(
        store_root=store,
        run_id="m14-binary-hunter-test",
        snapshot=snapshot,
        ir=ir,
        discovery=discovery,
        report=report,
        ranking=ranking,
        context_plan=context_plan,
        scope=scope,
        budget=BudgetPolicy(max_hunter_sessions=sessions),
        retained_input_sha256s=(_INPUT,) if retained else (),
    )
    return plan, (snapshot, ir, discovery, report, ranking, context_plan, scope)


def _evidence(packet: dict, kind: str) -> str:
    return next(item["evidence_id"] for item in packet["evidence_refs"] if item["kind"] == kind)


def _assessment(
    packet: dict,
    *,
    disposition: str = "static_hypothesis",
    experiment_kind: str | None = None,
) -> dict:
    supporting = sorted([_evidence(packet, "static_finding"), _evidence(packet, "parser_input")])
    hypothesis_id = "binhypothesis-length-allocation"
    request: dict[str, Any] | None = None
    if experiment_kind is not None:
        request = {
            "request_id": "binexperiment-bounded-observation",
            "hypothesis_id": hypothesis_id,
            "kind": experiment_kind,
            "rationale": "One bounded observation distinguishes the static relation.",
            "retained_input_sha256": _INPUT,
            "target_format": None,
            "target_field": None,
            "baseline_route": None,
            "route": "full_decode",
            "boundary_values": [],
            "incremental_chunk_sizes": [],
            "context_function_ids": [],
            "target_build": None,
            "execution_limit": 1,
            "expected_observation": "The same parser state reaches the cited relation.",
            "falsification_condition": "The parser rejects the input before the cited relation.",
            "evidence_refs": supporting,
            "auto_execute": False,
        }
        if experiment_kind == "structured_field_boundary":
            request.update(
                target_format="dicom",
                target_field="Rows",
                boundary_values=[0, 65535],
            )
        elif experiment_kind == "api_route_differential":
            request.update(baseline_route="image_properties", route="full_decode")
        elif experiment_kind == "incremental_chunk_schedule":
            request.update(route="incremental_decode", incremental_chunk_sizes=[1, 8, 64])
        elif experiment_kind == "binary_context":
            request.update(
                retained_input_sha256=None,
                route=None,
                context_function_ids=[packet["known_function_ids"][0]],
            )
        elif experiment_kind == "guard_malloc":
            request.update(route="full_decode")
        elif experiment_kind == "cross_build_replay":
            request.update(target_build="26.1-25B100")
        elif experiment_kind == "raw_output_differential":
            request.update(route="full_decode")
        elif experiment_kind == "canary_propagation":
            request.update(route="full_decode", canary_value=165)
    return {
        "work_id": packet["work_id"],
        "pack_id": packet["pack"]["pack_id"],
        "pack_sequence": packet["pack"]["sequence"],
        "disposition": disposition,
        "summary": "The digest-bound evidence supports a bounded static hypothesis.",
        "hypotheses": [
            {
                "hypothesis_id": hypothesis_id,
                "title": "Input length may exceed its allocation relation",
                "vulnerability_class": packet["findings"][0]["vulnerability_class"],
                "input_control": "The normalized input-length parameter is attacker controlled.",
                "parser_state": "The DICOM parser is preparing a memory operation.",
                "security_relation": "Input-derived arithmetic reaches the cited memory sink.",
                "root_cause_hypothesis": "The arithmetic may wrap before allocation.",
                "falsification_condition": "A dominating bound proves the arithmetic safe.",
                "confidence": 0.72,
                "supporting_evidence_ids": supporting,
                "contradicting_evidence_ids": [],
            }
        ],
        "experiment_requests": [request] if request is not None else [],
        "evidence_refs": supporting,
        "unresolved_questions": ["The dynamic behavior has not been observed."],
    }


class _FakeClient:
    model_id = "test-binary-hunter-model"
    transport = "test"

    def __init__(self, response: Callable[[dict, int], dict]) -> None:
        self.response = response
        self.calls = 0
        self.system_prompts: list[str] = []

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
        del tools, max_tokens, cache_system, cache_tools, cache_last_user
        self.calls += 1
        self.system_prompts.append(system or "")
        packet = json.loads(messages[0]["content"][0]["text"].split("\n", 1)[1])
        text = json.dumps(self.response(packet, self.calls))
        return LLMResponse(
            text=text,
            input_tokens=100,
            output_tokens=50,
            cache_read_tokens=0,
            cache_write_tokens=0,
            stop_reason="end_turn",
            content_blocks=[{"text": text}],
        )


def test_scope_and_packet_bind_complete_chain_and_fixed_permissions(tmp_path: Path) -> None:
    store = tmp_path / "private"
    store.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    plan, chain = _plan(store, evidence)
    packet = load_binary_hunter_packet(
        store_root=store,
        work_item=plan.admitted_work_items[0],
    )
    snapshot, ir, discovery, report, ranking, context_plan, scope = chain

    assert packet.snapshot_sha256 == snapshot.snapshot_sha256
    assert packet.ir_sha256 == ir.ir_sha256
    assert packet.discovery_sha256 == discovery.discovery_sha256
    assert packet.report_sha256 == report.report_sha256
    assert packet.ranking_sha256 == ranking.ranking_sha256
    assert packet.context_plan_sha256 == context_plan.plan_sha256
    assert packet.scope.scope_sha256 == scope.scope_sha256
    assert packet.host_execution_allowed is False
    assert packet.network_allowed is False
    assert packet.auto_execute is False
    assert "authorized defensive research" in AUTHORIZED_RESEARCH_SCOPE_PROMPT


@pytest.mark.parametrize(
    "field",
    [
        "host_image_execution_allowed",
        "network_allowed",
        "third_party_access_allowed",
        "credential_access_allowed",
        "persistence_allowed",
        "evasion_allowed",
        "weaponization_allowed",
        "public_disclosure_allowed",
        "external_submission_allowed",
        "auto_execute",
    ],
)
def test_scope_rejects_permission_broadening(tmp_path: Path, field: str) -> None:
    _, _, _, _, _, _, scope = _pipeline(tmp_path)
    payload = scope.model_dump(mode="json")
    payload[field] = True

    with pytest.raises(ValidationError):
        BinaryResearchScope.model_validate(payload)


@pytest.mark.parametrize(
    ("component", "digest_field"),
    [
        ("snapshot", "snapshot_sha256"),
        ("ir", "ir_sha256"),
        ("discovery", "discovery_sha256"),
        ("report", "report_sha256"),
        ("ranking", "ranking_sha256"),
        ("context_plan", "plan_sha256"),
        ("scope", "scope_sha256"),
    ],
)
def test_plan_rejects_changed_upstream_digest_before_packet_write(
    tmp_path: Path,
    component: str,
    digest_field: str,
) -> None:
    store = tmp_path / "private"
    store.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    values = list(_pipeline(evidence))
    positions = {
        "snapshot": 0,
        "ir": 1,
        "discovery": 2,
        "report": 3,
        "ranking": 4,
        "context_plan": 5,
        "scope": 6,
    }
    position = positions[component]
    values[position] = values[position].model_copy(update={digest_field: "sha256:" + "f" * 64})
    snapshot, ir, discovery, report, ranking, context_plan, scope = values

    with pytest.raises(ValueError, match="digest does not match"):
        build_binary_hunter_plan(
            store_root=store,
            run_id="changed-chain",
            snapshot=snapshot,
            ir=ir,
            discovery=discovery,
            report=report,
            ranking=ranking,
            context_plan=context_plan,
            scope=scope,
            budget=BudgetPolicy(max_hunter_sessions=2),
        )


def test_packet_rejects_skipped_pack_prefix(tmp_path: Path) -> None:
    store = tmp_path / "private"
    store.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    plan, _ = _plan(store, evidence)
    assert len(plan.routing.work_items) >= 2
    second = load_binary_hunter_packet(store_root=store, work_item=plan.routing.work_items[1])
    payload = second.model_dump(mode="json")
    payload["prior_pack_ids"] = []

    with pytest.raises(ValidationError, match="declared prefix"):
        BinaryHunterPacket.model_validate(payload)


def test_replanning_budget_writes_distinct_content_addressed_manifests(tmp_path: Path) -> None:
    store = tmp_path / "private"
    store.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    first, chain = _plan(store, evidence, sessions=1)
    snapshot, ir, discovery, report, ranking, context_plan, scope = chain

    second = build_binary_hunter_plan(
        store_root=store,
        run_id=first.run_id,
        snapshot=snapshot,
        ir=ir,
        discovery=discovery,
        report=report,
        ranking=ranking,
        context_plan=context_plan,
        scope=scope,
        budget=BudgetPolicy(max_hunter_sessions=2),
        retained_input_sha256s=(_INPUT,),
    )

    assert first.plan_sha256 != second.plan_sha256
    manifests = tuple((store / "binary-hunter-plans").glob("binary-hunter-plan-*.json"))
    assert len(manifests) == 2


def test_static_hypothesis_requires_finding_and_input_evidence(tmp_path: Path) -> None:
    store = tmp_path / "private"
    store.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    plan, _ = _plan(store, evidence)
    packet = load_binary_hunter_packet(store_root=store, work_item=plan.admitted_work_items[0])
    payload = _assessment(packet.model_dump(mode="json"))
    context_ref = next(
        item.evidence_id for item in packet.evidence_refs if item.kind.value == "context_pack"
    )
    input_ref = next(
        item.evidence_id for item in packet.evidence_refs if item.kind.value == "parser_input"
    )
    payload["hypotheses"][0]["supporting_evidence_ids"] = sorted([context_ref, input_ref])
    assessment = BinaryHunterAssessment.model_validate(payload)

    with pytest.raises(ValueError, match="deterministic finding"):
        validate_binary_hunter_assessment(packet, assessment)


def test_unsafe_or_unbound_model_output_is_rejected(tmp_path: Path) -> None:
    store = tmp_path / "private"
    store.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    plan, _ = _plan(store, evidence)
    packet = load_binary_hunter_packet(store_root=store, work_item=plan.admitted_work_items[0])
    payload = _assessment(packet.model_dump(mode="json"))
    payload["summary"] = "Run curl https://example.invalid to continue."
    unsafe = BinaryHunterAssessment.model_validate(payload)
    with pytest.raises(ValueError, match="prohibited network URL"):
        validate_binary_hunter_assessment(packet, unsafe)

    payload = _assessment(packet.model_dump(mode="json"))
    payload["evidence_refs"] = ["binevidence_" + "f" * 20]
    unbound = BinaryHunterAssessment.model_validate(payload)
    with pytest.raises(ValueError, match="outside its packet"):
        validate_binary_hunter_assessment(packet, unbound)


@pytest.mark.parametrize(
    ("kind", "status"),
    [
        ("exact_replay", BinaryExperimentPlanStatus.REVIEW_REQUIRED),
        ("structured_field_boundary", BinaryExperimentPlanStatus.REVIEW_REQUIRED),
        ("api_route_differential", BinaryExperimentPlanStatus.REVIEW_REQUIRED),
        ("incremental_chunk_schedule", BinaryExperimentPlanStatus.REVIEW_REQUIRED),
        ("guard_malloc", BinaryExperimentPlanStatus.REQUIRES_HARNESS),
        ("cross_build_replay", BinaryExperimentPlanStatus.REQUIRES_SNAPSHOT),
        ("binary_context", BinaryExperimentPlanStatus.REQUIRES_CONTEXT),
        ("raw_output_differential", BinaryExperimentPlanStatus.REVIEW_REQUIRED),
        ("canary_propagation", BinaryExperimentPlanStatus.REVIEW_REQUIRED),
    ],
)
def test_typed_experiment_requests_map_without_execution(
    tmp_path: Path,
    kind: str,
    status: BinaryExperimentPlanStatus,
) -> None:
    store = tmp_path / "private"
    store.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    hunter_plan, _ = _plan(store, evidence)
    packet = load_binary_hunter_packet(
        store_root=store,
        work_item=hunter_plan.admitted_work_items[0],
    )
    disposition = "needs_context" if kind == "binary_context" else "needs_experiment"
    assessment = BinaryHunterAssessment.model_validate(
        _assessment(
            packet.model_dump(mode="json"),
            disposition=disposition,
            experiment_kind=kind,
        )
    )

    planned = plan_binary_experiments(packet=packet, assessment=assessment)[0]

    assert planned.status is status
    assert planned.auto_execute is False
    assert planned.host_execution_allowed is False
    assert planned.network_allowed is False
    assert (planned.execution_limit > 0) is (status is BinaryExperimentPlanStatus.REVIEW_REQUIRED)


@pytest.mark.asyncio
async def test_agent_repairs_invalid_citation_and_includes_scope_prompt(tmp_path: Path) -> None:
    store = tmp_path / "private"
    store.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    plan, _ = _plan(store, evidence, sessions=1)
    item = plan.admitted_work_items[0]
    packet = load_binary_hunter_packet(store_root=store, work_item=item)

    def response(value: dict, call: int) -> dict:
        payload = _assessment(value)
        if call == 1:
            payload["evidence_refs"] = ["binevidence_" + "f" * 20]
        return payload

    client = _FakeClient(response)
    assessment, usage, raw = await BinaryHunterAgent(client).analyze(item, packet)

    assert assessment.work_id == item.work_id
    assert usage.calls == 2
    assert len(raw) == 2
    assert all(AUTHORIZED_RESEARCH_SCOPE_PROMPT in value for value in client.system_prompts)


@pytest.mark.asyncio
async def test_durable_execution_preserves_prefix_and_persists_private_evidence(
    tmp_path: Path,
) -> None:
    store = tmp_path / "private"
    store.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    plan, chain = _plan(store, evidence, sessions=2)
    snapshot = chain[0]
    database = store / "state.db"
    with SqliteRepository(database) as repository:
        repository.save_run(RunRecord(run_id=plan.run_id, source_snapshot=snapshot.snapshot_sha256))
    client = _FakeClient(lambda packet, _call: _assessment(packet))

    results = await execute_binary_hunter_plan(
        plan=plan,
        store_root=store,
        database=database,
        client=client,
        budget=BudgetPolicy(max_hunter_sessions=2),
    )

    assert len(results) == 2
    assert [item.packet.pack.sequence for item in results] == [1, 2]
    assert client.calls == 2
    for result in results:
        output = store / "hunters" / result.packet.work_id / "binary-analysis"
        assert (output / "packet.json").stat().st_mode & 0o777 == 0o600
        assert (output / "assessment.json").exists()
        assert (output / "raw-response-01.txt").exists()
    queue = DurableHuntQueueStore(store / "hunters", database, plan.run_id).load()
    assert [task.status for task in queue.tasks] == ["done", "done"]
    with SqliteRepository(database, read_only=True) as repository:
        assert len(repository.list_budget_usage(plan.run_id, scope="hunter")) == 2


@pytest.mark.asyncio
async def test_invalid_response_defers_first_pack_without_skipping_second(tmp_path: Path) -> None:
    store = tmp_path / "private"
    store.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    plan, chain = _plan(store, evidence, sessions=2)
    database = store / "state.db"
    with SqliteRepository(database) as repository:
        repository.save_run(RunRecord(run_id=plan.run_id, source_snapshot=chain[0].snapshot_sha256))
    client = _FakeClient(
        lambda packet, _call: {
            **_assessment(packet),
            "evidence_refs": ["binevidence_" + "f" * 20],
        }
    )

    results = await execute_binary_hunter_plan(
        plan=plan,
        store_root=store,
        database=database,
        client=client,
        budget=BudgetPolicy(max_hunter_sessions=2),
    )

    assert results == ()
    assert client.calls == 2
    queue = DurableHuntQueueStore(store / "hunters", database, plan.run_id).load()
    statuses = {task.work_id: task.status for task in queue.tasks}
    assert statuses[plan.admitted_work_ids[0]] == "budget_deferred"
    assert statuses[plan.admitted_work_ids[1]] == "pending"
    first = store / "hunters" / plan.admitted_work_ids[0] / "binary-analysis"
    attempts = tuple((first / "deferrals").glob("attempt-*"))
    assert len(attempts) == 1
    assert json.loads((attempts[0] / "deferral.json").read_text())["reason"] == (
        "invalid_model_response"
    )
    assert (attempts[0] / "raw-response-02.txt").exists()


@pytest.mark.asyncio
async def test_budget_exhaustion_starts_no_model_and_preserves_pack_cursor(tmp_path: Path) -> None:
    store = tmp_path / "private"
    store.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    plan, chain = _plan(store, evidence, sessions=2)
    database = store / "state.db"
    with SqliteRepository(database) as repository:
        repository.save_run(RunRecord(run_id=plan.run_id, source_snapshot=chain[0].snapshot_sha256))
    client = _FakeClient(lambda packet, _call: _assessment(packet))

    results = await execute_binary_hunter_plan(
        plan=plan,
        store_root=store,
        database=database,
        client=client,
        budget=BudgetPolicy(
            max_hunter_sessions=2,
            max_input_tokens=1,
            max_output_tokens=1,
        ),
    )

    assert results == ()
    assert client.calls == 0
    queue = DurableHuntQueueStore(store / "hunters", database, plan.run_id).load()
    statuses = {task.work_id: task.status for task in queue.tasks}
    assert statuses[plan.admitted_work_ids[0]] == "budget_deferred"
    assert statuses[plan.admitted_work_ids[1]] == "pending"
    with SqliteRepository(database, read_only=True) as repository:
        assert repository.list_budget_usage(plan.run_id, scope="hunter") == []
