from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
import uuid

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.binary_analysis import (
    BinaryDisclosureAnalysisReport,
    BinaryDisclosureStatus,
    BinaryExperimentPlanStatus,
    BinaryHunterAssessment,
    BinaryRankingPolicy,
    BinaryVulnerabilityClass,
    DyldArchitecture,
    GhidraJSONAdapter,
    analyze_binary_candidates,
    analyze_partial_initialization_disclosures,
    binary_vulnerability_metadata,
    build_binary_hunter_plan,
    capture_dyld_shared_cache_snapshot,
    create_binary_research_scope,
    discover_imageio_parsers,
    load_binary_hunter_packet,
    pack_ranked_binary_contexts,
    plan_binary_experiments,
    rank_binary_functions,
    validate_binary_hunter_assessment,
)
from vulnhunt_agent.domain.schemas import BudgetPolicy

_SNAPSHOT = "sha256:" + "8" * 64
_UUID = "82345678-1234-5678-9ABC-DEF012345678"
_BASE = 0x100001000


def _instruction(
    address: int,
    operation: str,
    *,
    result: str | None = None,
    inputs: list[str] | None = None,
    target: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "address": hex(address),
        "op": operation,
        "inputs": inputs or [],
        "text": operation,
    }
    if result is not None:
        value["result"] = result
    if target is not None:
        value["target"] = target
    if tags is not None:
        value["tags"] = tags
    return value


def _block(
    name: str,
    start: int,
    instructions: list[dict[str, Any]],
    *,
    successors: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "start": hex(start),
        "size": 0x80,
        "successors": successors or [],
        "instructions": instructions,
    }


def _branch(address: int, condition: str, target: int) -> dict[str, Any]:
    return _instruction(
        address,
        "branch",
        inputs=[f"v_ram_{target:x}_1", condition],
        tags=["conditional_branch", f"branch_target:{target:x}"],
    )


def _table_setup(start: int) -> list[dict[str, Any]]:
    tags = [
        "input_buffer_operand:1",
        "read_session_input",
        "scalar_role:offset:2",
        "scalar_role:requested_length:3",
    ]
    return [
        _instruction(
            start,
            "call",
            inputs=["session", "offset_table", "const_20", "table_size"],
            target="getBytesAtOffset",
            tags=["decoder_entry", *tags],
        ),
        _instruction(
            start + 4,
            "call",
            inputs=["session", "length_table", "const_40", "table_size"],
            target="getBytesAtOffset",
            tags=tags,
        ),
        _instruction(
            start + 8,
            "load",
            result="offset",
            inputs=["ram", "offset_table"],
        ),
        _instruction(
            start + 12,
            "load",
            result="length",
            inputs=["ram", "length_table"],
        ),
    ]


def _range_read(address: int) -> dict[str, Any]:
    return _instruction(
        address,
        "call",
        result="actual",
        inputs=["session", "compressed", "offset", "length"],
        target="getBytesAtOffset",
        tags=[
            "input_buffer_operand:1",
            "read_session_input",
            "scalar_role:offset:2",
            "scalar_role:requested_length:3",
        ],
    )


def _chain(
    *,
    allocation: str = "malloc",
    consume_length: str = "length",
    observable: bool = True,
    overwrite: bool = False,
) -> list[dict[str, Any]]:
    result = _table_setup(_BASE)
    result.extend(
        [
            _instruction(
                _BASE + 0x10,
                "alloc",
                result="compressed",
                inputs=["const_1", "capacity"] if allocation == "calloc" else ["capacity"],
                target=allocation,
            ),
            _range_read(_BASE + 0x14),
            _instruction(
                _BASE + 0x18,
                "call",
                result="decoded",
                inputs=["compressed", consume_length],
                target="decodeRows",
            ),
        ]
    )
    if overwrite:
        result.append(
            _instruction(
                _BASE + 0x1C,
                "call",
                inputs=["decoded", "const_0", "capacity"],
                target="replaceDecodedBytes",
                tags=["full_output_overwrite"],
            )
        )
    if observable:
        result.append(
            _instruction(
                _BASE + 0x20,
                "call",
                inputs=["decoded"],
                target="publishImage",
                tags=["observable_output"],
            )
        )
    result.append(_instruction(_BASE + 0x24, "return"))
    return result


def _ir(
    blocks: list[dict[str, Any]],
    *,
    snapshot_sha256: str = _SNAPSHOT,
    extra_functions: list[dict[str, Any]] | None = None,
):
    payload = {
        "schema_version": "ghidra-imageio-export-v1",
        "decompiler_version": "12.1.2",
        "snapshot_sha256": snapshot_sha256,
        "image": {
            "name": "ImageIO",
            "uuid": _UUID,
            "architecture": "arm64",
            "base_address": "0x100000000",
        },
        "imports": [],
        "strings": [],
        "functions": [
            {
                "entry": hex(_BASE),
                "size": 0x800,
                "name": "decode_sgi_rle",
                "parameters": [],
                "pseudocode": "void decode_sgi_rle(void) { /* generalized fixture */ }",
                "blocks": blocks,
            },
            *(extra_functions or []),
        ],
    }
    return GhidraJSONAdapter().normalize(
        payload,
        expected_snapshot_sha256=snapshot_sha256,
        created_at=datetime(2026, 7, 31, 10, 0, tzinfo=UTC),
    )


def _analyze(blocks: list[dict[str, Any]]):
    ir = _ir(blocks)
    discovery = discover_imageio_parsers(ir)
    report = analyze_partial_initialization_disclosures(ir, discovery)
    target = next(item for item in report.summaries if item.range_call_address == _BASE + 0x14)
    return ir, discovery, report, target


def test_partial_fill_full_consume_output_is_cwe_908_candidate() -> None:
    ir, discovery, report, target = _analyze([_block("entry", _BASE, _chain())])

    assert target.status is BinaryDisclosureStatus.CANDIDATE
    assert target.allocation_capacity == "capacity"
    assert target.maximum_initialized_bytes == "actual"
    assert target.downstream_consumed_bytes == "length"
    assert target.output_route == "publishimage"
    assert len(report.findings) == 1
    assert (
        report.findings[0].vulnerability_class
        is BinaryVulnerabilityClass.PARTIAL_INITIALIZATION_DISCLOSURE
    )
    assert any(
        item.vulnerability_class
        is BinaryVulnerabilityClass.PARTIAL_INITIALIZATION_DISCLOSURE
        for item in analyze_binary_candidates(ir, discovery).findings
    )
    metadata = binary_vulnerability_metadata(
        BinaryVulnerabilityClass.PARTIAL_INITIALIZATION_DISCLOSURE
    )
    assert metadata is not None and metadata.cwe_id == "CWE-908"


@pytest.mark.parametrize(
    ("kwargs", "status"),
    [
        ({"allocation": "calloc"}, BinaryDisclosureStatus.ZERO_INITIALIZED),
        ({"consume_length": "actual"}, BinaryDisclosureStatus.ACTUAL_LENGTH_BOUNDED),
        ({"observable": False}, BinaryDisclosureStatus.NOT_OBSERVABLE),
        ({"overwrite": True}, BinaryDisclosureStatus.FULLY_OVERWRITTEN),
    ],
)
def test_disclosure_suppressions_remain_negative(
    kwargs: dict[str, Any],
    status: BinaryDisclosureStatus,
) -> None:
    _ir_value, _discovery, report, target = _analyze(
        [_block("entry", _BASE, _chain(**kwargs))]
    )

    assert target.status is status
    assert report.findings == ()
    assert target.suppression_reasons


def test_actual_length_guard_controls_full_consumer() -> None:
    reject = _BASE + 0x100
    consume = _BASE + 0x180
    entry_instructions = _table_setup(_BASE)
    entry_instructions.extend(
        [
            _instruction(
                _BASE + 0x10,
                "alloc",
                result="compressed",
                inputs=["capacity"],
                target="malloc",
            ),
            _range_read(_BASE + 0x14),
            _instruction(
                _BASE + 0x18,
                "compare",
                result="short",
                inputs=["actual", "length"],
                tags=["comparison:unsigned_less"],
            ),
            _branch(_BASE + 0x1C, "short", reject),
        ]
    )
    blocks = [
        _block("entry", _BASE, entry_instructions, successors=["consume", "reject"]),
        _block("reject", reject, [_instruction(reject, "return")]),
        _block(
            "consume",
            consume,
            [
                _instruction(
                    consume,
                    "call",
                    result="decoded",
                    inputs=["compressed", "length"],
                    target="decodeRows",
                ),
                _instruction(
                    consume + 4,
                    "call",
                    inputs=["decoded"],
                    target="publishImage",
                    tags=["observable_output"],
                ),
            ],
        ),
    ]

    _ir_value, _discovery, report, target = _analyze(blocks)

    assert target.status is BinaryDisclosureStatus.ACTUAL_LENGTH_BOUNDED
    assert report.findings == ()


def test_combined_range_proof_suppresses_disclosure() -> None:
    reject = _BASE + 0x100
    decode = _BASE + 0x180
    entry = _table_setup(_BASE)
    entry.extend(
        [
            _instruction(
                _BASE + 0x10,
                "alloc",
                result="compressed",
                inputs=["capacity"],
                target="malloc",
            ),
            _instruction(
                _BASE + 0x14,
                "compare",
                result="bad_offset",
                inputs=["capacity", "offset"],
                tags=["comparison:unsigned_less"],
            ),
            _instruction(
                _BASE + 0x18,
                "compare",
                result="bad_length",
                inputs=["capacity", "length"],
                tags=["comparison:unsigned_less"],
            ),
            _instruction(
                _BASE + 0x1C,
                "add",
                result="range_end",
                inputs=["offset", "length"],
            ),
            _instruction(
                _BASE + 0x20,
                "compare",
                result="bad_range",
                inputs=["capacity", "range_end"],
                tags=["comparison:unsigned_less"],
            ),
            _instruction(
                _BASE + 0x24,
                "boolean_or",
                result="bad_fields",
                inputs=["bad_offset", "bad_length"],
            ),
            _instruction(
                _BASE + 0x28,
                "boolean_or",
                result="bad_any",
                inputs=["bad_fields", "bad_range"],
            ),
            _branch(_BASE + 0x2C, "bad_any", reject),
        ]
    )
    blocks = [
        _block("entry", _BASE, entry, successors=["decode", "reject"]),
        _block("reject", reject, [_instruction(reject, "return")]),
        _block(
            "decode",
            decode,
            [
                _range_read(decode),
                _instruction(
                    decode + 4,
                    "call",
                    result="decoded",
                    inputs=["compressed", "length"],
                    target="decodeRows",
                ),
                _instruction(
                    decode + 8,
                    "call",
                    inputs=["decoded"],
                    target="publishImage",
                    tags=["observable_output"],
                ),
            ],
        ),
    ]
    ir = _ir(blocks)
    discovery = discover_imageio_parsers(ir)
    report = analyze_partial_initialization_disclosures(ir, discovery)
    target = next(item for item in report.summaries if item.range_call_address == decode)

    assert target.status is BinaryDisclosureStatus.SAFE_COMBINED_RANGE
    assert report.findings == ()


def test_consumer_summary_is_bounded_to_one_direct_callee_hop() -> None:
    callee = {
        "entry": hex(_BASE + 0x1000),
        "size": 0x100,
        "name": "decodeRows",
        "parameters": ["compressed", "length"],
        "pseudocode": "void decodeRows(void);",
        "blocks": [
            _block(
                "callee",
                _BASE + 0x1000,
                [_instruction(_BASE + 0x1000, "return")],
            )
        ],
    }
    ir = _ir(
        [_block("entry", _BASE, _chain())],
        extra_functions=[callee],
    )
    discovery = discover_imageio_parsers(ir)
    report = analyze_partial_initialization_disclosures(ir, discovery)
    target = next(item for item in report.summaries if item.range_call_address == _BASE + 0x14)

    assert target.status is BinaryDisclosureStatus.CANDIDATE
    assert target.call_depth == 1


def test_disclosure_report_digest_rejects_status_tampering() -> None:
    _ir_value, _discovery, report, _target = _analyze(
        [_block("entry", _BASE, _chain())]
    )
    payload = report.model_dump(mode="json")
    payload["summaries"][-1]["status"] = "not_observable"

    with pytest.raises(ValidationError):
        BinaryDisclosureAnalysisReport.model_validate(payload)


def _hunter_packet(tmp_path: Path):
    cache = tmp_path / "dyld_shared_cache_arm64e"
    header = bytearray(104)
    header[:16] = b"dyld_v1  arm64e\0"
    header[88:104] = uuid.UUID("92345678-1234-5678-9abc-def012345678").bytes
    cache.write_bytes(bytes(header) + b"m16-4-hunter-contract")
    snapshot = capture_dyld_shared_cache_snapshot(
        cache,
        product_version="26.0",
        build_version="25A123",
        architecture=DyldArchitecture.ARM64,
        captured_at=datetime(2026, 7, 31, 10, 30, tzinfo=UTC),
    )
    ir = _ir(
        [_block("entry", _BASE, _chain())],
        snapshot_sha256=snapshot.snapshot_sha256,
    )
    discovery = discover_imageio_parsers(ir)
    report = analyze_binary_candidates(ir, discovery)
    policy = BinaryRankingPolicy(
        context_budget_bytes=4096,
        maximum_segment_bytes=4096,
        maximum_packs=4,
        maximum_pseudocode_bytes=1024,
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
        authorization_basis="Analyst-owned disposable macOS VM ImageIO research",
    )
    store = tmp_path / "private"
    store.mkdir()
    plan = build_binary_hunter_plan(
        store_root=store,
        run_id="m16-4-hunter-contract",
        snapshot=snapshot,
        ir=ir,
        discovery=discovery,
        report=report,
        ranking=ranking,
        context_plan=context_plan,
        scope=scope,
        budget=BudgetPolicy(max_hunter_sessions=2),
        retained_input_sha256s=("sha256:" + "a" * 64,),
    )
    return store, load_binary_hunter_packet(
        store_root=store,
        work_item=plan.admitted_work_items[0],
    )


def _evidence_id(packet: Any, kind: str) -> str:
    return next(item.evidence_id for item in packet.evidence_refs if item.kind.value == kind)


def _disclosure_assessment(packet: Any, *, experiment: str | None = None) -> dict[str, Any]:
    hypothesis_id = "binhypothesis-partial-output"
    supporting = sorted(
        [
            _evidence_id(packet, "static_finding"),
            _evidence_id(packet, "parser_input"),
            _evidence_id(packet, "allocation_initialization"),
            _evidence_id(packet, "full_consumption_output"),
        ]
    )
    requests: list[dict[str, Any]] = []
    if experiment is not None:
        requests.append(
            {
                "request_id": "binexperiment-disclosure-oracle",
                "hypothesis_id": hypothesis_id,
                "kind": experiment,
                "rationale": "A bounded output observation discriminates initialized bytes.",
                "retained_input_sha256": "sha256:" + "a" * 64,
                "route": "full_decode",
                "canary_value": 165 if experiment == "canary_propagation" else None,
                "execution_limit": 1,
                "expected_observation": "Only the cited output range changes.",
                "falsification_condition": "Every output byte is input-derived or initialized.",
                "evidence_refs": supporting,
                "auto_execute": False,
            }
        )
    return {
        "work_id": packet.work_id,
        "pack_id": packet.pack.pack_id,
        "pack_sequence": packet.pack.sequence,
        "disposition": "needs_experiment" if requests else "static_hypothesis",
        "summary": "The static chain supports a bounded disclosure hypothesis.",
        "hypotheses": [
            {
                "hypothesis_id": hypothesis_id,
                "title": "Partial initialization may reach decoded output",
                "vulnerability_class": "partial_initialization_disclosure",
                "input_control": "Input-backed offset and length reach the range reader.",
                "parser_state": "A non-zeroed compressed buffer has been allocated.",
                "security_relation": "Actual initialized bytes may be below consumed bytes.",
                "root_cause_hypothesis": "Requested length, not actual length, controls decode.",
                "falsification_condition": "A full-read proof or initialization covers output.",
                "confidence": 0.84,
                "supporting_evidence_ids": supporting,
                "contradicting_evidence_ids": [],
            }
        ],
        "experiment_requests": requests,
        "evidence_refs": supporting,
        "unresolved_questions": ["No dynamic output observation exists yet."],
    }


def test_disclosure_hunter_requires_all_four_evidence_classes(tmp_path: Path) -> None:
    _store, packet = _hunter_packet(tmp_path)
    valid = BinaryHunterAssessment.model_validate(_disclosure_assessment(packet))
    validate_binary_hunter_assessment(packet, valid)

    for missing in ("allocation_initialization", "full_consumption_output"):
        payload = _disclosure_assessment(packet)
        evidence = _evidence_id(packet, missing)
        payload["hypotheses"][0]["supporting_evidence_ids"].remove(evidence)
        assessment = BinaryHunterAssessment.model_validate(payload)
        with pytest.raises(ValueError, match="allocation and full-consumption/output"):
            validate_binary_hunter_assessment(packet, assessment)


def test_model_cannot_promote_composite_or_invent_experiment(tmp_path: Path) -> None:
    _store, packet = _hunter_packet(tmp_path)
    promoted = _disclosure_assessment(packet)
    promoted["disposition"] = "reportable"
    promoted["hypotheses"][0]["vulnerability_class"] = "composite_range_gap"
    with pytest.raises(ValidationError):
        BinaryHunterAssessment.model_validate(promoted)

    unsupported = _disclosure_assessment(packet, experiment="raw_output_differential")
    unsupported["experiment_requests"][0]["kind"] = "unsupported_memory_probe"
    with pytest.raises(ValidationError):
        BinaryHunterAssessment.model_validate(unsupported)


@pytest.mark.parametrize("kind", ["raw_output_differential", "canary_propagation"])
def test_disclosure_experiments_are_typed_and_human_review_gated(
    tmp_path: Path,
    kind: str,
) -> None:
    _store, packet = _hunter_packet(tmp_path)
    assessment = BinaryHunterAssessment.model_validate(
        _disclosure_assessment(packet, experiment=kind)
    )

    plan = plan_binary_experiments(packet=packet, assessment=assessment)[0]

    assert plan.status is BinaryExperimentPlanStatus.REVIEW_REQUIRED
    assert plan.auto_execute is False
    assert plan.host_execution_allowed is False
    assert plan.network_allowed is False
