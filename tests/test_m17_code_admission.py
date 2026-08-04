from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.binary_analysis import (
    CodeHuntAdmission,
    CodeHuntAdmissionPolicy,
    CodeHuntAdmissionReason,
    CodeHuntOmissionReason,
    GhidraJSONAdapter,
    admit_code_hunt_roots,
    analyze_binary_candidates,
    discover_imageio_parsers,
    rank_binary_functions,
)

_SNAPSHOT = "sha256:" + "7" * 64
_UUID = "72345678-1234-5678-9ABC-DEF012345678"


def _instruction(
    address: int,
    op: str,
    *,
    result: str | None = None,
    inputs: list[str] | None = None,
    target: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "address": hex(address),
        "op": op,
        "inputs": inputs or [],
        "text": op,
    }
    if result is not None:
        payload["result"] = result
    if target is not None:
        payload["target"] = target
    if tags:
        payload["tags"] = tags
    return payload


def _function(
    address: int,
    name: str,
    instructions: list[dict[str, Any]],
    pseudocode: str,
) -> dict[str, Any]:
    return {
        "entry": hex(address),
        "size": 256,
        "name": name,
        "parameters": [],
        "pseudocode": pseudocode,
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


def _inputs():
    base = 0x100001000
    payload = {
        "schema_version": "ghidra-imageio-export-v1",
        "decompiler_version": "11.4",
        "snapshot_sha256": _SNAPSHOT,
        "image": {
            "name": "ImageIO",
            "uuid": _UUID,
            "architecture": "arm64",
            "base_address": "0x100000000",
        },
        "imports": ["free", "malloc"],
        "strings": [],
        "functions": [
            _function(
                base,
                "decode_png_row",
                [
                    _instruction(base, "param", result="data", tags=["input_data"]),
                    _instruction(base + 4, "load", result="pixel", inputs=["data"]),
                    _instruction(base + 8, "return", inputs=["pixel"]),
                ],
                "pixel = *data; return pixel;",
            ),
            _function(
                base + 0x1000,
                "decode_tiff_lifetime",
                [
                    _instruction(
                        base + 0x1000,
                        "param",
                        result="data",
                        tags=["input_data"],
                    ),
                    _instruction(
                        base + 0x1004,
                        "free",
                        inputs=["data"],
                        target="free",
                    ),
                    _instruction(base + 0x1008, "load", result="value", inputs=["data"]),
                ],
                "free(data); return *data;",
            ),
            _function(
                base + 0x2000,
                "image_allocator",
                [
                    _instruction(
                        base + 0x2000,
                        "alloc",
                        result="buffer",
                        inputs=["size"],
                        target="malloc",
                        tags=["source_op:CALL"],
                    ),
                    _instruction(base + 0x2004, "return", inputs=["buffer"]),
                ],
                "return malloc(size);",
            ),
            _function(
                base + 0x3000,
                "decode_gif_pixel",
                [
                    _instruction(
                        base + 0x3000,
                        "param",
                        result="data",
                        tags=["input_data"],
                    ),
                    _instruction(base + 0x3004, "load", result="pixel", inputs=["data"]),
                    _instruction(base + 0x3008, "return", inputs=["pixel"]),
                ],
                "pixel = *data; return pixel;",
            ),
        ],
    }
    ir = GhidraJSONAdapter().normalize(
        payload,
        expected_snapshot_sha256=_SNAPSHOT,
        created_at=datetime(2026, 8, 4, tzinfo=UTC),
    )
    discovery = discover_imageio_parsers(ir)
    report = analyze_binary_candidates(ir, discovery)
    ranking = rank_binary_functions(ir, discovery, report)
    return ir, discovery, report, ranking


def _policy(**overrides: object) -> CodeHuntAdmissionPolicy:
    values: dict[str, object] = {
        "maximum_roots": 3,
        "diversity_slots": 1,
        "require_function_coverage": False,
    }
    values.update(overrides)
    return CodeHuntAdmissionPolicy.model_validate(values)


def test_zero_finding_parser_code_is_admitted_and_allocator_is_excluded() -> None:
    ir, discovery, report, ranking = _inputs()
    admission = admit_code_hunt_roots(
        ir,
        discovery,
        report,
        ranking,
        policy=_policy(),
    )

    root = next(item for item in admission.roots if item.function_name == "decode_png_row")
    assert root.finding_ids == ()
    assert CodeHuntAdmissionReason.INPUT_EVIDENCE in root.admission_reasons
    assert CodeHuntAdmissionReason.SECURITY_SINK in root.admission_reasons

    allocator = next(
        item for item in admission.omissions if item.function_name == "image_allocator"
    )
    assert allocator.reason is CodeHuntOmissionReason.GENERIC_NON_PARSER


def test_static_findings_are_a_signal_not_an_admission_requirement() -> None:
    ir, discovery, report, ranking = _inputs()
    admission = admit_code_hunt_roots(
        ir,
        discovery,
        report,
        ranking,
        policy=_policy(),
    )

    vulnerable = next(
        item for item in admission.roots if item.function_name == "decode_tiff_lifetime"
    )
    no_finding = next(item for item in admission.roots if item.function_name == "decode_png_row")
    assert vulnerable.finding_ids
    assert CodeHuntAdmissionReason.STATIC_FINDING_SIGNAL in vulnerable.admission_reasons
    assert no_finding.finding_ids == ()
    assert CodeHuntAdmissionReason.STATIC_FINDING_SIGNAL not in no_finding.admission_reasons


def test_diversity_selection_keeps_binary_rank_as_exact_execution_order() -> None:
    ir, discovery, report, ranking = _inputs()
    admission = admit_code_hunt_roots(
        ir,
        discovery,
        report,
        ranking,
        policy=_policy(maximum_roots=2, diversity_slots=1),
    )

    assert admission.execution_function_ids == tuple(item.function_id for item in admission.roots)
    assert [item.binary_rank for item in admission.roots] == sorted(
        item.binary_rank for item in admission.roots
    )
    assert [item.admission_rank for item in admission.roots] == [1, 2]
    assert any(
        CodeHuntAdmissionReason.FORMAT_DIVERSITY in item.admission_reasons
        for item in admission.roots
    )
    assert len(admission.roots) + len(admission.omissions) == len(ranking.entries)


def test_admission_is_deterministic_and_rejects_reordered_execution() -> None:
    ir, discovery, report, ranking = _inputs()
    first = admit_code_hunt_roots(ir, discovery, report, ranking, policy=_policy())
    second = admit_code_hunt_roots(ir, discovery, report, ranking, policy=_policy())
    assert first == second

    payload = first.model_dump(mode="json")
    payload["execution_function_ids"] = list(reversed(payload["execution_function_ids"]))
    with pytest.raises(ValidationError, match="execution function ids"):
        CodeHuntAdmission.model_validate(payload)


def test_coverage_is_required_by_default_but_can_be_explicitly_relaxed() -> None:
    ir, discovery, report, ranking = _inputs()
    strict = admit_code_hunt_roots(ir, discovery, report, ranking)
    assert not strict.roots
    assert {item.reason for item in strict.omissions} == {
        CodeHuntOmissionReason.COVERAGE_MISSING
    }

    relaxed = admit_code_hunt_roots(
        ir,
        discovery,
        report,
        ranking,
        policy=_policy(),
    )
    assert relaxed.roots
