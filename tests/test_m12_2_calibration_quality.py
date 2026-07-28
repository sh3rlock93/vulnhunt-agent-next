from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from benchmarks.m12.calibration import load_calibration_catalog
from benchmarks.m12.calibration_controls import (
    _link_arguments_from_commands,
    _prepared_compile_argv,
    _validate,
    _variant_passed,
    assess_differential_controls,
    load_differential_controls,
)
from benchmarks.m12.calibration_evaluation import assess_calibration_gates
from benchmarks.m12.calibration_quality import reduce_knowledge_quality
from benchmarks.run_libtiff_blind_benchmark import BenchmarkContractError


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _quality_fixture(
    root: Path,
    *,
    source_reads: list[dict[str, Any]] | None = None,
    leaked_title: str = "generalized format expansion",
) -> tuple[list[dict[str, str]], Path]:
    run_id = "run_1111111111111111"
    frozen = root / "frozen" / run_id
    _write_json(frozen / "discovery.json", {
        "run_identity": {"run_id": run_id},
    })
    _write_json(frozen / "plan.json", {
        "work_items": [{
            "work_id": "work_1",
            "obligation_ids": ["obligation_1"],
        }],
    })
    _write_json(frozen / "findings.json", [{
        "candidate_id": "candidate_1",
        "task_key": "work_1",
        "state": "reportable",
    }])
    _write_json(frozen / "contexts/context_1.json", {
        "cache_key": "context_1",
        "invariant_obligations": [{"obligation_id": "obligation_1"}],
        "vulnerability_knowledge": {
            "cards": [{
                "pattern_id": "vpattern_formatted_output_expansion",
                "title": leaked_title,
            }],
        },
    })
    _write_json(
        frozen
        / run_id
        / "hunters"
        / "work_1"
        / "hunts"
        / "c-memory-lifetime"
        / "findings.json",
        {
            "findings": [{
                "title": "bounded write",
                "type": "memory_safety",
                "status": "unverified",
                "entry_file": "format.c",
                "entry_line": 10,
                "sink_file": "format.c",
                "sink_line": 20,
            }],
            "target_dispositions": [{
                "target_id": "obligation_1",
                "status": "no_finding",
            }],
            "source_reads": (
                source_reads
                if source_reads is not None
                else [{"path": "format.c", "start": 1, "end": 30, "bytes": 500}]
            ),
        },
    )
    ledger = root / "finding-ledger.json"
    _write_json(ledger, {
        "records": [{
            "finding_id": "historical-finding-id",
            "project": "HistoricalProject",
            "source_repository": "https://example.invalid/historical.git",
            "source_revision": "a" * 40,
            "locations": ["old/source-file.c"],
        }],
    })
    return ([{"run_id": run_id, "freeze_root": f"frozen/{run_id}"}], ledger)


def test_knowledge_quality_counts_conversion_yield_and_falsification(
    tmp_path: Path,
) -> None:
    runs, ledger = _quality_fixture(tmp_path)

    metrics = reduce_knowledge_quality(tmp_path, runs, ledger_path=ledger)

    assert metrics["selected_card_count"] == 1
    assert metrics["card_to_obligation_conversion"]["rate"] == 1.0
    assert metrics["candidate_yield"]["canonical_candidate_count"] == 1
    assert metrics["falsified_card_count"] == 1
    assert metrics["findings_without_current_source_evidence"] == 0
    assert metrics["reportable_without_current_source_evidence"] == 0
    assert metrics["ledger_identity_leaks"] == []


def test_knowledge_quality_rejects_reportable_without_current_source_read(
    tmp_path: Path,
) -> None:
    runs, ledger = _quality_fixture(tmp_path, source_reads=[])

    metrics = reduce_knowledge_quality(tmp_path, runs, ledger_path=ledger)

    assert metrics["findings_without_current_source_evidence"] == 1
    assert metrics["reportable_without_current_source_evidence"] == 1


def test_knowledge_quality_detects_ledger_identity_in_prompt_projection(
    tmp_path: Path,
) -> None:
    runs, ledger = _quality_fixture(
        tmp_path,
        leaked_title="https://example.invalid/historical.git",
    )

    metrics = reduce_knowledge_quality(tmp_path, runs, ledger_path=ledger)

    assert metrics["ledger_identity_leaks"][0]["token"] == (
        "https://example.invalid/historical.git"
    )


def test_knowledge_quality_rejects_duplicate_canonical_records(tmp_path: Path) -> None:
    runs, ledger = _quality_fixture(tmp_path)
    frozen = tmp_path / runs[0]["freeze_root"]
    findings = json.loads((frozen / "findings.json").read_text(encoding="utf-8"))
    findings.append(dict(findings[0]))
    _write_json(frozen / "findings.json", findings)

    metrics = reduce_knowledge_quality(tmp_path, runs, ledger_path=ledger)

    assert metrics["duplicate_accounting"]["logical_findings_count_once"] is False


def _attempt(index: int, *, vulnerable: bool) -> dict[str, Any]:
    return {
        "attempt": index,
        "exit_code": 1 if vulnerable else 0,
        "timed_out": False,
        "sanitizer_failure": vulnerable,
        "expected_sanitizer_present": vulnerable,
        "target_frame_present": vulnerable,
        "fixed_stdout_present": not vulnerable,
        "evidence_sha256": "sha256:" + f"{index:x}" * 64,
    }


def _controls() -> dict[str, Any]:
    runs = []
    counter = 1
    for case_index in range(1, 5):
        case_id = f"case_{case_index:016x}"
        for variant in ("vulnerable", "fixed"):
            vulnerable = variant == "vulnerable"
            runs.append({
                "run_id": f"control_{counter:016x}",
                "case_id": case_id,
                "variant": variant,
                "source": {
                    "repository": f"https://example.invalid/{case_index}.git",
                    "commit": f"{case_index:x}" * 40,
                    "tree": f"{case_index + 4:x}" * 40,
                },
                "image_digest": "sha256:" + f"{case_index:x}" * 64,
                "oracle_sha256": "sha256:" + f"{case_index + 4:x}" * 64,
                "attempt": [
                    _attempt(1, vulnerable=vulnerable),
                    _attempt(2, vulnerable=vulnerable),
                ],
                "passed": True,
            })
            counter += 1
    return {
        "schema_version": 1,
        "policy_version": "calibration-differential-controls-v1",
        "cohort_id": "cohort_1111111111111111",
        "plan_sha256": "sha256:" + "1" * 64,
        "catalog_sha256": "sha256:" + "2" * 64,
        "run": runs,
    }


def test_differential_control_contract_requires_four_complete_pairs() -> None:
    controls = _controls()
    _validate(controls)

    assessment = assess_differential_controls(
        controls,
        case_ids=[f"case_{value:016x}" for value in range(1, 5)],
    )

    assert assessment["passed"] is True
    controls["run"][0]["variant"] = "fixed"
    with pytest.raises(BenchmarkContractError, match="duplicated"):
        _validate(controls)


def test_control_compile_exposes_generated_prepared_headers() -> None:
    argv = _prepared_compile_argv(
        ("cc", "-I/code/include", "{source}", "{artifact}"),
        {"source": "/workspace/control.c", "artifact": "/build/libcase.a"},
        ("/opt/vulnhunt/build/include/case", "/opt/vulnhunt/build/include"),
        ("/usr/lib/libdependency.so",),
    )

    assert argv == (
        "cc",
        "-I/code/include",
        "/workspace/control.c",
        "/build/libcase.a",
        "-I/opt/vulnhunt/build/include",
        "-I/opt/vulnhunt/build/include/case",
        "-DCOAP_REQUEST_CODE_GET=COAP_REQUEST_GET",
        "/usr/lib/libdependency.so",
    )


def test_control_compile_recovers_static_target_link_dependencies() -> None:
    arguments = _link_arguments_from_commands(
        (
            "cc object.o -o unrelated libother.a -lm",
            "cc object.o -o control libcase.a /usr/lib/libssl.so "
            "/usr/lib/libcrypto.so",
        ),
        "libcase.a",
    )

    assert arguments == ("/usr/lib/libssl.so", "/usr/lib/libcrypto.so")


def test_variant_pass_requires_two_reproductions_and_a_clean_fixed_control() -> None:
    spec = {"attempts": 2}
    assert _variant_passed(
        "vulnerable",
        spec,
        [_attempt(1, vulnerable=True), _attempt(2, vulnerable=True)],
    )
    assert _variant_passed(
        "fixed",
        spec,
        [_attempt(1, vulnerable=False), _attempt(2, vulnerable=False)],
    )
    broken = _attempt(2, vulnerable=False)
    broken["fixed_stdout_present"] = False
    assert not _variant_passed(
        "fixed",
        spec,
        [_attempt(1, vulnerable=False), broken],
    )


def test_control_loader_recomputes_pass_from_sealed_case_evidence(
    tmp_path: Path,
) -> None:
    catalog = load_calibration_catalog()
    plan = tmp_path / "cohort-plan.json"
    _write_json(plan, {"cohort_id": "cohort_1111111111111111"})
    records = []
    counter = 1
    for definition in catalog.definitions:
        for variant in ("vulnerable", "fixed"):
            vulnerable = variant == "vulnerable"
            records.append({
                "run_id": f"control_{counter:016x}",
                "case_id": definition.case.case_id,
                "variant": variant,
                "source": (
                    {
                        "repository": definition.case.source.repository,
                        "commit": definition.case.source.commit,
                        "tree": definition.case.source.tree,
                    }
                    if vulnerable
                    else definition.oracle["fixed_source"]
                ),
                "image_digest": "sha256:" + f"{counter:x}" * 64,
                "oracle_sha256": definition.case.evaluation.sha256,
                "attempt": [
                    _attempt(1, vulnerable=vulnerable),
                    _attempt(2, vulnerable=vulnerable),
                ],
                "passed": True,
            })
            counter += 1
    controls: dict[str, Any] = {
        "schema_version": 1,
        "policy_version": "calibration-differential-controls-v1",
        "cohort_id": "cohort_1111111111111111",
        "plan_sha256": (
            "sha256:" + hashlib.sha256(plan.read_bytes()).hexdigest()
        ),
        "catalog_sha256": catalog.sha256,
        "run": records,
    }
    path = tmp_path / "controls.json"
    _write_json(path, controls)

    loaded = load_differential_controls(
        path,
        cohort_id="cohort_1111111111111111",
        plan_path=plan,
        catalog=catalog,
    )
    assert len(loaded["run"]) == 8

    controls["run"][0]["passed"] = False
    _write_json(path, controls)
    with pytest.raises(BenchmarkContractError, match="sealed case"):
        load_differential_controls(
            path,
            cohort_id="cohort_1111111111111111",
            plan_path=plan,
            catalog=catalog,
        )


def test_release_gate_requires_per_case_recovery_controls_and_source_evidence() -> None:
    case_results = []
    provenance = []
    for value in range(1, 5):
        case_id = f"case_{value:016x}"
        case_results.append({
            "case_id": case_id,
            "supported_family": f"family-{value}",
            "admission_case_success_rate": {"numerator": 3},
            "hunter_case_success_rate": {"numerator": 2},
        })
    for value in range(12):
        provenance.append({
            "run_id": f"run_{value:016x}",
            "outcome": "completed",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 10,
                "cache_read_tokens": 20,
                "cache_write_tokens": 0,
            },
        })
    metrics = {
        "case_results": case_results,
        "run_accounting": {"valid_run_rate": {"rate": 1.0}},
        "detection": {
            "hunter_detection_at_k": {"12": {"rate": 0.75}},
            "reportable_detection_at_k": {"12": {"rate": 0.5}},
        },
        "cost": {
            "tokens_per_valid_run": {"median": 120},
            "tokens_per_reportable": {"numerator": 1560},
        },
        "provenance": {"runs": provenance},
    }
    knowledge = {
        "findings_without_current_source_evidence": 0,
        "reportable_without_current_source_evidence": 0,
        "ledger_identity_leaks": [],
        "duplicate_accounting": {"logical_findings_count_once": True},
    }

    assessment = assess_calibration_gates(
        metrics,
        knowledge_metrics=knowledge,
        controls=_controls(),
    )

    assert assessment["failed_gates"] == []
    assert assessment["decision"] == "pending_protected_regression"
