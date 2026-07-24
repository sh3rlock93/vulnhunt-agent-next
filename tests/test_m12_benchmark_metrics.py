from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from benchmarks.m12.benchmark_case import BENCHMARK_CASE_POLICY, load_benchmark_case
from benchmarks.m12.metrics import (
    SCHEMA_ROOT,
    canonical_json_bytes,
    reduce_metrics,
    render_markdown,
)
from benchmarks.run_libtiff_blind_benchmark import (
    BenchmarkContractError,
    freeze_discovery,
)

SOURCE = {
    "repository": "https://example.invalid/project.git",
    "commit": "1" * 40,
    "tree": "2" * 40,
}


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _build_run(
    root: Path,
    *,
    run_id: str,
    case_id: str = "case_1111111111111111",
    repetition_index: int = 1,
    partition: str = "calibration",
    evaluation_kind: str = "oracle",
    outcome: str = "completed",
    candidate: bool = True,
    target_match: bool = True,
    admission_target_match: bool = True,
    validity: str = "real",
    candidate_state: str = "reportable",
    duplicate_findings: bool = False,
    input_tokens: int = 100,
    cache_read_tokens: int = 20,
    output_tokens: int = 10,
) -> dict[str, str]:
    suffix = run_id.removeprefix("run_")
    artifact_root = root / "artifacts" / suffix
    candidate_id = "canonical_shared_root"
    candidates = {
        "schema_version": 1,
        "policy_version": "benchmark-candidates-v1",
        "run_id": run_id,
        "candidate": (
            [{
                "canonical_candidate_id": candidate_id,
                "state": candidate_state,
                "first_session_index": 5,
                "first_observed_ms": 900,
            }]
            if candidate
            else []
        ),
    }
    adjudications = {
        "schema_version": 1,
        "policy_version": "benchmark-adjudications-v1",
        "run_id": run_id,
        "admission": [{
            "target_id": "target_1",
            "target_match": admission_target_match,
            "evidence_sha256": "sha256:" + "5" * 64,
        }],
        "adjudication": (
            [{
                "canonical_candidate_id": candidate_id,
                "target_match": target_match,
                "validity": validity,
                "adjudicator": "sealed-evaluator-v1",
                "evidence_sha256": "sha256:" + "3" * 64,
            }]
            if candidate
            else []
        ),
    }
    candidate_path = artifact_root / "candidates.json"
    adjudication_path = artifact_root / "adjudications.json"
    _write_json(candidate_path, candidates)
    _write_json(adjudication_path, adjudications)

    scan_path = root / "inputs" / f"scan-{suffix}.toml"
    scan_path.parent.mkdir(parents=True, exist_ok=True)
    scan_path.write_text("[scan]\nenvironment = 'c:gcc-13'\n", encoding="utf-8")
    case_path = root / "cases" / f"case-{suffix}.toml"
    case_path.parent.mkdir(parents=True, exist_ok=True)
    case_path.write_text(
        f"""\
[case]
schema_version = 1
policy_version = "{BENCHMARK_CASE_POLICY}"
id = "{case_id}"
partition = "{partition}"
supported_family = "parser-cursor-oob-read"
required_hunter = "c-parser-state"
repetition_index = {repetition_index}

[source]
repository = "{SOURCE['repository']}"
commit = "{SOURCE['commit']}"
tree = "{SOURCE['tree']}"

[discovery]
scan_manifest = "{scan_path.relative_to(root).as_posix()}"
scan_manifest_sha256 = "{_sha256(scan_path)}"

[budget]
max_hunter_sessions = 12
max_input_tokens = 2000000
max_output_tokens = 200000
max_wall_clock_minutes = 60
max_context_bytes = 24000
max_retries_per_work_item = 1
max_format_repairs_per_work_item = 1
max_parallel_hunters = 2

[evaluation]
kind = "{evaluation_kind}"
reference = "{adjudication_path.relative_to(root).as_posix()}"
sha256 = "{_sha256(adjudication_path)}"
""",
        encoding="utf-8",
    )
    case = load_benchmark_case(case_path, repository_root=root)

    discovery = root / "working" / suffix
    _write_json(discovery / "discovery.json", {"phase": "discover", "complete": True})
    frozen = root / "frozen" / suffix
    freeze = freeze_discovery(discovery, frozen)
    freeze_sha = "sha256:" + freeze["root_sha256"]

    findings = []
    if candidate:
        findings.append({
            "finding_id": f"finding-{suffix}-1",
            "hunter": "c-parser-state",
            "session_index": 4,
            "canonical_candidate_id": candidate_id,
        })
        if duplicate_findings:
            findings.append({
                "finding_id": f"finding-{suffix}-2",
                "hunter": "c-parser-state",
                "session_index": 5,
                "canonical_candidate_id": candidate_id,
            })
    receipt = {
        "schema_version": 1,
        "policy_version": "authenticated-benchmark-receipt-v1",
        "run_id": run_id,
        "case_id": case_id,
        "repetition_index": repetition_index,
        "case_discovery_sha256": case.discovery_sha256,
        "freeze_root_sha256": freeze_sha,
        "source": SOURCE,
        "model": {"adapter": "codex_subscription", "model_id": "gpt-test"},
        "policies": {"ranking": "ranking-v1", "hunter": "hunter-v1"},
        "outcome": outcome,
        "authenticated": True,
        "oracle_isolated": True,
        "usage": {
            "sessions": 6,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_tokens": cache_read_tokens,
            "cache_write_tokens": 0,
            "wall_time_ms": 1000,
        },
        "admission": [{
            "target_id": "target_1",
            "hunter": "c-parser-state",
            "session_index": 2,
        }],
        "hunter_findings": findings,
    }
    receipt_path = artifact_root / "receipt.json"
    _write_json(receipt_path, receipt)
    return {
        "run_id": run_id,
        "case_manifest": case_path.relative_to(root).as_posix(),
        "case_manifest_sha256": _sha256(case_path),
        "freeze_root": frozen.relative_to(root).as_posix(),
        "freeze_root_sha256": freeze_sha,
        "receipt": receipt_path.relative_to(root).as_posix(),
        "receipt_sha256": _sha256(receipt_path),
        "candidates": candidate_path.relative_to(root).as_posix(),
        "candidates_sha256": _sha256(candidate_path),
        "adjudications": adjudication_path.relative_to(root).as_posix(),
        "adjudications_sha256": _sha256(adjudication_path),
    }


def _write_input(root: Path, runs: list[dict[str, str]], *, name: str = "input.toml") -> Path:
    blocks = [
        "[cohort]",
        "schema_version = 1",
        'policy_version = "benchmark-metrics-input-v1"',
        'id = "cohort_0123456789abcdef"',
        f'snapshot_sha256 = "sha256:{"4" * 64}"',
        "",
    ]
    for run in runs:
        blocks.append("[[run]]")
        blocks.extend(f'{key} = "{value}"' for key, value in run.items())
        blocks.append("")
    path = root / name
    path.write_text("\n".join(blocks), encoding="utf-8")
    return path


def test_all_metrics_schemas_are_valid_draft_2020_12() -> None:
    for path in sorted(SCHEMA_ROOT.glob("*metrics*v1.schema.json")) + sorted(
        SCHEMA_ROOT.glob("authenticated-benchmark-receipt-v1.schema.json")
    ) + sorted(SCHEMA_ROOT.glob("benchmark-candidates-v1.schema.json")) + sorted(
        SCHEMA_ROOT.glob("benchmark-adjudications-v1.schema.json")
    ):
        Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))


def test_reducer_reports_exact_detection_precision_and_cost_denominators(tmp_path: Path) -> None:
    first = _build_run(
        tmp_path,
        run_id="run_aaaaaaaaaaaaaaaa",
        repetition_index=1,
        duplicate_findings=True,
    )
    second = _build_run(
        tmp_path,
        run_id="run_bbbbbbbbbbbbbbbb",
        repetition_index=2,
        candidate=False,
        input_tokens=200,
        cache_read_tokens=30,
        output_tokens=20,
    )

    metrics = reduce_metrics(_write_input(tmp_path, [first, second]), repository_root=tmp_path)

    assert metrics["run_accounting"]["valid_run_rate"]["numerator"] == 2
    assert metrics["detection"]["admission_at_k"]["3"]["rate"] == 1.0
    assert metrics["detection"]["hunter_detection_at_k"]["3"]["rate"] == 0.0
    assert metrics["detection"]["hunter_detection_at_k"]["6"]["rate"] == 0.5
    assert metrics["detection"]["reportable_detection_at_k"]["6"]["rate"] == 0.5
    assert metrics["precision"]["reportable_precision"]["numerator"] == 1
    assert metrics["precision"]["reportable_precision"]["denominator"] == 1
    assert metrics["precision"]["unique_reportable_candidates"] == 1
    assert metrics["cost"]["tokens_per_valid_run"] == {
        "total": 350,
        "denominator": 2,
        "mean": 175.0,
        "median": 175,
    }
    assert metrics["cost"]["tokens_per_reportable"] == {
        "numerator": 380,
        "denominator": 1,
        "value": 380.0,
        "status": "defined",
    }
    assert metrics["cost"]["time_to_first_reportable_ms"]["median"] == 900


def test_reordering_requested_runs_produces_byte_identical_outputs(tmp_path: Path) -> None:
    first = _build_run(tmp_path, run_id="run_aaaaaaaaaaaaaaaa", repetition_index=1)
    second = _build_run(
        tmp_path,
        run_id="run_bbbbbbbbbbbbbbbb",
        repetition_index=2,
        candidate=False,
    )
    forward = reduce_metrics(
        _write_input(tmp_path, [first, second], name="forward.toml"),
        repository_root=tmp_path,
    )
    reverse = reduce_metrics(
        _write_input(tmp_path, [second, first], name="reverse.toml"),
        repository_root=tmp_path,
    )

    assert canonical_json_bytes(forward) == canonical_json_bytes(reverse)
    assert render_markdown(forward) == render_markdown(reverse)


def test_unverified_artifact_cannot_become_a_detection(tmp_path: Path) -> None:
    run = _build_run(tmp_path, run_id="run_aaaaaaaaaaaaaaaa")
    manifest = _write_input(tmp_path, [run])
    candidate_path = tmp_path / run["candidates"]
    candidate_path.write_text("{}\n", encoding="utf-8")

    metrics = reduce_metrics(manifest, repository_root=tmp_path)

    assert metrics["run_accounting"]["valid_run_rate"]["denominator"] == 1
    assert metrics["run_accounting"]["valid_run_rate"]["numerator"] == 0
    assert metrics["detection"]["reportable_detection_at_k"]["12"]["numerator"] == 0
    assert metrics["run_accounting"]["artifact_failures"][0]["run_id"] == run["run_id"]
    assert metrics["cost"]["usage_complete"] is False
    assert metrics["cost"]["tokens_per_reportable"]["status"] == "incomplete"
    assert metrics["cost"]["tokens_per_reportable"]["value"] is None
    assert "| tokens_per_reportable | incomplete |" in render_markdown(metrics)


def test_evaluator_is_not_opened_until_freeze_verification_passes(tmp_path: Path) -> None:
    run = _build_run(tmp_path, run_id="run_aaaaaaaaaaaaaaaa")
    manifest = _write_input(tmp_path, [run])
    frozen_discovery = tmp_path / run["freeze_root"] / "discovery.json"
    frozen_discovery.write_text('{"complete": false}\n', encoding="utf-8")
    (tmp_path / run["adjudications"]).unlink()

    metrics = reduce_metrics(manifest, repository_root=tmp_path)

    failure = metrics["run_accounting"]["artifact_failures"][0]["reason"]
    assert "frozen artifact SHA-256 verification failed" in failure
    assert "adjudication" not in failure


@pytest.mark.parametrize("outcome", ["invalid", "interrupted"])
def test_invalid_or_interrupted_execution_retains_cost_but_not_detection(
    tmp_path: Path,
    outcome: str,
) -> None:
    run = _build_run(tmp_path, run_id="run_aaaaaaaaaaaaaaaa", outcome=outcome)

    metrics = reduce_metrics(_write_input(tmp_path, [run]), repository_root=tmp_path)

    assert metrics["run_accounting"]["valid_run_rate"]["numerator"] == 0
    assert metrics["detection"]["hunter_detection_at_k"]["12"]["denominator"] == 0
    assert metrics["cost"]["source_run_ids"] == [run["run_id"]]
    assert metrics["cost"]["tokens_per_reportable"]["numerator"] == 130


def test_zero_reportable_findings_have_undefined_cost_per_reportable(tmp_path: Path) -> None:
    run = _build_run(tmp_path, run_id="run_aaaaaaaaaaaaaaaa", candidate=False)

    metrics = reduce_metrics(_write_input(tmp_path, [run]), repository_root=tmp_path)

    assert metrics["cost"]["tokens_per_reportable"]["value"] is None
    assert metrics["cost"]["tokens_per_reportable"]["status"] == "undefined"
    assert "undefined" in render_markdown(metrics)


def test_negative_metrics_require_adjudicated_false_reportable(tmp_path: Path) -> None:
    run = _build_run(
        tmp_path,
        run_id="run_aaaaaaaaaaaaaaaa",
        partition="negative",
        evaluation_kind="absence_oracle",
        validity="false",
    )

    metrics = reduce_metrics(_write_input(tmp_path, [run]), repository_root=tmp_path)

    assert metrics["negative"]["fixed_target_false_positive_rate"]["rate"] == 1.0
    assert metrics["negative"]["false_escalation_rate"]["rate"] == 1.0
    assert metrics["precision"]["reportable_precision"]["rate"] == 0.0


def test_admission_requires_oracle_matching_target_and_required_hunter(tmp_path: Path) -> None:
    run = _build_run(
        tmp_path,
        run_id="run_aaaaaaaaaaaaaaaa",
        admission_target_match=False,
    )

    metrics = reduce_metrics(_write_input(tmp_path, [run]), repository_root=tmp_path)

    assert metrics["detection"]["admission_at_k"]["12"]["numerator"] == 0


def test_case_identity_cannot_change_between_repetitions(tmp_path: Path) -> None:
    first = _build_run(tmp_path, run_id="run_aaaaaaaaaaaaaaaa", repetition_index=1)
    second = _build_run(
        tmp_path,
        run_id="run_bbbbbbbbbbbbbbbb",
        repetition_index=2,
        partition="negative",
    )
    manifest = _write_input(tmp_path, [first, second])

    with pytest.raises(BenchmarkContractError, match="case identity changes"):
        reduce_metrics(manifest, repository_root=tmp_path)


def test_duplicate_requested_run_ids_fail_the_closed_contract(tmp_path: Path) -> None:
    run = _build_run(tmp_path, run_id="run_aaaaaaaaaaaaaaaa")
    manifest = _write_input(tmp_path, [run, run])

    with pytest.raises(BenchmarkContractError, match="duplicate run IDs"):
        reduce_metrics(manifest, repository_root=tmp_path)


def test_generated_adjudications_remain_bound_to_the_case_evaluator(tmp_path: Path) -> None:
    run = _build_run(tmp_path, run_id="run_aaaaaaaaaaaaaaaa")
    evaluator_path = tmp_path / "oracles" / "calibration.toml"
    evaluator_path.parent.mkdir(parents=True)
    evaluator_path.write_text("[oracle]\npolicy = 'sealed'\n", encoding="utf-8")
    evaluator_sha = _sha256(evaluator_path)

    case_path = tmp_path / run["case_manifest"]
    case_text = case_path.read_text(encoding="utf-8")
    case_text = case_text.replace(
        f'reference = "{run["adjudications"]}"',
        'reference = "oracles/calibration.toml"',
    ).replace(
        f'sha256 = "{run["adjudications_sha256"]}"',
        f'sha256 = "{evaluator_sha}"',
    )
    case_path.write_text(case_text, encoding="utf-8")
    run["case_manifest_sha256"] = _sha256(case_path)

    adjudication_path = tmp_path / run["adjudications"]
    adjudications = json.loads(adjudication_path.read_text(encoding="utf-8"))
    for item in adjudications["admission"] + adjudications["adjudication"]:
        item["evidence_sha256"] = evaluator_sha
    _write_json(adjudication_path, adjudications)
    run["adjudications_sha256"] = _sha256(adjudication_path)
    run["evaluation_reference"] = "oracles/calibration.toml"
    run["evaluation_sha256"] = evaluator_sha

    metrics = reduce_metrics(_write_input(tmp_path, [run]), repository_root=tmp_path)

    assert metrics["run_accounting"]["valid_run_rate"]["rate"] == 1.0

    adjudications["adjudication"][0]["evidence_sha256"] = "sha256:" + "0" * 64
    _write_json(adjudication_path, adjudications)
    run["adjudications_sha256"] = _sha256(adjudication_path)
    metrics = reduce_metrics(
        _write_input(tmp_path, [run], name="tampered.toml"),
        repository_root=tmp_path,
    )

    assert metrics["run_accounting"]["valid_run_rate"]["rate"] == 0.0
    assert "adjudication evidence mismatch" in metrics["run_accounting"]["artifact_failures"][0]["reason"]
