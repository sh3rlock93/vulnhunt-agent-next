from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from benchmarks.m12.benchmark_case import (
    BENCHMARK_CASE_POLICY,
    SCHEMA_PATH,
    load_benchmark_case,
)
from benchmarks.run_libtiff_blind_benchmark import BenchmarkContractError


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _write_case(root: Path) -> Path:
    scan = root / "inputs" / "scan.toml"
    evaluator = root / "sealed" / "evaluator.toml"
    scan.parent.mkdir(parents=True, exist_ok=True)
    evaluator.parent.mkdir(parents=True, exist_ok=True)
    scan.write_text("[scan]\nenvironment = 'c:gcc-13'\n", encoding="utf-8")
    evaluator.write_text("[oracle]\nid = 'withheld'\n", encoding="utf-8")

    manifest = root / "cases" / "case.toml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        f"""\
[case]
schema_version = 1
policy_version = "{BENCHMARK_CASE_POLICY}"
id = "case_0123456789abcdef"
partition = "sealed_holdout"
supported_family = "parser-cursor-oob-read"
required_hunter = "c-parser-state"
repetition_index = 1

[source]
repository = "https://example.invalid/project.git"
commit = "{'1' * 40}"
tree = "{'2' * 40}"

[discovery]
scan_manifest = "inputs/scan.toml"
scan_manifest_sha256 = "{_sha256(scan)}"

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
kind = "oracle"
reference = "sealed/evaluator.toml"
sha256 = "{_sha256(evaluator)}"
""",
        encoding="utf-8",
    )
    return manifest


def test_benchmark_case_schema_is_valid_draft_2020_12() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    Draft202012Validator.check_schema(schema)
    assert schema["$id"].endswith("benchmark-case-v1.schema.json")


def test_case_loads_closed_contract_and_canonical_discovery_view(tmp_path: Path) -> None:
    manifest = _write_case(tmp_path)

    case = load_benchmark_case(manifest, repository_root=tmp_path)

    assert case.partition == "sealed_holdout"
    assert case.supported_family == "parser-cursor-oob-read"
    assert case.required_hunter == "c-parser-state"
    assert case.manifest_sha256.startswith("sha256:")
    assert case.discovery_sha256.startswith("sha256:")
    assert json.loads(case.discovery_bytes()) == case.discovery_payload()


def test_discovery_projection_excludes_all_evaluator_only_fields(tmp_path: Path) -> None:
    manifest = _write_case(tmp_path)
    case = load_benchmark_case(manifest, repository_root=tmp_path)

    encoded = case.discovery_bytes().decode("utf-8")

    for withheld in (
        "sealed_holdout",
        "parser-cursor-oob-read",
        "c-parser-state",
        "evaluator.toml",
        "evaluation",
        "oracle",
    ):
        assert withheld not in encoded
    assert set(case.discovery_payload()) == {"case", "source", "discovery", "budget"}


def test_manifest_order_does_not_change_discovery_bytes(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first = _write_case(first_root)
    second = _write_case(second_root)
    second_text = second.read_text(encoding="utf-8")
    second.write_text(
        second_text.replace(
            "max_hunter_sessions = 12\nmax_input_tokens = 2000000",
            "max_input_tokens = 2000000\nmax_hunter_sessions = 12",
        ),
        encoding="utf-8",
    )

    first_case = load_benchmark_case(first, repository_root=first_root)
    second_case = load_benchmark_case(second, repository_root=second_root)

    assert first_case.discovery_bytes() == second_case.discovery_bytes()
    assert first_case.discovery_sha256 == second_case.discovery_sha256


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        ('id = "case_0123456789abcdef"', 'id = "cve_2023_1234"', "case.id"),
        ('partition = "sealed_holdout"', 'partition = "training"', "case.partition"),
        (
            'supported_family = "parser-cursor-oob-read"',
            'supported_family = "memory-safety"',
            "case.supported_family",
        ),
        ('required_hunter = "c-parser-state"', 'required_hunter = "C Parser"', "case.required_hunter"),
        ("repetition_index = 1", "repetition_index = 0", "case.repetition_index"),
        ("max_hunter_sessions = 12", "max_hunter_sessions = 13", "budget.max_hunter_sessions"),
    ],
)
def test_case_rejects_open_or_out_of_budget_values(
    tmp_path: Path,
    old: str,
    new: str,
    match: str,
) -> None:
    manifest = _write_case(tmp_path)
    manifest.write_text(manifest.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")

    with pytest.raises(BenchmarkContractError, match=match):
        load_benchmark_case(manifest, repository_root=tmp_path)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ('scan_manifest = "inputs/scan.toml"', 'scan_manifest = "../scan.toml"'),
        ('reference = "sealed/evaluator.toml"', 'reference = "/private/evaluator.toml"'),
        ('scan_manifest = "inputs/scan.toml"', r'scan_manifest = "inputs\\scan.toml"'),
    ],
)
def test_case_rejects_non_repository_relative_references(
    tmp_path: Path,
    old: str,
    new: str,
) -> None:
    manifest = _write_case(tmp_path)
    manifest.write_text(manifest.read_text(encoding="utf-8").replace(old, new), encoding="utf-8")

    with pytest.raises(BenchmarkContractError, match="repository-relative"):
        load_benchmark_case(manifest, repository_root=tmp_path)


def test_case_rejects_reference_hash_mismatch(tmp_path: Path) -> None:
    manifest = _write_case(tmp_path)
    scan = tmp_path / "inputs" / "scan.toml"
    scan.write_text("[scan]\ntampered = true\n", encoding="utf-8")

    with pytest.raises(BenchmarkContractError, match="scan manifest reference hash mismatch"):
        load_benchmark_case(manifest, repository_root=tmp_path)
