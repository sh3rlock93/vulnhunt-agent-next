from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from benchmarks.m12.calibration import (
    DEFAULT_CATALOG,
    ORACLE_ROOT,
    ORACLE_SCHEMA,
    PROJECT_ROOT,
    REQUIRED_FAMILIES,
    load_calibration_catalog,
)
from benchmarks.run_libtiff_blind_benchmark import (
    BenchmarkContractError,
    _worker_environment,
)


def test_calibration_oracle_schema_is_valid_draft_2020_12() -> None:
    schema = json.loads(ORACLE_SCHEMA.read_text(encoding="utf-8"))

    Draft202012Validator.check_schema(schema)
    assert schema["$id"].endswith("calibration-oracle-v1.schema.json")


def test_catalog_has_four_opaque_unused_repositories_and_all_families() -> None:
    catalog = load_calibration_catalog()
    historical = tomllib.loads(
        (PROJECT_ROOT / "benchmarks/historical-detections.toml").read_text(
            encoding="utf-8"
        )
    )
    historical_repositories = {
        _normalize(item["source_repository"])
        for item in historical["detection"]
    }
    calibration_repositories = {
        _normalize(item.case.source.repository)
        for item in catalog.definitions
    }

    assert len(catalog.definitions) == 4
    assert len(calibration_repositories) == 4
    assert calibration_repositories.isdisjoint(historical_repositories)
    assert REQUIRED_FAMILIES <= {
        item.case.supported_family for item in catalog.definitions
    }
    assert catalog.repetitions_per_case == 3
    assert all(
        item.case.case_id == Path(item.manifest).stem
        and item.case.case_id.startswith("case_")
        for item in catalog.definitions
    )


def test_discovery_envelope_contains_no_oracle_or_target_knowledge() -> None:
    catalog = load_calibration_catalog()
    projection = catalog.discovery_envelope()
    encoded = catalog.discovery_bytes().decode("utf-8")

    assert len(projection["cases"]) == 4
    assert set(projection) == {
        "schema_version",
        "policy_version",
        "catalog_sha256",
        "repetitions_per_case",
        "cases",
    }
    for token in (
        "evaluation",
        "oracle",
        "fixed_source",
        "upstream_reference",
        "weakness",
        "supported_family",
        "required_hunter",
        "reproduction",
    ):
        assert token not in encoded


def test_each_scan_is_separate_from_fixed_control_and_trigger() -> None:
    catalog = load_calibration_catalog()

    for item in catalog.definitions:
        scan = (PROJECT_ROOT / item.case.discovery.scan_manifest).read_text(
            encoding="utf-8"
        )
        oracle = item.oracle
        assert oracle["fixed_source"]["commit"] not in scan
        assert oracle["fixed_source"]["tree"] not in scan
        assert oracle["oracle"]["upstream_reference"] not in scan
        assert oracle["oracle"]["weakness"] not in scan
        assert not any(
            required_path in scan
            for required_path in oracle["location"]["required_paths"]
        )
        assert str(ORACLE_ROOT.relative_to(PROJECT_ROOT)) not in scan


def test_discovery_process_audit_hook_blocks_oracle_open() -> None:
    oracle = next(iter(sorted(ORACLE_ROOT.glob("*.toml"))))
    worker_environment, _forwarded = _worker_environment(authenticated=False)
    worker_environment["PYTHONPATH"] = "src:."
    script = """
import json
from pathlib import Path
from benchmarks.run_libtiff_blind_benchmark import _install_oracle_access_guard
root = Path(__import__('sys').argv[1]).resolve()
target = Path(__import__('sys').argv[2]).resolve()
denied = []
_install_oracle_access_guard(root, denied)
try:
    target.read_bytes()
except PermissionError:
    print(json.dumps(denied))
else:
    raise SystemExit(3)
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(ORACLE_ROOT), str(oracle)],
        cwd=PROJECT_ROOT,
        env=worker_environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == [str(oracle)]


def test_catalog_fails_closed_when_a_scan_changes(tmp_path: Path) -> None:
    shutil.copytree(PROJECT_ROOT / "benchmarks", tmp_path / "benchmarks")
    scan = tmp_path / "benchmarks/m12/calibration/scans/case_f521543734c7e34a.toml"
    scan.write_text(scan.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(BenchmarkContractError, match="scan manifest reference hash mismatch"):
        load_calibration_catalog(
            tmp_path / DEFAULT_CATALOG.relative_to(PROJECT_ROOT),
            repository_root=tmp_path,
        )


def test_catalog_fails_closed_when_oracle_identity_changes(tmp_path: Path) -> None:
    shutil.copytree(PROJECT_ROOT / "benchmarks", tmp_path / "benchmarks")
    oracle = tmp_path / "benchmarks/oracles/m12-calibration/case_f521543734c7e34a.toml"
    oracle.write_text(
        oracle.read_text(encoding="utf-8").replace(
            'required_hunter = "c-bounds-integers"',
            'required_hunter = "c-parser-state"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(BenchmarkContractError, match="evaluator reference hash mismatch"):
        load_calibration_catalog(
            tmp_path / DEFAULT_CATALOG.relative_to(PROJECT_ROOT),
            repository_root=tmp_path,
        )


def _normalize(value: str) -> str:
    return value.rstrip("/").removesuffix(".git").lower()
