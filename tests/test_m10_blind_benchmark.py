from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks.run_libtiff_blind_benchmark import (
    BenchmarkContractError,
    _first_valid_finding_metrics,
    build_parser,
    evaluate_frozen,
    freeze_discovery,
    load_scan_manifest,
    run_discover_parent,
    verify_frozen,
)
from vulnhunt_agent.pipeline.hunt import _tasks_in_admission_order


def _source(*, guarded: bool) -> str:
    guard = (
        "    if (!bands || span > UINT_MAX / bands / unit) return 1;\n"
        if guarded
        else ""
    )
    return (
        "#include <limits.h>\n"
        "#include <stdint.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "void *project_malloc(unsigned long);\n"
        "int main(int argc, char **argv) {\n"
        "    uint32_t span, bands, unit = 4, total, index;\n"
        "    unsigned char input[4] = {0};\n"
        "    unsigned char *output;\n"
        "    span = atoi(argv[1]);\n"
        "    bands = atoi(argv[2]);\n"
        + guard
        + "    total = span * bands * unit;\n"
        "    output = (unsigned char *)project_malloc(total);\n"
        "    for (index = 0; index < span; index++)\n"
        "        memcpy(output + index * bands * unit, input, unit);\n"
        "    return output == 0 || argc == 0;\n"
        "}\n"
    )


def _git_repo(path: Path, *, guarded: bool) -> tuple[str, str]:
    path.mkdir()
    (path / "convert.c").write_text(_source(guarded=guarded))
    subprocess.run(["git", "-C", str(path), "init", "-b", "main"], check=True)
    subprocess.run(
        ["git", "-C", str(path), "config", "user.name", "M10 Fixture"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "config",
            "user.email",
            "m10@example.invalid",
        ],
        check=True,
    )
    subprocess.run(["git", "-C", str(path), "add", "convert.c"], check=True)
    subprocess.run(
        ["git", "-C", str(path), "commit", "-m", "fixture"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    commit = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD^{tree}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return commit, tree


def _write_scan(path: Path, *, commit: str, tree: str) -> None:
    path.write_text(
        f"""
[benchmark]
schema_version = 1
id = "neutral-native-fixture"

[source]
repository = "fixture"
commit = "{commit}"
tree = "{tree}"

[scan]
environment = "c:gcc-13"
hunters = ["c-bounds-integers"]

[policies]
signal_router = "c-signal-router-v3"
risk_chain = "c-risk-chain-v1"
slice_work = "c-slice-work-v4"
context = "c-context-v4"
admission = "c-diverse-admission-v1"
evidence = "native-evidence-v2"
model_protocol = "strict-tool-json-v3"

[budget]
max_hunter_sessions = 24
max_input_tokens = 2000000
max_output_tokens = 200000
max_wall_clock_minutes = 60
max_retries_per_work_item = 1
max_format_repairs_per_work_item = 1

[limits]
max_target_signals_per_work = 6
max_context_bytes = 24000
max_parallel_hunters = 2
""".strip()
        + "\n"
    )


def _write_oracle(path: Path, *, commit: str, tree: str) -> None:
    path.write_text(
        f"""
[oracle]
schema_version = 1
id = "neutral-evaluation"
cve = "CVE-2099-0001"
weakness = "integer size overflow leading to heap buffer overflow"

[fixed_source]
commit = "{commit}"
tree = "{tree}"

[location]
entry_file = "convert.c"
entry_function = "main"
source_line_min = 1
source_line_max = 30
sink_file = "convert.c"
sink_function = "main"
sink_line_min = 1
sink_line_max = 40
fixed_sink_line_min = 1
fixed_sink_line_max = 40

[reproduction]
workspace_input = "input.bin"
workspace_input_text = "AA"
argv = ["/opt/fixture"]
attempts = 2
timeout_seconds = 5
expected_vulnerable_failure = "heap-buffer-overflow"
expected_fixed_stderr = "rejected"
""".strip()
        + "\n"
    )


def _discover_args(repo: Path, scan: Path, output: Path) -> argparse.Namespace:
    return argparse.Namespace(
        repo=repo,
        scan_manifest=scan,
        output=output,
        mode="deterministic",
        image="",
        model_id=None,
        skip_verify=False,
    )


def _evaluation_args(
    *,
    frozen: Path,
    oracle: Path,
    scan: Path,
    vulnerable: Path,
    fixed: Path,
    output: Path,
) -> argparse.Namespace:
    return argparse.Namespace(
        frozen=frozen,
        oracle=oracle,
        scan_manifest=scan,
        vulnerable_repo=vulnerable,
        fixed_repo=fixed,
        output=output,
        run_reproduction=False,
        vulnerable_image="",
        fixed_image="",
    )


def test_scan_manifest_rejects_withheld_fields(tmp_path) -> None:
    path = tmp_path / "leaky.toml"
    path.write_text(
        """
[benchmark]
schema_version = 1
sink_file = "convert.c"
"""
    )

    with pytest.raises(BenchmarkContractError, match="withheld knowledge"):
        load_scan_manifest(path)


def test_discover_parser_refuses_evaluation_options() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args([
            "discover",
            "--repo",
            ".",
            "--scan-manifest",
            "scan.toml",
            "--output",
            "out",
            "--mode",
            "deterministic",
            "--oracle",
            "oracle.toml",
        ])


def test_hunter_launch_order_is_the_persisted_admission_rank() -> None:
    tasks = [
        SimpleNamespace(work_id="work-c"),
        SimpleNamespace(work_id="work-a"),
        SimpleNamespace(work_id="work-b"),
    ]

    ordered = _tasks_in_admission_order(
        tasks,  # type: ignore[arg-type]
        ("work-b", "work-c"),
    )

    assert [item.work_id for item in ordered] == ["work-b", "work-c"]


def test_first_valid_finding_metrics_are_derived_from_frozen_artifacts(
    tmp_path,
) -> None:
    frozen = tmp_path / "frozen"
    run = frozen / "run"
    hunt = run / "hunters" / "work" / "hunts" / "c-bounds-integers"
    hunt.mkdir(parents=True)
    (run / "events.jsonl").write_text(
        '{"ts":"2026-01-01T00:00:00+00:00","type":"step_start"}\n'
        '{"ts":"2026-01-01T00:00:03+00:00","type":"hunter_done",'
        '"file":"convert.c","findings":1}\n'
    )
    (hunt / "findings.json").write_text(json.dumps({
        "findings": [{
            "title": "integer wrap reaches heap buffer overflow",
            "type": "integer_overflow",
            "entry_file": "convert.c",
            "entry_line": 10,
            "sink_file": "convert.c",
            "sink_line": 20,
            "description": "wrapped size causes memory corruption",
        }],
    }))
    (hunt / "usage-checkpoint.json").write_text(json.dumps({
        "input_tokens": 1200,
        "output_tokens": 300,
        "cache_read_tokens": 50,
    }))
    oracle = {
        "location": {
            "sink_file": "convert.c",
            "source_line_min": 1,
            "sink_line_min": 15,
            "sink_line_max": 25,
        },
    }

    metrics = _first_valid_finding_metrics(frozen, oracle)

    assert metrics == {
        "time_to_first_valid_finding_ms": 3000,
        "input_tokens_to_first_valid_finding": 1200,
        "output_tokens_to_first_valid_finding": 300,
        "cache_tokens_to_first_valid_finding": 50,
    }


def test_three_phase_blind_contract_and_static_negative_control(tmp_path) -> None:
    vulnerable = tmp_path / "vulnerable"
    fixed = tmp_path / "fixed"
    vulnerable_commit, vulnerable_tree = _git_repo(vulnerable, guarded=False)
    fixed_commit, fixed_tree = _git_repo(fixed, guarded=True)
    scan = tmp_path / "scan.toml"
    oracle = tmp_path / "oracle.toml"
    _write_scan(scan, commit=vulnerable_commit, tree=vulnerable_tree)
    _write_oracle(oracle, commit=fixed_commit, tree=fixed_tree)
    discovery_root = tmp_path / "discovery"
    frozen = tmp_path / "frozen"

    discovery = run_discover_parent(
        _discover_args(vulnerable, scan, discovery_root)
    )
    assert discovery["complete"] is True
    assert discovery["mode"] == "deterministic"
    assert discovery["oracle_access_audit"]["oracle_received"] is False
    assert discovery["oracle_access_audit"]["fixed_tree_received"] is False
    assert discovery["oracle_access_audit"]["denied_attempts"] == []
    serialized = json.dumps(discovery)
    assert "CVE-2099-0001" not in serialized
    assert discovery["summary"]["max_target_signals"] <= 6
    assert discovery["summary"]["max_context_bytes"] <= 24_000

    frozen_manifest = freeze_discovery(discovery_root, frozen)
    assert verify_frozen(frozen) == frozen_manifest
    result = evaluate_frozen(_evaluation_args(
        frozen=frozen,
        oracle=oracle,
        scan=scan,
        vulnerable=vulnerable,
        fixed=fixed,
        output=tmp_path / "evaluation",
    ))

    assert result["passed"] is True
    assert result["target"]["admission_rank"] <= 24
    assert result["checks"]["vulnerable_chain_found"] is True
    assert result["checks"]["fixed_guard_lowers_chain"] is True
    assert result["oracle"]["loaded_after_freeze_verification"] is True


def test_evaluation_rejects_tampering_before_opening_oracle(tmp_path) -> None:
    discovery = tmp_path / "discovery"
    discovery.mkdir()
    (discovery / "discovery.json").write_text(
        json.dumps({"phase": "discover", "complete": True})
    )
    (discovery / "artifact.json").write_text("{}")
    frozen = tmp_path / "frozen"
    freeze_discovery(discovery, frozen)
    (frozen / "artifact.json").write_text('{"tampered":true}')

    args = _evaluation_args(
        frozen=frozen,
        oracle=tmp_path / "does-not-exist.toml",
        scan=tmp_path / "does-not-exist-scan.toml",
        vulnerable=tmp_path / "does-not-exist-vulnerable",
        fixed=tmp_path / "does-not-exist-fixed",
        output=tmp_path / "evaluation",
    )
    with pytest.raises(BenchmarkContractError, match="SHA-256 verification failed"):
        evaluate_frozen(args)


def test_source_pin_mismatch_fails_closed(tmp_path) -> None:
    repo = tmp_path / "repo"
    commit, tree = _git_repo(repo, guarded=False)
    scan = tmp_path / "scan.toml"
    _write_scan(scan, commit="0" * 40, tree=tree)

    with pytest.raises(BenchmarkContractError, match="worker failed with exit"):
        run_discover_parent(_discover_args(repo, scan, tmp_path / "output"))
    assert commit != "0" * 40
