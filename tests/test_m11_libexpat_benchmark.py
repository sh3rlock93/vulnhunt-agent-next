from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from benchmarks.run_libexpat_live_benchmark import (
    BenchmarkContractError,
    _candidate_outcome_counts,
    _input_token_usage,
    _load_manifest,
    _metrics,
    _model_token_usage,
    _time_to_first_supported_candidate,
    _write_freeze_manifest,
    verify_freeze,
)


def test_live_manifest_is_pinned_budgeted_and_oracle_free() -> None:
    path = Path("benchmarks/libexpat-live-scan.toml")
    manifest = _load_manifest(path)
    raw = path.read_text(encoding="utf-8").casefold()

    assert manifest["source"]["commit"] == (
        "7d93af0965eee44fde42d9e9ec8761ae2894e8e8"
    )
    assert manifest["source"]["tree"] == (
        "47d69feb0ab11908f74f53af86da533e864472f7"
    )
    assert manifest["budget"]["max_hunter_sessions"] == 12
    assert all(
        token not in raw
        for token in ("cve-", "patch", "fixed_", "ground_truth")
    )


def test_live_manifest_rejects_withheld_knowledge(tmp_path: Path) -> None:
    source = Path("benchmarks/libexpat-live-scan.toml").read_text(encoding="utf-8")
    path = tmp_path / "leaky.toml"
    path.write_text(source + '\nwithheld_note = "CVE-2099-9999"\n')

    with pytest.raises(BenchmarkContractError, match="withheld"):
        _load_manifest(path)


def test_freeze_manifest_detects_any_artifact_mutation(tmp_path: Path) -> None:
    output = tmp_path / "operational"
    output.mkdir()
    metrics = output / "metrics.json"
    metrics.write_text(json.dumps({"passed": True}) + "\n")

    _write_freeze_manifest(output)

    assert verify_freeze(output) is True
    metrics.write_text(json.dumps({"passed": False}) + "\n")
    assert verify_freeze(output) is False


def test_deterministic_metrics_have_zeroed_complete_usage_dimensions() -> None:
    metrics = _metrics({
        "mode": "deterministic",
        "passed": True,
        "digests": {},
        "scope": {},
        "planning": {},
    })

    assert metrics["usage"] == {
        "sessions": 0,
        "calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "tool_calls": 0,
        "wall_time_ms": 0,
    }


def test_candidate_outcomes_are_complete_and_group_terminal_states() -> None:
    counts = _candidate_outcome_counts(Counter({
        "confirmed": 2,
        "statically_refuted": 3,
        "resource_infeasible": 4,
        "reproduction_rejected": 5,
        "verification_deferred": 6,
    }))

    assert counts == {
        "confirmed": 2,
        "refuted": 7,
        "rejected": 5,
        "deferred": 6,
    }


def test_supported_candidate_time_uses_durable_candidate_creation(
    tmp_path: Path,
) -> None:
    (tmp_path / "events.jsonl").write_text(
        '{"ts":"2026-01-01T00:00:00+00:00","type":"step_start"}\n'
        '{"ts":"2026-01-01T00:00:02+00:00","findings":1}\n'
    )
    candidates = [{
        "state": "rejected",
        "created_at": "2026-01-01T00:00:05+00:00",
        "resolution": {"disposition": "reproduction_rejected"},
    }]

    assert _time_to_first_supported_candidate(tmp_path, candidates) == 5_000


def test_budget_and_efficiency_tokens_include_cache_usage() -> None:
    usage = {
        "input_tokens": 100,
        "cache_read_tokens": 20,
        "cache_write_tokens": 3,
        "output_tokens": 10,
    }

    assert _input_token_usage(usage) == 123
    assert _model_token_usage(usage) == 133
