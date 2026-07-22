from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from vulnhunt_agent.core.events import EventBus
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.pipeline import hunt as hunt_pipeline
from vulnhunt_agent.pipeline.analysis_graph import run_analysis_graph
from vulnhunt_agent.pipeline.file_selector import run_file_selector
from vulnhunt_agent.pipeline.filter_files import run_filter
from vulnhunt_agent.pipeline.source_snapshot import run_source_snapshot
from vulnhunt_agent.pipeline.outcome import classify_run_outcome


def _summary(**changes) -> dict:
    baseline = {
        "total": 3,
        "done": 3,
        "failed": 0,
        "pending": 0,
        "running": 0,
        "budget_deferred": 0,
        "total_findings": 0,
        "target_completion": {
            "total": 3,
            "finding": 0,
            "no_finding": 3,
            "deferred": 0,
            "missing": 0,
        },
    }
    baseline.update(changes)
    return baseline


def _scope() -> dict:
    return {
        "policy_version": "scan-scope-v1",
        "digest": "sha256:" + "a" * 64,
        "mode": "files",
        "selected_files": ["src/a.c", "src/b.c"],
        "scope_deferred_critical_sink_ids": ["signal-outside"],
        "repository_complete": False,
    }


def test_complete_zero_finding_is_scoped_and_explicit() -> None:
    result = classify_run_outcome(
        _summary(),
        plan={"budget_allocation": {"admitted_sessions": 3}},
        scan_scope=_scope(),
        source_snapshot="sha256:" + "b" * 64,
    )

    assert result["outcome"] == "valid_complete"
    assert result["zero_findings"] is True
    assert result["zero_finding_label"] == (
        "0 findings in completed files scope (2 files; 1 scope-deferred critical "
        "targets; 0 unadmitted budget-deferred work; 0 admitted deferred work; "
        "0 deferred targets)"
    )
    assert result["scope"]["scope_deferred_critical_targets"] == 1
    assert result["scope"]["repository_complete"] is False


def test_budget_deferral_is_valid_but_never_called_complete() -> None:
    result = classify_run_outcome(
        _summary(
            done=2,
            budget_deferred=1,
            target_completion={
                "total": 3,
                "finding": 0,
                "no_finding": 2,
                "deferred": 1,
                "missing": 0,
            },
        ),
        plan={"budget_allocation": {"admitted_sessions": 2}},
        scan_scope=_scope(),
    )

    assert result["outcome"] == "valid_budget_limited"
    assert result["valid"] is True
    assert result["complete"] is False
    assert result["zero_findings"] is True
    assert "budget-limited" in result["zero_finding_label"]
    assert "1 scope-deferred critical targets" in result["zero_finding_label"]
    assert "1 unadmitted budget-deferred work" in result["zero_finding_label"]
    assert "0 admitted deferred work" in result["zero_finding_label"]
    assert "1 deferred targets" in result["zero_finding_label"]
    assert result["work"]["budget_deferred"] == 1


@pytest.mark.parametrize(
    ("changes", "kwargs", "expected"),
    [
        ({"failed": 1, "done": 2}, {}, "invalid_execution"),
        (
            {
                "target_completion": {
                    "total": 3,
                    "finding": 0,
                    "no_finding": 2,
                    "deferred": 0,
                    "missing": 1,
                },
            },
            {},
            "invalid_execution",
        ),
        ({"pending": 1, "done": 2}, {}, "interrupted"),
        ({}, {"interrupted": True}, "interrupted"),
        (
            {
                "running": 1,
                "done": 2,
                "target_completion": {
                    "total": 3,
                    "finding": 0,
                    "no_finding": 2,
                    "deferred": 0,
                    "missing": 1,
                },
            },
            {"interrupted": True},
            "interrupted",
        ),
        ({}, {"invalid_reason": "provider_preflight_failed"}, "invalid_execution"),
    ],
)
def test_invalid_or_interrupted_runs_never_claim_zero_findings(
    changes: dict,
    kwargs: dict,
    expected: str,
) -> None:
    result = classify_run_outcome(
        _summary(**changes),
        scan_scope=_scope(),
        **kwargs,
    )

    assert result["outcome"] == expected
    assert result["zero_findings"] is False
    assert result["zero_finding_label"] == ""
    assert result["trustworthy"] is False


async def test_cancelled_hunt_persists_resumable_interrupted_outcome(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "source"
    repo.mkdir()
    (repo / "parser.c").write_text(
        "#include <string.h>\n"
        "void parse(char *dst, const char *src, unsigned long size) {\n"
        "  memcpy(dst, src, size);\n"
        "}\n"
    )
    store = RunStore(tmp_path / "run-interrupted")
    store.save_config({
        "repo_path": str(repo),
        "environment": "c:gcc-13",
        "model_id": "gpt-test",
        "max_hunters_parallel": 1,
        "hunter_max_iterations": 3,
        "hunter_lease_seconds": 30,
    })
    bus = EventBus(store.dir / "events.jsonl")
    await run_source_snapshot(store, bus)
    await run_filter(store, bus)
    await run_analysis_graph(store, bus)
    await run_file_selector(store, bus)
    store.save_step("sandbox_prepare", {"status": "failed"})

    class BlockingClient:
        model_id = "gpt-test"
        transport = "test"

        def __init__(self) -> None:
            self.started = asyncio.Event()

        async def chat(self, **kwargs):
            self.started.set()
            await asyncio.Event().wait()

    client = BlockingClient()
    monkeypatch.setattr(hunt_pipeline, "LLMClient", lambda **kwargs: client)
    monkeypatch.setattr(
        hunt_pipeline,
        "base_image_for",
        lambda environment: "unused:latest",
    )

    execution = asyncio.create_task(hunt_pipeline.run_hunt(store, bus))
    await asyncio.wait_for(client.started.wait(), timeout=2)
    execution.cancel()
    with pytest.raises(asyncio.CancelledError):
        await execution

    summary = store.load_step("hunt")
    assert summary is not None
    assert summary["outcome"] == "interrupted"
    assert summary["zero_findings"] is False
    assert summary["running"] == 1
    assert summary["run_outcome"]["targets"]["all_admitted_terminal"] is False
    events = [
        json.loads(line)
        for line in (store.dir / "events.jsonl").read_text().splitlines()
    ]
    assert any(event["type"] == "step_interrupted" for event in events)
