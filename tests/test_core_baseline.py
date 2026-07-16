from __future__ import annotations

import pytest

from vulnhunt_agent.agents.queue import HuntQueueStore
from vulnhunt_agent.agents.reviewer import ReviewResult
from vulnhunt_agent.core import cvss
from vulnhunt_agent.core.events import EventBus
from vulnhunt_agent.core.jsonx import extract_array, extract_object, try_extract_object
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.pipeline import finalize


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_baseline_vectors(vector: str, expected: float) -> None:
    assert cvss.base_score(vector) == expected


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0.0, "none"), (3.9, "low"), (6.9, "medium"), (8.9, "high"), (9.0, "critical")],
)
def test_cvss_severity_boundaries(score: float, expected: str) -> None:
    assert cvss.severity(score) == expected


def test_lenient_json_extractors_preserve_current_contract() -> None:
    assert extract_object("prefix {\"ok\": true} suffix") == {"ok": True}
    assert extract_array("```json\n[1, 2]\n```") == [1, 2]
    assert try_extract_object("not json") is None
    assert try_extract_object("{invalid}") is None
    with pytest.raises(ValueError, match="no JSON object"):
        extract_object("not json")
    with pytest.raises(ValueError, match="no JSON array"):
        extract_array("not json")


def test_event_bus_empty_and_append_only_log(tmp_path) -> None:
    bus = EventBus(tmp_path / "events.jsonl")
    assert bus.read_all() == []
    bus.emit("rank_done", files=2)
    events = bus.read_all()
    assert events[0]["type"] == "rank_done"
    assert events[0]["files"] == 2
    assert "ts" in events[0]


def test_run_store_and_queue_resume_state(tmp_path) -> None:
    store = RunStore(tmp_path / "run")
    store.save_config({"environment": "python:3.12"})
    assert store.load_config() == {"environment": "python:3.12"}

    qstore = HuntQueueStore(store.dir / "hunters")
    queue = qstore.init_from_pairs([
        ("insecure_app/app.py", "python"),
        ("insecure_app/auth.py", "python"),
    ])
    first = queue.tasks[0]
    qstore.mark_file_running(first)
    qstore.mark_hunt_done(first, "python", findings_count=1)

    reloaded = qstore.load()
    assert reloaded.tasks[0].status == "hunting"
    assert reloaded.tasks[0].hunters[0].status == "done"
    assert reloaded.tasks[0].hunters[0].findings_count == 1


def test_finalize_scores_and_materializes_report(tmp_path) -> None:
    review = ReviewResult(
        reviewed=[{
            "title": "Remote command execution",
            "verdict": "real",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }],
        reports=[{
            "finding_idx": 0,
            "cwe": "CWE-78",
            "markdown": "Score {{cvss_score}} {{severity}} {{cvss_vector}}",
        }],
    )

    finalize.enrich_with_cvss(review)
    finalize.materialize_reports(tmp_path, review)

    assert review.reviewed[0]["cvss_score"] == 9.8
    assert review.reviewed[0]["severity"] == "critical"
    assert "Score 9.8 critical CVSS:3.1" in review.reports[0]["markdown"]
    report_files = list((tmp_path / "reports").glob("*/report.md"))
    assert len(report_files) == 1
    assert report_files[0].read_text() == review.reports[0]["markdown"]


def test_rewrite_poc_paths_only_strips_workspace_prefix() -> None:
    findings = [
        {"poc_file": "/workspace/poc.py"},
        {"poc_file": "inline.py"},
    ]
    finalize.rewrite_poc_paths(findings)
    assert findings == [{"poc_file": "poc.py"}, {"poc_file": "inline.py"}]
