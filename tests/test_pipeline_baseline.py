from __future__ import annotations

import json
from pathlib import Path

from vulnhunt_agent.core.events import EventBus
from vulnhunt_agent.core.llm import LLMResponse
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.pipeline import STEPS
from vulnhunt_agent.pipeline.file_selector import run_file_selector
from vulnhunt_agent.pipeline.filter_files import run_filter
from vulnhunt_agent.pipeline import rank as rank_module

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "python_insecure_app"
GOLDEN_PATH = Path(__file__).parent / "golden" / "python_insecure_app_baseline.json"


class FakeRankClient:
    """Deterministic stand-in that preserves the Ranker request/response contract."""

    async def chat(self, *, messages, **kwargs) -> LLMResponse:
        prompt = messages[0]["content"][0]["text"]
        paths = [
            line.split(" (loc=", 1)[0]
            for line in prompt.splitlines()
            if " (loc=" in line
        ]
        scores = {
            "insecure_app/app.py": 5,
            "insecure_app/auth.py": 4,
            "insecure_app/__init__.py": 1,
        }
        text = json.dumps([{"p": path, "s": scores[path]} for path in paths])
        return LLMResponse(
            text=text,
            input_tokens=17,
            output_tokens=11,
            cache_read_tokens=0,
            cache_write_tokens=0,
            stop_reason="end_turn",
            content_blocks=[{"text": text}],
        )


async def test_filter_rank_selector_matches_golden(tmp_path, monkeypatch) -> None:
    store = RunStore(tmp_path / "run")
    store.save_config({
        "repo_path": str(FIXTURE_REPO),
        "environment": "python:3.12",
        "model_id": "test.model",
        "model_id_ranker": "test.model",
    })
    bus = EventBus(store.dir / "events.jsonl")
    monkeypatch.setattr(rank_module, "LLMClient", lambda **kwargs: FakeRankClient())

    await run_filter(store, bus)
    await rank_module.run_rank(store, bus)
    await run_file_selector(store, bus)

    actual = {
        "filtered_files": store.load_step("filtered_files"),
        "ranked_files": store.load_step("ranked_files"),
        "file_selector": store.load_step("file_selector"),
    }
    expected = json.loads(GOLDEN_PATH.read_text())
    assert actual == expected

    event_types = [event["type"] for event in bus.read_all()]
    assert event_types.count("step_done") == 3
    assert "rank_indexed" in event_types
    assert "rank_batch_done" in event_types


def test_registered_pipeline_order_is_stable() -> None:
    assert [step.name for step in STEPS] == [
        "filtered_files",
        "ranked_files",
        "file_selector",
        "sandbox_prepare",
        "hunt",
    ]
    assert STEPS[-1].depends_on == ["file_selector", "sandbox_prepare"]
