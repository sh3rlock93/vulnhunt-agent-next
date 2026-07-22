from __future__ import annotations

import json
from typing import Any, cast

from vulnhunt_agent.agents.hunter import HunterAgent
from vulnhunt_agent.agents.tools import HunterTools
from vulnhunt_agent.core.llm import LLMResponse


def _response(payload: dict | None = None, *, tool: dict | None = None) -> LLMResponse:
    blocks: list[dict]
    if tool is not None:
        blocks = [{"toolUse": tool}]
        text = ""
        reason = "tool_use"
    else:
        text = json.dumps(payload)
        blocks = [{"text": text}]
        reason = "end_turn"
    return LLMResponse(
        text=text,
        input_tokens=10,
        output_tokens=5,
        cache_read_tokens=0,
        cache_write_tokens=0,
        stop_reason=reason,
        content_blocks=blocks,
    )


def _final(status: str) -> dict:
    return {
        "target_dispositions": [{
            "target_id": "sig-focus",
            "status": status,
            "finding_indices": [],
            "rationale": "More source evidence is needed." if status == "deferred" else (
                "The focused allocation and write use the same checked bound."
            ),
        }],
        "findings": [],
    }


def _context(chain_id: str, path: str, line: int) -> dict:
    return {
        "focus_chain_ids": [chain_id],
        "change_focus": {"target_signal_ids": ["sig-focus"]},
        "risk_chains": [{
            "chain_id": chain_id,
            "path": path,
            "source_lines": [line],
            "transform_steps": [],
            "guard_lines": [],
            "sink_lines": [line + 1],
        }],
        "capacity_risk_chains": [],
        "source_excerpts": [{
            "path": path,
            "kind": "target",
            "content": f"{line}: int focused = input;",
        }],
    }


class FocusedRetryClient:
    def __init__(self) -> None:
        self.calls = 0
        self.messages: list[list[dict]] = []

    async def chat(self, *, messages, **kwargs) -> LLMResponse:
        self.calls += 1
        self.messages.append(list(messages))
        if self.calls == 1:
            return _response(_final("deferred"))
        if self.calls == 2:
            return _response(tool={
                "toolUseId": "read-focused-shard",
                "name": "read_file",
                "input": {"path": "callee.c", "start": 1, "end": 12},
            })
        return _response(_final("no_finding"))


async def test_deferred_without_source_read_retries_with_next_focus_shard(tmp_path) -> None:
    (tmp_path / "caller.c").write_text("int caller(int input) { return input; }\n")
    (tmp_path / "callee.c").write_text("int callee(int input) { return input; }\n")
    client = FocusedRetryClient()
    tools = HunterTools(tmp_path)
    agent = HunterAgent(
        client=cast(Any, client),
        tools=tools,
        arch={"language": "c", "environment": "c:gcc-13"},
        hunter_prompt="Review the capacity chain.",
        max_iterations=4,
    )

    result = await agent.hunt(
        "caller.c",
        _context("risk_aaaaaaaaaaaaaaaaaaaa", "caller.c", 1),
        focused_retry_contexts=(
            _context("risk_bbbbbbbbbbbbbbbbbbbb", "callee.c", 1),
        ),
    )

    assert result.stopped == "final_json"
    assert result.source_evidence_retries == 1
    assert result.incomplete_target_ids == []
    assert len(result.source_reads) == 1
    assert result.source_reads[0]["path"] == "callee.c"
    assert result.source_reads[0]["start"] == 1
    assert result.source_reads[0]["end"] == 12
    assert result.source_reads[0]["bytes"] > 0
    retry_prompt = client.messages[1][-1]["content"][0]["text"]
    assert "Source-evidence gate blocked finalization" in retry_prompt
    assert "risk_bbbbbbbbbbbbbbbbbbbb" in retry_prompt
    assert "callee.c" in retry_prompt


class NoReadClient:
    async def chat(self, **kwargs) -> LLMResponse:
        return _response(_final("no_finding"))


async def test_final_answer_without_focused_read_fails_closed_after_one_retry(
    tmp_path,
) -> None:
    (tmp_path / "target.c").write_text("int target(int input) { return input; }\n")
    result = await HunterAgent(
        client=cast(Any, NoReadClient()),
        tools=HunterTools(tmp_path),
        arch={"language": "c", "environment": "c:gcc-13"},
        hunter_prompt="Review the target.",
        max_iterations=3,
    ).hunt(
        "target.c",
        _context("risk_cccccccccccccccccccc", "target.c", 1),
    )

    assert result.stopped == "source_evidence_missing"
    assert result.budget_reason == "source_evidence_missing"
    assert result.source_evidence_retries == 1
    assert result.findings == []
    assert result.incomplete_target_ids == ["sig-focus"]
    assert result.target_dispositions[0]["status"] == "deferred"


class CapacityNegativeRecheckClient:
    def __init__(self) -> None:
        self.calls = 0
        self.messages: list[list[dict]] = []

    async def chat(self, *, messages, **kwargs) -> LLMResponse:
        self.calls += 1
        self.messages.append(list(messages))
        if self.calls == 1:
            return _response(tool={
                "toolUseId": "read-capacity",
                "name": "read_file",
                "input": {"path": "target.c", "start": 1, "end": 2},
            })
        return _response(_final("no_finding"))


async def test_complete_unchecked_no_finding_gets_one_adversarial_recheck(
    tmp_path,
) -> None:
    (tmp_path / "target.c").write_text(
        "void target(char *dst, int n) {\n  copy(dst, n);\n}\n"
    )
    client = CapacityNegativeRecheckClient()
    context = {
        "focus_chain_ids": ["capacity_risk_" + "a" * 20],
        "change_focus": {"target_signal_ids": ["sig-focus"]},
        "risk_chains": [],
        "capacity_risk_chains": [{
            "chain_id": "capacity_risk_" + "a" * 20,
            "priority_class": "complete_unchecked_capacity_path",
            "base": "dst",
            "element_count": "capacity",
            "guard_state": "absent",
            "evidence_lines": {"target.c": [1, 2]},
            "evidence_facts": [{
                "kind": "write",
                "write_extent": "rounded_width",
                "evidence": "copy writes rounded_width bytes",
            }],
        }],
    }

    result = await HunterAgent(
        client=cast(Any, client),
        tools=HunterTools(tmp_path),
        arch={"language": "c", "environment": "c:gcc-13"},
        hunter_prompt="Review the capacity chain.",
        max_iterations=4,
    ).hunt("target.c", context)

    assert client.calls == 3
    assert result.stopped == "final_json"
    assert result.capacity_negative_rechecks == 1
    recheck_prompt = client.messages[2][-1]["content"][0]["text"]
    assert "Capacity negative-result gate" in recheck_prompt
    assert "rounded_width" in recheck_prompt
    assert "normalized enum/category" in recheck_prompt


async def test_hunter_tools_record_only_successful_unique_source_reads(tmp_path) -> None:
    (tmp_path / "target.c").write_text("line one\nline two\n")
    tools = HunterTools(tmp_path)

    await tools.dispatch("read_file", {"path": "target.c", "start": 2, "end": 2})
    await tools.dispatch("read_file", {"path": "target.c", "start": 2, "end": 2})
    await tools.dispatch("read_file", {"path": "missing.c"})

    assert tools.source_reads == [{
        "path": "target.c",
        "start": 2,
        "end": 2,
        "bytes": len("     2: line two".encode()),
    }]
