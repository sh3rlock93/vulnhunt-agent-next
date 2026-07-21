from __future__ import annotations

import json
from typing import Any, cast

from vulnhunt_agent.agents.hunter import HunterAgent
from vulnhunt_agent.agents.tools.executor import HunterTools
from vulnhunt_agent.core.llm import LLMResponse
from vulnhunt_agent.sandbox.base import ExecResult


def _response(*, text: str = "", blocks: list[dict], in_tokens: int, out_tokens: int):
    return LLMResponse(
        text=text,
        input_tokens=in_tokens,
        output_tokens=out_tokens,
        cache_read_tokens=0,
        cache_write_tokens=0,
        stop_reason="tool_use" if any("toolUse" in block for block in blocks) else "end_turn",
        content_blocks=blocks,
    )


class FakeHunterClient:
    def __init__(self) -> None:
        finding_json = json.dumps({
            "findings": [{
                "title": "Unvalidated outbound URL",
                "type": "ssrf",
                "severity": "high",
                "status": "unverified",
                "entry_file": "insecure_app/app.py",
                "entry_line": 5,
                "sink_file": "insecure_app/app.py",
                "sink_line": 7,
                "files_touched": ["insecure_app/app.py"],
                "description": "Attacker input reaches urlopen.",
                "attack": "Pass a link-local metadata URL.",
                "evidence": "fetch_url passes target_url directly.",
                "poc_file": "```python\nprint('not executed')\n```",
                "exec_output": "",
            }]
        })
        self.responses = [
            _response(
                blocks=[{"toolUse": {
                    "toolUseId": "call-1",
                    "name": "read_file",
                    "input": {"path": "insecure_app/app.py"},
                }}],
                in_tokens=10,
                out_tokens=3,
            ),
            _response(
                text=finding_json,
                blocks=[{"text": finding_json}],
                in_tokens=12,
                out_tokens=8,
            ),
        ]
        self.messages_seen: list[list[dict]] = []

    async def chat(self, *, messages, **kwargs) -> LLMResponse:
        self.messages_seen.append(list(messages))
        return self.responses.pop(0)


class FakeHunterTools:
    sandbox = None

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def dispatch(self, name: str, tool_input: dict) -> str:
        self.calls.append((name, tool_input))
        return "     1: def fetch_url(target_url): ..."


async def test_hunter_tool_loop_and_final_json_contract() -> None:
    client = FakeHunterClient()
    tools = FakeHunterTools()
    agent = HunterAgent(
        client=cast(Any, client),
        tools=cast(Any, tools),
        arch={"language": "python", "environment": "python:3.12"},
        hunter_prompt="Review the target.",
        max_iterations=3,
    )

    result = await agent.hunt(
        "insecure_app/app.py",
        {"policy_version": "c-coverage-v1", "slices": [{"slice_id": "slice-1"}]},
    )

    assert result.stopped == "final_json"
    assert result.iterations == 2
    assert result.input_tokens == 22
    assert result.output_tokens == 11
    assert result.findings[0]["status"] == "unverified"
    assert tools.calls == [("read_file", {"path": "insecure_app/app.py"})]
    second_request = client.messages_seen[1]
    assert second_request[-1]["content"][0]["toolResult"]["toolUseId"] == "call-1"
    first_prompt = client.messages_seen[0][0]["content"][0]["text"]
    assert "c-coverage-v1" in first_prompt
    assert "slice-1" in first_prompt


class TargetCompletionClient:
    def __init__(self) -> None:
        self.calls = 0

    async def chat(self, **kwargs) -> LLMResponse:
        self.calls += 1
        payload = (
            {"findings": []}
            if self.calls == 1
            else {
                "target_dispositions": [{
                    "target_id": "sig-alloc",
                    "status": "no_finding",
                    "finding_indices": [],
                    "rationale": "The allocation size is capped before ALLOC.",
                }],
                "findings": [],
            }
        )
        text = json.dumps(payload)
        return _response(
            text=text,
            blocks=[{"text": text}],
            in_tokens=10,
            out_tokens=5,
        )


async def test_hunter_requires_one_disposition_per_target_with_one_repair() -> None:
    client = TargetCompletionClient()
    agent = HunterAgent(
        client=cast(Any, client),
        tools=cast(Any, FakeHunterTools()),
        arch={"language": "c", "environment": "c:gcc-13"},
        hunter_prompt="Review the allocation target.",
        max_iterations=5,
    )

    result = await agent.hunt(
        "zip.c",
        {
            "change_focus": {
                "target_signal_ids": ["sig-alloc"],
                "target_node_ids": ["node-zip"],
            },
            "slices": [],
        },
    )

    assert client.calls == 2
    assert result.stopped == "final_json"
    assert result.incomplete_target_ids == []
    assert result.target_dispositions == [{
        "target_id": "sig-alloc",
        "status": "no_finding",
        "finding_indices": [],
        "rationale": "The allocation size is capped before ALLOC.",
    }]


class MissingTargetClient:
    def __init__(self) -> None:
        self.calls = 0

    async def chat(self, **kwargs) -> LLMResponse:
        self.calls += 1
        text = '{"findings": []}'
        return _response(
            text=text,
            blocks=[{"text": text}],
            in_tokens=10,
            out_tokens=5,
        )


async def test_missing_target_contract_stops_after_one_repair_and_defers() -> None:
    client = MissingTargetClient()
    agent = HunterAgent(
        client=cast(Any, client),
        tools=cast(Any, FakeHunterTools()),
        arch={"language": "c", "environment": "c:gcc-13"},
        hunter_prompt="Review the target.",
        max_iterations=20,
    )

    result = await agent.hunt(
        "zip.c",
        {"change_focus": {"target_signal_ids": ["sig-alloc"]}},
    )

    assert client.calls == 2
    assert result.stopped == "target_incomplete"
    assert result.incomplete_target_ids == ["sig-alloc"]
    assert result.target_dispositions[0]["status"] == "deferred"


class FakeContainer:
    def __init__(self) -> None:
        self.writes: list[tuple[str, str]] = []

    async def write_file(self, path: str, content: str) -> None:
        self.writes.append((path, content))

    async def exec_argv(self, argv, *, timeout, cwd) -> ExecResult:
        return ExecResult(
            exit_code=1,
            stdout="",
            stderr="AddressSanitizer: heap-buffer-overflow",
            duration_ms=12,
        )


async def test_hunter_tools_persist_exact_poc_and_execution_ledger(tmp_path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    pocs = tmp_path / "pocs"
    sandbox = FakeContainer()
    tools = HunterTools(
        source,
        sandbox=cast(Any, sandbox),
        poc_root=pocs,
    )

    await tools.dispatch("write_poc", {
        "path": "native/poc.c",
        "content": "int main(void) { return 0; }\n",
    })
    output = await tools.dispatch("exec", {
        "argv": ["/workspace/exec/poc"],
        "cwd": "/code",
        "timeout": 27,
    })

    assert tools.written_pocs == ["native/poc.c"]
    assert (pocs / "native" / "poc.c").is_file()
    assert tools.execution_records == [{
        "argv": ["/workspace/exec/poc"],
        "cwd": "/code",
        "timeout": 27,
        "exit_code": 1,
        "timed_out": False,
        "duration_ms": 12,
        "stdout": "",
        "stderr": "AddressSanitizer: heap-buffer-overflow",
    }]
    assert "exit_code=1" in output
