from __future__ import annotations

import json
from typing import Any, cast

from vulnhunt_agent.agents.hunter import HunterAgent
from vulnhunt_agent.core.llm import LLMResponse


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

    result = await agent.hunt("insecure_app/app.py")

    assert result.stopped == "final_json"
    assert result.iterations == 2
    assert result.input_tokens == 22
    assert result.output_tokens == 11
    assert result.findings[0]["status"] == "unverified"
    assert tools.calls == [("read_file", {"path": "insecure_app/app.py"})]
    second_request = client.messages_seen[1]
    assert second_request[-1]["content"][0]["toolResult"]["toolUseId"] == "call-1"
