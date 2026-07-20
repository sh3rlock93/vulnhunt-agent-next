"""HunterAgent — tool-use loop over one file.

Drives a single LLM session against one starting file using a system prompt
loaded from prompts/hunters/.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..core.jsonx import try_extract_object
from ..core.llm import LLMClient
from ..scheduling.budget import BudgetExceededError
from .tools import HunterTools, tool_specs


FINAL_REPORT_INSTRUCTIONS = """VERIFY WITH A PoC.
For every concrete hypothesis, try to produce a Proof-of-Concept that exercises it.
- If `write_poc` and `exec` tools are available, write the PoC into /workspace
  and run it. The immutable repo snapshot is baked read-only into /code.
- `exec` accepts an argv array, not a shell command. Pass each argument as a
  separate item and do not use pipes, redirects, command substitution, or `sh -c`.
- The container is already prepared: the target is installed/importable when
  the user message says so. **Do not install packages or rebuild the target** —
  network is disabled and source/build artifacts are immutable. Use the prepared
  runtime and artifacts directly.
- Native PoC source belongs under `/workspace`; native binaries must be written
  below `/workspace/exec`, the only executable temporary filesystem.
- If those tools are NOT available, produce the PoC as a code block embedded in
  the finding's `poc_file` field — do not claim it executed.

Mark `status`:
- "confirmed" only if you ran the PoC and observed evidence of the bug.
- "unverified" if you didn't or couldn't execute it.

For each confirmed finding, include a machine-readable `reproduction` recipe:
- `setup_argvs` is the ordered list of `exec` argv calls needed before the
  triggering execution (for C this normally contains the compiler invocation);
- `argv`, `cwd`, and `timeout` must exactly match an `exec` call you actually made;
- `oracle` must be a concrete stable signal observed in that final call. Use
  `combined_regex` for ASan/UBSan evidence and escape regex metacharacters;
- `poc_file` must name a file written with `write_poc`.
The harness rejects recipes that do not match the recorded tool calls. For an
unverified finding set `reproduction` to null.

Do NOT fabricate execution results.

Before stopping, self-check: did you read the *callers* of suspicious functions, not just their definitions? Did you check sibling files in the same module? For each "looks safe" sink, what input would make it unsafe — and does that input flow in? If any of these is unanswered, keep exploring.

When done, STOP calling tools and output ONLY this JSON:
{
  "findings": [
    {
      "title": "<concise>",
      "type": "<e.g. sqli, auth_bypass, ssrf, path_traversal, logic, ...>",
      "severity": "critical|high|medium|low",
      "status": "confirmed|unverified",
      "entry_file": "<path>",
      "entry_line": <int>,
      "sink_file": "<path>",
      "sink_line": <int>,
      "files_touched": ["<path>", ...],
      "description": "<what the bug is>",
      "attack": "<how it would be exploited>",
      "evidence": "<code snippets or trace, concise>",
      "poc_file": "<path in /workspace OR inline code block>",
      "exec_output": "<key output from running the PoC, else ''>",
      "reproduction": null | {
        "setup_argvs": [["cc", "..."]],
        "argv": ["<executable>", "<arg>", "..."],
        "cwd": "/workspace",
        "timeout": 60,
        "oracle": {
          "type": "exit_code|stdout_regex|stderr_regex|combined_regex",
          "expected_exit_code": null,
          "pattern": "<observed non-trivial regex or null>"
        }
      }
    }
  ]
}

If nothing significant, return an empty findings array."""


USER_TEMPLATE = """# Target file
{target}

# Deterministic analysis slices
{analysis_context}

# Stack (from arch analysis)
{arch}

# Sandbox state
{sandbox_info}

Investigate this file and anything it touches. Produce the final JSON report when done.
"""


@dataclass
class HuntResult:
    findings: list[dict] = field(default_factory=list)
    executions: list[dict] = field(default_factory=list)
    written_pocs: list[str] = field(default_factory=list)
    iterations: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    tool_calls: int = 0
    repeated_reads: int = 0
    poc_writes: int = 0
    exec_calls: int = 0
    stopped: str = ""   # "final_json" | "max_iter" | "error"
    budget_reason: str = ""


class HunterAgent:
    def __init__(
        self,
        client: LLMClient,
        tools: HunterTools,
        arch: dict,
        hunter_prompt: str,
        sandbox_info: str = "",
        max_iterations: int = 100,
        max_tokens_per_call: int = 4000,
        on_event=None,
    ):
        self.client = client
        self.tools = tools
        self.arch = arch
        self.hunter_prompt = hunter_prompt
        self.sandbox_info = sandbox_info or "No prepare info."
        self.max_iterations = max_iterations
        self.max_tokens_per_call = max_tokens_per_call
        self.on_event = on_event or (lambda *a, **k: None)

    async def hunt(
        self,
        target_file: str,
        analysis_context: dict | None = None,
    ) -> HuntResult:
        result = HuntResult()
        with_sandbox = self.tools.sandbox is not None
        specs = tool_specs(with_sandbox)

        system_prompt = f"{self.hunter_prompt}\n\n{FINAL_REPORT_INSTRUCTIONS}"

        messages: list[dict] = [{
            "role": "user",
            "content": [{"text": USER_TEMPLATE.format(
                target=target_file,
                analysis_context=json.dumps(
                    analysis_context or {"slices": []}, ensure_ascii=False
                ),
                arch=json.dumps(self.arch, ensure_ascii=False),
                sandbox_info=self.sandbox_info,
            )}],
        }]

        for i in range(self.max_iterations):
            self.on_event("iter", n=i + 1)
            try:
                resp = await self.client.chat(
                    messages=messages,
                    system=system_prompt,
                    tools=specs,
                    max_tokens=self.max_tokens_per_call,
                    cache_system=True,
                    cache_tools=True,
                    cache_last_user=True,
                )
            except BudgetExceededError as exc:
                result.stopped = "budget_exhausted"
                result.budget_reason = exc.reason
                self._attach_tool_ledger(result)
                return result
            result.iterations = i + 1
            result.input_tokens += resp.input_tokens
            result.output_tokens += resp.output_tokens
            result.cache_read_tokens += resp.cache_read_tokens
            result.cache_write_tokens += resp.cache_write_tokens

            # Defense against models that occasionally return zero blocks —
            # Bedrock rejects messages whose content list is empty.
            assistant_content = resp.content_blocks or [{"text": "(no output)"}]
            messages.append({"role": "assistant", "content": assistant_content})
            tool_uses = [b for b in resp.content_blocks if "toolUse" in b]

            if not tool_uses:
                parsed = try_extract_object(resp.text)
                if parsed is not None:
                    result.findings = parsed.get("findings", [])
                    result.stopped = "final_json"
                    self._attach_tool_ledger(result)
                    return result
                messages.append({
                    "role": "user",
                    "content": [{"text": "Please output ONLY the final JSON report as specified."}],
                })
                continue

            tool_results = []
            for block in tool_uses:
                tu = block["toolUse"]
                name = tu["name"]
                tool_input = tu.get("input", {})
                use_id = tu["toolUseId"]
                self.on_event("tool_call", name=name, input=tool_input)
                output = await self.tools.dispatch(name, tool_input)
                self.on_event("tool_result", name=name, bytes=len(output))
                tool_results.append({
                    "toolResult": {
                        "toolUseId": use_id,
                        "content": [{"text": output}],
                    }
                })
            messages.append({"role": "user", "content": tool_results})

        result.stopped = "max_iter"
        self._attach_tool_ledger(result)
        return result

    def _attach_tool_ledger(self, result: HuntResult) -> None:
        result.executions = list(
            getattr(self.tools, "execution_records", [])
        )
        result.written_pocs = list(
            getattr(self.tools, "written_pocs", [])
        )
        result.tool_calls = int(getattr(self.tools, "tool_calls", 0))
        result.repeated_reads = int(getattr(self.tools, "repeated_reads", 0))
        result.poc_writes = int(getattr(self.tools, "poc_write_calls", 0))
        result.exec_calls = len(result.executions)
