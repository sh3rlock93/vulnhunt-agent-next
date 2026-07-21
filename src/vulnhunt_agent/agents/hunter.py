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

TARGET_COMPLETION_POLICY = "c-target-completion-v1"


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

When `risk_chains` are present in the immutable context, start with them. Trace
the external source and conversion, each arithmetic/type transform, the guard
or missing guard, the allocation, and the later copy/index/loop bound in that
order. Compare the value that sizes the allocation with any independent value
that controls the later write. Treat the chain as a prioritization hypothesis,
not proof: verify reachability and the actual C types before reporting.

When done, STOP calling tools and output ONLY this JSON:
{
  "target_dispositions": [
    {
      "target_id": "<exact target signal/node id from change_focus>",
      "status": "finding|no_finding|deferred",
      "finding_indices": [<zero-based indexes into findings>],
      "rationale": "<concise evidence-based reason>"
    }
  ],
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

For every ID in `change_focus.target_signal_ids`, return exactly one target
disposition. If that list is empty, use `change_focus.target_node_ids` instead.
`finding` requires at least one valid finding index. `no_finding` requires no
finding indexes and a concrete reason the target is safe. Use `deferred` only
when evidence is insufficient; the work will remain incomplete. Do not return
unknown or duplicate target IDs.

If nothing significant, return an empty findings array and explicit
`no_finding` dispositions for every target."""


USER_TEMPLATE = """# Target file
{target}

# Shared immutable analysis context
{analysis_context}

# Stack (from arch analysis)
{arch}

# Sandbox state
{sandbox_info}

The target IDs are exact completion obligations; this is not a repository-root
exploration task. The shared excerpts are a starting point, not a read boundary. Use read_file or
grep whenever you need missing ranges, callers, headers, or sibling files.
Investigate this file and anything it touches. Produce the final JSON report when done.
"""


@dataclass
class HuntResult:
    findings: list[dict] = field(default_factory=list)
    target_dispositions: list[dict] = field(default_factory=list)
    incomplete_target_ids: list[str] = field(default_factory=list)
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
        expected_targets = _expected_target_ids(analysis_context)
        completion_repairs = 0
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
                result.incomplete_target_ids = list(expected_targets)
                result.target_dispositions = _deferred_dispositions(
                    expected_targets,
                    f"budget exhausted: {exc.reason}",
                )
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
                    findings = parsed.get("findings", [])
                    findings = findings if isinstance(findings, list) else []
                    dispositions, incomplete, error = _validate_dispositions(
                        parsed.get("target_dispositions"),
                        expected_targets=expected_targets,
                        findings=findings,
                    )
                    if error and expected_targets:
                        if completion_repairs < 1 and i + 1 < self.max_iterations:
                            completion_repairs += 1
                            messages.append({
                                "role": "user",
                                "content": [{"text": (
                                    "Target completion contract invalid: " + error + ". "
                                    "Return ONLY the complete final JSON once, with exactly "
                                    "one disposition for each expected target: "
                                    + json.dumps(expected_targets)
                                )}],
                            })
                            continue
                        result.findings = findings
                        result.target_dispositions = _deferred_dispositions(
                            expected_targets,
                            "target completion contract missing or invalid",
                        )
                        result.incomplete_target_ids = list(expected_targets)
                        result.stopped = "target_incomplete"
                        result.budget_reason = "target_completion_missing"
                        self._attach_tool_ledger(result)
                        return result
                    result.findings = findings
                    result.target_dispositions = dispositions
                    result.incomplete_target_ids = incomplete
                    result.stopped = (
                        "target_deferred" if incomplete else "final_json"
                    )
                    if incomplete:
                        result.budget_reason = "target_deferred"
                    self._attach_tool_ledger(result)
                    return result
                if expected_targets and completion_repairs >= 1:
                    result.target_dispositions = _deferred_dispositions(
                        expected_targets,
                        "final JSON was missing or invalid",
                    )
                    result.incomplete_target_ids = list(expected_targets)
                    result.stopped = "target_incomplete"
                    result.budget_reason = "target_completion_missing"
                    self._attach_tool_ledger(result)
                    return result
                completion_repairs += 1
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
        result.incomplete_target_ids = list(expected_targets)
        result.target_dispositions = _deferred_dispositions(
            expected_targets,
            "maximum Hunter iterations reached",
        )
        if expected_targets:
            result.budget_reason = "target_completion_missing"
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


def _expected_target_ids(analysis_context: dict | None) -> tuple[str, ...]:
    focus = (analysis_context or {}).get("change_focus") or {}
    signal_ids = tuple(dict.fromkeys(focus.get("target_signal_ids") or ()))
    if signal_ids:
        return signal_ids
    return tuple(dict.fromkeys(focus.get("target_node_ids") or ()))


def _validate_dispositions(
    raw: object,
    *,
    expected_targets: tuple[str, ...],
    findings: list[dict],
) -> tuple[list[dict], list[str], str]:
    if not expected_targets:
        return [], [], ""
    if not isinstance(raw, list):
        return [], list(expected_targets), "target_dispositions must be an array"

    expected = set(expected_targets)
    seen: set[str] = set()
    valid: list[dict] = []
    errors: list[str] = []
    for item in raw:
        if not isinstance(item, dict):
            errors.append("every disposition must be an object")
            continue
        target_id = item.get("target_id")
        status = item.get("status")
        indexes = item.get("finding_indices", [])
        rationale = item.get("rationale")
        if not isinstance(target_id, str) or target_id not in expected:
            errors.append(f"unknown target {target_id!r}")
            continue
        if target_id in seen:
            errors.append(f"duplicate target {target_id}")
            continue
        if status not in {"finding", "no_finding", "deferred"}:
            errors.append(f"invalid status for {target_id}")
            continue
        if not isinstance(indexes, list) or any(
            not isinstance(index, int) or isinstance(index, bool)
            or index < 0 or index >= len(findings)
            for index in indexes
        ):
            errors.append(f"invalid finding_indices for {target_id}")
            continue
        if status == "finding" and not indexes:
            errors.append(f"finding disposition lacks finding index for {target_id}")
            continue
        if status != "finding" and indexes:
            errors.append(f"non-finding disposition has finding index for {target_id}")
            continue
        if not isinstance(rationale, str) or not rationale.strip():
            errors.append(f"missing rationale for {target_id}")
            continue
        valid.append({
            "target_id": target_id,
            "status": status,
            "finding_indices": list(dict.fromkeys(indexes)),
            "rationale": rationale.strip(),
        })
        seen.add(target_id)

    missing = [target_id for target_id in expected_targets if target_id not in seen]
    deferred = [
        item["target_id"] for item in valid if item["status"] == "deferred"
    ]
    if missing:
        errors.append("missing targets: " + ", ".join(missing))
    return valid, [*missing, *deferred], "; ".join(errors)


def _deferred_dispositions(
    target_ids: tuple[str, ...] | list[str],
    rationale: str,
) -> list[dict]:
    return [
        {
            "target_id": target_id,
            "status": "deferred",
            "finding_indices": [],
            "rationale": rationale,
        }
        for target_id in target_ids
    ]
