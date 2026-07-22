"""HunterAgent — tool-use loop over one file.

Drives a single LLM session against one starting file using a system prompt
loaded from prompts/hunters/.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..core.jsonx import try_extract_object
from ..core.llm import LLMClient
from ..core.model_errors import ModelClientError
from ..core.tool_protocol import TOOL_ARGUMENTS_INVALID
from ..scheduling.budget import BudgetExceededError
from .tools import HunterTools, tool_specs

TARGET_COMPLETION_POLICY = "c-target-completion-v1"
SOURCE_EVIDENCE_POLICY = "c-source-read-evidence-v1"
SOURCE_EVIDENCE_RETRY_LIMIT = 1


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

When `focus_chain_ids` are present, use `read_file` on at least one matching
chain evidence range before finalizing. The source-evidence gate will reject a
finding, no-finding, or deferred result based only on packet excerpts.

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
    source_reads: list[dict] = field(default_factory=list)
    iterations: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    tool_calls: int = 0
    repeated_reads: int = 0
    poc_writes: int = 0
    exec_calls: int = 0
    tool_argument_errors: int = 0
    protocol_repairs: int = 0
    protocol_repair_successes: int = 0
    transient_retries: int = 0
    source_evidence_retries: int = 0
    model_failures: dict[str, int] = field(default_factory=dict)
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
        initial_metrics: dict | None = None,
        on_checkpoint=None,
    ):
        self.client = client
        self.tools = tools
        self.arch = arch
        self.hunter_prompt = hunter_prompt
        self.sandbox_info = sandbox_info or "No prepare info."
        self.max_iterations = max_iterations
        self.max_tokens_per_call = max_tokens_per_call
        self.on_event = on_event or (lambda *a, **k: None)
        self.initial_metrics = initial_metrics or {}
        self.on_checkpoint = on_checkpoint or (lambda result: None)

    async def hunt(
        self,
        target_file: str,
        analysis_context: dict | None = None,
        *,
        focused_retry_contexts: tuple[dict, ...] = (),
    ) -> HuntResult:
        result = _result_with_initial_metrics(self.initial_metrics)
        expected_targets = _expected_target_ids(analysis_context)
        source_requirements = _focused_source_requirements(analysis_context)
        retry_contexts = iter(focused_retry_contexts)
        completion_repairs = 0
        protocol_repair_pending = (
            result.protocol_repairs > result.protocol_repair_successes
        )
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
                self._checkpoint(result)
                return result
            except ModelClientError as exc:
                result.iterations += 1
                category = exc.category.value
                result.model_failures[category] = (
                    result.model_failures.get(category, 0) + 1
                )
                self.on_event(
                    "model_failure",
                    category=category,
                    retryable=exc.retryable,
                )
                if (
                    exc.retryable
                    and result.transient_retries < 1
                    and i + 1 < self.max_iterations
                ):
                    result.transient_retries += 1
                    self.on_event(
                        "model_retry",
                        category=category,
                        retry=result.transient_retries,
                    )
                    self._attach_tool_ledger(result)
                    self._checkpoint(result)
                    continue
                if exc.retryable:
                    result.stopped = "model_retry_exhausted"
                    result.budget_reason = f"model_{category}_retry_exhausted"
                    result.incomplete_target_ids = list(expected_targets)
                    result.target_dispositions = _deferred_dispositions(
                        expected_targets,
                        f"model {category} retry exhausted",
                    )
                    self._attach_tool_ledger(result)
                    self._checkpoint(result)
                    return result
                self._attach_tool_ledger(result)
                self._checkpoint(result)
                exc.partial_result = result
                raise
            result.iterations += 1
            result.input_tokens += resp.input_tokens
            result.output_tokens += resp.output_tokens
            result.cache_read_tokens += resp.cache_read_tokens
            result.cache_write_tokens += resp.cache_write_tokens

            invalid_arguments = [
                block["toolArgumentsInvalid"]
                for block in resp.content_blocks
                if "toolArgumentsInvalid" in block
            ]
            if protocol_repair_pending and not invalid_arguments:
                result.protocol_repair_successes += 1
                protocol_repair_pending = False
                self.on_event("tool_arguments_repair_succeeded")
            if invalid_arguments:
                result.tool_argument_errors += len(invalid_arguments)
                self.on_event(
                    TOOL_ARGUMENTS_INVALID,
                    count=len(invalid_arguments),
                    reasons=sorted({
                        str(item.get("reason") or "contract")
                        for item in invalid_arguments
                    }),
                )
                if result.protocol_repairs < 1 and i + 1 < self.max_iterations:
                    result.protocol_repairs += 1
                    protocol_repair_pending = True
                    messages.append({
                        "role": "assistant",
                        "content": [{"text": "Host tool arguments failed validation."}],
                    })
                    messages.append({
                        "role": "user",
                        "content": [{"text": _tool_repair_message(invalid_arguments)}],
                    })
                    self._checkpoint(result)
                    continue
                result.stopped = "tool_arguments_invalid"
                result.budget_reason = TOOL_ARGUMENTS_INVALID
                result.incomplete_target_ids = list(expected_targets)
                result.target_dispositions = _deferred_dispositions(
                    expected_targets,
                    "tool arguments remained invalid after one protocol repair",
                )
                self._attach_tool_ledger(result)
                self._checkpoint(result)
                return result

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
                            self._checkpoint(result)
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
                        self._checkpoint(result)
                        return result
                    has_source_evidence = _has_focused_source_read(
                        getattr(self.tools, "source_reads", []),
                        source_requirements,
                    )
                    if source_requirements and (
                        not has_source_evidence or incomplete
                    ):
                        if (
                            result.source_evidence_retries
                            < SOURCE_EVIDENCE_RETRY_LIMIT
                            and i + 1 < self.max_iterations
                        ):
                            result.source_evidence_retries += 1
                            retry_context = next(
                                retry_contexts,
                                analysis_context or {"slices": []},
                            )
                            source_requirements = (
                                _focused_source_requirements(retry_context)
                                or source_requirements
                            )
                            messages.append({
                                "role": "user",
                                "content": [{"text": _source_evidence_retry_message(
                                    retry_context,
                                    source_requirements,
                                    incomplete,
                                )}],
                            })
                            self.on_event(
                                "source_evidence_retry",
                                retry=result.source_evidence_retries,
                                required_paths=sorted(source_requirements),
                                incomplete_targets=incomplete,
                            )
                            self._attach_tool_ledger(result)
                            self._checkpoint(result)
                            continue
                        if not has_source_evidence:
                            result.findings = []
                            result.target_dispositions = _deferred_dispositions(
                                expected_targets,
                                "focused source evidence was not read",
                            )
                            result.incomplete_target_ids = list(expected_targets)
                            result.stopped = "source_evidence_missing"
                            result.budget_reason = "source_evidence_missing"
                            self._attach_tool_ledger(result)
                            self._checkpoint(result)
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
                    self._checkpoint(result)
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
                    self._checkpoint(result)
                    return result
                completion_repairs += 1
                messages.append({
                    "role": "user",
                    "content": [{"text": "Please output ONLY the final JSON report as specified."}],
                })
                self._checkpoint(result)
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
            self._attach_tool_ledger(result)
            self._checkpoint(result)

        result.stopped = "max_iter"
        result.incomplete_target_ids = list(expected_targets)
        result.target_dispositions = _deferred_dispositions(
            expected_targets,
            "maximum Hunter iterations reached",
        )
        if expected_targets:
            result.budget_reason = "target_completion_missing"
        self._attach_tool_ledger(result)
        self._checkpoint(result)
        return result

    def _attach_tool_ledger(self, result: HuntResult) -> None:
        result.executions = list(
            getattr(self.tools, "execution_records", [])
        )
        result.written_pocs = list(
            getattr(self.tools, "written_pocs", [])
        )
        result.source_reads = list(
            getattr(self.tools, "source_reads", [])
        )
        result.tool_calls = int(self.initial_metrics.get("tool_calls", 0)) + int(
            getattr(self.tools, "tool_calls", 0)
        )
        result.repeated_reads = int(
            self.initial_metrics.get("repeated_reads", 0)
        ) + int(getattr(self.tools, "repeated_reads", 0))
        result.poc_writes = int(self.initial_metrics.get("poc_writes", 0)) + int(
            getattr(self.tools, "poc_write_calls", 0)
        )
        result.exec_calls = int(self.initial_metrics.get("exec_calls", 0)) + len(
            result.executions
        )

    def _checkpoint(self, result: HuntResult) -> None:
        self.on_checkpoint(result)


def _result_with_initial_metrics(raw: dict) -> HuntResult:
    result = HuntResult()
    integer_fields = (
        "iterations",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "tool_calls",
        "repeated_reads",
        "poc_writes",
        "exec_calls",
        "tool_argument_errors",
        "protocol_repairs",
        "protocol_repair_successes",
        "transient_retries",
    )
    for name in integer_fields:
        value = raw.get(name, 0)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            setattr(result, name, value)
    failures = raw.get("model_failures")
    if isinstance(failures, dict):
        result.model_failures = {
            str(key): value
            for key, value in failures.items()
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        }
    return result


def _tool_repair_message(invalid_arguments: list[dict]) -> str:
    contracts = [
        {
            "error_code": TOOL_ARGUMENTS_INVALID,
            "tool": item.get("name") or "",
            "reason": item.get("reason") or "contract",
            "allowed_schema": item.get("allowedSchema") or {},
        }
        for item in invalid_arguments
    ]
    return (
        "Host tool arguments were rejected and no tool was executed. Repair this "
        "protocol error exactly once. Return the intended tool call with strict JSON "
        "that matches its allowed schema; do not repeat or explain the invalid payload. "
        + json.dumps(contracts, ensure_ascii=False, separators=(",", ":"))
    )


def _expected_target_ids(analysis_context: dict | None) -> tuple[str, ...]:
    focus = (analysis_context or {}).get("change_focus") or {}
    signal_ids = tuple(dict.fromkeys(focus.get("target_signal_ids") or ()))
    if signal_ids:
        return signal_ids
    return tuple(dict.fromkeys(focus.get("target_node_ids") or ()))


def _focused_source_requirements(
    analysis_context: dict | None,
) -> dict[str, tuple[int, ...]]:
    context = analysis_context or {}
    focus_ids = set(context.get("focus_chain_ids") or ())
    if not focus_ids:
        return {}
    requirements: dict[str, set[int]] = {}
    for chain in context.get("risk_chains") or ():
        if str(chain.get("chain_id", "")) not in focus_ids:
            continue
        path = str(chain.get("path", ""))
        if not path:
            continue
        requirements.setdefault(path, set()).update(
            int(line)
            for line in (
                *chain.get("source_lines", ()),
                *(step.get("line", 1) for step in chain.get("transform_steps", ())),
                *chain.get("guard_lines", ()),
                *chain.get("sink_lines", ()),
            )
        )
    for chain in context.get("capacity_risk_chains") or ():
        if str(chain.get("chain_id", "")) not in focus_ids:
            continue
        evidence_lines = chain.get("evidence_lines") or {}
        if evidence_lines:
            for path, lines in evidence_lines.items():
                requirements.setdefault(str(path), set()).update(
                    int(line) for line in lines
                )
            continue
        for path in (
            chain.get("root_path", ""),
            *(chain.get("paths") or ()),
        ):
            if path:
                requirements.setdefault(str(path), set())
    if not requirements:
        target = next(
            (
                item for item in context.get("source_excerpts") or ()
                if item.get("kind") == "target" and item.get("path")
            ),
            None,
        )
        if target is not None:
            requirements[str(target["path"])] = set()
    return {
        path: tuple(sorted(lines))
        for path, lines in sorted(requirements.items())
    }


def _has_focused_source_read(
    source_reads: object,
    requirements: dict[str, tuple[int, ...]],
) -> bool:
    if not requirements or not isinstance(source_reads, list):
        return not requirements
    for record in source_reads:
        if not isinstance(record, dict):
            continue
        path = str(record.get("path", ""))
        if path not in requirements:
            continue
        if int(record.get("bytes", 0)) <= 0:
            continue
        lines = requirements[path]
        if not lines:
            return True
        start = max(1, int(record.get("start", 1)))
        end = record.get("end")
        if end is None or any(start <= line <= int(end) for line in lines):
            return True
    return False


def _source_evidence_retry_message(
    context: dict,
    requirements: dict[str, tuple[int, ...]],
    incomplete_targets: list[str],
) -> str:
    reads = []
    for path, lines in requirements.items():
        if lines:
            reads.append({
                "path": path,
                "start": max(1, lines[0] - 6),
                "end": lines[0] + 6,
            })
        else:
            reads.append({"path": path, "start": 1})
    return (
        "Source-evidence gate blocked finalization. Use read_file on at least one "
        "focused evidence range below, then verify the allocation/write relationship "
        "before returning final JSON. Do not defer merely because an excerpt is short. "
        f"Incomplete targets: {json.dumps(incomplete_targets)}. "
        f"Suggested reads: {json.dumps(reads, ensure_ascii=False)}. "
        "Focused immutable context shard: "
        + json.dumps(context, ensure_ascii=False, separators=(",", ":"))
    )


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
