"""ReviewerAgent — two-phase review of a HunterAgent's findings.

Phase 1: verdict for every finding (read code, judge, score).
Phase 2: write a markdown report for each verdict=real finding (same session,
         so the model already has the code in context). PoC code can be cited
         via the read_poc tool.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..core.jsonx import try_extract_object
from ..core.llm import LLMClient
from .tools import HunterTools, POC_READ_TOOL, READ_TOOLS

REVIEW_TOOLS = READ_TOOLS + [POC_READ_TOOL]


VERDICT_SYSTEM_PROMPT = """You are a senior security reviewer auditing another agent's vulnerability findings.

You have read-only tools (read_file, grep, list_dir, read_poc). No code execution.

You receive a **group** of findings that an upstream clusterer judged to share
the same root cause. Treat the group as one candidate bug, but apply this rule:

- If the findings really are the same root cause, write ONE merged review entry
  that covers all of them (one verdict, one CVSS vector, one report). Mention in
  notes which input findings were merged ("merged from #0, #2").
- If the clusterer over-merged and they are actually distinct bugs, write
  SEPARATE entries — one per real bug. Do not collapse genuinely different
  vulnerabilities just because they were grouped.

For each finding (or merged group):
1. Read the relevant code (entry_file, sink_file, files_touched) to verify the claim.
2. Check upstream defenses. When the claim depends on attacker-controlled input
   reaching a sink, actively investigate whether upstream layers block the attack:
   request-body sanitizers, parameter allow/deny lists, auth middleware, feature
   flags, proxy validation, type coercion. Grep for the parameter name across
   proxy/auth/middleware directories. If a default-on defense blocks the attack,
   the finding is a hardening issue (lower score), NOT a critical bypass.
3. Check exploitability preconditions. If exploitation requires a non-default
   option or a rare deployment topology, REFLECT IT IN THE CVSS VECTOR (AC, PR),
   do NOT mark it false_positive just because the option is opt-in.
4. Decide verdict:
   - "real": the bypass actually works (PoC ran, or code path is clearly reachable),
     EVEN IF a non-default option is required to trigger it. Documented-as-unsafe
     options used in real workflows still count (e.g., `secrets_from_env=True`
     is used by saved-chain loaders, so a bypass behind it is real).
   - "false_positive": the bypass does NOT actually work (PoC failed, code path
     unreachable, hypothetical pattern with no evidence), OR it's a style /
     hardening issue with no security impact.
   - "unclear": you couldn't verify the claim from the code; needs human review.
5. Pick CVSS vector. Use these rules — do not invent worst-case scenarios:
   AV (Attack Vector):
     N = network input (HTTP, JSON, message queue)
     A = adjacent network only
     L = local user (shell, local IPC)
     P = physical access
   AC (Attack Complexity):
     L = attacker only needs to shape input bytes that pass validation
     H = needs Python-side object injection, races, timing, or a non-default
         option to be enabled by the operator
   PR (Privileges Required):
     N = unauthenticated; L = any authenticated user; H = privileged role only
   UI (User Interaction):
     N = automatic; R = victim must click/open something
   S (Scope):
     C only when impact crosses a documented trust boundary (tenant→tenant,
     sandbox escape, kernel from userspace). Don't use C for "many users in
     the same trust zone".
   C / I / A (Confidentiality / Integrity / Availability):
     H = arbitrary read / write / DoS in the demonstrated flow
     L = bounded read / write / DoS, or impact only extends with a non-default
         option (mention the option in notes)
     N = no impact in this dimension
   Schema: "CVSS:3.1/AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?"
   The harness computes the score; you only pick the vector. Omit for non-real.
- notes: 1-3 sentences (cite file:line, mention any required non-default option).

When done with verdicts, STOP calling tools and output ONLY this JSON:
{
  "reviewed": [
    {
      "title": "<concise title — from a single finding, or synthesized for a merge>",
      "verdict": "real|false_positive|unclear",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "merged_from": [<input finding id>, ...],
      "notes": "<short>"
    }
  ]
}
For verdict != "real", set cvss_vector to "" (empty string).
`merged_from` lists which input ids contributed to this entry (1 id if the
group was kept as 1 finding; multiple if you merged; 1 each if you split)."""


REPORT_USER_PROMPT = """Now write a markdown report for each verdict=real finding.

For each one, use this format exactly (5 sections):

### {{title}}

**CVSS:** {{cvss_score}} ({{severity}}) — `{{cvss_vector}}`
**CWE:** {{cwe or 'unknown'}}

**Summary** — one or two sentences: what it is, who is impacted.

**Details** — code locations, data flow, why it's vulnerable. Cite path:line.

**PoC** — one-line run instruction + a fenced code block. Use the `read_poc`
tool to fetch the actual exploit code that was executed; quote it verbatim.

**Impact** — what an attacker gains.

The harness will fill `{{cvss_score}}` and `{{severity}}` from the vector you
already chose — leave those placeholders verbatim in your output.

Skip findings whose verdict is not "real".

Output ONLY this JSON, no prose:
{
  "reports": [
    {
      "finding_idx": <int — index into the reviewed array>,
      "cwe": "CWE-XXX or empty string",
      "markdown": "<the 5-section markdown above with the {{cvss_score}} and {{severity}} placeholders left untouched>"
    }
  ]
}"""


VERDICT_USER_TEMPLATE = """# Hunter target file
{target}

# Stack
{arch}

# Cluster context
{cluster_context}

# Findings to review (id-indexed)
{findings_json}

Review the code, decide verdicts (merge or split as appropriate), and produce
the JSON.
"""


@dataclass
class ReviewResult:
    reviewed: list[dict] = field(default_factory=list)
    reports: list[dict] = field(default_factory=list)
    manual_review_reports: list[dict] = field(default_factory=list)
    iterations: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    stopped: str = ""


class ReviewerAgent:
    def __init__(
        self,
        client: LLMClient,
        tools: HunterTools,
        arch: dict,
        max_iterations: int = 30,
        max_tokens_per_call: int = 4000,
        on_event=None,
    ):
        self.client = client
        self.tools = tools
        self.arch = arch
        self.max_iterations = max_iterations
        self.max_tokens_per_call = max_tokens_per_call
        self.on_event = on_event or (lambda *a, **k: None)

    async def review(
        self,
        target_file: str,
        findings: list[dict],
        cluster_reason: str = "",
    ) -> ReviewResult:
        result = ReviewResult()
        if not findings:
            result.stopped = "no_findings"
            return result

        ctx = (
            f"This group has {len(findings)} finding(s). "
            f"Clusterer reasoning: {cluster_reason}"
            if cluster_reason
            else f"This group has {len(findings)} finding(s) (no cluster step ran)."
        )
        indexed = [{"id": i, **f} for i, f in enumerate(findings)]
        messages: list[dict] = [{
            "role": "user",
            "content": [{"text": VERDICT_USER_TEMPLATE.format(
                target=target_file,
                arch=json.dumps(self.arch, ensure_ascii=False),
                cluster_context=ctx,
                findings_json=json.dumps(indexed, ensure_ascii=False, indent=2),
            )}],
        }]

        verdicts = await self._loop(messages, result, phase="verdict")
        if verdicts is None:
            return result
        result.reviewed = verdicts.get("reviewed", [])

        if not any(r.get("verdict") == "real" for r in result.reviewed):
            result.stopped = "no_real"
            return result

        messages.append({"role": "user", "content": [{"text": REPORT_USER_PROMPT}]})
        reports = await self._loop(messages, result, phase="report")
        if reports is None:
            return result
        result.reports = reports.get("reports", [])
        result.stopped = "final_json"
        return result

    async def _loop(
        self, messages: list[dict], result: ReviewResult, phase: str,
    ) -> dict | None:
        for _ in range(self.max_iterations):
            result.iterations += 1
            self.on_event(f"review_{phase}_iter", n=result.iterations)

            resp = await self.client.chat(
                messages=messages,
                system=VERDICT_SYSTEM_PROMPT,
                tools=REVIEW_TOOLS,
                max_tokens=self.max_tokens_per_call,
                cache_system=True,
                cache_tools=True,
                cache_last_user=True,
            )
            result.input_tokens += resp.input_tokens
            result.output_tokens += resp.output_tokens
            result.cache_read_tokens += resp.cache_read_tokens
            result.cache_write_tokens += resp.cache_write_tokens

            assistant_content = resp.content_blocks or [{"text": "(no output)"}]
            messages.append({"role": "assistant", "content": assistant_content})
            tool_uses = [b for b in resp.content_blocks if "toolUse" in b]

            if not tool_uses:
                parsed = try_extract_object(resp.text)
                if parsed is not None:
                    return parsed
                messages.append({
                    "role": "user",
                    "content": [{"text": "Please output ONLY the JSON as specified."}],
                })
                continue

            tool_results = []
            for block in tool_uses:
                tu = block["toolUse"]
                name = tu["name"]
                inp = tu.get("input", {})
                self.on_event(f"review_{phase}_tool_call", name=name, input=inp)
                output = await self.tools.dispatch(name, inp)
                self.on_event(f"review_{phase}_tool_result", name=name, bytes=len(output))
                tool_results.append({
                    "toolResult": {
                        "toolUseId": tu["toolUseId"],
                        "content": [{"text": output}],
                    }
                })
            messages.append({"role": "user", "content": tool_results})

        result.stopped = f"max_iter_{phase}"
        return None
