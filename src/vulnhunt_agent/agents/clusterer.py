"""ClustererAgent — pre-review grouping pass owned by the Reviewer phase.

Before deciding verdicts on findings for a file, it groups items that share a
root cause. Isolated as its own LLM turn (no tools, no code reads) so the
heavy verdict pass only runs once per real bug. Shares the Reviewer's model
and cost scope — operators don't see a separate "Clusterer" knob.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..core.jsonx import try_extract_object
from ..core.llm import LLMClient


SYSTEM_PROMPT = """You group similar vulnerability findings from the same file.

Two findings belong in the same group if they describe the **same root cause** —
the same parser flaw, the same missing check, the same primitive bypass — even
when the title or wording differs.

Two findings belong in **different** groups if their root cause is independent,
even if they share the same file or function (e.g. one is an SSRF allow-list
bypass and the other is a missing auth check on the same endpoint).

When in doubt, prefer **over-merging** (fewer, larger groups). The downstream
reviewer can split a group back apart if the items turn out to be different,
but cannot un-split independently-reviewed findings.

Output ONLY this JSON:
{
  "groups": [
    {
      "finding_ids": [<int>, ...],
      "reason": "<short explanation of what makes these one bug>"
    }
  ]
}

Every input finding_id MUST appear in exactly one group."""


USER_TEMPLATE = """# File
{file}

# Findings (id-indexed)
{findings_json}

Group them by root cause. Output the JSON.
"""


@dataclass
class ClusterResult:
    groups: list[dict] = field(default_factory=list)
    iterations: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    stopped: str = ""


class ClustererAgent:
    def __init__(
        self,
        client: LLMClient,
        max_iterations: int = 3,
        max_tokens_per_call: int = 2000,
        on_event=None,
    ):
        self.client = client
        self.max_iterations = max_iterations
        self.max_tokens_per_call = max_tokens_per_call
        self.on_event = on_event or (lambda *a, **k: None)

    async def cluster(self, file: str, findings: list[dict]) -> ClusterResult:
        result = ClusterResult()
        if not findings:
            result.stopped = "no_findings"
            return result

        slim = [_slim(i, f) for i, f in enumerate(findings)]
        messages = [{
            "role": "user",
            "content": [{"text": USER_TEMPLATE.format(
                file=file,
                findings_json=json.dumps(slim, ensure_ascii=False, indent=2),
            )}],
        }]

        for _ in range(self.max_iterations):
            result.iterations += 1
            self.on_event("cluster_iter", n=result.iterations)

            resp = await self.client.chat(
                messages=messages,
                system=SYSTEM_PROMPT,
                max_tokens=self.max_tokens_per_call,
                cache_system=True,
            )
            result.input_tokens += resp.input_tokens
            result.output_tokens += resp.output_tokens
            result.cache_read_tokens += resp.cache_read_tokens
            result.cache_write_tokens += resp.cache_write_tokens

            messages.append({"role": "assistant", "content": resp.content_blocks})
            parsed = try_extract_object(resp.text)
            if parsed is not None and "groups" in parsed:
                result.groups = _validate(parsed["groups"], len(findings))
                result.stopped = "final_json"
                return result
            messages.append({
                "role": "user",
                "content": [{"text": "Please output ONLY the JSON as specified."}],
            })

        result.stopped = "max_iter"
        return result


def _slim(idx: int, f: dict) -> dict:
    return {
        "id": idx,
        "title": f.get("title", ""),
        "type": f.get("type", ""),
        "sink_file": f.get("sink_file", ""),
        "sink_line": f.get("sink_line", 0),
        "description": (f.get("description") or "")[:300],
    }


def _validate(groups: list, n: int) -> list[dict]:
    """Drop bad ids; ensure every finding ends up in exactly one group."""
    seen: set[int] = set()
    clean: list[dict] = []
    for g in groups:
        ids = [i for i in g.get("finding_ids", []) if isinstance(i, int) and 0 <= i < n and i not in seen]
        if not ids:
            continue
        seen.update(ids)
        clean.append({"finding_ids": ids, "reason": g.get("reason", "")})
    missing = [i for i in range(n) if i not in seen]
    if missing:
        clean.append({"finding_ids": missing, "reason": "(unassigned by clusterer)"})
    return clean
