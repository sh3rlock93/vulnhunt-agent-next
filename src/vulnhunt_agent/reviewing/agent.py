"""A read-only Reviewer that can cite evidence or request another experiment."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from ..core.jsonx import try_extract_object
from ..core.llm import LLMClient
from ..domain.schemas import ReproductionVariantType, Verdict
from .packet import EvidenceReviewPacket

PROMPT_VERSION = "evidence-review-v1"

SYSTEM_PROMPT = """You are an independent security Reviewer.

You receive a validated candidate and machine-generated evidence packet. You
cannot execute commands or modify evidence. Base every security claim on cited
evidence IDs. Never infer a successful exploit from a Hunter status string.

Decide one of:
- real: the reproduced behavior and source/dataflow support the claimed root cause;
- false_positive: the evidence contradicts the claim or shows no security impact;
- unclear: another controlled experiment is required.

For real findings, choose one CWE from allowed_cwes and a CVSS 3.1 vector.
For false_positive or unclear, leave cwe_id and cvss_vector empty.

If another experiment is needed, request one structured reproduction variant.
The request is queued for the Reproducer; you do not provide or run a command.

Output only:
{
  "verdict": "real|false_positive|unclear",
  "notes": "<evidence-grounded explanation>",
  "cvss_vector": "<CVSS:3.1/... or empty>",
  "cwe_id": "<CWE-NNN or empty>",
  "evidence_ids": ["<cited id>", ...],
  "variant_request": null | {
    "variant_type": "safe_input|config_toggle|fixed_revision|alternate_trigger",
    "rationale": "<why this resolves uncertainty>",
    "requested_change": "<declarative change, not a command>"
  }
}"""


class VariantProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    variant_type: ReproductionVariantType
    rationale: str = Field(min_length=1)
    requested_change: str = Field(min_length=1)


class ReviewProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    notes: str = Field(min_length=1)
    cvss_vector: str = ""
    cwe_id: str = ""
    evidence_ids: tuple[str, ...] = ()
    variant_request: VariantProposal | None = None


@dataclass(frozen=True)
class EvidenceReviewerAgent:
    client: LLMClient
    reviewer: str
    model_id: str
    prompt_variant: str = "independent"
    max_attempts: int = 3
    max_tokens: int = 3000

    @property
    def configuration_id(self) -> str:
        prompt_digest = hashlib.sha256(self.prompt_variant.encode()).hexdigest()[:12]
        return f"{PROMPT_VERSION}:{prompt_digest}"

    async def review(self, packet: EvidenceReviewPacket) -> ReviewProposal:
        user = (
            f"# Reviewer variant\n{self.prompt_variant}\n\n"
            "# Evidence packet\n"
            + json.dumps(packet.model_dump(mode="json"), indent=2, ensure_ascii=False)
        )
        messages: list[dict] = [{
            "role": "user",
            "content": [{"text": user}],
        }]
        for _ in range(self.max_attempts):
            response = await self.client.chat(
                messages=messages,
                system=SYSTEM_PROMPT,
                max_tokens=self.max_tokens,
            )
            parsed = try_extract_object(response.text)
            if parsed is not None:
                return ReviewProposal.model_validate(parsed)
            messages.append({"role": "assistant", "content": response.content_blocks})
            messages.append({
                "role": "user",
                "content": [{"text": "Return only the specified JSON object."}],
            })
        raise RuntimeError(f"reviewer {self.reviewer!r} did not return valid JSON")
