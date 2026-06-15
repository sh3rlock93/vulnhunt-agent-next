from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.config import Config as BotoConfig

from . import settings as _settings


@dataclass
class LLMResponse:
    text: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    stop_reason: str
    content_blocks: list[dict] = field(default_factory=list)


class LLMClient:
    """Bedrock Converse API wrapper with prompt caching support.

    Dispatches by the model's resolved provider.kind:
      - bedrock_converse  -> this class (boto3 Converse, SigV4)
      - openai_compat     -> OpenAIBedrockClient (OpenAI Responses API, Bearer)
    """

    def __new__(cls, model_id: str, *args, **kwargs):
        _, provider = _settings.resolve(model_id)
        if provider.kind == "openai_compat":
            from .openai_client import OpenAIBedrockClient
            return OpenAIBedrockClient(model_id, *args, **kwargs)
        if provider.kind != "bedrock_converse":
            raise RuntimeError(f"unknown provider kind: {provider.kind}")
        return super().__new__(cls)

    def __init__(self, model_id: str, max_tokens: int | None = None):
        self.model_id = model_id
        _, provider = _settings.resolve(model_id)
        if not provider.region:
            raise RuntimeError(
                f"provider {provider.name!r} (bedrock_converse) needs `region`."
            )
        self.region = provider.region
        self.max_tokens = max_tokens or _settings.MAX_TOKENS
        self._client = boto3.client(
            "bedrock-runtime",
            region_name=self.region,
            endpoint_url=provider.endpoint or None,
            config=BotoConfig(
                read_timeout=900,
                connect_timeout=10,
                retries={"max_attempts": 3, "mode": "standard"},
            ),
        )

    async def chat(
        self,
        messages: list[dict],
        system: str | None = None,
        tools: list[dict] | None = None,
        max_tokens: int | None = None,
        cache_system: bool = False,
        cache_tools: bool = False,
        cache_last_user: bool = False,
    ) -> LLMResponse:
        """
        Args:
            cache_system:    cachePoint after system text
            cache_tools:     cachePoint after tool specs
            cache_last_user: cachePoint after the last user message's content
                             (covers accumulated tool_results across iterations)
        """
        spec = _settings.by_id(self.model_id)
        if spec and not spec.supports_caching:
            cache_system = cache_tools = cache_last_user = False

        msgs = messages
        if cache_last_user and messages:
            msgs = [m for m in messages]
            user_idxs = [i for i, m in enumerate(msgs) if m.get("role") == "user"]
            for target in {user_idxs[0], user_idxs[-1]} if user_idxs else set():
                content = list(msgs[target]["content"])
                if not content or "cachePoint" not in content[-1]:
                    content.append({"cachePoint": {"type": "default"}})
                    msgs[target] = {**msgs[target], "content": content}

        kwargs: dict[str, Any] = {
            "modelId": self.model_id,
            "messages": msgs,
            "inferenceConfig": {
                "maxTokens": max_tokens or self.max_tokens,
            },
        }
        if system:
            sys_blocks: list[dict] = [{"text": system}]
            if cache_system:
                sys_blocks.append({"cachePoint": {"type": "default"}})
            kwargs["system"] = sys_blocks
        if tools:
            tool_items: list[dict] = list(tools)
            if cache_tools:
                tool_items.append({"cachePoint": {"type": "default"}})
            kwargs["toolConfig"] = {"tools": tool_items}

        resp = await asyncio.to_thread(self._client.converse, **kwargs)

        # Some models (e.g. Fable 5) return empty content with a content_filtered
        # / refusal stop_reason on offensive-security prompts. Surface it as a
        # hard error so the agent loop doesn't spin on empty content_blocks.
        if resp.get("stopReason") in ("content_filtered", "refusal"):
            raise RuntimeError(
                f"model {self.model_id} refused the request "
                f"(stop_reason={resp['stopReason']}). "
                "This model has stricter content policies than Opus/Sonnet; "
                "switch the hunter/reviewer model in the sidebar."
            )

        blocks = resp["output"]["message"]["content"]
        # Fable 5 (and possibly other models) emit a `type: "tool_use"` field
        # inside toolUse blocks that Converse rejects on the next turn.
        for b in blocks:
            if "toolUse" in b and isinstance(b["toolUse"], dict):
                b["toolUse"].pop("type", None)
        text = "".join(b["text"] for b in blocks if "text" in b)
        usage = resp["usage"]
        return LLMResponse(
            text=text,
            input_tokens=usage.get("inputTokens", 0),
            output_tokens=usage.get("outputTokens", 0),
            cache_read_tokens=usage.get("cacheReadInputTokens", 0),
            cache_write_tokens=usage.get("cacheWriteInputTokens", 0),
            stop_reason=resp["stopReason"],
            content_blocks=blocks,
        )
