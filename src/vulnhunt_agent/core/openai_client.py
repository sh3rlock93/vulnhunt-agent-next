"""OpenAI Responses API client for openai_compat providers (bedrock-mantle,
LiteLLM, in-house OpenAI-compatible proxies).

Speaks Bedrock Converse-shaped messages on the outside (so HunterAgent /
ReviewerAgent are unchanged), translates to OpenAI Responses API on the
inside.
"""
from __future__ import annotations

import asyncio
import json
import uuid

from openai import OpenAI

from . import settings as _settings
from .llm import LLMResponse


class OpenAIBedrockClient:
    """Drop-in replacement for LLMClient targeting openai_compat providers.

    Outside surface (chat()) returns content_blocks shaped like Anthropic's
    Converse output, so the agent loops don't change.
    """

    def __init__(self, model_id: str, max_tokens: int | None = None):
        self.model_id = model_id
        _, provider = _settings.resolve(model_id)
        if not provider.endpoint:
            raise RuntimeError(
                f"provider {provider.name!r} (openai_compat) needs `endpoint`."
            )
        if not provider.api_key:
            raise RuntimeError(
                f"provider {provider.name!r} (openai_compat) needs `api_key` "
                "in settings.toml."
            )
        self.max_tokens = max_tokens or _settings.MAX_TOKENS
        self._client = OpenAI(api_key=provider.api_key, base_url=provider.endpoint)

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
        oai_input = _to_openai_input(messages)
        oai_tools = _to_openai_tools(tools) if tools else None

        kwargs: dict = {
            "model": self.model_id,
            "input": oai_input,
            "max_output_tokens": max_tokens or self.max_tokens,
        }
        if system:
            kwargs["instructions"] = system
        if oai_tools:
            kwargs["tools"] = oai_tools

        resp = await asyncio.to_thread(self._client.responses.create, **kwargs)
        return _to_anthropic_response(resp)


# ---------- conversion: Anthropic Converse -> OpenAI Responses ----------


def _to_openai_tools(tools: list[dict]) -> list[dict]:
    """Strip cachePoint entries; map toolSpec -> OpenAI function tool."""
    out = []
    for t in tools:
        if "toolSpec" not in t:
            continue
        spec = t["toolSpec"]
        out.append({
            "type": "function",
            "name": spec["name"],
            "description": spec.get("description", ""),
            "parameters": spec["inputSchema"]["json"],
        })
    return out


def _to_openai_input(messages: list[dict]) -> list[dict]:
    """Flatten Converse messages into OpenAI Responses input items."""
    out: list[dict] = []
    for m in messages:
        role = m.get("role")
        content = m.get("content", [])
        if isinstance(content, str):
            out.append({"role": role, "content": content})
            continue
        text_parts: list[str] = []
        for block in content:
            if "cachePoint" in block:
                continue
            if "text" in block:
                text_parts.append(block["text"])
            elif "toolUse" in block:
                if text_parts:
                    out.append({"role": role, "content": "\n".join(text_parts)})
                    text_parts = []
                tu = block["toolUse"]
                out.append({
                    "type": "function_call",
                    "call_id": tu["toolUseId"],
                    "name": tu["name"],
                    "arguments": json.dumps(tu.get("input", {})),
                })
            elif "toolResult" in block:
                if text_parts:
                    out.append({"role": role, "content": "\n".join(text_parts)})
                    text_parts = []
                tr = block["toolResult"]
                output_text = "\n".join(
                    c.get("text", "") for c in tr.get("content", []) if "text" in c
                )
                out.append({
                    "type": "function_call_output",
                    "call_id": tr["toolUseId"],
                    "output": output_text,
                })
        if text_parts:
            out.append({"role": role, "content": "\n".join(text_parts)})
    return out


# ---------- conversion: OpenAI Responses -> Anthropic Converse ----------


def _to_anthropic_response(resp) -> LLMResponse:
    """Build Converse-shaped LLMResponse from OpenAI Responses output."""
    blocks: list[dict] = []
    text_chunks: list[str] = []
    stop_reason = "end_turn"

    for item in (resp.output or []):
        itype = getattr(item, "type", None)
        if itype == "message":
            for c in (item.content or []):
                ctype = getattr(c, "type", None)
                if ctype in ("output_text", "text"):
                    txt = getattr(c, "text", "") or ""
                    text_chunks.append(txt)
                    blocks.append({"text": txt})
        elif itype == "function_call":
            stop_reason = "tool_use"
            try:
                args = json.loads(getattr(item, "arguments", "") or "{}")
            except json.JSONDecodeError:
                args = {}
            blocks.append({"toolUse": {
                "toolUseId": getattr(item, "call_id", None) or f"call_{uuid.uuid4().hex[:8]}",
                "name": getattr(item, "name", ""),
                "input": args,
            }})

    usage = getattr(resp, "usage", None)
    return LLMResponse(
        text="".join(text_chunks),
        input_tokens=getattr(usage, "input_tokens", 0) if usage else 0,
        output_tokens=getattr(usage, "output_tokens", 0) if usage else 0,
        cache_read_tokens=0,
        cache_write_tokens=0,
        stop_reason=stop_reason,
        content_blocks=blocks,
    )
