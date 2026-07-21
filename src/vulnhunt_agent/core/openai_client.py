"""OpenAI Responses API client.

Speaks Bedrock Converse-shaped messages on the outside (so HunterAgent /
ReviewerAgent are unchanged), translates to OpenAI Responses API on the
inside.
"""
from __future__ import annotations

import asyncio
import json
import os

from openai import OpenAI

from . import settings as _settings
from .llm import LLMResponse
from .model_errors import ModelClientError, ModelFailureCategory
from .tool_protocol import tool_schema_map, validated_tool_block


class OpenAIResponsesClient:
    """Drop-in replacement for LLMClient targeting a Responses API endpoint.

    Outside surface (chat()) returns content_blocks shaped like Anthropic's
    Converse output, so the agent loops don't change.
    """

    transport = "responses_api"

    def __init__(
        self,
        model_id: str,
        max_tokens: int | None = None,
        *,
        api_key: str | None = None,
    ):
        self.model_id = model_id
        _, provider = _settings.resolve(model_id)
        endpoint = provider.endpoint
        if provider.kind == "openai_auto":
            endpoint = endpoint or "https://api.openai.com/v1"
        if not endpoint:
            raise RuntimeError(
                f"provider {provider.name!r} (openai_compat) needs `endpoint`."
            )
        resolved_key = api_key or resolve_api_key(provider)
        if not resolved_key:
            key_hint = provider.api_key_env or "OPENAI_API_KEY"
            raise RuntimeError(
                f"provider {provider.name!r} needs an API key in {key_hint}."
            )
        self.max_tokens = max_tokens or _settings.MAX_TOKENS
        self.reasoning_effort = provider.reasoning_effort
        self.preserve_reasoning = provider.kind == "openai_auto"
        self._client = OpenAI(api_key=resolved_key, base_url=endpoint)

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
        if self.preserve_reasoning:
            kwargs["store"] = False
            kwargs["include"] = ["reasoning.encrypted_content"]
        if system:
            kwargs["instructions"] = system
        if oai_tools:
            kwargs["tools"] = oai_tools
        if self.reasoning_effort:
            kwargs["reasoning"] = {"effort": self.reasoning_effort}

        try:
            resp = await asyncio.to_thread(self._client.responses.create, **kwargs)
        except Exception as exc:
            raise _classify_openai_failure(exc) from exc
        return _to_anthropic_response(
            resp,
            tool_schemas=tool_schema_map(oai_tools or []),
        )


def resolve_api_key(provider: _settings.ProviderSpec) -> str | None:
    """Resolve a provider key without inspecting Codex's credential store."""
    if provider.api_key:
        return provider.api_key.strip() or None
    env_name = provider.api_key_env
    if env_name:
        return os.environ.get(env_name, "").strip() or None
    return None


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
            elif "openaiReasoning" in block:
                reasoning = block["openaiReasoning"]
                if isinstance(reasoning, dict) and reasoning.get("type") == "reasoning":
                    out.append(reasoning)
        if text_parts:
            out.append({"role": role, "content": "\n".join(text_parts)})
    return out


# ---------- conversion: OpenAI Responses -> Anthropic Converse ----------


def _to_anthropic_response(
    resp,
    *,
    tool_schemas: dict[str, dict] | None = None,
) -> LLMResponse:
    """Build Converse-shaped LLMResponse from OpenAI Responses output."""
    blocks: list[dict] = []
    text_chunks: list[str] = []
    stop_reason = "end_turn"
    schemas = dict(tool_schemas or {})
    allow_legacy_unknown_tools = tool_schemas is None

    for item in (resp.output or []):
        itype = getattr(item, "type", None)
        if itype == "reasoning":
            if hasattr(item, "model_dump"):
                reasoning = item.model_dump(exclude_none=True)
            else:
                reasoning = {
                    key: getattr(item, key)
                    for key in ("id", "type", "summary", "encrypted_content", "status")
                    if getattr(item, key, None) is not None
                }
            blocks.append({"openaiReasoning": reasoning})
        elif itype == "message":
            for c in (item.content or []):
                ctype = getattr(c, "type", None)
                if ctype in ("output_text", "text"):
                    txt = getattr(c, "text", "") or ""
                    text_chunks.append(txt)
                    blocks.append({"text": txt})
        elif itype == "function_call":
            stop_reason = "tool_use"
            name = getattr(item, "name", "")
            if name not in schemas and allow_legacy_unknown_tools:
                schemas[name] = {"type": "object"}
            blocks.append(validated_tool_block(
                call_id=getattr(item, "call_id", None),
                name=name,
                arguments_text=getattr(item, "arguments", ""),
                schemas=schemas,
            ))

    usage = getattr(resp, "usage", None)
    input_total = getattr(usage, "input_tokens", 0) if usage else 0
    input_details = getattr(usage, "input_tokens_details", None) if usage else None
    cached = getattr(input_details, "cached_tokens", 0) if input_details else 0
    if any("toolArgumentsInvalid" in block for block in blocks):
        stop_reason = "tool_arguments_invalid"
    return LLMResponse(
        text="".join(text_chunks),
        input_tokens=max(input_total - cached, 0),
        output_tokens=getattr(usage, "output_tokens", 0) if usage else 0,
        cache_read_tokens=cached,
        cache_write_tokens=0,
        stop_reason=stop_reason,
        content_blocks=blocks,
    )


# Backwards-compatible import for callers that used the old class name.
OpenAIBedrockClient = OpenAIResponsesClient


def _classify_openai_failure(exc: Exception) -> ModelClientError:
    status = getattr(exc, "status_code", None)
    kind = type(exc).__name__.casefold()
    if status == 401:
        return ModelClientError(
            ModelFailureCategory.AUTHENTICATION,
            "OpenAI API authentication failed; verify the configured API key.",
            retryable=False,
        )
    if status == 403:
        return ModelClientError(
            ModelFailureCategory.AUTHORIZATION,
            "OpenAI API authorization failed for the requested operation.",
            retryable=False,
        )
    if status == 404:
        return ModelClientError(
            ModelFailureCategory.MODEL_UNAVAILABLE,
            "The requested OpenAI model or endpoint is unavailable.",
            retryable=False,
        )
    if status == 429:
        return ModelClientError(
            ModelFailureCategory.RATE_LIMIT,
            "The OpenAI API rate limit was reached.",
            retryable=True,
        )
    if "timeout" in kind:
        return ModelClientError(
            ModelFailureCategory.TIMEOUT,
            "The OpenAI API request timed out.",
            retryable=True,
        )
    if "connection" in kind:
        return ModelClientError(
            ModelFailureCategory.TRANSPORT,
            "The OpenAI API transport failed.",
            retryable=True,
        )
    if isinstance(status, int) and status >= 500:
        return ModelClientError(
            ModelFailureCategory.TRANSPORT,
            "The OpenAI API reported a transient server failure.",
            retryable=True,
        )
    return ModelClientError(
        ModelFailureCategory.CONFIGURATION,
        "The OpenAI API request was rejected; verify model and provider settings.",
        retryable=False,
    )
