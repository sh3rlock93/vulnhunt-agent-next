"""API-first selection for the OpenAI provider."""
from __future__ import annotations

from . import settings as _settings
from .codex_client import CodexSubscriptionClient
from .openai_client import OpenAIResponsesClient, resolve_api_key


def create_openai_auto_client(
    model_id: str,
    max_tokens: int | None = None,
) -> OpenAIResponsesClient | CodexSubscriptionClient:
    """Prefer Platform API billing, falling back only when no key is configured."""
    _, provider = _settings.resolve(model_id)
    api_key = resolve_api_key(provider)
    if api_key:
        return OpenAIResponsesClient(model_id, max_tokens=max_tokens, api_key=api_key)
    return CodexSubscriptionClient(model_id, max_tokens=max_tokens)
