"""Typed, redacted model-transport failures used by durable Hunter work."""
from __future__ import annotations

from enum import StrEnum


class ModelFailureCategory(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    MODEL_UNAVAILABLE = "model_unavailable"
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    TRANSPORT = "transport"
    PROTOCOL = "protocol"
    CONFIGURATION = "configuration"
    BUDGET = "budget"
    INTERNAL = "internal"


class ModelClientError(RuntimeError):
    """A safe model failure that may be persisted without raw diagnostics."""

    def __init__(
        self,
        category: ModelFailureCategory,
        message: str,
        *,
        retryable: bool,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.retryable = retryable
        self.partial_result: object | None = None

    def __str__(self) -> str:
        return f"[{self.category.value}] {super().__str__()}"
