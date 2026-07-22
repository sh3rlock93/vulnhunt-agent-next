"""Provider-neutral, non-billable readiness checks for model transports."""
from __future__ import annotations

import hashlib
import inspect
import re
from typing import Any

from ..domain.schemas import (
    ProviderPreflightCheck,
    ProviderPreflightCode,
    ProviderPreflightResult,
)
from .model_errors import ModelClientError, ModelFailureCategory


async def preflight_model_client(
    client: Any,
    *,
    model_probe: bool = False,
) -> ProviderPreflightResult:
    """Check one client before scheduling work.

    Clients may provide a transport-specific ``preflight`` method. Test and
    legacy clients without one receive a local contract check, which keeps the
    readiness interface provider-neutral without issuing a model request.
    """
    transport = str(getattr(client, "transport", "test_or_legacy"))
    model_id = str(getattr(client, "model_id", "unspecified"))
    method = getattr(client, "preflight", None)
    try:
        if method is None:
            if not callable(getattr(client, "chat", None)):
                return _failure_result(
                    transport,
                    model_id,
                    ProviderPreflightCode.PROVIDER_PROTOCOL_ERROR,
                    "Configure a provider client that implements the chat contract.",
                    "provider client has no callable chat method",
                )
            result = _ready_result(
                transport,
                model_id,
                check=ProviderPreflightCheck(
                    name="client_contract",
                    status="passed",
                    detail="chat-compatible client is available",
                ),
            )
        else:
            candidate = method()
            result = await candidate if inspect.isawaitable(candidate) else candidate
            if not isinstance(result, ProviderPreflightResult):
                return _failure_result(
                    transport,
                    model_id,
                    ProviderPreflightCode.PROVIDER_PROTOCOL_ERROR,
                    "Update the provider adapter to return ProviderPreflightResult.",
                    "provider preflight returned an invalid result contract",
                )
    except ModelClientError as exc:
        return _from_model_error(transport, model_id, exc)
    except Exception as exc:
        return _failure_result(
            transport,
            model_id,
            ProviderPreflightCode.PROVIDER_TRANSPORT_ERROR,
            "Inspect the provider configuration and local transport, then retry.",
            f"{type(exc).__name__}: provider readiness check failed",
        )

    if not result.ready or not model_probe:
        return result

    try:
        await client.chat(
            messages=[{
                "role": "user",
                "content": [{"text": "Reply with the single word ready."}],
            }],
            max_tokens=16,
        )
    except ModelClientError as exc:
        failure = _from_model_error(transport, model_id, exc)
        return failure.model_copy(update={
            "model_probe_requested": True,
            "billable_model_calls": 1,
            "checks": result.checks + (
                ProviderPreflightCheck(
                    name="model_probe",
                    status="failed",
                    detail="explicit model probe failed",
                ),
            ),
        })
    except Exception as exc:
        return _failure_result(
            transport,
            model_id,
            ProviderPreflightCode.PROVIDER_TRANSPORT_ERROR,
            "Inspect model availability and provider transport diagnostics, then retry.",
            f"{type(exc).__name__}: explicit model probe failed",
            model_probe_requested=True,
            billable_model_calls=1,
            checks=result.checks,
        )
    return result.model_copy(update={
        "model_probe_requested": True,
        "billable_model_calls": 1,
        "checks": result.checks + (
            ProviderPreflightCheck(
                name="model_probe",
                status="passed",
                detail="explicit billable model probe completed",
            ),
        ),
    })


def failed_client_initialization(
    *,
    model_id: str,
    transport: str,
    error: Exception,
) -> ProviderPreflightResult:
    """Convert constructor failures into the same persisted readiness contract."""
    if isinstance(error, ModelClientError):
        return _from_model_error(transport, model_id, error)
    return _failure_result(
        transport,
        model_id,
        ProviderPreflightCode.PROVIDER_CONFIGURATION_ERROR,
        "Correct the model provider configuration and retry.",
        f"{type(error).__name__}: provider client initialization failed",
    )


def diagnostic_fingerprint(diagnostic: str) -> str:
    """Return a one-way fingerprint without persisting provider diagnostics."""
    redacted = re.sub(
        r"(?i)\b(bearer|authorization|api[_-]?key|token)\s*[:=]?\s*\S+",
        r"\1 <redacted>",
        diagnostic,
    )
    redacted = re.sub(r"(?i)\bsk-[a-z0-9_-]{6,}", "<redacted>", redacted)
    redacted = re.sub(
        r"(?<![A-Za-z0-9_.-])/(?:[^\s:]+/?)+",
        "<path>",
        redacted,
    )
    normalized = " ".join(redacted.casefold().split())
    return "sha256:" + hashlib.sha256(normalized.encode()).hexdigest()


def _ready_result(
    transport: str,
    model_id: str,
    *,
    check: ProviderPreflightCheck,
) -> ProviderPreflightResult:
    return ProviderPreflightResult(
        transport=transport,
        model_id=model_id,
        ready=True,
        code=ProviderPreflightCode.READY,
        checks=(check,),
    )


def _failure_result(
    transport: str,
    model_id: str,
    code: ProviderPreflightCode,
    remediation: str,
    diagnostic: str,
    *,
    model_probe_requested: bool = False,
    billable_model_calls: int = 0,
    checks: tuple[ProviderPreflightCheck, ...] = (),
) -> ProviderPreflightResult:
    return ProviderPreflightResult(
        transport=transport,
        model_id=model_id,
        ready=False,
        code=code,
        remediation=remediation,
        diagnostic_fingerprint=diagnostic_fingerprint(diagnostic),
        model_probe_requested=model_probe_requested,
        billable_model_calls=billable_model_calls,
        checks=checks + (
            ProviderPreflightCheck(
                name="provider_readiness",
                status="failed",
                detail=code.value,
            ),
        ),
    )


def _from_model_error(
    transport: str,
    model_id: str,
    exc: ModelClientError,
) -> ProviderPreflightResult:
    mapping = {
        ModelFailureCategory.AUTHENTICATION: (
            ProviderPreflightCode.AUTHENTICATION_REQUIRED,
            "Authenticate the configured provider and retry.",
        ),
        ModelFailureCategory.MODEL_UNAVAILABLE: (
            ProviderPreflightCode.MODEL_UNAVAILABLE,
            "Select a model available to the configured provider account.",
        ),
        ModelFailureCategory.PROTOCOL: (
            ProviderPreflightCode.PROVIDER_PROTOCOL_ERROR,
            "Update or reconfigure the provider adapter, then retry.",
        ),
        ModelFailureCategory.CONFIGURATION: (
            ProviderPreflightCode.PROVIDER_CONFIGURATION_ERROR,
            "Correct the provider configuration and retry.",
        ),
    }
    code, remediation = mapping.get(
        exc.category,
        (
            ProviderPreflightCode.PROVIDER_TRANSPORT_ERROR,
            "Inspect the provider transport and retry.",
        ),
    )
    return _failure_result(
        transport,
        model_id,
        code,
        remediation,
        f"{exc.category.value}: {type(exc).__name__}",
    )
