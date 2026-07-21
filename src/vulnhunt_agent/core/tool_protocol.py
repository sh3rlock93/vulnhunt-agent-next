"""Strict provider-neutral validation for model-requested host tools."""
from __future__ import annotations

import json
import uuid
from typing import Any

from jsonschema import Draft202012Validator

TOOL_ARGUMENTS_INVALID = "tool_arguments_invalid"


def tool_schema_map(tools: list[dict]) -> dict[str, dict]:
    return {
        str(tool["name"]): dict(tool.get("parameters") or {"type": "object"})
        for tool in tools
        if isinstance(tool, dict) and isinstance(tool.get("name"), str)
    }


def validated_tool_block(
    *,
    call_id: object,
    name: object,
    arguments_text: object,
    schemas: dict[str, dict],
) -> dict[str, Any]:
    normalized_id = (
        call_id if isinstance(call_id, str) and call_id else f"call_{uuid.uuid4().hex[:8]}"
    )
    if not isinstance(name, str) or name not in schemas:
        return invalid_tool_block(
            call_id=normalized_id,
            name=name if isinstance(name, str) else "",
            reason="unavailable_tool",
            schema={},
        )
    schema = schemas[name]
    if not isinstance(arguments_text, str):
        return invalid_tool_block(
            call_id=normalized_id,
            name=name,
            reason="arguments_not_json_string",
            schema=schema,
        )
    try:
        arguments = json.loads(arguments_text)
    except json.JSONDecodeError:
        return invalid_tool_block(
            call_id=normalized_id,
            name=name,
            reason="invalid_json",
            schema=schema,
        )
    if not isinstance(arguments, dict):
        return invalid_tool_block(
            call_id=normalized_id,
            name=name,
            reason="arguments_not_object",
            schema=schema,
        )
    errors = sorted(
        Draft202012Validator(schema).iter_errors(arguments),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if errors:
        validator = str(errors[0].validator or "contract").replace(" ", "_")
        return invalid_tool_block(
            call_id=normalized_id,
            name=name,
            reason=f"schema_{validator}",
            schema=schema,
        )
    return {
        "toolUse": {
            "toolUseId": normalized_id,
            "name": name,
            "input": arguments,
        }
    }


def invalid_tool_block(
    *,
    call_id: str,
    name: str,
    reason: str,
    schema: dict,
) -> dict[str, Any]:
    return {
        "toolArgumentsInvalid": {
            "toolUseId": call_id,
            "name": name,
            "errorCode": TOOL_ARGUMENTS_INVALID,
            "reason": reason,
            "allowedSchema": schema,
        }
    }
