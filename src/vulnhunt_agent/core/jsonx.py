"""Lenient JSON extraction from LLM text output."""
from __future__ import annotations

import json
import re


def extract_object(text: str) -> dict:
    """Find the first {...} block and parse it. Raise on miss."""
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError(f"no JSON object in response: {text[:200]}")
    return json.loads(m.group(0))


def extract_array(text: str) -> list:
    """Find the first [...] block and parse it. Raise on miss."""
    m = re.search(r"\[.*\]", text, re.S)
    if not m:
        raise ValueError(f"no JSON array in response: {text[:200]}")
    return json.loads(m.group(0))


def try_extract_object(text: str) -> dict | None:
    """Same as extract_object but returns None on miss/parse error."""
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
