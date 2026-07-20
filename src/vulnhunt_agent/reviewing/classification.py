"""Deterministic CWE normalization and allow-list enforcement."""
from __future__ import annotations

import re

ALLOWED_CWES = frozenset({
    "CWE-20",
    "CWE-22",
    "CWE-74",
    "CWE-77",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-94",
    "CWE-119",
    "CWE-120",
    "CWE-125",
    "CWE-190",
    "CWE-200",
    "CWE-269",
    "CWE-276",
    "CWE-287",
    "CWE-306",
    "CWE-327",
    "CWE-352",
    "CWE-400",
    "CWE-416",
    "CWE-434",
    "CWE-502",
    "CWE-611",
    "CWE-639",
    "CWE-732",
    "CWE-776",
    "CWE-787",
    "CWE-798",
    "CWE-862",
    "CWE-863",
    "CWE-918",
})

_ALIASES = {
    "auth_bypass": "CWE-287",
    "buffer_overflow": "CWE-787",
    "command_injection": "CWE-78",
    "deserialization": "CWE-502",
    "integer_overflow": "CWE-190",
    "out_of_bounds_read": "CWE-125",
    "out_of_bounds_write": "CWE-787",
    "path_traversal": "CWE-22",
    "sqli": "CWE-89",
    "ssrf": "CWE-918",
    "use_after_free": "CWE-416",
    "xss": "CWE-79",
}


def normalize_cwe(value: str) -> str:
    candidate = value.strip().upper()
    if re.fullmatch(r"CWE-[1-9][0-9]{0,4}", candidate) is None:
        candidate = _ALIASES.get(value.strip().casefold(), "")
    if candidate not in ALLOWED_CWES:
        raise ValueError(f"unsupported CWE classification: {value!r}")
    return candidate
