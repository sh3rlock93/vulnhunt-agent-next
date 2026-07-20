"""Deterministic first-pass grouping before the semantic LLM Clusterer."""
from __future__ import annotations

import re


def deterministic_partitions(findings: list[dict]) -> list[list[int]]:
    groups: dict[tuple, list[int]] = {}
    order: list[tuple] = []
    for index, finding in enumerate(findings):
        key = _fingerprint(finding, index)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(index)
    return [groups[key] for key in order]


def _fingerprint(finding: dict, index: int) -> tuple:
    weakness = _normalize(finding.get("type") or finding.get("weakness"))
    sink_path = _normalize_path(finding.get("sink_file"))
    sink_line = _positive_int(finding.get("sink_line"))
    entry_path = _normalize_path(finding.get("entry_file"))
    entry_line = _positive_int(finding.get("entry_line"))
    if not weakness or not sink_path or sink_line == 0:
        return ("unique", index)
    return (weakness, sink_path, sink_line, entry_path, entry_line)


def _normalize(value) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").casefold()).strip("_")


def _normalize_path(value) -> str:
    return str(value or "").replace("\\", "/").casefold().strip()


def _positive_int(value) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 0
    return number if number > 0 else 0
