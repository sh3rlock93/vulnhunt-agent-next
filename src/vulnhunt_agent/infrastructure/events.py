"""Append-only JSONL adapter for domain and UI event streaming."""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator


class JsonlEventAdapter:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event_type: str, **data: Any) -> dict[str, Any]:
        event = {
            "ts": datetime.now(UTC).isoformat(timespec="seconds"),
            "type": event_type,
            **data,
        }
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
        descriptor = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, line.encode())
        finally:
            os.close(descriptor)
        return event

    def iter_events(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open() as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSONL event at line {line_number}") from exc
                if not isinstance(event, dict) or "type" not in event or "ts" not in event:
                    raise ValueError(f"invalid event contract at line {line_number}")
                yield event

    def read_all(self) -> list[dict[str, Any]]:
        return list(self.iter_events())
