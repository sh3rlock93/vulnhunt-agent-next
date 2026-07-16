from __future__ import annotations

from pathlib import Path
from typing import Any

from ..infrastructure.events import JsonlEventAdapter


class EventBus:
    """Append-only event log. One line of JSON per event."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self._adapter = JsonlEventAdapter(log_path)

    def emit(self, type: str, **data: Any) -> None:
        self._adapter.append(type, **data)

    def read_all(self) -> list[dict]:
        return self._adapter.read_all()
