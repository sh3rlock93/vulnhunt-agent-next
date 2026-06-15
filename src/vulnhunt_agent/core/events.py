from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class EventBus:
    """Append-only event log. One line of JSON per event."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, type: str, **data: Any) -> None:
        event = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "type": type,
            **data,
        }
        with self.log_path.open("a") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    def read_all(self) -> list[dict]:
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text().splitlines() if line]
