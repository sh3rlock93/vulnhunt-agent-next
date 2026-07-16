from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

RUNS_ROOT = Path(__file__).resolve().parents[3] / "runs"


def new_run_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


class RunStore:
    """File-backed storage for one scan run. All step inputs/outputs live here."""

    def __init__(self, run_dir: Path):
        self.dir = run_dir
        (self.dir / "steps").mkdir(parents=True, exist_ok=True)

    @classmethod
    def create(cls, run_id: str | None = None) -> "RunStore":
        run_id = run_id or new_run_id()
        return cls(RUNS_ROOT / run_id)

    @classmethod
    def list_runs(cls) -> list[str]:
        if not RUNS_ROOT.exists():
            return []
        return sorted((p.name for p in RUNS_ROOT.iterdir() if p.is_dir()), reverse=True)

    # --- config ---

    def save_config(self, config: dict) -> None:
        self._write("config.json", config)

    def load_config(self) -> dict | None:
        return self._read("config.json")

    # --- steps ---

    def save_step(self, name: str, data: Any) -> None:
        self._write(f"steps/{name}.json", _to_jsonable(data))

    def load_step(self, name: str) -> Any | None:
        return self._read(f"steps/{name}.json")

    def has_step(self, name: str) -> bool:
        return (self.dir / "steps" / f"{name}.json").exists()

    # --- internal ---

    def _write(self, rel: str, data: Any) -> None:
        path = self.dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False))

    def _read(self, rel: str) -> Any | None:
        path = self.dir / rel
        if not path.exists():
            return None
        return json.loads(path.read_text())


def _to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(cast(Any, obj))
    if isinstance(obj, list):
        return [_to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, Path):
        return str(obj)
    return obj
