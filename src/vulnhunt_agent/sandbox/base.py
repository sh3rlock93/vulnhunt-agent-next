from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_ms: int = 0
    captured_files: dict[str, bytes] | None = None


@dataclass(frozen=True)
class SandboxJob:
    image: str
    source_tar: Path
    poc_file: Path
    poc_path: str
    argv: tuple[str, ...]
    cwd: str
    env: dict[str, str]
    timeout_seconds: int
    setup_argvs: tuple[tuple[str, ...], ...] = ()
    capture_files: tuple[str, ...] = ()


@dataclass(frozen=True)
class SandboxExecution:
    image_digest: str
    result: ExecResult
    setup_results: tuple[ExecResult, ...] = ()
    environment_id: str = ""


class SandboxBackend(Protocol):
    async def execute(self, job: SandboxJob) -> SandboxExecution:
        """Execute one job in a new sandbox instance."""


def validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
    normalized = tuple(argv)
    if not normalized or any(not arg or "\0" in arg for arg in normalized):
        raise ValueError("argv must be non-empty and may not contain empty or NUL entries")
    return normalized
