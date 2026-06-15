from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
