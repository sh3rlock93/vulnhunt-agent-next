"""Lockfile-based process tracking for background pipeline steps."""
from __future__ import annotations

import os
import signal
from pathlib import Path


def lock_path(run_dir: Path, step_name: str) -> Path:
    return run_dir / f".{step_name}.pid"


def read_pid(run_dir: Path, step_name: str) -> int | None:
    p = lock_path(run_dir, step_name)
    if not p.exists():
        return None
    try:
        return int(p.read_text().strip())
    except ValueError:
        return None


def is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def is_running(run_dir: Path, step_name: str) -> bool:
    pid = read_pid(run_dir, step_name)
    if pid is None:
        return False
    if is_alive(pid):
        return True
    lock_path(run_dir, step_name).unlink(missing_ok=True)
    return False


def stop(run_dir: Path, step_name: str) -> bool:
    pid = read_pid(run_dir, step_name)
    if pid is None or not is_alive(pid):
        lock_path(run_dir, step_name).unlink(missing_ok=True)
        return False
    os.kill(pid, signal.SIGTERM)
    lock_path(run_dir, step_name).unlink(missing_ok=True)
    return True
