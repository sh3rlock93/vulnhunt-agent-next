"""Cleanup helpers for sandbox containers.

Two layers of protection against container leaks:
  1. Normal path: ContainerExecutor.stop() in finally block
  2. Abnormal exit: atexit + signal handlers kill any tracked containers
"""
from __future__ import annotations

import atexit
import signal
import subprocess
import threading

NAME_PREFIX = "scanner_sbx_"

_active: set[str] = set()
_lock = threading.Lock()
_handlers_installed = False


def register(name: str) -> None:
    with _lock:
        _active.add(name)
    _ensure_handlers()


def unregister(name: str) -> None:
    with _lock:
        _active.discard(name)


def kill_active() -> int:
    """Kill all sandbox containers tracked in this process. Returns count killed."""
    with _lock:
        names = list(_active)
        _active.clear()
    count = 0
    for name in names:
        if _kill_one(name):
            count += 1
    return count


def _kill_one(name: str) -> bool:
    try:
        subprocess.run(
            ["docker", "rm", "-f", name],
            capture_output=True, timeout=10,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _ensure_handlers() -> None:
    global _handlers_installed
    if _handlers_installed:
        return
    atexit.register(kill_active)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            prev = signal.getsignal(sig)

            def _handler(signum, frame, _prev=prev):
                kill_active()
                if callable(_prev):
                    _prev(signum, frame)
                else:
                    signal.signal(signum, signal.SIG_DFL)
                    signal.raise_signal(signum)

            signal.signal(sig, _handler)
        except (ValueError, OSError):
            pass
    _handlers_installed = True
