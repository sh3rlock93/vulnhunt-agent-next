from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable

from ..core.events import EventBus
from ..core.run_store import RunStore

StepFn = Callable[[RunStore, EventBus], Awaitable[None]]


@dataclass
class Step:
    name: str                 # storage key, e.g. "arch"
    title: str                # UI label
    fn: StepFn
    depends_on: list[str]     # names of steps that must exist first


STEPS: list[Step] = []


def register(step: Step) -> Step:
    STEPS.append(step)
    return step
