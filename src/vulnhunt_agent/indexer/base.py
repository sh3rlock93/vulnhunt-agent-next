from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

SymbolKind = Literal["function", "method", "class"]


@dataclass
class Symbol:
    name: str
    kind: SymbolKind
    line: int
    signature: str = ""   # "def foo(x, y) -> int"
    parent: str = ""      # class name if method


@dataclass
class FileIndex:
    path: str
    language: str
    loc: int
    imports: list[str] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)


@dataclass
class RepoIndex:
    files: list[FileIndex] = field(default_factory=list)
