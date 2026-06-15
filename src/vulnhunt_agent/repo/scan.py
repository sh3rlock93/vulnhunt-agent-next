"""Lightweight repo introspection for the ArchAnalyzer step."""
from __future__ import annotations

from pathlib import Path

META_FILES = [
    "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile",
    "package.json", "tsconfig.json",
    "go.mod", "Cargo.toml",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "Dockerfile", "docker-compose.yml",
    "README.md", "README.rst",
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv",
             "dist", "build", "target", ".mypy_cache", ".pytest_cache"}


def top_level_tree(repo: Path, max_depth: int = 2) -> list[str]:
    """Return a pruned list of relative paths up to max_depth."""
    paths: list[str] = []

    def walk(p: Path, depth: int):
        try:
            entries = sorted(p.iterdir())
        except PermissionError:
            return
        for e in entries:
            if e.name.startswith(".") and e.name not in {".github"}:
                continue
            if e.is_dir() and e.name in SKIP_DIRS:
                continue
            rel = e.relative_to(repo)
            paths.append(str(rel) + ("/" if e.is_dir() else ""))
            if e.is_dir() and depth < max_depth:
                walk(e, depth + 1)

    walk(repo, 1)
    return paths


def read_meta_files(repo: Path, max_bytes: int = 8000) -> dict[str, str]:
    """Read known meta files (truncated)."""
    out = {}
    for name in META_FILES:
        p = repo / name
        if p.is_file():
            try:
                out[name] = p.read_text(errors="replace")[:max_bytes]
            except Exception:
                pass
    return out
