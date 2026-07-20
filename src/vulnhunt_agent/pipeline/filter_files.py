"""Step 2: pre-filter source files (no LLM)."""
from __future__ import annotations

from pathlib import Path

from ..core.events import EventBus
from ..core.run_store import RunStore
from ..sandbox import language_of
from .registry import Step, register


LANG_EXTENSIONS = {
    "python":     {".py"},
    "node":       {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"},
    "java":       {".java", ".kt"},
    "c":          {".c", ".h", ".l", ".y"},
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", "target", ".mypy_cache", ".pytest_cache", ".tox",
    "vendor", "third_party", "docs", "examples", "migrations",
}

TEST_HINTS = ("test", "tests", "__tests__", "spec", "specs")


def _is_test_path(rel: Path) -> bool:
    return any(part.lower() in TEST_HINTS for part in rel.parts)


def _walk(repo: Path, exts: set[str]) -> list[Path]:
    files: list[Path] = []
    for p in repo.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(repo)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if p.suffix.lower() not in exts:
            continue
        files.append(rel)
    return files


async def run_filter(store: RunStore, bus: EventBus) -> None:
    cfg = store.load_config() or {}
    repo = Path(cfg["repo_path"])
    lang = language_of(cfg["environment"])

    bus.emit("step_start", step="filter", language=lang)

    exts = LANG_EXTENSIONS[lang]
    all_files = _walk(repo, exts)
    source_files = [str(p) for p in all_files if not _is_test_path(p)]
    test_files   = [str(p) for p in all_files if _is_test_path(p)]

    result = {
        "extensions": sorted(exts),
        "total_matched": len(all_files),
        "test_files_excluded": len(test_files),
        "source_files": sorted(source_files),
    }
    store.save_step("filtered_files", result)
    bus.emit("step_done", step="filter", kept=len(source_files), excluded=len(test_files))


register(Step(
    name="filtered_files",
    title="2. File Filter",
    fn=run_filter,
    depends_on=["source_snapshot"],
))
