"""Resolve a repo source (git URL or local path) into a local directory."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[3] / "workspace/repos"


def is_git_url(s: str) -> bool:
    return bool(re.match(r"^(https?://|git@|ssh://|git://)", s))


def repo_name_from_url(url: str) -> str:
    name = url.rstrip("/").split("/")[-1]
    return name.removesuffix(".git")


def resolve(source: str, pull: bool = False) -> Path:
    """Return local path for source. Clones if needed."""
    if not is_git_url(source):
        path = Path(source).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"repo path not found: {path}")
        return path

    WORKSPACE.mkdir(parents=True, exist_ok=True)
    target = WORKSPACE / repo_name_from_url(source)

    if target.exists():
        if pull:
            subprocess.run(["git", "-C", str(target), "pull", "--ff-only"], check=True)
        return target.resolve()

    subprocess.run(["git", "clone", "--depth", "1", source, str(target)], check=True)
    return target.resolve()
