"""Canonical full and explicitly bounded scan-scope manifests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from ..domain.schemas import ScanScopeManifest, ScanScopeMode
from .models import CAnalysisGraph, CoveragePlan

SCAN_SCOPE_POLICY = "scan-scope-v1"


def build_scan_scope(
    repo: Path,
    *,
    source_files: list[str],
    graph: CAnalysisGraph,
    coverage: CoveragePlan,
    mode: str | ScanScopeMode = ScanScopeMode.FULL,
    include_paths: list[str] | tuple[str, ...] = (),
    exclude_paths: list[str] | tuple[str, ...] = (),
) -> ScanScopeManifest:
    """Resolve declared scope paths against the real immutable source tree."""
    repo = repo.resolve()
    selected_mode = ScanScopeMode(mode)
    includes = _canonical_paths(repo, include_paths, label="include")
    excludes = _canonical_paths(repo, exclude_paths, label="exclude")
    source_set = set(source_files)

    if selected_mode is ScanScopeMode.FULL:
        if includes or excludes:
            raise ValueError("full scope does not accept include or exclude paths")
        selected = tuple(sorted(coverage.selected_files))
    else:
        if not includes:
            raise ValueError("bounded scope requires at least one include path")
        if selected_mode is ScanScopeMode.FILES:
            missing = sorted(set(includes) - source_set)
            if missing:
                raise ValueError(
                    "file scope path is not an analysed source file: " + missing[0]
                )
            selected_set = set(includes)
        else:
            selected_set = {
                path
                for path in source_set
                if any(_path_matches(path, root) for root in includes)
            }
        selected_set = {
            path
            for path in selected_set
            if not any(_path_matches(path, root) for root in excludes)
        }
        if not selected_set:
            raise ValueError("bounded scope selects no analysed source files")
        selected = tuple(sorted(selected_set))

    selected_set = set(selected)
    critical_by_path = {
        signal.signal_id: signal.path
        for signal in graph.signals
        if signal.signal_id in graph.critical_sink_ids
    }
    in_scope = tuple(sorted(
        signal_id
        for signal_id, path in critical_by_path.items()
        if selected_mode is ScanScopeMode.FULL or path in selected_set
    ))
    deferred = tuple(sorted(set(graph.critical_sink_ids) - set(in_scope)))
    digest = _scope_digest(selected_mode, includes, excludes)
    return ScanScopeManifest(
        mode=selected_mode,
        include_paths=includes,
        exclude_paths=excludes,
        selected_files=selected,
        in_scope_critical_sink_ids=in_scope,
        scope_deferred_critical_sink_ids=deferred,
        digest=digest,
        repository_complete=selected_mode is ScanScopeMode.FULL,
    )


def _canonical_paths(
    repo: Path,
    paths: list[str] | tuple[str, ...],
    *,
    label: str,
) -> tuple[str, ...]:
    canonical: set[str] = set()
    for raw in paths:
        value = str(raw).strip().replace("\\", "/")
        path = PurePosixPath(value)
        if not value or value == "." or path.is_absolute() or ".." in path.parts:
            raise ValueError(f"scope {label} path must be a repository-relative path")
        normalized = path.as_posix().rstrip("/")
        candidate = repo / normalized
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(repo)
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            raise ValueError(
                f"scope {label} path is missing or escapes the repository: {normalized}"
            ) from exc
        canonical.add(normalized)
    return tuple(sorted(canonical))


def _path_matches(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _scope_digest(
    mode: ScanScopeMode,
    includes: tuple[str, ...],
    excludes: tuple[str, ...],
) -> str:
    canonical = json.dumps(
        {
            "policy_version": SCAN_SCOPE_POLICY,
            "mode": mode.value,
            "include_paths": includes,
            "exclude_paths": excludes,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
