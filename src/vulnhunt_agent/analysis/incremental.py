"""Safe Git-diff impact expansion for C analysis."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path, PurePosixPath

from .models import CAnalysisGraph, CoveragePlan, IncrementalScope

INCREMENTAL_POLICY = "c-git-diff-v1"
_C_SUFFIXES = frozenset({".c", ".h", ".l", ".y"})
_GRAMMAR_SUFFIXES = frozenset({".l", ".y"})
_BUILD_FILES = frozenset({
    "CMakeLists.txt",
    "meson.build",
    "configure.ac",
    "configure",
    "Makefile",
    "GNUmakefile",
})
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_LOCAL_INCLUDE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.MULTILINE)
_MAX_CHANGED_FILES = 20_000


def build_incremental_scope(
    repo: Path,
    *,
    base_ref: str | None,
    head_ref: str | None,
    graph: CAnalysisGraph,
    coverage: CoveragePlan,
) -> IncrementalScope:
    """Return a conservative incremental scope or an explicit full fallback."""
    repo = repo.resolve()
    base = (base_ref or "").strip()
    head = (head_ref or "").strip()
    if not base or not head:
        return _full_scope(
            coverage,
            graph,
            base_ref=base,
            head_ref=head,
            reason="refs_not_configured",
        )
    if _git(repo, "rev-parse", "--is-inside-work-tree").stdout.strip() != "true":
        return _full_scope(
            coverage, graph, base_ref=base, head_ref=head, reason="not_a_git_worktree"
        )
    base_commit = _resolve_commit(repo, base)
    head_commit = _resolve_commit(repo, head)
    if not base_commit or not head_commit:
        return _full_scope(
            coverage,
            graph,
            base_ref=base,
            head_ref=head,
            reason="ref_not_available",
        )
    checked_out = _resolve_commit(repo, "HEAD")
    if checked_out != head_commit:
        return _full_scope(
            coverage,
            graph,
            base_ref=base,
            head_ref=head,
            reason="head_ref_not_checked_out",
            base_commit=base_commit,
            head_commit=head_commit,
        )
    if _git(
        repo,
        "status",
        "--porcelain=v1",
        "--untracked-files=normal",
    ).stdout:
        return _full_scope(
            coverage,
            graph,
            base_ref=base,
            head_ref=head,
            reason="working_tree_dirty",
            base_commit=base_commit,
            head_commit=head_commit,
        )
    merge_base = _git(repo, "merge-base", "--", base_commit, head_commit)
    if merge_base.returncode != 0 or not merge_base.stdout.strip():
        return _full_scope(
            coverage,
            graph,
            base_ref=base,
            head_ref=head,
            reason="merge_base_unavailable",
            base_commit=base_commit,
            head_commit=head_commit,
        )
    merge_base_commit = merge_base.stdout.strip()
    changes = _changed_paths(repo, merge_base_commit, head_commit)
    if changes is None:
        return _full_scope(
            coverage,
            graph,
            base_ref=base,
            head_ref=head,
            reason="diff_too_large_or_unreadable",
            base_commit=base_commit,
            head_commit=head_commit,
            merge_base_commit=merge_base_commit,
        )
    if any(Path(path).name in _BUILD_FILES for _, path in changes):
        return _full_scope(
            coverage,
            graph,
            base_ref=base,
            head_ref=head,
            reason="build_configuration_changed",
            base_commit=base_commit,
            head_commit=head_commit,
            merge_base_commit=merge_base_commit,
            changed_files=tuple(sorted(path for _, path in changes)),
        )
    if any(
        status == "D" and Path(path).suffix.lower() in _C_SUFFIXES
        for status, path in changes
    ):
        return _full_scope(
            coverage,
            graph,
            base_ref=base,
            head_ref=head,
            reason="deleted_c_source",
            base_commit=base_commit,
            head_commit=head_commit,
            merge_base_commit=merge_base_commit,
            changed_files=tuple(sorted(path for _, path in changes)),
        )

    relevant = tuple(sorted({
        path for _, path in changes if Path(path).suffix.lower() in _C_SUFFIXES
    }))
    line_ranges = {
        path: _changed_line_ranges(repo, merge_base_commit, head_commit, path)
        for path in relevant
        if Path(path).suffix.lower() != ".h"
    }
    nodes_by_path: dict[str, list[str]] = {}
    nodes = {node.node_id: node for node in graph.nodes}
    for node in graph.nodes:
        nodes_by_path.setdefault(node.path, []).append(node.node_id)

    changed_nodes: set[str] = set()
    changed_headers = [
        path for path in relevant if Path(path).suffix.lower() == ".h"
    ]
    for path in relevant:
        if Path(path).suffix.lower() == ".h":
            continue
        ranges = line_ranges.get(path) or ()
        for node_id in nodes_by_path.get(path, []):
            node = nodes[node_id]
            if not ranges or any(
                _overlaps(node.line, node.end_line, start, end)
                for start, end in ranges
            ):
                changed_nodes.add(node_id)

    header_consumers, unresolved_headers = _header_consumers(
        repo,
        changed_headers,
        nodes_by_path,
    )
    if unresolved_headers:
        return _full_scope(
            coverage,
            graph,
            base_ref=base,
            head_ref=head,
            reason="header_consumers_unknown",
            base_commit=base_commit,
            head_commit=head_commit,
            merge_base_commit=merge_base_commit,
            changed_files=relevant,
        )
    for path in header_consumers:
        changed_nodes.update(nodes_by_path.get(path, ()))

    expanded_nodes = set(changed_nodes)
    for edge in graph.edges:
        if edge.source in changed_nodes or edge.target in changed_nodes:
            expanded_nodes.add(edge.source)
            expanded_nodes.add(edge.target)

    changed_source_files = {
        path for path in relevant if Path(path).suffix.lower() != ".h"
    }
    impacted_slices = [
        item
        for item in coverage.slices
        if (
            set(item.node_ids) & expanded_nodes
            or set(item.files) & changed_source_files
        )
    ]
    for item in impacted_slices:
        expanded_nodes.update(item.node_ids)
    selected_files = {
        nodes[node_id].path
        for node_id in expanded_nodes
        if node_id in nodes
    }
    selected_files.update(changed_source_files)
    for item in impacted_slices:
        selected_files.update(item.files)
    selected_files.update(header_consumers)
    critical = {
        item.sink_signal_id
        for item in impacted_slices
        if item.sink_signal_id in graph.critical_sink_ids
    }
    critical.update(
        signal.signal_id
        for signal in graph.signals
        if (
            signal.signal_id in graph.critical_sink_ids
            and signal.path in selected_files
        )
    )
    return IncrementalScope(
        policy_version=INCREMENTAL_POLICY,
        mode="incremental",
        base_ref=base,
        head_ref=head,
        base_commit=base_commit,
        head_commit=head_commit,
        merge_base_commit=merge_base_commit,
        changed_files=relevant,
        changed_line_ranges={
            path: tuple(ranges)
            for path, ranges in sorted(line_ranges.items())
        },
        changed_node_ids=tuple(sorted(changed_nodes)),
        expanded_node_ids=tuple(sorted(expanded_nodes)),
        selected_slice_ids=tuple(sorted(
            item.slice_id for item in impacted_slices
        )),
        selected_files=tuple(sorted(selected_files)),
        critical_sink_ids=tuple(sorted(critical)),
        full_selected_files=len(coverage.selected_files),
    )


def _full_scope(
    coverage: CoveragePlan,
    graph: CAnalysisGraph,
    *,
    base_ref: str,
    head_ref: str,
    reason: str,
    base_commit: str = "",
    head_commit: str = "",
    merge_base_commit: str = "",
    changed_files: tuple[str, ...] = (),
) -> IncrementalScope:
    return IncrementalScope(
        policy_version=INCREMENTAL_POLICY,
        mode="full",
        base_ref=base_ref,
        head_ref=head_ref,
        base_commit=base_commit,
        head_commit=head_commit,
        merge_base_commit=merge_base_commit,
        fallback_reason=reason,
        changed_files=changed_files,
        selected_slice_ids=tuple(item.slice_id for item in coverage.slices),
        selected_files=coverage.selected_files,
        critical_sink_ids=graph.critical_sink_ids,
        full_selected_files=len(coverage.selected_files),
    )


def _resolve_commit(repo: Path, ref: str) -> str:
    result = _git(
        repo,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{ref}^{{commit}}",
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _changed_paths(
    repo: Path,
    base_commit: str,
    head_commit: str,
) -> list[tuple[str, str]] | None:
    result = _git(
        repo,
        "diff",
        "--name-status",
        "-z",
        "--find-renames",
        base_commit,
        head_commit,
        "--",
    )
    if result.returncode != 0:
        return None
    tokens = result.stdout.split("\0")
    out: list[tuple[str, str]] = []
    index = 0
    while index < len(tokens) and tokens[index]:
        status_text = tokens[index]
        index += 1
        status = status_text[:1]
        if status in {"R", "C"}:
            if index + 1 >= len(tokens):
                return None
            index += 1
            path = tokens[index]
            index += 1
        else:
            if index >= len(tokens):
                return None
            path = tokens[index]
            index += 1
        out.append((status, path))
        if len(out) > _MAX_CHANGED_FILES:
            return None
    return out


def _changed_line_ranges(
    repo: Path,
    base_commit: str,
    head_commit: str,
    path: str,
) -> tuple[tuple[int, int], ...]:
    result = _git(
        repo,
        "diff",
        "--unified=0",
        "--no-color",
        base_commit,
        head_commit,
        "--",
        path,
    )
    ranges: list[tuple[int, int]] = []
    if result.returncode != 0:
        return ()
    for line in result.stdout.splitlines():
        match = _HUNK.match(line)
        if not match:
            continue
        start = max(1, int(match.group(1)))
        count = int(match.group(2) or "1")
        end = start if count == 0 else start + count - 1
        ranges.append((start, end))
    return tuple(ranges)


def _header_consumers(
    repo: Path,
    headers: list[str],
    nodes_by_path: dict[str, list[str]],
) -> tuple[set[str], set[str]]:
    wanted = set(headers)
    consumers_by_header: dict[str, set[str]] = {
        header: set() for header in headers
    }
    for source in sorted(nodes_by_path):
        path = (repo / source).resolve()
        if not path.is_file():
            continue
        for include in _LOCAL_INCLUDE.findall(path.read_text(errors="replace")):
            joined = PurePosixPath(source).parent / include
            normalized = joined.as_posix().removeprefix("./")
            matched = wanted & {normalized, PurePosixPath(include).as_posix()}
            for header in matched:
                consumers_by_header[header].add(source)
    consumers = set().union(*consumers_by_header.values()) if headers else set()
    unresolved = {
        header
        for header, paths in consumers_by_header.items()
        if not paths
    }
    return consumers, unresolved


def _overlaps(
    first_start: int,
    first_end: int,
    second_start: int,
    second_end: int,
) -> bool:
    return first_start <= second_end and second_start <= first_end


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(args, 1, "", "")
