"""Content-addressed, immutable context packets shared across Hunters."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from ..domain.schemas import HunterWorkItem
from .context import context_for_work_item

CONTEXT_CACHE_POLICY = "c-shared-context-v1"
MAX_CONTEXT_BYTES = 48_000
MAX_LINES_PER_FILE = 100
CONTEXT_LINE_RADIUS = 6
MAX_RELATED_HEADERS = 4
MAX_BUILD_FILES = 2

_BUILD_FILES = (
    "CMakeLists.txt",
    "meson.build",
    "configure.ac",
    "configure",
    "Makefile",
    "GNUmakefile",
)
_LOCAL_INCLUDE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.MULTILINE)


class SharedContextCache:
    """Build and verify immutable context packets below one run directory."""

    def __init__(
        self,
        root: Path,
        repo: Path,
        *,
        source_snapshot: str,
        analysis: dict | None,
    ):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.repo = repo.resolve()
        self.source_snapshot = source_snapshot
        self.analysis = analysis or {}
        self.hits = 0
        self.misses = 0
        self.bytes = 0
        self._seen_keys: set[str] = set()

    def get(self, work_item: HunterWorkItem) -> dict:
        cache_key = context_cache_key(
            source_snapshot=self.source_snapshot,
            analysis=self.analysis,
            work_item=work_item,
        )
        path = self.root / f"{cache_key}.json"
        cached = self._read_valid(path, cache_key)
        if cached is not None:
            self.hits += 1
            self.bytes += path.stat().st_size
            self._seen_keys.add(cache_key)
            return cached

        packet = self._build(work_item, cache_key)
        packet["packet_digest"] = _packet_digest(packet)
        encoded = (
            json.dumps(packet, indent=2, ensure_ascii=False, sort_keys=True)
            + "\n"
        )
        temporary = path.with_suffix(".tmp")
        temporary.write_text(encoded)
        temporary.replace(path)
        self.misses += 1
        self.bytes += len(encoded.encode("utf-8"))
        self._seen_keys.add(cache_key)
        return packet

    def stats(self) -> dict[str, int | str]:
        return {
            "policy_version": CONTEXT_CACHE_POLICY,
            "entries": len(self._seen_keys),
            "hits": self.hits,
            "misses": self.misses,
            "bytes": self.bytes,
        }

    def _read_valid(self, path: Path, cache_key: str) -> dict | None:
        if not path.is_file():
            return None
        try:
            packet = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if (
            not isinstance(packet, dict)
            or packet.get("cache_key") != cache_key
            or packet.get("source_snapshot") != self.source_snapshot
            or packet.get("context_policy") != CONTEXT_CACHE_POLICY
            or packet.get("packet_digest") != _packet_digest(packet)
        ):
            return None
        return packet

    def _build(
        self,
        work_item: HunterWorkItem,
        cache_key: str,
    ) -> dict:
        compact = context_for_work_item(self.analysis, work_item)
        for field in (
            "work_id",
            "target_file",
            "risk",
            "required",
            "routing_reasons",
        ):
            compact.pop(field, None)
        related_headers = self._related_headers(work_item.files)
        build_files = tuple(
            name for name in _BUILD_FILES if (self.repo / name).is_file()
        )[:MAX_BUILD_FILES]
        ordered_files = tuple(dict.fromkeys((
            *work_item.files,
            *related_headers,
            *build_files,
        )))
        ranges = _relevant_ranges(
            self.analysis,
            slice_ids=set(work_item.slice_ids),
            files=set(work_item.files),
        )
        excerpts = self._excerpts(
            ordered_files,
            ranges,
            slice_files=set(work_item.files),
            header_files=set(related_headers),
            build_files=set(build_files),
        )
        graph = self.analysis.get("graph") or {}
        plan = self.analysis.get("coverage_plan") or {}
        return {
            "cache_key": cache_key,
            "source_snapshot": self.source_snapshot,
            "context_policy": CONTEXT_CACHE_POLICY,
            "graph_schema_version": int(graph.get("schema_version", 1)),
            "coverage_policy_version": str(plan.get("policy_version", "")),
            **compact,
            "related_headers": list(related_headers),
            "build_files": list(build_files),
            "source_excerpts": excerpts,
            "exploration_hint": (
                "These excerpts are immutable starting context, not a read restriction. "
                "Use read_file/grep for missing ranges, callers, headers, and sibling files."
            ),
        }

    def _related_headers(self, source_files: tuple[str, ...]) -> tuple[str, ...]:
        headers: set[str] = set()
        for relative in source_files:
            path = self._safe_file(relative)
            if path is None:
                continue
            text = path.read_text(errors="replace")
            for include in _LOCAL_INCLUDE.findall(text):
                for candidate in (
                    path.parent / include,
                    self.repo / include,
                ):
                    resolved = candidate.resolve()
                    if (
                        resolved.is_file()
                        and self.repo in resolved.parents
                    ):
                        headers.add(resolved.relative_to(self.repo).as_posix())
                        break
        return tuple(sorted(headers))[:MAX_RELATED_HEADERS]

    def _excerpts(
        self,
        files: tuple[str, ...],
        ranges: dict[str, list[tuple[int, int]]],
        *,
        slice_files: set[str],
        header_files: set[str],
        build_files: set[str],
    ) -> list[dict]:
        remaining = MAX_CONTEXT_BYTES
        out: list[dict] = []
        for relative in files:
            if remaining <= 0:
                break
            path = self._safe_file(relative)
            if path is None:
                continue
            lines = path.read_text(errors="replace").splitlines()
            selected = _selected_lines(
                len(lines),
                ranges.get(relative, []),
                whole_file=(
                    Path(relative).suffix.lower() in {".h", ".l", ".y"}
                    or relative in build_files
                ),
            )
            content = "\n".join(
                f"{line:6}: {lines[line - 1]}"
                for line in selected
                if 1 <= line <= len(lines)
            )
            encoded = content.encode("utf-8")
            truncated = len(encoded) > remaining
            if truncated:
                content = encoded[:remaining].decode("utf-8", errors="ignore")
                content += "\n... (shared context byte limit reached)"
            kind = (
                "build"
                if relative in build_files
                else "header"
                if relative in header_files
                else "parser"
                if Path(relative).suffix.lower() in {".l", ".y"}
                else "slice"
                if relative in slice_files
                else "related"
            )
            out.append({
                "path": relative,
                "kind": kind,
                "line_count": len(selected),
                "truncated": truncated or len(selected) < len(lines),
                "content": content,
            })
            remaining -= min(len(encoded), remaining)
        return out

    def _safe_file(self, relative: str) -> Path | None:
        path = (self.repo / relative).resolve()
        if (
            path == self.repo
            or self.repo not in path.parents
            or not path.is_file()
        ):
            return None
        return path


def context_cache_key(
    *,
    source_snapshot: str,
    analysis: dict | None,
    work_item: HunterWorkItem,
) -> str:
    analysis = analysis or {}
    graph = analysis.get("graph") or {}
    plan = analysis.get("coverage_plan") or {}
    identity = {
        "source_snapshot": source_snapshot,
        "graph_schema_version": int(graph.get("schema_version", 1)),
        "coverage_policy_version": str(plan.get("policy_version", "")),
        "slice_ids": sorted(work_item.slice_ids),
        "context_files": sorted(work_item.files),
        "context_policy": CONTEXT_CACHE_POLICY,
        "max_context_bytes": MAX_CONTEXT_BYTES,
        "max_lines_per_file": MAX_LINES_PER_FILE,
        "line_radius": CONTEXT_LINE_RADIUS,
        "max_related_headers": MAX_RELATED_HEADERS,
        "max_build_files": MAX_BUILD_FILES,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return "context_" + hashlib.sha256(canonical.encode()).hexdigest()


def _relevant_ranges(
    analysis: dict,
    *,
    slice_ids: set[str],
    files: set[str],
) -> dict[str, list[tuple[int, int]]]:
    graph = analysis.get("graph") or {}
    plan = analysis.get("coverage_plan") or {}
    nodes = {
        item["node_id"]: item
        for item in graph.get("nodes", [])
    }
    selected_nodes = {
        node_id
        for item in plan.get("slices", [])
        if item.get("slice_id") in slice_ids
        for node_id in item.get("node_ids", [])
    }
    out: dict[str, list[tuple[int, int]]] = {}
    for signal in graph.get("signals", []):
        if (
            signal.get("node_id") in selected_nodes
            and signal.get("path") in files
        ):
            line = int(signal.get("line", 1))
            out.setdefault(signal["path"], []).append((line, line))
    for node_id in sorted(selected_nodes):
        node = nodes.get(node_id)
        if not node or node.get("path") not in files:
            continue
        start = int(node.get("line", 1))
        end = int(node.get("end_line", start))
        out.setdefault(node["path"], []).extend(((start, start), (end, end)))
    return out


def _selected_lines(
    line_count: int,
    ranges: list[tuple[int, int]],
    *,
    whole_file: bool,
) -> list[int]:
    if line_count <= 0:
        return []
    if whole_file or not ranges:
        return list(range(1, min(line_count, MAX_LINES_PER_FILE) + 1))
    selected: set[int] = set()
    for start, end in ranges:
        lower = max(1, start - CONTEXT_LINE_RADIUS)
        upper = min(line_count, end + CONTEXT_LINE_RADIUS)
        selected.update(range(lower, upper + 1))
        if len(selected) >= MAX_LINES_PER_FILE:
            break
    return sorted(selected)[:MAX_LINES_PER_FILE]


def _packet_digest(packet: dict) -> str:
    content = {
        key: value
        for key, value in packet.items()
        if key != "packet_digest"
    }
    canonical = json.dumps(
        content,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
