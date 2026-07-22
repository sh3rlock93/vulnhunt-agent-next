"""Content-addressed, immutable context packets shared across Hunters."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from ..domain.schemas import HunterWorkItem
from .context import (
    context_for_work_item,
    matching_capacity_risk_chains_for_targets,
    matching_risk_chains,
    matching_risk_chains_for_targets,
)

CONTEXT_CACHE_POLICY = "c-context-v6"
MAX_CONTEXT_BYTES = 24_000
MIN_EVIDENCE_EXCERPT_BYTES = 512
MAX_LINES_PER_FILE = 80
CONTEXT_LINE_RADIUS = 6
MAX_RELATED_HEADERS = 4
MAX_BUILD_FILES = 2
CONTEXT_KIND_LINE_LIMITS = {
    "target": 72,
    "constraint": 48,
    "capacity_chain": 48,
    "caller": 48,
    "callee": 48,
    "related": 40,
    "header": 32,
    "build": 24,
    "parser": 64,
}

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
        packet = _fit_packet(packet)
        packet["packet_digest"] = _packet_digest(packet)
        encoded = json.dumps(
            packet,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
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
        related_nodes = compact.get("related_nodes") or []
        constraint_facts = compact.get("constraint_facts") or []
        capacity_chains = compact.get("capacity_risk_chains") or []
        constraint_files = tuple(dict.fromkeys(
            str(item.get("path", ""))
            for item in constraint_facts
            if item.get("path") and item.get("path") not in work_item.files
        ))
        relationship_by_file: dict[str, str] = {}
        for chain in capacity_chains:
            for path in chain.get("paths", ()):
                if path and path not in work_item.files:
                    relationship_by_file.setdefault(str(path), "capacity_chain")
        for item in related_nodes:
            path = str(item.get("path", ""))
            if path and path not in work_item.files:
                relationship_by_file.setdefault(
                    path,
                    str(item.get("relationship", "related")),
                )
        relationship_files = tuple(sorted(
            relationship_by_file,
            key=lambda path: (
                0 if relationship_by_file[path] == "caller" else 1,
                path,
            ),
        ))
        context_source_files = tuple(dict.fromkeys((
            *work_item.files,
            *constraint_files,
            *relationship_files,
        )))
        context_hints = self._context_hints(work_item, related_nodes)
        related_headers = self._related_headers(
            context_source_files,
            hints=context_hints,
        )
        build_files = tuple(
            name for name in _BUILD_FILES if (self.repo / name).is_file()
        )[:MAX_BUILD_FILES]
        ordered_files = tuple(dict.fromkeys((
            *context_source_files,
            *related_headers,
            *build_files,
        )))
        focus_paths = _focus_evidence_paths(compact)
        ordered_files = tuple(sorted(
            ordered_files,
            key=lambda path: (0 if path in focus_paths else 1, ordered_files.index(path)),
        ))
        all_context_files = set(context_source_files)
        ranges = _relevant_ranges(
            self.analysis,
            slice_ids=set(work_item.slice_ids),
            files=all_context_files,
            target_signal_ids=set(work_item.target_signal_ids),
            target_node_ids=set(work_item.target_node_ids),
            changed_line_ranges=work_item.changed_line_ranges,
            related_nodes=related_nodes,
            constraint_facts=constraint_facts,
        )
        for header in related_headers:
            header_ranges = self._matching_header_ranges(header, context_hints)
            if header_ranges:
                ranges.setdefault(header, []).extend(header_ranges)
        file_kinds = {
            **{path: "target" for path in work_item.files},
            **{path: "constraint" for path in constraint_files},
            **relationship_by_file,
            **{path: "header" for path in related_headers},
            **{path: "build" for path in build_files},
        }
        excerpts, truncation = self._excerpts(
            ordered_files,
            ranges,
            file_kinds=file_kinds,
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
            "hydrated_context_files": list(context_source_files),
            "context_hints": list(context_hints),
            "related_headers": list(related_headers),
            "build_files": list(build_files),
            "selected_ranges": {
                path: [list(pair) for pair in selected]
                for path, selected in sorted(ranges.items())
            },
            "source_excerpts": excerpts,
            "truncation": truncation,
            "exploration_hint": (
                "These excerpts are immutable starting context, not a read restriction. "
                "Use read_file/grep for missing ranges, callers, headers, and sibling files."
            ),
        }

    def _related_headers(
        self,
        source_files: tuple[str, ...],
        *,
        hints: tuple[str, ...],
    ) -> tuple[str, ...]:
        headers: dict[str, int] = {}
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
                        relative_header = resolved.relative_to(self.repo).as_posix()
                        header_text = resolved.read_text(errors="replace")
                        headers[relative_header] = max(
                            headers.get(relative_header, 0),
                            sum(
                                (20 if not hint.isupper() else 1)
                                for hint in hints
                                if hint in header_text
                            ),
                        )
                        break
        return tuple(sorted(
            headers,
            key=lambda relative: (-headers[relative], relative),
        ))[:MAX_RELATED_HEADERS]

    def _context_hints(
        self,
        work_item: HunterWorkItem,
        related_nodes: list[dict],
    ) -> tuple[str, ...]:
        graph = self.analysis.get("graph") or {}
        nodes = {item["node_id"]: item for item in graph.get("nodes", [])}
        signals = {item["signal_id"]: item for item in graph.get("signals", [])}
        node_ids = set(work_item.target_node_ids)
        node_ids.update(
            signals[signal_id]["node_id"]
            for signal_id in work_item.target_signal_ids
            if signal_id in signals
        )
        node_ids.update(str(item.get("node_id", "")) for item in related_nodes)
        primary_hints: set[str] = set()
        type_hints: set[str] = set()
        for node_id in sorted(node_ids):
            node = nodes.get(node_id)
            if not node:
                continue
            primary_hints.update(
                (str(node.get("symbol", "")), *node.get("aliases", ()))
            )
            path = self._safe_file(str(node.get("path", "")))
            if path is None:
                continue
            lines = path.read_text(errors="replace").splitlines()
            start = max(0, int(node.get("line", 1)) - 1)
            declaration = " ".join(lines[start : start + 8])
            type_hints.update(
                re.findall(r"\b[A-Z][A-Za-z0-9_]{2,}\b", declaration)
            )
        primary = sorted(hint for hint in primary_hints if hint)
        types = sorted(hint for hint in type_hints - primary_hints if hint)
        return tuple((*primary, *types))[:40]

    def _matching_header_ranges(
        self,
        relative: str,
        hints: tuple[str, ...],
    ) -> list[tuple[int, int]]:
        path = self._safe_file(relative)
        if path is None:
            return []
        lines = path.read_text(errors="replace").splitlines()
        selected: list[tuple[int, int]] = []
        seen: set[int] = set()
        for hint in hints:
            for line_number, line in enumerate(lines, start=1):
                if hint in line and line_number not in seen:
                    selected.append((line_number, line_number))
                    seen.add(line_number)
        return selected

    def _excerpts(
        self,
        files: tuple[str, ...],
        ranges: dict[str, list[tuple[int, int]]],
        *,
        file_kinds: dict[str, str],
    ) -> tuple[list[dict], dict]:
        remaining = MAX_CONTEXT_BYTES
        out: list[dict] = []
        omitted: list[dict[str, str]] = []
        trimmed: list[dict[str, str]] = []
        for relative in files:
            if remaining <= 0:
                omitted.append({"path": relative, "reason": "context_byte_limit"})
                continue
            path = self._safe_file(relative)
            if path is None:
                omitted.append({"path": relative, "reason": "not_snapshot_file"})
                continue
            lines = path.read_text(errors="replace").splitlines()
            initial_kind = file_kinds.get(relative, "related")
            if Path(relative).suffix.lower() in {".l", ".y"}:
                initial_kind = "parser"
            selected = _selected_lines(
                len(lines),
                ranges.get(relative, []),
                whole_file=(
                    Path(relative).suffix.lower() in {".l", ".y"}
                    or file_kinds.get(relative) == "build"
                ),
                max_lines=CONTEXT_KIND_LINE_LIMITS[initial_kind],
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
                trimmed.append({"path": relative, "reason": "context_byte_limit"})
            if len(selected) < len(lines):
                trimmed.append({"path": relative, "reason": "line_selection_limit"})
            kind = initial_kind
            out.append({
                "path": relative,
                "kind": kind,
                "line_count": len(selected),
                "truncated": truncated or len(selected) < len(lines),
                "content": content,
            })
            remaining -= min(len(encoded), remaining)
        return out, {
            "max_context_bytes": MAX_CONTEXT_BYTES,
            "max_lines_per_file": MAX_LINES_PER_FILE,
            "kind_line_limits": CONTEXT_KIND_LINE_LIMITS,
            "omitted": omitted,
            "trimmed": sorted(
                {f"{item['path']}\0{item['reason']}": item for item in trimmed}.values(),
                key=lambda item: (item["path"], item["reason"]),
            ),
            "packet_fit_applied": False,
            "removed_slices": 0,
            "removed_risk_chains": 0,
            "removed_capacity_risk_chains": 0,
            "removed_related_nodes": 0,
            "removed_constraints": 0,
            "removed_source_excerpts": 0,
            "minimum_evidence_excerpt_bytes": MIN_EVIDENCE_EXCERPT_BYTES,
            "evidence_excerpt_guaranteed": False,
        }

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
    compact = context_for_work_item(analysis, work_item)
    related_nodes = compact.get("related_nodes") or []
    constraint_facts = compact.get("constraint_facts") or []
    capacity_chains = compact.get("capacity_risk_chains") or []
    context_files = set(work_item.files)
    context_files.update(
        str(item.get("path", ""))
        for item in (*related_nodes, *constraint_facts)
        if item.get("path")
    )
    context_files.update(
        str(path)
        for chain in capacity_chains
        for path in chain.get("paths", ())
        if path
    )
    selected_ranges = _relevant_ranges(
        analysis,
        slice_ids=set(work_item.slice_ids),
        files=context_files,
        target_signal_ids=set(work_item.target_signal_ids),
        target_node_ids=set(work_item.target_node_ids),
        changed_line_ranges=work_item.changed_line_ranges,
        related_nodes=related_nodes,
        constraint_facts=constraint_facts,
    )
    identity = {
        "source_snapshot": source_snapshot,
        "scan_scope_digest": work_item.scan_scope_digest,
        "graph_schema_version": int(graph.get("schema_version", 1)),
        "coverage_policy_version": str(plan.get("policy_version", "")),
        "slice_ids": sorted(work_item.slice_ids),
        "context_files": sorted(work_item.files),
        "target_node_ids": sorted(work_item.target_node_ids),
        "target_signal_ids": sorted(work_item.target_signal_ids),
        "focus_chain_ids": list(work_item.focus_chain_ids),
        "risk_chains": matching_risk_chains(graph, work_item)[:6],
        "capacity_risk_chains": capacity_chains[:3],
        "related_nodes": related_nodes,
        "constraint_policy_version": compact.get("constraint_policy_version", ""),
        "constraint_facts": constraint_facts,
        "selected_ranges": {
            path: sorted(ranges)
            for path, ranges in sorted(selected_ranges.items())
        },
        "changed_line_ranges": {
            path: sorted(ranges)
            for path, ranges in sorted(work_item.changed_line_ranges.items())
        },
        "context_policy": CONTEXT_CACHE_POLICY,
        "max_context_bytes": MAX_CONTEXT_BYTES,
        "max_lines_per_file": MAX_LINES_PER_FILE,
        "kind_line_limits": CONTEXT_KIND_LINE_LIMITS,
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
    target_signal_ids: set[str],
    target_node_ids: set[str],
    changed_line_ranges: dict[str, tuple[tuple[int, int], ...]],
    related_nodes: list[dict] | tuple[dict, ...] = (),
    constraint_facts: list[dict] | tuple[dict, ...] = (),
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
    out: dict[str, list[tuple[int, int]]] = {
        path: list(ranges)
        for path, ranges in changed_line_ranges.items()
        if path in files
    }
    for chain in matching_risk_chains_for_targets(
        graph,
        target_signal_ids=target_signal_ids,
        target_node_ids=target_node_ids,
    )[:6]:
        path = str(chain.get("path", ""))
        if path not in files:
            continue
        ordered_lines = (
            *chain.get("source_lines", ()),
            *(step.get("line", 1) for step in chain.get("transform_steps", ())),
            *chain.get("guard_lines", ()),
            *chain.get("sink_lines", ()),
        )
        out.setdefault(path, []).extend(
            (int(line), int(line)) for line in ordered_lines
        )
    for chain in matching_capacity_risk_chains_for_targets(
        graph,
        target_signal_ids=target_signal_ids,
        target_node_ids=target_node_ids,
    )[:3]:
        for path, lines in chain.get("evidence_lines", {}).items():
            if path in files:
                out.setdefault(path, []).extend(
                    (int(line), int(line)) for line in lines
                )
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
    for related in related_nodes:
        path = str(related.get("path", ""))
        if path not in files:
            continue
        start = int(related.get("line", 1))
        end = int(related.get("end_line", start))
        out.setdefault(path, []).extend(((start, start), (end, end)))
    for fact in constraint_facts:
        path = str(fact.get("path", ""))
        if path not in files:
            continue
        start = int(fact.get("line", 1))
        end = int(fact.get("end_line", start))
        out.setdefault(path, []).append((start, end))
    for path, selected in tuple(out.items()):
        out[path] = sorted(set(selected))
    return out


def _selected_lines(
    line_count: int,
    ranges: list[tuple[int, int]],
    *,
    whole_file: bool,
    max_lines: int = MAX_LINES_PER_FILE,
) -> list[int]:
    if line_count <= 0:
        return []
    if whole_file or not ranges:
        return list(range(1, min(line_count, max_lines) + 1))
    selected: set[int] = set()
    for start, end in ranges:
        lower = max(1, start - CONTEXT_LINE_RADIUS)
        upper = min(line_count, end + CONTEXT_LINE_RADIUS)
        selected.update(range(lower, upper + 1))
        if len(selected) >= max_lines:
            break
    return sorted(selected)[:max_lines]


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


def _fit_packet(packet: dict) -> dict:
    """Fit metadata around source evidence while preserving one useful excerpt."""
    placeholder = "sha256:" + "0" * 64
    truncation = packet["truncation"]
    truncation.setdefault("removed_source_excerpts", 0)
    truncation.setdefault("minimum_evidence_excerpt_bytes", MIN_EVIDENCE_EXCERPT_BYTES)
    truncation.setdefault("evidence_excerpt_guaranteed", False)
    focus_ids = set(packet.get("focus_chain_ids") or ())
    focus_paths = _focus_evidence_paths(packet)
    excerpts = packet.get("source_excerpts") or []
    had_source_evidence = any(str(item.get("content", "")) for item in excerpts)
    protected = next(
        (
            item for item in excerpts
            if item.get("path") in focus_paths and item.get("content")
        ),
        None,
    ) or next(
        (item for item in excerpts if item.get("kind") == "target" and item.get("content")),
        None,
    ) or next((item for item in excerpts if item.get("content")), None)

    def encoded_size() -> int:
        measured = {**packet, "packet_digest": placeholder}
        return len((json.dumps(
            measured,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n").encode("utf-8"))

    def mark_fit() -> None:
        truncation["packet_fit_applied"] = True

    def pop_last(field: str, *, non_focus: bool = False) -> bool:
        items = packet.get(field) or []
        for index in range(len(items) - 1, -1, -1):
            if non_focus and str(items[index].get("chain_id", "")) in focus_ids:
                continue
            items.pop(index)
            mark_fit()
            return True
        return False

    def trim_content(entry: dict, *, floor: int) -> bool:
        content = str(entry.get("content", ""))
        encoded = content.encode("utf-8")
        if len(encoded) <= floor:
            return False
        excess = encoded_size() - MAX_CONTEXT_BYTES
        keep = max(floor, len(encoded) - excess - 256)
        entry["content"] = encoded[:keep].decode("utf-8", errors="ignore")
        entry["truncated"] = True
        mark_fit()
        decision = {
            "path": str(entry.get("path", "")),
            "reason": "packet_byte_limit",
        }
        if decision not in truncation["trimmed"]:
            truncation["trimmed"].append(decision)
            truncation["trimmed"].sort(key=lambda item: (item["path"], item["reason"]))
        return True

    while encoded_size() > MAX_CONTEXT_BYTES:
        slices = packet.get("slices") or []
        if slices:
            slices.pop()
            mark_fit()
            truncation["removed_slices"] += 1
            continue
        if pop_last("risk_chains", non_focus=True):
            truncation["removed_risk_chains"] += 1
            continue
        if pop_last("capacity_risk_chains", non_focus=True):
            truncation["removed_capacity_risk_chains"] += 1
            continue
        related_nodes = packet.get("related_nodes") or []
        non_focus_related = next(
            (
                index for index in range(len(related_nodes) - 1, -1, -1)
                if str(related_nodes[index].get("path", "")) not in focus_paths
            ),
            None,
        )
        if non_focus_related is not None:
            related_nodes.pop(non_focus_related)
            mark_fit()
            truncation["removed_related_nodes"] += 1
            continue
        constraints = packet.get("constraint_facts") or []
        non_focus_constraint = next(
            (
                index for index in range(len(constraints) - 1, -1, -1)
                if str(constraints[index].get("path", "")) not in focus_paths
            ),
            None,
        )
        if non_focus_constraint is not None:
            constraints.pop(non_focus_constraint)
            mark_fit()
            truncation["removed_constraints"] += 1
            continue
        content_entry = next(
            (
                item for item in reversed(excerpts)
                if item is not protected and item.get("content")
            ),
            None,
        )
        if content_entry is not None and trim_content(content_entry, floor=0):
            continue
        removable_excerpt = next(
            (
                index for index in range(len(excerpts) - 1, -1, -1)
                if excerpts[index] is not protected and not excerpts[index].get("content")
            ),
            None,
        )
        if removable_excerpt is not None:
            removed = excerpts.pop(removable_excerpt)
            truncation["omitted"].append({
                "path": str(removed.get("path", "")),
                "reason": "packet_byte_limit",
            })
            mark_fit()
            truncation["removed_source_excerpts"] += 1
            continue
        if protected is not None:
            protected_size = len(str(protected.get("content", "")).encode("utf-8"))
            floor = min(MIN_EVIDENCE_EXCERPT_BYTES, max(1, protected_size))
            if trim_content(protected, floor=floor):
                continue
        if related_nodes:
            related_nodes.pop()
            mark_fit()
            truncation["removed_related_nodes"] += 1
            continue
        if constraints:
            constraints.pop()
            mark_fit()
            truncation["removed_constraints"] += 1
            continue
        chains = packet.get("risk_chains") or []
        if len(chains) > 1:
            chains.pop()
            mark_fit()
            truncation["removed_risk_chains"] += 1
            continue
        capacity_chains = packet.get("capacity_risk_chains") or []
        if len(capacity_chains) > 1:
            capacity_chains.pop()
            mark_fit()
            truncation["removed_capacity_risk_chains"] += 1
            continue
        raise ValueError("context packet metadata exceeds the hard byte limit")

    if had_source_evidence and not any(item.get("content") for item in excerpts):
        raise ValueError("context packet lost all source evidence while fitting")
    truncation["evidence_excerpt_guaranteed"] = bool(
        had_source_evidence and any(item.get("content") for item in excerpts)
    )
    return packet


def _focus_evidence_paths(packet: dict) -> set[str]:
    focus_ids = set(packet.get("focus_chain_ids") or ())
    paths: set[str] = set()
    for field in ("risk_chains", "capacity_risk_chains"):
        for chain in packet.get(field) or ():
            if focus_ids and str(chain.get("chain_id", "")) not in focus_ids:
                continue
            for path in (
                chain.get("path", ""),
                chain.get("root_path", ""),
                *(chain.get("paths") or ()),
                *((chain.get("evidence_lines") or {}).keys()),
            ):
                if path:
                    paths.add(str(path))
    return paths
