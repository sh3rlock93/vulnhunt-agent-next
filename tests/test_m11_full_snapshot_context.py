from __future__ import annotations

import copy
import json
from pathlib import Path

from tests.factories import HASH_A, HASH_B
from vulnhunt_agent.analysis import (
    SharedContextCache,
    build_c_analysis_graph,
    build_coverage_plan,
    build_scan_scope,
    context_cache_key,
)
from vulnhunt_agent.scheduling import build_routing_plan, build_slice_work_items


def _macro_callback_fixture(tmp_path: Path):
    repo = tmp_path / "callback"
    repo.mkdir()
    (repo / "target_impl.c").write_text(
        """#define PREFIX(name) name
typedef struct { const char *name; } ATTRIBUTE;
static int PREFIX(getAtts)(const char *ptr, int attsMax, ATTRIBUTE *atts) {
  int nAtts = 0;
  for (ptr += 1;; ptr += 1) {
    if (*ptr == 0) return nAtts;
    if (nAtts < attsMax) atts[nAtts].name = ptr;
    nAtts++;
  }
}
"""
    )
    (repo / "api.h").write_text(
        """typedef struct ENCODING ENCODING;
#define XmlGetAttributes(enc, ptr, attsMax, atts) \\
  (((enc)->getAtts)(ptr, attsMax, atts))
"""
    )
    (repo / "parser.c").write_text(
        """#include <limits.h>
#include <stddef.h>
#include "api.h"
static int storeAtts(ENCODING *enc, const char *text,
                     size_t parser_atts_size, void *atts) {
  if (parser_atts_size > (size_t)INT_MAX)
    return -1;
  return XmlGetAttributes(enc, text, (int)parser_atts_size, atts);
}
"""
    )
    (repo / "oracle.c").write_text(
        "const char *hidden_oracle = \"CVE-fix-diff-secret\";\n"
    )
    outside = tmp_path / "outside.c"
    outside.write_text("const char *outside_secret = \"do-not-read\";\n")
    files = ["api.h", "oracle.c", "parser.c", "target_impl.c"]
    graph = build_c_analysis_graph(repo, files)
    coverage = build_coverage_plan(graph)
    scope = build_scan_scope(
        repo,
        source_files=files,
        graph=graph,
        coverage=coverage,
        mode="files",
        include_paths=["target_impl.c"],
    )
    analysis = {
        "language": "c",
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": coverage.model_dump(mode="json"),
        "incremental_scope": {"mode": "full"},
        "scan_scope": scope.model_dump(mode="json"),
    }
    routed = build_routing_plan(
        run_id="run-full-context",
        source_snapshot=HASH_A,
        selected_files=list(scope.selected_files),
        enabled_hunters=["c-bounds-integers"],
        analysis=analysis,
    )
    target = next(
        node for node in graph.nodes
        if node.path == "target_impl.c" and "getAtts" in node.aliases
    )
    target_signals = {
        signal.signal_id for signal in graph.signals
        if signal.node_id == target.node_id
    }
    work = next(
        item for item in build_slice_work_items(routed, analysis)
        if target_signals.intersection(item.target_signal_ids)
    )
    return repo, graph, analysis, work, outside


def test_bounded_work_hydrates_indirect_caller_and_buffer_constraint(
    tmp_path: Path,
) -> None:
    repo, _graph, analysis, work, _outside = _macro_callback_fixture(tmp_path)
    cache_root = tmp_path / "cache"
    packet = SharedContextCache(
        cache_root,
        repo,
        source_snapshot=HASH_A,
        analysis=analysis,
    ).get(work)

    assert work.files == ("target_impl.c",)
    assert packet["context_policy"] == "c-context-v10"
    assert packet["full_snapshot_context"] is True
    assert packet["scan_scope_digest"] == analysis["scan_scope"]["digest"]
    assert packet["source_excerpts"][0]["path"] == "target_impl.c"
    assert any(
        item["symbol"] == "storeAtts"
        and item["relationship"] == "caller"
        and item["via"] == "indirect:XmlGetAttributes"
        for item in packet["related_nodes"]
    )
    assert any(
        item["kind"] == "buffer_size_bound"
        and item["subject"] == "parser_atts_size"
        and item["relation"] == "<="
        and item["bound"] == "INT_MAX"
        for item in packet["constraint_facts"]
    )
    caller = next(
        item for item in packet["source_excerpts"]
        if item["path"] == "parser.c"
    )
    assert caller["kind"] == "caller"
    assert "XmlGetAttributes" in caller["content"]
    assert "parser_atts_size" in caller["content"]
    type_header = next(
        item for item in packet["source_excerpts"]
        if item["path"] == "api.h"
    )
    assert "getAtts" in type_header["content"]
    cache_file = next(cache_root.glob("context_*.json"))
    assert cache_file.stat().st_size <= 24_000
    assert packet["truncation"]["max_context_bytes"] == 24_000


def test_context_selection_is_deterministic_and_excludes_unrelated_content(
    tmp_path: Path,
) -> None:
    repo, _graph, analysis, work, outside = _macro_callback_fixture(tmp_path)
    first = SharedContextCache(
        tmp_path / "cache-a",
        repo,
        source_snapshot=HASH_A,
        analysis=analysis,
    ).get(work)
    second = SharedContextCache(
        tmp_path / "cache-b",
        repo,
        source_snapshot=HASH_A,
        analysis=analysis,
    ).get(work)

    assert first == second
    encoded = json.dumps(first, sort_keys=True)
    assert "CVE-fix-diff-secret" not in encoded
    assert "do-not-read" not in encoded
    assert "oracle.c" not in {item["path"] for item in first["source_excerpts"]}
    assert outside.as_posix() not in encoded


def test_cache_key_covers_snapshot_scope_constraints_and_selected_ranges(
    tmp_path: Path,
) -> None:
    _repo, _graph, analysis, work, _outside = _macro_callback_fixture(tmp_path)
    baseline = context_cache_key(
        source_snapshot=HASH_A,
        analysis=analysis,
        work_item=work,
    )

    altered_scope = work.model_copy(update={"scan_scope_digest": HASH_B})
    changed_constraint = copy.deepcopy(analysis)
    relevant_fact = next(
        item for item in changed_constraint["graph"]["constraint_facts"]
        if item["subject"] == "parser_atts_size"
    )
    relevant_fact["expression"] += " /* changed */"
    changed_range = copy.deepcopy(analysis)
    caller = next(
        item for item in changed_range["graph"]["nodes"]
        if item["symbol"] == "storeAtts"
    )
    caller["end_line"] += 1

    assert baseline != context_cache_key(
        source_snapshot=HASH_B,
        analysis=analysis,
        work_item=work,
    )
    assert baseline != context_cache_key(
        source_snapshot=HASH_A,
        analysis=analysis,
        work_item=altered_scope,
    )
    assert baseline != context_cache_key(
        source_snapshot=HASH_A,
        analysis=changed_constraint,
        work_item=work,
    )
    assert baseline != context_cache_key(
        source_snapshot=HASH_A,
        analysis=changed_range,
        work_item=work,
    )
