from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from tests.factories import HASH_A
from vulnhunt_agent.analysis import (
    build_c_analysis_graph,
    build_coverage_plan,
    build_scan_scope,
)
from vulnhunt_agent.interfaces.cli import _load_scan_scope_config, build_parser
from vulnhunt_agent.scheduling import build_routing_plan, build_slice_work_items


TOKENIZER_FILES = (
    "expat/xmlrole.c",
    "expat/xmltok.c",
    "expat/xmltok_impl.c",
    "expat/xmltok_ns.c",
)


def _libexpat_shape(tmp_path: Path):
    repo = tmp_path / "libexpat-shape"
    (repo / "expat").mkdir(parents=True)
    sources = {
        "expat/xmlrole.c": (
            "#include <string.h>\n"
            "void role(char *d, const char *s, unsigned long n) { memcpy(d,s,n); }\n"
        ),
        "expat/xmltok.c": (
            "#include <string.h>\n"
            "void tok(char *d, const char *s, unsigned long n) { memcpy(d,s,n); }\n"
        ),
        "expat/xmltok_impl.c": (
            "#include <string.h>\n"
            "void impl(char *d, const char *s, unsigned long n) { memcpy(d,s,n); }\n"
        ),
        "expat/xmltok_ns.c": (
            "#include <string.h>\n"
            "void ns(char *d, const char *s, unsigned long n) { memcpy(d,s,n); }\n"
        ),
        "expat/xmlparse.c": (
            "#include <string.h>\n"
            "void parse(char *d, const char *s, unsigned long n) { memcpy(d,s,n); }\n"
        ),
    }
    for path, source in sources.items():
        (repo / path).write_text(source)
    files = sorted(sources)
    graph = build_c_analysis_graph(repo, files)
    coverage = build_coverage_plan(graph)
    return repo, files, graph, coverage


def test_four_file_scope_does_not_force_xmlparse_and_defers_its_signals(
    tmp_path: Path,
) -> None:
    repo, files, graph, coverage = _libexpat_shape(tmp_path)
    scope = build_scan_scope(
        repo,
        source_files=files,
        graph=graph,
        coverage=coverage,
        mode="files",
        include_paths=list(reversed(TOKENIZER_FILES)),
    )
    analysis = {
        "language": "c",
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": coverage.model_dump(mode="json"),
        "incremental_scope": {"mode": "full"},
        "scan_scope": scope.model_dump(mode="json"),
    }

    routed = build_routing_plan(
        run_id="run-scope",
        source_snapshot=HASH_A,
        selected_files=[*TOKENIZER_FILES, "expat/xmlparse.c"],
        enabled_hunters=["c-bounds-integers", "c-memory-lifetime"],
        analysis=analysis,
    )
    work = build_slice_work_items(routed, analysis)

    assert {item.seed_file for item in work} <= set(TOKENIZER_FILES)
    assert "expat/xmlparse.c" not in routed.forced_files
    assert routed.uncovered_critical_sink_ids == ()
    assert routed.repository_complete is False
    assert routed.scope_deferred_critical_sink_ids
    assert all(item.scan_scope_digest == scope.digest for item in work)
    deferred_paths = {
        signal.path
        for signal in graph.signals
        if signal.signal_id in scope.scope_deferred_critical_sink_ids
    }
    assert "expat/xmlparse.c" in deferred_paths


def test_full_scope_preserves_critical_sink_coverage(tmp_path: Path) -> None:
    repo, files, graph, coverage = _libexpat_shape(tmp_path)
    scope = build_scan_scope(
        repo,
        source_files=files,
        graph=graph,
        coverage=coverage,
    )
    routed = build_routing_plan(
        run_id="run-full",
        source_snapshot=HASH_A,
        selected_files=list(coverage.selected_files),
        enabled_hunters=["c-bounds-integers"],
        analysis={
            "language": "c",
            "graph": graph.model_dump(mode="json"),
            "coverage_plan": coverage.model_dump(mode="json"),
            "incremental_scope": {"mode": "full"},
            "scan_scope": scope.model_dump(mode="json"),
        },
    )

    assert routed.detected_critical_sink_ids == graph.critical_sink_ids
    assert routed.covered_critical_sink_ids == graph.critical_sink_ids
    assert routed.uncovered_critical_sink_ids == ()
    assert routed.scope_deferred_critical_sink_ids == ()
    assert routed.repository_complete is True


@pytest.mark.parametrize(
    "path",
    ["../outside.c", "/tmp/outside.c", ".", "expat/missing.c"],
)
def test_scope_rejects_traversal_absolute_root_and_missing_paths(
    tmp_path: Path,
    path: str,
) -> None:
    repo, files, graph, coverage = _libexpat_shape(tmp_path)

    with pytest.raises(ValueError, match="scope|file scope"):
        build_scan_scope(
            repo,
            source_files=files,
            graph=graph,
            coverage=coverage,
            mode="files",
            include_paths=[path],
        )


def test_scope_order_is_canonical_and_changes_work_identity(tmp_path: Path) -> None:
    repo, files, graph, coverage = _libexpat_shape(tmp_path)
    first = build_scan_scope(
        repo,
        source_files=files,
        graph=graph,
        coverage=coverage,
        mode="files",
        include_paths=list(TOKENIZER_FILES),
    )
    reordered = build_scan_scope(
        repo,
        source_files=list(reversed(files)),
        graph=graph,
        coverage=coverage,
        mode="files",
        include_paths=list(reversed(TOKENIZER_FILES)),
    )
    narrower = build_scan_scope(
        repo,
        source_files=files,
        graph=graph,
        coverage=coverage,
        mode="files",
        include_paths=list(TOKENIZER_FILES[:-1]),
    )

    assert first == reordered
    assert first.digest != narrower.digest

    def work_ids(scope):
        routed = build_routing_plan(
            run_id="run-scope-id",
            source_snapshot=HASH_A,
            selected_files=list(scope.selected_files),
            enabled_hunters=["c-bounds-integers"],
            analysis={
                "language": "c",
                "graph": graph.model_dump(mode="json"),
                "coverage_plan": coverage.model_dump(mode="json"),
                "incremental_scope": {"mode": "full"},
                "scan_scope": scope.model_dump(mode="json"),
            },
        )
        return {item.work_id for item in build_slice_work_items(routed, {
            "coverage_plan": coverage.model_dump(mode="json")
        })}

    assert work_ids(first) == work_ids(reordered)
    assert work_ids(first) != work_ids(narrower)


def test_component_scope_selects_prefix_and_applies_exclusion(tmp_path: Path) -> None:
    repo, files, graph, coverage = _libexpat_shape(tmp_path)
    scope = build_scan_scope(
        repo,
        source_files=files,
        graph=graph,
        coverage=coverage,
        mode="component",
        include_paths=["expat"],
        exclude_paths=["expat/xmlparse.c"],
    )

    assert set(scope.selected_files) == set(TOKENIZER_FILES)
    assert scope.repository_complete is False


def test_cli_loads_canonical_scope_manifest_and_rejects_mixed_options(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "scope.json"
    manifest.write_text(json.dumps({
        "policy_version": "scan-scope-v1",
        "mode": "files",
        "include_paths": ["expat/xmltok.c"],
        "exclude_paths": [],
    }))
    parser = build_parser()
    args = parser.parse_args([
        "scan",
        ".",
        "--scope-manifest",
        str(manifest),
        "--plan-only",
    ])

    assert _load_scan_scope_config(args) == {
        "scan_scope_mode": "files",
        "scan_scope_include_paths": ["expat/xmltok.c"],
        "scan_scope_exclude_paths": [],
    }

    mixed = argparse.Namespace(
        scope_manifest=manifest,
        scope_mode="files",
        include_path=[],
        exclude_path=[],
    )
    with pytest.raises(ValueError, match="cannot be combined"):
        _load_scan_scope_config(mixed)
