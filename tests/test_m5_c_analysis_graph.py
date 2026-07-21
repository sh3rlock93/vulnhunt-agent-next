from __future__ import annotations

import json

from vulnhunt_agent.agents.queue import HuntQueueStore
from vulnhunt_agent.analysis import (
    build_c_analysis_graph,
    build_coverage_plan,
    context_for_file,
)
from vulnhunt_agent.core.events import EventBus
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.indexer.tree_sitter_indexer import TreeSitterIndexer
from vulnhunt_agent.pipeline.analysis_graph import run_analysis_graph
from vulnhunt_agent.pipeline.file_selector import run_file_selector
from vulnhunt_agent.pipeline.hunt.cluster import run_clusterer


def _native_fixture(tmp_path):
    repo = tmp_path / "native"
    repo.mkdir()
    (repo / "cue_scanner.l").write_text(
        "[[:digit:]]+ { yylval.ival = atoi(yytext); return NUMBER; }\n"
    )
    (repo / "cue_parser.y").write_text(
        "index: INDEX NUMBER { track_set_index(track, $2, 0); };\n"
    )
    (repo / "state.h").write_text(
        "void track_set_index(struct track *track, int index, long value);\n"
    )
    (repo / "state.c").write_text(
        '#include "state.h"\n'
        "void track_set_index(struct track *track, int index, long value) {\n"
        "    if (index > 99) return;\n"
        "    track->values[index] = value;\n"
        "}\n"
    )
    return repo, ["cue_parser.y", "cue_scanner.l", "state.c", "state.h"]


def test_c_graph_and_coverage_trace_flex_bison_to_array_write(tmp_path) -> None:
    repo, files = _native_fixture(tmp_path)

    first = build_c_analysis_graph(repo, files)
    second = build_c_analysis_graph(repo, list(reversed(files)))
    plan = build_coverage_plan(first)

    assert first == second
    source = next(
        item for item in first.signals
        if item.role.value == "source" and item.operation == "atoi"
    )
    sink = next(
        item for item in first.signals
        if item.category == "array_index_write"
    )
    assert source.path == "cue_scanner.l"
    assert sink.path == "state.c"
    assert sink.risk == 5
    assert any(edge.kind.value == "parser_flow" for edge in first.edges)
    assert any(
        edge.target.startswith("state.c::track_set_index")
        for edge in first.edges
    )
    cross_file = next(
        item for item in plan.slices
        if item.sink_signal_id == sink.signal_id
        and "cue_scanner.l" in item.files
    )
    assert cross_file.files == ("cue_parser.y", "cue_scanner.l", "state.c")
    assert plan.complete
    assert set(plan.selected_files) == set(files) - {"state.h"}

    context = context_for_file({
        "language": "c",
        "graph": first.model_dump(mode="json"),
        "coverage_plan": plan.model_dump(mode="json"),
    }, "state.c")
    assert context["policy_version"] == "c-coverage-v1"
    assert any(
        item["sink"]["category"] == "array_index_write"
        for item in context["slices"]
        if item["sink"]
    )


async def test_analysis_coverage_bypasses_rank_threshold(tmp_path) -> None:
    repo, files = _native_fixture(tmp_path)
    store = RunStore(tmp_path / "run")
    store.save_config({
        "repo_path": str(repo),
        "environment": "c:gcc-13",
    })
    store.save_step("filtered_files", {"source_files": files})
    store.save_step("ranked_files", {
        "all": [{"path": path, "score": 1} for path in files]
    })
    bus = EventBus(store.dir / "events.jsonl")

    await run_analysis_graph(store, bus)
    await run_file_selector(store, bus)

    selector = store.load_step("file_selector")
    assert selector is not None
    assert selector["coverage_complete"] is True
    assert {"cue_scanner.l", "cue_parser.y", "state.c"}.issubset(
        selector["selected"]
    )
    state_row = next(
        item for item in selector["files"] if item["path"] == "state.c"
    )
    assert state_row["score"] == 1
    assert state_row["analysis_priority"] == 5
    assert any(
        reason.startswith("critical-sink:")
        for reason in state_row["coverage_reasons"]
    )


def test_lower_and_upper_index_guards_reduce_array_sink_priority(tmp_path) -> None:
    repo, files = _native_fixture(tmp_path)
    (repo / "state.c").write_text(
        '#include "state.h"\n'
        "void track_set_index(struct track *track, int index, long value) {\n"
        "    if (index < 0 || index > 99) return;\n"
        "    track->values[index] = value;\n"
        "}\n"
    )

    graph = build_c_analysis_graph(repo, files)
    signal = next(
        item for item in graph.signals
        if item.category == "array_index_write_guarded"
    )

    assert signal.risk == 2
    assert "lower_guard=yes" in signal.detail
    assert "upper_guard=yes" in signal.detail
    assert signal.signal_id not in graph.critical_sink_ids


def test_macro_decorated_long_function_is_recovered_with_security_signals(
    tmp_path,
) -> None:
    repo = tmp_path / "macro-native"
    repo.mkdir()
    (repo / "zip.c").write_text(_macro_decorated_source())

    graph = build_c_analysis_graph(repo, ["zip.c"])
    node = next(
        item for item in graph.nodes
        if item.symbol == "zipOpenNewFileInZip4_64"
    )
    signal = next(
        item for item in graph.signals
        if item.node_id == node.node_id and item.operation == "ALLOC"
    )
    index = TreeSitterIndexer().index_repo(repo, ["zip.c"])

    assert node.line == 3
    assert node.end_line > node.line
    assert signal.category == "allocation_size"
    assert signal.risk == 4
    assert signal.signal_id in graph.critical_sink_ids
    assert any(
        symbol.name == "zipOpenNewFileInZip4_64"
        for file_index in index.files
        for symbol in file_index.symbols
    )


def test_16_bit_reject_guard_lowers_allocation_signal_priority(tmp_path) -> None:
    repo = tmp_path / "macro-guarded"
    repo.mkdir()
    source = _macro_decorated_source().replace(
        "    header = (char *)ALLOC((unsigned)size + 32);\n",
        "    if (global_size > 0xffff) return -1;\n"
        "    header = (char *)ALLOC((unsigned)size + 32);\n",
    )
    (repo / "zip.c").write_text(source)

    graph = build_c_analysis_graph(repo, ["zip.c"])
    signal = next(item for item in graph.signals if item.operation == "ALLOC")

    assert signal.category == "allocation_size_guarded"
    assert signal.risk == 2
    assert "16-bit reject guards=1" in signal.detail
    assert signal.signal_id not in graph.critical_sink_ids


class _NeverCalledClient:
    async def chat(self, **kwargs):
        raise AssertionError("exact deterministic duplicates must not call the LLM")


async def test_exact_cross_hunter_duplicates_skip_semantic_clusterer(tmp_path) -> None:
    qstore = HuntQueueStore(tmp_path / "hunters")
    queue = qstore.init_from_pairs([
        ("state.c", "c-bounds-integers"),
        ("state.c", "c-parser-state"),
    ])
    task = queue.tasks[0]
    finding = {
        "title": "Negative index write",
        "type": "out_of_bounds_write",
        "entry_file": "cue_scanner.l",
        "entry_line": 1,
        "sink_file": "state.c",
        "sink_line": 4,
        "description": "Missing lower bound permits an indexed write.",
    }
    bus = EventBus(tmp_path / "events.jsonl")

    groups = await run_clusterer(
        task,
        qstore,
        _NeverCalledClient(),
        [finding, {**finding, "title": "OOB through parser index"}],
        ["c-bounds-integers", "c-parser-state"],
        bus,
    )

    assert groups == [{
        "finding_ids": [0, 1],
        "reason": "deterministic fingerprint match",
    }]
    payload = json.loads((qstore.task_dir(task) / "clusters.json").read_text())
    assert payload["strategy"] == "deterministic"


def _macro_decorated_source() -> str:
    return (
        "#define ALLOC(size) malloc(size)\n"
        "#define ZEXPORT\n"
        "extern int ZEXPORT zipOpenNewFileInZip4_64(\n"
        "    void *file, const char *filename, const void *zipfi,\n"
        "    const void *local, unsigned local_size, const void *global,\n"
        "    unsigned global_size, const char *comment, int method, int level,\n"
        "    int raw, int window_bits, int memory_level, int strategy,\n"
        "    const char *password, unsigned crc, unsigned made_by,\n"
        "    unsigned flag, int zip64) {\n"
        "    unsigned size = 46 + global_size;\n"
        "    char *header;\n"
        "    header = (char *)ALLOC((unsigned)size + 32);\n"
        "    return header == 0;\n"
        "}\n"
    )
