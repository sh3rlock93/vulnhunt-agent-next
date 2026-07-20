from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from vulnhunt_agent.core.events import EventBus
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.indexer.tree_sitter_indexer import TreeSitterIndexer
from vulnhunt_agent.pipeline.filter_files import run_filter
from vulnhunt_agent.pipeline.hunt import _resolve_hunter_selection
from vulnhunt_agent.pipeline.rank import _index_with_text_fallbacks
from vulnhunt_agent.pipeline.sandbox_prepare import _install_cmds, _verify_cmds
from vulnhunt_agent.prompts import hunters_for, ranker_addendum

ROOT = Path(__file__).parents[1]
SANITIZER_FLAGS = "-fsanitize=address,undefined"


async def test_c_filter_and_tree_sitter_index(tmp_path) -> None:
    repo = tmp_path / "c-project"
    (repo / "tests").mkdir(parents=True)
    (repo / "parser.c").write_text(
        '#include "parser.h"\n'
        "int parse_index(const char *value) { return value[0] - '0'; }\n"
    )
    (repo / "parser.h").write_text("int parse_index(const char *value);\n")
    (repo / "scanner.l").write_text("[0-9]+ return NUMBER;\n")
    (repo / "grammar.y").write_text("input: NUMBER;\n")
    (repo / "tests" / "parser_test.c").write_text("int main(void) { return 0; }\n")

    store = RunStore(tmp_path / "run")
    store.save_config({"repo_path": str(repo), "environment": "c:gcc-13"})
    await run_filter(store, EventBus(store.dir / "events.jsonl"))

    filtered = store.load_step("filtered_files")
    assert filtered == {
        "extensions": [".c", ".h", ".l", ".y"],
        "total_matched": 5,
        "test_files_excluded": 1,
        "source_files": ["grammar.y", "parser.c", "parser.h", "scanner.l"],
    }

    index = TreeSitterIndexer().index_repo(repo, filtered["source_files"])
    parser = next(item for item in index.files if item.path == "parser.c")
    assert parser.language == "c"
    assert parser.imports == ["parser.h"]
    assert any(symbol.name == "parse_index" for symbol in parser.symbols)

    ranked_inputs = _index_with_text_fallbacks(
        repo, filtered["source_files"], language="c"
    )
    assert [item.path for item in ranked_inputs] == filtered["source_files"]
    scanner = next(item for item in ranked_inputs if item.path == "scanner.l")
    assert scanner.language == "c"
    assert scanner.loc == 2


def test_c_prompt_catalog_is_native_and_sanitizer_aware() -> None:
    hunters = hunters_for("c")
    assert len(hunters) == 6
    assert {hunter.name for hunter in hunters} == {
        "c-bounds-integers",
        "c-concurrency-state",
        "c-error-contracts",
        "c-injection-format",
        "c-memory-lifetime",
        "c-parser-state",
    }
    assert {hunter.name for hunter in hunters if hunter.default} == {
        "c-bounds-integers",
        "c-memory-lifetime",
        "c-parser-state",
    }
    assert "signed/unsigned" in next(
        item.system_prompt for item in hunters
        if item.name == "c-bounds-integers"
    )
    assert "lexer/parser" in ranker_addendum("c")


def test_c_hunt_defaults_work_without_rendering_the_ui(tmp_path) -> None:
    steps = tmp_path / "steps"

    assert set(_resolve_hunter_selection(steps, "c")) == {
        "c-bounds-integers",
        "c-memory-lifetime",
        "c-parser-state",
    }

    steps.mkdir()
    (steps / "hunter_selection.json").write_text('{"hunters": []}')
    assert _resolve_hunter_selection(steps, "c") == []


@pytest.mark.parametrize(
    ("marker", "expected"),
    [
        ("CMakeLists.txt", "cmake -S /code -B /opt/vulnhunt/build"),
        ("meson.build", "meson setup /opt/vulnhunt/build /code"),
        ("configure.ac", "/code/configure --disable-shared --enable-static"),
        ("Makefile", "make -C /code -j2"),
    ],
)
def test_c_prepare_build_plans_use_sanitizers(
    tmp_path, marker: str, expected: str
) -> None:
    (tmp_path / marker).write_text("")
    commands = _install_cmds(tmp_path, "c:gcc-13")

    assert "cmake" in commands[0]
    assert expected in "\n".join(commands)
    assert SANITIZER_FLAGS in "\n".join(commands)
    assert _verify_cmds("c:gcc-13") == ["cc --version"]


def test_c_environment_and_benchmark_are_pinned() -> None:
    settings = tomllib.loads((ROOT / "settings.example.toml").read_text())
    benchmark = tomllib.loads(
        (ROOT / "benchmarks" / "libcue-cve-2023-43641.toml").read_text()
    )

    assert "c:gcc-13" in settings["sandbox"]["environments"]
    assert settings["sandbox"]["images"]["c:gcc-13"] == "gcc:13-bookworm"
    assert len(benchmark["vulnerable_commit"]) == 40
    assert len(benchmark["fixed_commit"]) == 40
    assert benchmark["vulnerable_commit"] != benchmark["fixed_commit"]


def test_c_prepare_rejects_unknown_layout(tmp_path) -> None:
    with pytest.raises(RuntimeError, match="c repo has no"):
        _install_cmds(tmp_path, "c:gcc-13")
