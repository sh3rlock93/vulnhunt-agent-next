from __future__ import annotations

import asyncio
import json
import sqlite3
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.factories import HASH_A, HASH_B
from vulnhunt_agent.agents.tools import HunterTools
from vulnhunt_agent.agents.queue import HuntQueueStore
from vulnhunt_agent.agents.durable_queue import DurableHuntQueueStore
from vulnhunt_agent.analysis import (
    SharedContextCache,
    build_incremental_scope,
    context_cache_key,
    context_for_work_item,
)
from vulnhunt_agent.core.events import EventBus
from vulnhunt_agent.core.llm import LLMResponse
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.domain.schemas import (
    BudgetPolicy,
    BudgetUsage,
    HunterRoutingPlan,
    HunterWorkItem,
    RunRecord,
)
from vulnhunt_agent.analysis import build_c_analysis_graph, build_coverage_plan
from vulnhunt_agent.analysis.models import (
    AnalysisSlice,
    CAnalysisGraph,
    CoveragePlan,
    GraphNode,
    NodeKind,
    SecuritySignal,
    SignalRole,
)
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.interfaces.cli import main as cli_main
from vulnhunt_agent.pipeline.hunt.hunters import run_hunters
from vulnhunt_agent.pipeline.analysis_graph import run_analysis_graph
from vulnhunt_agent.pipeline.file_selector import run_file_selector
from vulnhunt_agent.pipeline.filter_files import run_filter
from vulnhunt_agent.pipeline.source_snapshot import run_source_snapshot
from vulnhunt_agent.pipeline import hunt as hunt_pipeline
from vulnhunt_agent.scheduling import (
    BudgetController,
    BudgetedLLMClient,
    BudgetExceededError,
    adaptive_iteration_limit,
    allocate_work_items,
    build_routing_plan,
    build_slice_work_items,
    build_shadow_plan,
    total_usage,
    work_id_for,
)


def test_shadow_plan_is_stable_and_preserves_legacy_cartesian_execution() -> None:
    analysis = {
        "coverage_plan": {
            "slices": [{
                "slice_id": "slice-critical",
                "files": ["parser.c", "state.c"],
                "risk": 5,
                "sink_signal_id": "sink-oob",
            }]
        }
    }
    first = build_shadow_plan(
        run_id="run-1",
        source_snapshot=HASH_A,
        selected_files=["state.c", "parser.c"],
        hunters=["c-parser-state", "c-bounds-integers"],
        analysis=analysis,
    )
    second = build_shadow_plan(
        run_id="run-1",
        source_snapshot=HASH_A,
        selected_files=["parser.c", "state.c"],
        hunters=["c-bounds-integers", "c-parser-state"],
        analysis=analysis,
    )

    assert first == second
    assert len(first) == 4
    assert {
        (item.seed_file, item.hunter)
        for item in first
    } == {
        ("parser.c", "c-bounds-integers"),
        ("parser.c", "c-parser-state"),
        ("state.c", "c-bounds-integers"),
        ("state.c", "c-parser-state"),
    }
    assert all(item.required and item.risk == 5 for item in first)
    assert all(item.routing_reasons == ("shadow:legacy-cartesian",) for item in first)


def test_work_contract_and_budget_policy_are_strict() -> None:
    work_id = work_id_for(
        source_snapshot=HASH_A,
        planning_policy="test-v1",
        slice_ids=("slice-b", "slice-a"),
        files=("state.c", "parser.c"),
        hunter="c-bounds-integers",
    )
    assert work_id == work_id_for(
        source_snapshot=HASH_A,
        planning_policy="test-v1",
        slice_ids=("slice-a", "slice-b"),
        files=("parser.c", "state.c"),
        hunter="c-bounds-integers",
    )
    with pytest.raises(ValidationError, match="seed file must be included"):
        HunterWorkItem(
            work_id=work_id,
            run_id="run-1",
            source_snapshot=HASH_A,
            planning_policy="test-v1",
            seed_file="other.c",
            files=("state.c",),
            hunter="c-bounds-integers",
            routing_reasons=("test",),
        )
    with pytest.raises(ValidationError):
        BudgetPolicy(max_hunter_sessions=0)


def test_budget_allocation_prioritizes_critical_high_and_retry_capacity() -> None:
    base = list(build_shadow_plan(
        run_id="run-1",
        source_snapshot=HASH_A,
        selected_files=[f"file-{index}.c" for index in range(6)],
        hunters=["c-bounds-integers"],
        analysis={},
    ))
    work = tuple(
        item.model_copy(update={
            "required": index < 3,
            "risk": 5 if index < 3 else (4 if index == 3 else 1),
        })
        for index, item in enumerate(base)
    )

    allocation = allocate_work_items(
        tuple(reversed(work)),
        BudgetPolicy(max_hunter_sessions=5),
    )

    assert allocation.critical_slots == 3
    assert allocation.high_risk_slots == 1
    assert allocation.general_slots == 0
    assert allocation.retry_slots == 1
    assert len(allocation.admitted_work_ids) == 4
    assert len(allocation.deferred) == 2
    assert all(reason == "max_hunter_sessions" for reason in allocation.deferred.values())


def test_adaptive_iteration_limits_use_8_30_100_tiers() -> None:
    item = build_shadow_plan(
        run_id="run-1",
        source_snapshot=HASH_A,
        selected_files=["state.c"],
        hunters=["c-bounds-integers"],
        analysis={},
    )[0]
    assert adaptive_iteration_limit(item, configured_cap=100) == 8
    assert adaptive_iteration_limit(
        item.model_copy(update={"risk": 4}),
        configured_cap=100,
    ) == 30
    assert adaptive_iteration_limit(
        item,
        configured_cap=100,
        attempt=2,
    ) == 100
    assert adaptive_iteration_limit(
        item,
        configured_cap=20,
        has_evidence=True,
    ) == 20


def test_v2_database_migrates_usage_metrics_without_losing_tasks(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.db"
    with SqliteRepository(path) as repository:
        repository.save_run(RunRecord(run_id="run-1"))
        repository.ensure_task("run-1", "hunter", "state.c")
    connection = sqlite3.connect(path)
    connection.execute("DROP TABLE work_usage")
    connection.execute("PRAGMA user_version=2")
    connection.commit()
    connection.close()

    usage = BudgetUsage(
        run_id="run-1",
        work_id="work_" + "a" * 64,
        scope="hunter",
        model_id="gpt-5.6-sol",
        transport="codex_subscription",
        sessions=1,
        calls=3,
        iterations=3,
        input_tokens=100,
        output_tokens=20,
        tool_calls=4,
        repeated_reads=1,
        poc_writes=1,
        exec_calls=1,
    )
    with SqliteRepository(path) as repository:
        assert repository.schema_version() == 3
        assert repository.list_tasks("run-1")[0]["task_key"] == "state.c"
        repository.save_budget_usage(usage)
        assert repository.save_budget_usage(usage) == usage
        assert repository.list_budget_usage("run-1", scope="hunter") == [usage]

    with SqliteRepository(path, read_only=True) as repository:
        assert repository.list_budget_usage("run-1") == [usage]
    totals = total_usage([usage])
    assert totals["sessions"] == 1
    assert totals["repeated_reads"] == 1
    assert totals["estimated_cost_usd"] is None


async def test_hunter_tools_meter_repeated_reads_and_poc_attempts(
    tmp_path: Path,
) -> None:
    (tmp_path / "state.c").write_text("int main(void) { return 0; }\n")
    tools = HunterTools(tmp_path)

    await tools.dispatch("read_file", {"path": "state.c"})
    repeated = await tools.dispatch("read_file", {"path": "state.c"})
    unavailable = await tools.dispatch(
        "write_poc", {"path": "poc.c", "content": "int main(void){}"}
    )

    assert "already read" in repeated
    assert unavailable == "ERROR: sandbox not available"
    assert tools.tool_calls == 3
    assert tools.repeated_reads == 1
    assert tools.poc_write_calls == 1


class _FinalJsonClient:
    model_id = "gpt-5.6-sol"
    transport = "codex_subscription"

    async def chat(self, **kwargs) -> LLMResponse:
        return LLMResponse(
            text='{"findings":[]}',
            input_tokens=30,
            output_tokens=5,
            cache_read_tokens=10,
            cache_write_tokens=0,
            stop_reason="end_turn",
            content_blocks=[{"text": '{"findings":[]}'}],
        )


class _MeteredClient(_FinalJsonClient):
    def __init__(self) -> None:
        self.max_tokens: list[int] = []

    async def chat(self, **kwargs) -> LLMResponse:
        self.max_tokens.append(kwargs["max_tokens"])
        return await super().chat(**kwargs)


async def test_budgeted_client_caps_output_and_stops_the_next_call() -> None:
    delegate = _MeteredClient()
    controller = BudgetController(BudgetPolicy(
        max_input_tokens=10_000,
        max_output_tokens=5,
        max_wall_clock_minutes=1,
    ))
    client = BudgetedLLMClient(delegate, controller)

    response = await client.chat(
        messages=[],
        system="",
        tools=[],
        max_tokens=4_000,
    )

    assert response.output_tokens == 5
    assert delegate.max_tokens == [5]
    with pytest.raises(BudgetExceededError, match="max_output_tokens"):
        await client.chat(messages=[], system="", tools=[], max_tokens=4_000)


def test_budget_controller_refuses_calls_after_deadline() -> None:
    current = [0.0]
    controller = BudgetController(
        BudgetPolicy(max_wall_clock_minutes=1),
        clock=lambda: current[0],
    )
    current[0] = 61.0
    with pytest.raises(BudgetExceededError, match="max_wall_clock_minutes"):
        controller.reserve_call(
            input_upper_bound=1,
            requested_output_tokens=1,
        )


async def test_completed_hunter_session_produces_durable_usage_shape(
    tmp_path: Path,
) -> None:
    (tmp_path / "state.c").write_text("int main(void) { return 0; }\n")
    qstore = HuntQueueStore(tmp_path / "hunters")
    task = qstore.init_from_pairs([
        ("state.c", "c-bounds-integers"),
    ]).tasks[0]
    item = build_shadow_plan(
        run_id="run-1",
        source_snapshot=HASH_A,
        selected_files=["state.c"],
        hunters=["c-bounds-integers"],
        analysis={},
    )[0]

    findings, usage, deferred = await run_hunters(
        task,
        qstore,
        tmp_path,
        _FinalJsonClient(),
        "unused:latest",
        {"language": "c"},
        {},
        "No sandbox.",
        3,
        asyncio.Semaphore(1),
        EventBus(tmp_path / "events.jsonl"),
        False,
        {item.hunter: item},
    )

    assert findings == {"c-bounds-integers": []}
    assert deferred == {}
    assert len(usage) == 1
    assert usage[0].sessions == 1
    assert usage[0].calls == usage[0].iterations == 1
    assert usage[0].input_tokens == 30
    assert usage[0].cache_read_tokens == 10
    assert usage[0].estimated_cost_usd is None


async def test_hunter_budget_stop_is_deferred_instead_of_failed(
    tmp_path: Path,
) -> None:
    (tmp_path / "state.c").write_text("int main(void) { return 0; }\n")
    qstore = HuntQueueStore(tmp_path / "hunters")
    task = qstore.init_from_pairs([
        ("state.c", "c-bounds-integers"),
    ]).tasks[0]
    item = build_shadow_plan(
        run_id="run-1",
        source_snapshot=HASH_A,
        selected_files=["state.c"],
        hunters=["c-bounds-integers"],
        analysis={},
    )[0]
    client = BudgetedLLMClient(
        _FinalJsonClient(),
        BudgetController(BudgetPolicy(
            max_input_tokens=1,
            max_output_tokens=100,
            max_wall_clock_minutes=1,
        )),
    )

    findings, usage, deferred = await run_hunters(
        task,
        qstore,
        tmp_path,
        client,
        "unused:latest",
        {"language": "c"},
        {},
        "No sandbox.",
        8,
        asyncio.Semaphore(1),
        EventBus(tmp_path / "events.jsonl"),
        False,
        {item.hunter: item},
    )

    assert findings == {"c-bounds-integers": []}
    assert deferred == {"c-bounds-integers": "max_input_tokens"}
    assert task.hunters[0].status == "budget_deferred"
    assert usage[0].calls == usage[0].iterations == 0


def _native_router_fixture(tmp_path: Path) -> tuple[Path, list[str]]:
    repo = tmp_path / "native-router"
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


def _commit_all(repo: Path, message: str) -> str:
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-m", message],
        check=True,
        capture_output=True,
    )
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _git_incremental_fixture(
    tmp_path: Path,
) -> tuple[Path, list[str], str, str]:
    repo, files = _native_router_fixture(tmp_path)
    (repo / "unrelated.c").write_text(
        "#include <stdio.h>\n"
        "void unrelated_log(const char *value) { printf(value); }\n"
    )
    files.append("unrelated.c")
    subprocess.run(["git", "-C", str(repo), "init", "-b", "main"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "tests@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Tests"],
        check=True,
    )
    base = _commit_all(repo, "base")
    (repo / "state.c").write_text(
        '#include "state.h"\n'
        "void track_set_index(struct track *track, int index, long value) {\n"
        "    /* changed validation path */\n"
        "    if (index > 99) return;\n"
        "    track->values[index] = value;\n"
        "}\n"
    )
    head = _commit_all(repo, "change state path")
    return repo, files, base, head


def test_git_diff_scope_expands_changed_function_and_parser_flow(
    tmp_path: Path,
) -> None:
    repo, files, base, head = _git_incremental_fixture(tmp_path)
    graph = build_c_analysis_graph(repo, files)
    coverage = build_coverage_plan(graph)

    scope = build_incremental_scope(
        repo,
        base_ref=base,
        head_ref=head,
        graph=graph,
        coverage=coverage,
    )

    assert scope.mode == "incremental"
    assert scope.fallback_reason == ""
    assert scope.changed_files == ("state.c",)
    assert scope.base_commit == base
    assert scope.head_commit == head
    assert any(node_id.startswith("state.c::track_set_index") for node_id in scope.changed_node_ids)
    assert {"state.c", "cue_parser.y", "cue_scanner.l"}.issubset(
        scope.selected_files
    )
    assert "unrelated.c" not in scope.selected_files
    assert set(scope.critical_sink_ids) < set(graph.critical_sink_ids)
    assert any(
        signal.path == "state.c"
        and signal.signal_id in scope.critical_sink_ids
        for signal in graph.signals
    )
    assert scope.file_reduction_percent > 0

    analysis = {
        "language": "c",
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": coverage.model_dump(mode="json"),
        "incremental_scope": scope.model_dump(mode="json"),
    }
    routed = build_routing_plan(
        run_id="run-incremental",
        source_snapshot=HASH_A,
        selected_files=list(scope.selected_files),
        enabled_hunters=[
            "c-bounds-integers",
            "c-parser-state",
        ],
        analysis=analysis,
    )
    assert set(routed.detected_critical_sink_ids) == set(scope.critical_sink_ids)
    assert routed.uncovered_critical_sink_ids == ()


def test_git_diff_scope_expands_header_consumers_and_falls_back_safely(
    tmp_path: Path,
) -> None:
    repo, files = _native_router_fixture(tmp_path)
    subprocess.run(["git", "-C", str(repo), "init", "-b", "main"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "tests@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Tests"],
        check=True,
    )
    base = _commit_all(repo, "base")
    (repo / "state.h").write_text(
        "/* contract changed */\n"
        "void track_set_index(struct track *track, int index, long value);\n"
    )
    head = _commit_all(repo, "change header")
    graph = build_c_analysis_graph(repo, files)
    coverage = build_coverage_plan(graph)

    header_scope = build_incremental_scope(
        repo,
        base_ref=base,
        head_ref=head,
        graph=graph,
        coverage=coverage,
    )
    assert header_scope.mode == "incremental"
    assert header_scope.changed_files == ("state.h",)
    assert "state.c" in header_scope.selected_files
    assert header_scope.critical_sink_ids

    (repo / "orphan.h").write_text("/* no known consumer */\n")
    orphan_base = _commit_all(repo, "add orphan header")
    (repo / "state.h").write_text(
        (repo / "state.h").read_text() + "/* second contract change */\n"
    )
    (repo / "orphan.h").write_text("/* changed without consumer */\n")
    orphan_head = _commit_all(repo, "change known and unknown headers")
    graph = build_c_analysis_graph(repo, [*files, "orphan.h"])
    coverage = build_coverage_plan(graph)
    unknown_consumer = build_incremental_scope(
        repo,
        base_ref=orphan_base,
        head_ref=orphan_head,
        graph=graph,
        coverage=coverage,
    )
    assert unknown_consumer.mode == "full"
    assert unknown_consumer.fallback_reason == "header_consumers_unknown"

    (repo / "state.c").write_text(
        (repo / "state.c").read_text() + "\n/* dirty */\n"
    )
    dirty = build_incremental_scope(
        repo,
        base_ref=orphan_base,
        head_ref=orphan_head,
        graph=graph,
        coverage=coverage,
    )
    assert dirty.mode == "full"
    assert dirty.fallback_reason == "working_tree_dirty"
    assert dirty.selected_files == coverage.selected_files

    subprocess.run(
        ["git", "-C", str(repo), "restore", "state.c"],
        check=True,
    )
    missing = build_incremental_scope(
        repo,
        base_ref="refs/heads/does-not-exist",
        head_ref="HEAD",
        graph=graph,
        coverage=coverage,
    )
    assert missing.mode == "full"
    assert missing.fallback_reason == "ref_not_available"


def test_scan_cli_materializes_incremental_plan(
    tmp_path: Path,
    capsys,
) -> None:
    repo, _, base, head = _git_incremental_fixture(tmp_path)
    run_root = tmp_path / "runs"

    result = cli_main([
        "scan",
        str(repo),
        "--base-ref",
        base,
        "--head-ref",
        head,
        "--plan-only",
        "--run-root",
        str(run_root),
        "--run-id",
        "cli-incremental",
    ])

    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == "plan_only"
    assert payload["run_id"] == "cli-incremental"
    assert payload["incremental_scope"]["mode"] == "incremental"
    assert "state.c" in payload["selected_files"]
    assert "unrelated.c" not in payload["selected_files"]
    assert (run_root / "cli-incremental" / "state.db").is_file()


def test_signal_router_reduces_libcue_shape_and_covers_critical_sink(
    tmp_path: Path,
) -> None:
    repo, files = _native_router_fixture(tmp_path)
    graph = build_c_analysis_graph(repo, files)
    coverage = build_coverage_plan(graph)
    analysis = {
        "language": "c",
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": coverage.model_dump(mode="json"),
    }
    selected = list(coverage.selected_files)
    enabled = [
        "c-bounds-integers",
        "c-memory-lifetime",
        "c-parser-state",
    ]

    first = build_routing_plan(
        run_id="run-1",
        source_snapshot=HASH_A,
        selected_files=selected,
        enabled_hunters=enabled,
        analysis=analysis,
    )
    second = build_routing_plan(
        run_id="run-1",
        source_snapshot=HASH_A,
        selected_files=list(reversed(selected)),
        enabled_hunters=list(reversed(enabled)),
        analysis=analysis,
    )

    assert first == second
    assert first.legacy_sessions == 9
    assert first.scheduled_sessions == 4
    assert first.session_reduction_percent > 50
    assert not first.uncovered_critical_sink_ids
    assert (
        set(first.detected_critical_sink_ids)
        == set(first.covered_critical_sink_ids)
        == set(graph.critical_sink_ids)
    )
    routed = {(item.seed_file, item.hunter) for item in first.work_items}
    assert routed == {
        ("cue_scanner.l", "c-parser-state"),
        ("cue_parser.y", "c-parser-state"),
        ("state.c", "c-bounds-integers"),
        ("state.c", "c-parser-state"),
    }


def test_critical_specialist_is_forced_even_when_not_manually_enabled() -> None:
    node = GraphNode(
        node_id="format.c::log_user@1",
        path="format.c",
        symbol="log_user",
        line=1,
        end_line=3,
        kind=NodeKind.FUNCTION,
        visibility="external",
    )
    signal = SecuritySignal(
        signal_id="sig-format",
        node_id=node.node_id,
        path=node.path,
        line=2,
        role=SignalRole.SINK,
        category="dynamic_format_string",
        operation="printf",
        risk=5,
    )
    graph = CAnalysisGraph(
        nodes=(node,),
        signals=(signal,),
        entrypoint_ids=(node.node_id,),
        critical_sink_ids=(signal.signal_id,),
    )
    coverage = CoveragePlan(
        slices=(AnalysisSlice(
            slice_id="slice-format",
            entrypoint_id=node.node_id,
            sink_signal_id=signal.signal_id,
            node_ids=(node.node_id,),
            files=(node.path,),
            categories=(signal.category,),
            risk=5,
            rationale="dynamic format",
        ),),
        selected_files=(node.path,),
        covered_entrypoint_ids=(node.node_id,),
        covered_sink_ids=(signal.signal_id,),
    )

    routed = build_routing_plan(
        run_id="run-1",
        source_snapshot=HASH_A,
        selected_files=[node.path],
        enabled_hunters=["c-bounds-integers"],
        analysis={
            "language": "c",
            "graph": graph.model_dump(mode="json"),
            "coverage_plan": coverage.model_dump(mode="json"),
        },
    )

    assert [item.hunter for item in routed.work_items] == [
        "c-injection-format"
    ]
    assert routed.work_items[0].required is True
    assert routed.covered_critical_sink_ids == ("sig-format",)


def test_overlapping_routes_collapse_to_bounded_slice_work(
    tmp_path: Path,
) -> None:
    repo, files = _native_router_fixture(tmp_path)
    graph = build_c_analysis_graph(repo, files)
    coverage = build_coverage_plan(graph)
    analysis = {
        "language": "c",
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": coverage.model_dump(mode="json"),
    }
    routing = build_routing_plan(
        run_id="run-1",
        source_snapshot=HASH_A,
        selected_files=list(coverage.selected_files),
        enabled_hunters=[
            "c-bounds-integers",
            "c-memory-lifetime",
            "c-parser-state",
        ],
        analysis=analysis,
    )

    work = build_slice_work_items(routing, analysis)
    replay = build_slice_work_items(routing, analysis)

    assert work == replay
    assert routing.scheduled_sessions == 4
    assert len(work) == 2
    assert {item.hunter for item in work} == {
        "c-bounds-integers",
        "c-parser-state",
    }
    assert all(1 <= len(item.files) <= 8 for item in work)
    assert all(item.seed_file == "state.c" for item in work)
    parser_work = next(
        item for item in work if item.hunter == "c-parser-state"
    )
    assert parser_work.files == (
        "state.c",
        "cue_parser.y",
        "cue_scanner.l",
    )
    context = context_for_work_item(analysis, parser_work)
    assert context["work_id"] == parser_work.work_id
    assert context["context_files"] == list(parser_work.files)
    assert {
        step["file"]
        for item in context["slices"]
        for step in item["path"]
    } == set(parser_work.files)


def test_shared_context_cache_reuses_cross_hunter_packet_and_snapshot_keys(
    tmp_path: Path,
) -> None:
    repo, files = _native_router_fixture(tmp_path)
    (repo / "Makefile").write_text("all:\n\t$(CC) -c state.c\n")
    graph = build_c_analysis_graph(repo, files)
    coverage = build_coverage_plan(graph)
    analysis = {
        "language": "c",
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": coverage.model_dump(mode="json"),
    }
    routing = build_routing_plan(
        run_id="run-1",
        source_snapshot=HASH_A,
        selected_files=list(coverage.selected_files),
        enabled_hunters=[
            "c-bounds-integers",
            "c-parser-state",
        ],
        analysis=analysis,
    )
    work = build_slice_work_items(routing, analysis)
    assert len(work) == 2
    cache_root = tmp_path / "cache"
    cache = SharedContextCache(
        cache_root,
        repo,
        source_snapshot=HASH_A,
        analysis=analysis,
    )

    first = cache.get(work[0])
    second = cache.get(work[1])

    assert first == second
    stats = cache.stats()
    assert stats["policy_version"] == "c-shared-context-v1"
    assert stats["entries"] == 1
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert int(stats["bytes"]) > 0
    assert "work_id" not in first
    assert first["source_snapshot"] == HASH_A
    excerpt_kinds = {
        item["path"]: item["kind"]
        for item in first["source_excerpts"]
    }
    assert excerpt_kinds["state.c"] == "slice"
    assert excerpt_kinds["cue_parser.y"] == "parser"
    assert excerpt_kinds["cue_scanner.l"] == "parser"
    assert excerpt_kinds["state.h"] == "header"
    assert excerpt_kinds["Makefile"] == "build"
    state_excerpt = next(
        item for item in first["source_excerpts"] if item["path"] == "state.c"
    )
    assert "track->values[index]" in state_excerpt["content"]
    assert len(list(cache_root.glob("context_*.json"))) == 1

    cache_path = next(cache_root.glob("context_*.json"))
    tampered = json.loads(cache_path.read_text())
    tampered["source_excerpts"][0]["content"] = "tampered"
    cache_path.write_text(json.dumps(tampered))
    repairing_cache = SharedContextCache(
        cache_root,
        repo,
        source_snapshot=HASH_A,
        analysis=analysis,
    )
    repaired = repairing_cache.get(work[0])
    assert repairing_cache.stats()["misses"] == 1
    assert repaired["source_excerpts"][0]["content"] != "tampered"

    new_snapshot_key = context_cache_key(
        source_snapshot=HASH_B,
        analysis=analysis,
        work_item=work[0],
    )
    assert new_snapshot_key != first["cache_key"]
    new_snapshot = SharedContextCache(
        cache_root,
        repo,
        source_snapshot=HASH_B,
        analysis=analysis,
    ).get(work[0])
    assert new_snapshot["source_snapshot"] == HASH_B
    assert new_snapshot["cache_key"] == new_snapshot_key
    assert len(list(cache_root.glob("context_*.json"))) == 2


def test_slice_work_splits_instead_of_omitting_ninth_routed_file() -> None:
    files = tuple(f"src/f{index}.c" for index in range(9))
    coverage = CoveragePlan(
        slices=(AnalysisSlice(
            slice_id="slice-wide",
            entrypoint_id="node-0",
            node_ids=("node-0",),
            files=files,
            risk=4,
            rationale="wide context",
        ),),
        selected_files=files,
    )
    routed = tuple(
        HunterWorkItem(
            work_id=work_id_for(
                source_snapshot=HASH_A,
                planning_policy="router-test",
                slice_ids=("slice-wide",),
                files=(path,),
                hunter="c-bounds-integers",
            ),
            run_id="run-1",
            source_snapshot=HASH_A,
            planning_policy="router-test",
            slice_ids=("slice-wide",),
            seed_file=path,
            files=(path,),
            hunter="c-bounds-integers",
            risk=4,
            required=True,
            routing_reasons=("test:wide",),
        )
        for path in files
    )
    plan = HunterRoutingPlan(
        policy_version="router-test",
        legacy_sessions=27,
        work_items=routed,
    )

    work = build_slice_work_items(
        plan,
        {"coverage_plan": coverage.model_dump(mode="json")},
    )

    assert len(work) == 2
    assert all(len(item.files) <= 8 for item in work)
    assert {
        path for item in work for path in item.files
    } == set(files)


def test_durable_slice_queue_uses_sqlite_lease_and_resumes_local_artifacts(
    tmp_path: Path,
) -> None:
    database = tmp_path / "state.db"
    with SqliteRepository(database) as repository:
        repository.save_run(RunRecord(run_id="run-1"))
    item = build_shadow_plan(
        run_id="run-1",
        source_snapshot=HASH_A,
        selected_files=["state.c"],
        hunters=["c-bounds-integers"],
        analysis={},
    )[0]
    qstore = DurableHuntQueueStore(
        tmp_path / "hunters",
        database,
        "run-1",
    )
    task = qstore.init_from_work_items((item,)).tasks[0]

    assert not (tmp_path / "hunters" / "_queue.json").exists()
    assert qstore.task_dir(task).name == item.work_id
    old = datetime(2000, 1, 1, tzinfo=UTC)
    with SqliteRepository(database) as repository:
        first = repository.acquire_task_lease(
            "run-1",
            "hunter",
            item.work_id,
            worker_id="dead-worker",
            lease_seconds=1,
            now=old,
        )
        assert first is not None
    qstore.mark_file_running(task)
    qstore.mark_hunt_done(task, item.hunter, findings_count=1)

    resumed_task = qstore.load().tasks[0]
    assert resumed_task.hunters[0].status == "done"
    second = qstore.acquire(
        resumed_task,
        worker_id="replacement-worker",
        lease_seconds=60,
        max_attempts=3,
    )
    assert second is not None
    assert second.attempt == 2
    qstore.finish(second, status="done")

    completed = qstore.load().tasks[0]
    assert completed.status == "done"
    with SqliteRepository(database, read_only=True) as repository:
        visible = repository.list_tasks("run-1")[0]
    assert visible["attempt"] == 2
    assert "lease_token" not in visible


async def test_hunt_pipeline_executes_slice_queue_without_legacy_json(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo, _ = _native_router_fixture(tmp_path)
    store = RunStore(tmp_path / "run-slice")
    store.save_config({
        "repo_path": str(repo),
        "environment": "c:gcc-13",
        "model_id": "gpt-5.6-sol",
        "max_hunters_parallel": 2,
        "hunter_max_iterations": 3,
        "hunter_lease_seconds": 30,
    })
    bus = EventBus(store.dir / "events.jsonl")
    await run_source_snapshot(store, bus)
    await run_filter(store, bus)
    await run_analysis_graph(store, bus)
    await run_file_selector(store, bus)
    store.save_step("sandbox_prepare", {"status": "failed"})
    monkeypatch.setattr(
        hunt_pipeline,
        "LLMClient",
        lambda **kwargs: _FinalJsonClient(),
    )
    monkeypatch.setattr(
        hunt_pipeline,
        "base_image_for",
        lambda environment: "unused:latest",
    )

    await hunt_pipeline.run_hunt(store, bus)

    plan = store.load_step("hunt_plan")
    summary = store.load_step("hunt")
    assert plan is not None
    assert summary is not None
    assert plan["mode"] == "slice"
    assert plan["scheduled_sessions"] == 2
    assert plan["context_cache"]["entries"] == 1
    assert plan["context_cache"]["misses"] == 1
    assert plan["context_cache"]["hits"] == 1
    assert len(set(plan["context_cache_keys"].values())) == 1
    assert summary["done"] == 2
    assert summary["failed"] == 0
    assert summary["context_cache"] == plan["context_cache"]
    assert not (store.dir / "hunters" / "_queue.json").exists()
    assert len(list((store.dir / "cache" / "context").glob("*.json"))) == 1
    with SqliteRepository(store.dir / "state.db", read_only=True) as repository:
        tasks = [
            task for task in repository.list_tasks(store.dir.name)
            if task["task_type"] == "hunter"
        ]
    assert len(tasks) == 2
    assert {task["status"] for task in tasks} == {"done"}
    assert all(task["attempt"] == 1 for task in tasks)


async def test_hunt_pipeline_reports_work_deferred_by_session_budget(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo, _ = _native_router_fixture(tmp_path)
    store = RunStore(tmp_path / "run-budget")
    store.save_config({
        "repo_path": str(repo),
        "environment": "c:gcc-13",
        "model_id": "gpt-5.6-sol",
        "max_hunters_parallel": 2,
        "hunter_max_iterations": 100,
        "hunter_lease_seconds": 30,
        "budget_max_hunter_sessions": 1,
        "budget_max_input_tokens": 100_000,
        "budget_max_output_tokens": 10_000,
        "budget_max_wall_clock_minutes": 1,
        "budget_max_retries_per_work_item": 0,
    })
    bus = EventBus(store.dir / "events.jsonl")
    await run_source_snapshot(store, bus)
    await run_filter(store, bus)
    await run_analysis_graph(store, bus)
    await run_file_selector(store, bus)
    store.save_step("sandbox_prepare", {"status": "failed"})
    monkeypatch.setattr(
        hunt_pipeline,
        "LLMClient",
        lambda **kwargs: _FinalJsonClient(),
    )
    monkeypatch.setattr(
        hunt_pipeline,
        "base_image_for",
        lambda environment: "unused:latest",
    )

    await hunt_pipeline.run_hunt(store, bus)

    plan = store.load_step("hunt_plan")
    summary = store.load_step("hunt")
    assert plan is not None
    assert summary is not None
    assert plan["budget_allocation"]["admitted_sessions"] == 1
    assert plan["budget_allocation"]["deferred_sessions"] == 1
    assert summary["done"] == 1
    assert summary["failed"] == 0
    assert summary["budget_deferred"] == 1
    assert len(summary["unanalysed_work_ids"]) == 1
    with SqliteRepository(store.dir / "state.db", read_only=True) as repository:
        deferred_rows = [
            task
            for task in repository.list_tasks(store.dir.name)
            if task["task_type"] == "hunter"
        ]
    assert {task["status"] for task in deferred_rows} == {
        "done",
        "budget_deferred",
    }
    deferred = next(
        task for task in deferred_rows if task["status"] == "budget_deferred"
    )
    assert deferred["last_error"] == "max_hunter_sessions"


async def test_incremental_scan_with_no_impacted_work_skips_model_client(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo, _ = _native_router_fixture(tmp_path)
    store = RunStore(tmp_path / "run-empty-incremental")
    store.save_config({
        "repo_path": str(repo),
        "environment": "c:gcc-13",
        "model_id": "must-not-be-created",
    })
    bus = EventBus(store.dir / "events.jsonl")
    await run_source_snapshot(store, bus)
    await run_filter(store, bus)
    await run_analysis_graph(store, bus)
    analysis = store.load_step("analysis_graph")
    assert analysis is not None
    analysis["incremental_scope"] = {
        "mode": "incremental",
        "base_ref": "main",
        "head_ref": "HEAD",
        "changed_files": [],
        "selected_files": [],
        "critical_sink_ids": [],
    }
    store.save_step("analysis_graph", analysis)
    store.save_step("file_selector", {"selected": []})
    store.save_step("sandbox_prepare", {"status": "failed"})

    def fail_if_created(**kwargs):
        raise AssertionError(f"model client was initialized: {kwargs}")

    monkeypatch.setattr(hunt_pipeline, "LLMClient", fail_if_created)
    monkeypatch.setattr(
        hunt_pipeline,
        "base_image_for",
        lambda environment: "unused:latest",
    )

    await hunt_pipeline.run_hunt(store, bus)

    plan = store.load_step("hunt_plan")
    summary = store.load_step("hunt")
    assert plan is not None
    assert summary is not None
    assert plan["scan_mode"] == "incremental"
    assert plan["scheduled_sessions"] == 0
    assert summary["total"] == 0
    assert summary["done"] == 0
