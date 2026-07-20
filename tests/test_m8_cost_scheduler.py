from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests.factories import HASH_A
from vulnhunt_agent.agents.tools import HunterTools
from vulnhunt_agent.agents.queue import HuntQueueStore
from vulnhunt_agent.core.events import EventBus
from vulnhunt_agent.core.llm import LLMResponse
from vulnhunt_agent.domain.schemas import (
    BudgetPolicy,
    BudgetUsage,
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
from vulnhunt_agent.pipeline.hunt.hunters import run_hunters
from vulnhunt_agent.scheduling import (
    build_routing_plan,
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

    findings, usage = await run_hunters(
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
    assert len(usage) == 1
    assert usage[0].sessions == 1
    assert usage[0].calls == usage[0].iterations == 1
    assert usage[0].input_tokens == 30
    assert usage[0].cache_read_tokens == 10
    assert usage[0].estimated_cost_usd is None


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
