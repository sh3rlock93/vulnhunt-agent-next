from __future__ import annotations

from pathlib import Path

import pytest

from vulnhunt_agent.core import codex_client as codex_module
from vulnhunt_agent.core.codex_client import CodexSubscriptionClient
from vulnhunt_agent.core.events import EventBus
from vulnhunt_agent.core.provider_preflight import preflight_model_client
from vulnhunt_agent.core.provider_preflight import diagnostic_fingerprint
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.core.settings import ProviderSpec
from vulnhunt_agent.domain.schemas import (
    ProviderPreflightCheck,
    ProviderPreflightCode,
    ProviderPreflightResult,
)
from vulnhunt_agent.domain.states import RunState
from vulnhunt_agent.infrastructure.sqlite_repository import SqliteRepository
from vulnhunt_agent.pipeline import hunt as hunt_pipeline
from vulnhunt_agent.pipeline.analysis_graph import run_analysis_graph
from vulnhunt_agent.pipeline.file_selector import run_file_selector
from vulnhunt_agent.pipeline.filter_files import run_filter
from vulnhunt_agent.pipeline.source_snapshot import run_source_snapshot


def _provider() -> ProviderSpec:
    return ProviderSpec(
        name="codex-test",
        kind="openai_auto",
        codex_command="codex",
    )


def _command_result(
    returncode: int,
    stdout: str = "",
    stderr: str = "",
) -> codex_module._PreflightCommandResult:
    return codex_module._PreflightCommandResult(returncode, stdout, stderr)


async def test_codex_preflight_classifies_read_only_state_before_admission(
    monkeypatch,
) -> None:
    monkeypatch.setattr(codex_module._settings, "resolve", lambda model_id: (None, _provider()))
    monkeypatch.setattr(codex_module.shutil, "which", lambda command: "/opt/bin/codex")

    async def fake_command(args, **kwargs):
        if args[1:] == ("--version",):
            return _command_result(0, "codex-cli 1.2.3\n")
        if args[1:] == ("exec", "--help"):
            return _command_result(0, " ".join(codex_module._REQUIRED_EXEC_OPTIONS))
        if args[1:] == ("login", "status"):
            return _command_result(0, "Logged in using ChatGPT\n")
        return _command_result(
            1,
            stderr=(
                "failed to initialize sqlite state runtime under /Users/alice/.codex: "
                "operation not permitted; bearer sk-secret-value"
            ),
        )

    monkeypatch.setattr(codex_module, "_run_preflight_command", fake_command)
    result = await CodexSubscriptionClient("gpt-test").preflight()

    assert result.ready is False
    assert result.code is ProviderPreflightCode.STATE_STORE_READ_ONLY
    assert result.billable_model_calls == 0
    persisted = result.model_dump_json()
    assert "/Users/alice" not in persisted
    assert "sk-secret-value" not in persisted
    assert result.diagnostic_fingerprint is not None
    assert "CODEX_HOME" in result.remediation


def test_app_server_denial_is_not_mislabelled_as_authentication() -> None:
    code, remediation = codex_module._classify_preflight_failure(
        "app-server permission denied while loading authentication cache"
    )

    assert code is ProviderPreflightCode.APP_SERVER_INIT_DENIED
    assert "app-server" in remediation


@pytest.mark.parametrize(
    "diagnostic, expected",
    [
        (
            "sqlite state database is readonly",
            ProviderPreflightCode.STATE_STORE_READ_ONLY,
        ),
        (
            "app-server permission denied",
            ProviderPreflightCode.APP_SERVER_INIT_DENIED,
        ),
        ("401 unauthorized", ProviderPreflightCode.AUTHENTICATION_REQUIRED),
        ("model gpt-x unavailable", ProviderPreflightCode.MODEL_UNAVAILABLE),
        ("unknown command app-server", ProviderPreflightCode.UNSUPPORTED_CLI_FEATURE),
        ("network connection timed out", ProviderPreflightCode.PROVIDER_TRANSPORT_ERROR),
        ("unexpected local failure", ProviderPreflightCode.PROVIDER_PROTOCOL_ERROR),
    ],
)
def test_codex_preflight_failure_taxonomy(diagnostic: str, expected) -> None:
    code, remediation = codex_module._classify_preflight_failure(diagnostic)

    assert code is expected
    assert remediation


def test_diagnostic_fingerprint_redacts_secret_and_host_path_variants() -> None:
    first = diagnostic_fingerprint(
        "failure under /Users/alice/.codex with bearer sk-first-secret"
    )
    second = diagnostic_fingerprint(
        "failure under /opt/worker/.codex with bearer sk-second-secret"
    )

    assert first == second


async def test_codex_preflight_accepts_structured_local_initialize(
    monkeypatch,
) -> None:
    monkeypatch.setattr(codex_module._settings, "resolve", lambda model_id: (None, _provider()))
    monkeypatch.setattr(codex_module.shutil, "which", lambda command: "/opt/bin/codex")

    async def fake_command(args, **kwargs):
        if args[1:] == ("--version",):
            return _command_result(0, "codex-cli 1.2.3\n")
        if args[1:] == ("exec", "--help"):
            return _command_result(0, " ".join(codex_module._REQUIRED_EXEC_OPTIONS))
        if args[1:] == ("login", "status"):
            return _command_result(0, "Logged in using ChatGPT\n")
        assert kwargs["stdin"].endswith("\n")
        return _command_result(0, '{"id":1,"result":{"serverInfo":{}}}\n')

    monkeypatch.setattr(codex_module, "_run_preflight_command", fake_command)
    result = await CodexSubscriptionClient("gpt-test").preflight()

    assert result.ready is True
    assert result.code is ProviderPreflightCode.READY
    assert result.billable_model_calls == 0
    assert [check.name for check in result.checks] == [
        "cli_version",
        "required_cli_features",
        "login_state",
        "temporary_output",
        "app_server_initialization",
    ]


@pytest.mark.parametrize("transport", ["responses_api", "codex_subscription", "fixture"])
async def test_all_provider_kinds_share_preflight_result_contract(transport: str) -> None:
    class Client:
        model_id = "model-test"

        def __init__(self) -> None:
            self.transport = transport

        async def chat(self, **kwargs):
            raise AssertionError("local preflight must not call the model")

    result = await preflight_model_client(Client())

    assert isinstance(result, ProviderPreflightResult)
    assert result.transport == transport
    assert result.ready is True
    assert result.billable_model_calls == 0


def _native_fixture(tmp_path: Path) -> Path:
    repo = tmp_path / "native"
    repo.mkdir()
    (repo / "scanner.l").write_text(
        "[[:digit:]]+ { yylval.ival = atoi(yytext); return NUMBER; }\n"
    )
    (repo / "parser.y").write_text(
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
    return repo


async def test_failed_preflight_creates_no_hunter_tasks_or_clean_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = _native_fixture(tmp_path)
    store = RunStore(tmp_path / "run-preflight-failed")
    store.save_config({
        "repo_path": str(repo),
        "environment": "c:gcc-13",
        "model_id": "gpt-test",
        "max_hunters_parallel": 2,
        "hunter_max_iterations": 3,
    })
    bus = EventBus(store.dir / "events.jsonl")
    await run_source_snapshot(store, bus)
    await run_filter(store, bus)
    await run_analysis_graph(store, bus)
    await run_file_selector(store, bus)
    store.save_step("sandbox_prepare", {"status": "failed"})

    class FailedClient:
        transport = "codex_subscription"
        model_id = "gpt-test"

        async def preflight(self) -> ProviderPreflightResult:
            return ProviderPreflightResult(
                transport=self.transport,
                model_id=self.model_id,
                ready=False,
                code=ProviderPreflightCode.STATE_STORE_READ_ONLY,
                remediation="Make CODEX_HOME writable.",
                diagnostic_fingerprint="sha256:" + "a" * 64,
                checks=(ProviderPreflightCheck(
                    name="app_server_initialization",
                    status="failed",
                    detail="state_store_read_only",
                ),),
            )

    client = FailedClient()
    monkeypatch.setattr(hunt_pipeline, "LLMClient", lambda **kwargs: client)
    monkeypatch.setattr(
        hunt_pipeline,
        "base_image_for",
        lambda environment: "unused:latest",
    )

    with pytest.raises(RuntimeError, match="before Hunter admission"):
        await hunt_pipeline.run_hunt(store, bus)

    preflight = store.load_step("provider_preflight")
    summary = store.load_step("hunt")
    plan = store.load_step("hunt_plan")
    assert preflight is not None
    assert summary is not None
    assert plan is not None
    assert preflight["run_outcome"] == "invalid_execution"
    assert summary["outcome"] == "invalid_execution"
    assert summary["zero_findings"] is False
    assert summary["total_findings"] is None
    assert summary["usage"]["calls"] == 0
    assert plan["budget_allocation"]["admitted_sessions"] == 0
    with SqliteRepository(store.dir / "state.db", read_only=True) as repository:
        run = repository.get_run(store.dir.name)
        tasks = repository.list_tasks(store.dir.name)
    assert run is not None and run.state is RunState.FAILED
    assert [task for task in tasks if task["task_type"] == "hunter"] == []
