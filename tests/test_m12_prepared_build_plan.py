from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from vulnhunt_agent.core.events import EventBus
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.core.v2_run import v2_repository
from vulnhunt_agent.domain.states import RunState
from vulnhunt_agent.pipeline import sandbox_prepare
from vulnhunt_agent.pipeline.sandbox_prepare import run_prepare
from vulnhunt_agent.pipeline.source_snapshot import run_source_snapshot
from vulnhunt_agent.sandbox.base import ExecResult
from vulnhunt_agent.sandbox.prepared_build import (
    CBuildSystem,
    PREPARED_BUILD_PLAN_POLICY,
    PREPARED_BUILD_RECEIPT_POLICY,
    PreparedArtifact,
    PreparedBuildFailureCode,
    PreparedBuildReceipt,
    PreparedBuildUnsupportedReason,
    PreparedBuildVerificationError,
    PreparedCommandResult,
    create_c_prepared_build_plan,
    parse_artifact_inventory,
    select_c_build,
)

SNAPSHOT = "sha256:" + "1" * 64
BASE_IMAGE = "gcc:13-bookworm"


@pytest.mark.parametrize(
    ("marker", "system", "descriptor", "command", "artifact_root"),
    [
        (
            "CMakeLists.txt",
            CBuildSystem.CMAKE,
            "CMakeLists.txt",
            "cmake -S /code -B /opt/vulnhunt/build",
            "/opt/vulnhunt/build",
        ),
        (
            "meson.build",
            CBuildSystem.MESON,
            "meson.build",
            "meson setup /opt/vulnhunt/build /code",
            "/opt/vulnhunt/build",
        ),
        (
            "configure.ac",
            CBuildSystem.AUTOTOOLS,
            "configure.ac",
            "/code/configure --disable-shared --enable-static",
            "/opt/vulnhunt/build",
        ),
        (
            "Makefile",
            CBuildSystem.MAKE,
            "Makefile",
            "make -C /code -j2",
            "/code",
        ),
    ],
)
def test_native_layout_becomes_closed_serializable_plan(
    tmp_path: Path,
    marker: str,
    system: CBuildSystem,
    descriptor: str,
    command: str,
    artifact_root: str,
) -> None:
    (tmp_path / marker).write_text("", encoding="utf-8")

    plan = create_c_prepared_build_plan(
        tmp_path,
        source_snapshot_sha256=SNAPSHOT,
        base_image=BASE_IMAGE,
    )
    payload = json.loads(plan.canonical_bytes())

    assert payload["schema_version"] == 1
    assert payload["policy_version"] == PREPARED_BUILD_PLAN_POLICY
    assert payload["supported"] is True
    assert payload["build_system"] == system.value
    assert payload["descriptor"] == descriptor
    assert command in "\n".join(payload["commands"]["install"])
    assert payload["expected_artifact_roots"] == [artifact_root]
    expected_flags = [
        "-O1",
        "-g",
        "-fno-omit-frame-pointer",
        "-fsanitize=address,undefined",
    ]
    if system is CBuildSystem.CMAKE:
        expected_flags.append("-Wno-error=format-overflow")
    assert payload["compiler"] == {
        "executable": "cc",
        "flags": expected_flags,
        "sanitizers": ["address", "undefined"],
    }
    assert payload["unsupported_reason"] == "none"
    assert str(tmp_path) not in plan.canonical_bytes().decode("utf-8")
    assert re.fullmatch(r"scanner/prepared:c-[0-9a-f]{24}", plan.image_tag)


def test_plan_and_image_identity_do_not_depend_on_absolute_host_path(tmp_path: Path) -> None:
    first = tmp_path / "first" / "project"
    second = tmp_path / "unrelated" / "project"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    (first / "CMakeLists.txt").write_text("", encoding="utf-8")
    (second / "CMakeLists.txt").write_text("", encoding="utf-8")

    first_plan = create_c_prepared_build_plan(
        first,
        source_snapshot_sha256=SNAPSHOT,
        base_image=BASE_IMAGE,
    )
    second_plan = create_c_prepared_build_plan(
        second,
        source_snapshot_sha256=SNAPSHOT,
        base_image=BASE_IMAGE,
    )

    assert first_plan.canonical_bytes() == second_plan.canonical_bytes()
    assert first_plan.plan_sha256 == second_plan.plan_sha256
    assert first_plan.image_tag == second_plan.image_tag


def test_source_snapshot_or_toolchain_change_changes_image_identity(tmp_path: Path) -> None:
    (tmp_path / "meson.build").write_text("", encoding="utf-8")
    baseline = create_c_prepared_build_plan(
        tmp_path,
        source_snapshot_sha256=SNAPSHOT,
        base_image=BASE_IMAGE,
    )
    source_changed = create_c_prepared_build_plan(
        tmp_path,
        source_snapshot_sha256="sha256:" + "2" * 64,
        base_image=BASE_IMAGE,
    )
    toolchain_changed = create_c_prepared_build_plan(
        tmp_path,
        source_snapshot_sha256=SNAPSHOT,
        base_image="gcc:14-bookworm",
    )

    assert len({baseline.image_tag, source_changed.image_tag, toolchain_changed.image_tag}) == 3


def test_layout_precedence_is_unchanged_and_source_relative(tmp_path: Path) -> None:
    for marker in ("Makefile", "configure", "meson.build", "CMakeLists.txt"):
        (tmp_path / marker).write_text("", encoding="utf-8")

    selection = select_c_build(tmp_path)

    assert selection.build_system is CBuildSystem.CMAKE
    assert selection.descriptor == "CMakeLists.txt"


def test_unknown_layout_has_typed_unsupported_plan(tmp_path: Path) -> None:
    plan = create_c_prepared_build_plan(
        tmp_path,
        source_snapshot_sha256=SNAPSHOT,
        base_image=BASE_IMAGE,
    )
    payload = plan.to_dict()

    assert plan.supported is False
    assert plan.build_system is CBuildSystem.UNSUPPORTED
    assert plan.unsupported_reason is PreparedBuildUnsupportedReason.MISSING_BUILD_DESCRIPTOR
    assert payload["commands"] == {
        "support": [],
        "install": [],
        "test": [],
        "verify": [],
    }
    assert payload["expected_artifact_roots"] == []


def test_build_descriptor_must_be_a_regular_file(tmp_path: Path) -> None:
    (tmp_path / "CMakeLists.txt").mkdir()

    selection = select_c_build(tmp_path)

    assert selection.supported is False


def test_source_snapshot_identity_must_be_content_addressed(tmp_path: Path) -> None:
    (tmp_path / "Makefile").write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="SHA-256"):
        create_c_prepared_build_plan(
            tmp_path,
            source_snapshot_sha256="local/path/source.tar",
            base_image=BASE_IMAGE,
        )


def test_benchmark_cmake_option_must_be_boolean_and_source_declared(
    tmp_path: Path,
) -> None:
    (tmp_path / "CMakeLists.txt").write_text(
        'option(ENABLE_PROJECT_TESTS "Build tests" ON)\n',
        encoding="utf-8",
    )

    plan = create_c_prepared_build_plan(
        tmp_path,
        source_snapshot_sha256=SNAPSHOT,
        base_image=BASE_IMAGE,
        cmake_options=("ENABLE_PROJECT_TESTS=OFF",),
    )

    assert "-DENABLE_PROJECT_TESTS=OFF" in plan.install_commands[0]
    with pytest.raises(ValueError, match="not declared"):
        create_c_prepared_build_plan(
            tmp_path,
            source_snapshot_sha256=SNAPSHOT,
            base_image=BASE_IMAGE,
            cmake_options=("UNKNOWN_OPTION=OFF",),
        )
    with pytest.raises(ValueError, match="DECLARED_BOOLEAN"):
        create_c_prepared_build_plan(
            tmp_path,
            source_snapshot_sha256=SNAPSHOT,
            base_image=BASE_IMAGE,
            cmake_options=("ENABLE_PROJECT_TESTS=../../escape",),
        )
    with pytest.raises(ValueError, match="names must be unique"):
        create_c_prepared_build_plan(
            tmp_path,
            source_snapshot_sha256=SNAPSHOT,
            base_image=BASE_IMAGE,
            cmake_options=("ENABLE_PROJECT_TESTS=ON", "ENABLE_PROJECT_TESTS=OFF"),
        )


def test_benchmark_autotools_option_must_be_boolean_and_source_declared(
    tmp_path: Path,
) -> None:
    (tmp_path / "configure.ac").write_text(
        "AC_ARG_ENABLE([test], [AS_HELP_STRING([--disable-test], [skip tests])])\n",
        encoding="utf-8",
    )

    plan = create_c_prepared_build_plan(
        tmp_path,
        source_snapshot_sha256=SNAPSHOT,
        base_image=BASE_IMAGE,
        configure_options=("test=OFF",),
    )

    assert plan.build_system is CBuildSystem.AUTOTOOLS
    assert plan.install_commands[0].endswith("--disable-test")
    with pytest.raises(ValueError, match="not declared"):
        create_c_prepared_build_plan(
            tmp_path,
            source_snapshot_sha256=SNAPSHOT,
            base_image=BASE_IMAGE,
            configure_options=("examples=OFF",),
        )
    with pytest.raises(ValueError, match=r"declared-option=ON\|OFF"):
        create_c_prepared_build_plan(
            tmp_path,
            source_snapshot_sha256=SNAPSHOT,
            base_image=BASE_IMAGE,
            configure_options=("test=../../escape",),
        )
    with pytest.raises(ValueError, match="names must be unique"):
        create_c_prepared_build_plan(
            tmp_path,
            source_snapshot_sha256=SNAPSHOT,
            base_image=BASE_IMAGE,
            configure_options=("test=ON", "test=OFF"),
        )


def test_legacy_autotools_without_vpath_builds_from_an_isolated_source_copy(
    tmp_path: Path,
) -> None:
    (tmp_path / "configure").write_text("#!/bin/sh\n", encoding="utf-8")
    (tmp_path / "Makefile.in").write_text(
        "library.o: library.c\n\t$(CC) -c library.c\n",
        encoding="utf-8",
    )

    plan = create_c_prepared_build_plan(
        tmp_path,
        source_snapshot_sha256=SNAPSHOT,
        base_image=BASE_IMAGE,
    )

    bootstrap = plan.install_commands[0]
    assert "tar -C /code" in bootstrap
    assert "--exclude=.git --exclude=.hg --exclude=.svn" in bootstrap
    assert "| tar -C /opt/vulnhunt/build -xf -" in bootstrap
    assert "CFLAGS=" in bootstrap
    assert "LDFLAGS=" in bootstrap
    assert "./configure --disable-shared --enable-static" in bootstrap
    assert "cd /code && autoreconf" not in bootstrap
    assert plan.install_commands[1].startswith("ASAN_OPTIONS=detect_leaks=0 make ")


@pytest.mark.parametrize(
    "makefile",
    [
        "VPATH = @srcdir@\nlibrary.o: library.c\n",
        "srcdir = @srcdir@\nlibrary.o: $(srcdir)/library.c\n",
    ],
)
def test_vpath_capable_autotools_keeps_out_of_tree_build(
    tmp_path: Path,
    makefile: str,
) -> None:
    (tmp_path / "configure").write_text("#!/bin/sh\n", encoding="utf-8")
    (tmp_path / "Makefile.in").write_text(makefile, encoding="utf-8")

    plan = create_c_prepared_build_plan(
        tmp_path,
        source_snapshot_sha256=SNAPSHOT,
        base_image=BASE_IMAGE,
    )

    bootstrap = plan.install_commands[0]
    assert "tar -C /code" not in bootstrap
    assert "/code/configure --disable-shared --enable-static" in bootstrap


def test_build_options_cannot_cross_build_systems(tmp_path: Path) -> None:
    (tmp_path / "CMakeLists.txt").write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="Autotools options require"):
        create_c_prepared_build_plan(
            tmp_path,
            source_snapshot_sha256=SNAPSHOT,
            base_image=BASE_IMAGE,
            configure_options=("test=OFF",),
        )


async def test_prepare_step_persists_plan_and_uses_content_addressed_image(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "source"
    repo.mkdir()
    (repo / "CMakeLists.txt").write_text("", encoding="utf-8")
    store = RunStore(tmp_path / "run")
    store.save_config({"repo_path": str(repo), "environment": "c:gcc-13"})
    bus = EventBus(store.dir / "events.jsonl")
    await run_source_snapshot(store, bus)
    executors: list[FakeExecutor] = []

    class FakeExecutor:
        def __init__(self, **kwargs: object) -> None:
            self.name = "m12-plan-test"
            self.commands: list[str] = []
            self.committed_image = ""
            executors.append(self)

        async def start(self) -> None:
            return None

        async def image_digest(self, image: str | None = None) -> str:
            return "sha256:" + ("b" if image is None else "f") * 64

        async def disconnect_network(self) -> None:
            return None

        async def exec(self, command: str, timeout: int) -> ExecResult:
            self.commands.append(command)
            if command.startswith("cat -- /opt/vulnhunt/apt-packages.lock"):
                return ExecResult(exit_code=0, stdout="cmake=3.25.1-1\n", stderr="")
            if command == "cc --version":
                return ExecResult(exit_code=0, stdout="cc 13.2.0\n", stderr="")
            if command.startswith("set -eu; count=0; find"):
                return ExecResult(
                    exit_code=0,
                    stdout=(
                        "/opt/vulnhunt/build/target.o\t123\t"
                        + "1" * 64
                        + "\taddress,undefined\n"
                    ),
                    stderr="",
                )
            return ExecResult(exit_code=0, stdout="ok", stderr="")

        async def commit(self, image: str) -> str:
            self.committed_image = image
            return "sha256:" + "f" * 64

        async def stop(self) -> None:
            return None

    monkeypatch.setattr(sandbox_prepare, "ContainerExecutor", FakeExecutor)
    monkeypatch.setattr(sandbox_prepare, "base_image_for", lambda environment: BASE_IMAGE)

    await run_prepare(store, bus)

    plan = store.load_step("prepared_build_plan")
    result = store.load_step("sandbox_prepare")
    snapshot = store.load_step("source_snapshot")
    assert isinstance(plan, dict)
    assert isinstance(result, dict)
    assert isinstance(snapshot, dict)
    assert plan["policy_version"] == PREPARED_BUILD_PLAN_POLICY
    assert plan["source_snapshot_sha256"] == snapshot["snapshot_artifact"]
    assert plan["image_tag"] == executors[0].committed_image == result["image"]
    assert result["build_plan_sha256"] == plan["plan_sha256"]
    receipt = store.load_step("prepared_build_receipt")
    assert isinstance(receipt, dict)
    assert receipt["policy_version"] == PREPARED_BUILD_RECEIPT_POLICY
    assert receipt["receipt_sha256"] == result["build_receipt_sha256"]
    assert receipt["network"]["isolated_before"][0] == "build"
    assert receipt["sanitizer_provenance"]["observed"] == ["address", "undefined"]
    assert str(repo) not in json.dumps(plan, sort_keys=True)


def test_receipt_equivalence_excludes_only_declared_runtime_metadata() -> None:
    artifact = PreparedArtifact(
        path="/opt/vulnhunt/build/target.o",
        size_bytes=123,
        sha256="sha256:" + "3" * 64,
        sanitizer_markers=("address", "undefined"),
    )
    first_command = PreparedCommandResult(
        phase="build",
        command="cmake --build /opt/vulnhunt/build",
        exit_code=0,
        timed_out=False,
        duration_ms=10,
        stdout_sha256="sha256:" + "4" * 64,
        stderr_sha256="sha256:" + "5" * 64,
    )
    second_command = PreparedCommandResult(
        phase=first_command.phase,
        command=first_command.command,
        exit_code=0,
        timed_out=False,
        duration_ms=999,
        stdout_sha256="sha256:" + "6" * 64,
        stderr_sha256="sha256:" + "7" * 64,
    )
    common: dict[str, Any] = {
        "source_snapshot_sha256": SNAPSHOT,
        "plan_sha256": "sha256:" + "2" * 64,
        "build_system": CBuildSystem.CMAKE,
        "base_image": BASE_IMAGE,
        "base_image_digest": "sha256:" + "8" * 64,
        "final_image": "scanner/prepared:c-example",
        "package_lock_entries": ("cmake=3.25.1-1",),
        "package_lock_sha256": "sha256:" + "9" * 64,
        "compiler_version": "cc 13.2.0",
        "test_results": (),
        "artifacts": (artifact,),
    }
    first = PreparedBuildReceipt(
        **common,
        final_image_digest="sha256:" + "a" * 64,
        command_results=(first_command,),
    )
    second = PreparedBuildReceipt(
        **common,
        final_image_digest="sha256:" + "b" * 64,
        command_results=(second_command,),
    )

    assert first.receipt_sha256 != second.receipt_sha256
    assert first.equivalence_sha256 == second.equivalence_sha256
    assert first.to_dict()["equivalence_exclusions"] == [
        "images.final.digest",
        "commands[*].duration_ms",
        "commands[*].stdout_sha256",
        "commands[*].stderr_sha256",
        "tests[*].duration_ms",
        "tests[*].stdout_sha256",
        "tests[*].stderr_sha256",
    ]


def test_artifact_inventory_requires_sanitizer_provenance() -> None:
    output = "/opt/vulnhunt/build/target.o\t12\t" + "1" * 64 + "\t\n"

    with pytest.raises(PreparedBuildVerificationError) as raised:
        parse_artifact_inventory(output)

    assert raised.value.code is PreparedBuildFailureCode.SANITIZER_PROVENANCE_MISSING


@pytest.mark.parametrize(
    ("failure_at", "expected_code"),
    [
        ("test", PreparedBuildFailureCode.TEST_COMMAND_FAILED),
        ("artifact_root", PreparedBuildFailureCode.ARTIFACT_ROOT_MISSING),
    ],
)
async def test_failed_test_or_missing_artifact_never_admits_hunter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_at: str,
    expected_code: PreparedBuildFailureCode,
) -> None:
    repo = tmp_path / "source"
    repo.mkdir()
    (repo / "CMakeLists.txt").write_text("", encoding="utf-8")
    store = RunStore(tmp_path / "run")
    store.save_config({"repo_path": str(repo), "environment": "c:gcc-13"})
    bus = EventBus(store.dir / "events.jsonl")
    await run_source_snapshot(store, bus)
    events: list[str] = []

    class FailingExecutor:
        name = "m12-failure-test"

        def __init__(self, **kwargs: object) -> None:
            return None

        async def image_digest(self, image: str | None = None) -> str:
            return "sha256:" + "b" * 64

        async def start(self) -> None:
            events.append("start")

        async def disconnect_network(self) -> None:
            events.append("disconnect")

        async def exec(self, command: str, timeout: int) -> ExecResult:
            if command.startswith("cat --"):
                return ExecResult(0, "cmake=3.25.1-1\n", "")
            if "ctest --test-dir" in command and failure_at == "test":
                events.append("test")
                return ExecResult(1, "", "test failed")
            if command.startswith("test -d ") and failure_at == "artifact_root":
                events.append("artifact_root")
                return ExecResult(1, "", "missing")
            if command.startswith("cmake -S"):
                events.append("build")
            if command == "cc --version":
                return ExecResult(0, "cc 13.2.0\n", "")
            return ExecResult(0, "ok", "")

        async def commit(self, image: str) -> str:
            events.append("commit")
            return "sha256:" + "f" * 64

        async def stop(self) -> None:
            events.append("stop")

    monkeypatch.setattr(sandbox_prepare, "ContainerExecutor", FailingExecutor)
    monkeypatch.setattr(sandbox_prepare, "base_image_for", lambda environment: BASE_IMAGE)

    with pytest.raises(PreparedBuildVerificationError) as raised:
        await run_prepare(store, bus)

    assert raised.value.code is expected_code
    assert events.index("disconnect") < events.index("build")
    assert "commit" not in events
    result = store.load_step("sandbox_prepare")
    assert isinstance(result, dict)
    assert result["status"] == "failed"
    assert result["error_code"] == expected_code.value
    assert not store.has_step("prepared_build_receipt")
    with v2_repository(store) as repository:
        run = repository.get_run(store.dir.name)
    assert run is not None
    assert run.state is RunState.BUILDING
