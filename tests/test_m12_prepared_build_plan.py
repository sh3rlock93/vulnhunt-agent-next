from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from vulnhunt_agent.core.events import EventBus
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.pipeline import sandbox_prepare
from vulnhunt_agent.pipeline.sandbox_prepare import run_prepare
from vulnhunt_agent.pipeline.source_snapshot import run_source_snapshot
from vulnhunt_agent.sandbox.base import ExecResult
from vulnhunt_agent.sandbox.prepared_build import (
    CBuildSystem,
    PREPARED_BUILD_PLAN_POLICY,
    PreparedBuildUnsupportedReason,
    create_c_prepared_build_plan,
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
    assert payload["compiler"] == {
        "executable": "cc",
        "flags": [
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fsanitize=address,undefined",
        ],
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
    assert payload["commands"] == {"support": [], "install": [], "verify": []}
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

        async def exec(self, command: str, timeout: int) -> ExecResult:
            self.commands.append(command)
            return ExecResult(exit_code=0, stdout="ok", stderr="")

        async def commit(self, image: str) -> None:
            self.committed_image = image

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
    assert str(repo) not in json.dumps(plan, sort_keys=True)
