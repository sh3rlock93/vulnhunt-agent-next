from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.m12.prepared_build import (
    VERIFIED_PREPARED_RUN_POLICY,
    load_verified_prepared_run,
    resolve_reproduction_image,
)
from benchmarks.run_cjson_cursor_benchmark import build_parser as cjson_parser
from benchmarks.run_libcue_specialist_benchmark import build_parser as libcue_parser
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.sandbox.prepared_build import (
    CBuildSystem,
    PreparedArtifact,
    PreparedBuildPlan,
    PreparedBuildReceipt,
    PreparedBuildUnsupportedReason,
    PreparedCommandResult,
)

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = "sha256:" + "1" * 64
BASE_DIGEST = "sha256:" + "2" * 64
FINAL_DIGEST = "sha256:" + "3" * 64


def test_verified_prepare_run_links_plan_receipt_snapshot_and_image(tmp_path: Path) -> None:
    run_dir = _write_verified_run(tmp_path / "run")

    summary = load_verified_prepared_run(run_dir)

    assert summary["policy_version"] == VERIFIED_PREPARED_RUN_POLICY
    assert summary["status"] == "verified"
    assert summary["build_system"] == "cmake"
    assert summary["image_digest"] == FINAL_DIGEST
    assert summary["artifact_count"] == 1
    assert summary["sanitizer_artifact_count"] == 1


def test_tampered_receipt_cannot_resolve_a_reproduction_image(tmp_path: Path) -> None:
    run_dir = _write_verified_run(tmp_path / "run")
    store = RunStore(run_dir)
    receipt = store.load_step("prepared_build_receipt")
    assert isinstance(receipt, dict)
    receipt["commands"][0]["exit_code"] = 1
    store.save_step("prepared_build_receipt", receipt)

    with pytest.raises(ValueError, match="receipt hash mismatch"):
        resolve_reproduction_image(
            image="",
            prepared_run=run_dir,
            label="vulnerable",
        )


@pytest.mark.parametrize(
    ("image", "prepared"),
    [("", None), ("scanner/prepared:legacy", Path("run"))],
)
def test_reproduction_image_source_must_be_unambiguous(
    image: str,
    prepared: Path | None,
) -> None:
    with pytest.raises(ValueError, match="exactly one"):
        resolve_reproduction_image(
            image=image,
            prepared_run=prepared,
            label="fixed",
        )


def test_cjson_and_libcue_evaluators_accept_verified_prepare_runs() -> None:
    common = [
        "evaluate",
        "--frozen", "frozen",
        "--oracle", "oracle.toml",
        "--scan-manifest", "scan.toml",
        "--vulnerable-repo", "vulnerable",
        "--fixed-repo", "fixed",
        "--output", "evaluation",
        "--run-reproduction",
        "--vulnerable-prepare-run", "vulnerable-run",
        "--fixed-prepare-run", "fixed-run",
    ]

    for parser in (cjson_parser(), libcue_parser()):
        args = parser.parse_args(common)
        assert args.vulnerable_prepare_run == Path("vulnerable-run")
        assert args.fixed_prepare_run == Path("fixed-run")
        assert args.vulnerable_image == ""
        assert args.fixed_image == ""


def test_ci_uses_verified_path_for_all_m12_1_layout_proofs() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert "docker create --name cjson" not in workflow
    assert "docker cp .benchmark/cjson" not in workflow
    assert "docker commit cjson" not in workflow
    assert "m12.prepared_build prepare" in workflow
    assert "zlib-vulnerable-prepared" in workflow
    assert "libmodbus-autotools-prepared" in workflow
    assert "AUTOTOOLS_STATUS" in workflow
    assert "libcue-m11-5-vulnerable-prepared" in workflow
    assert "cjson-m11-7-vulnerable-prepared" in workflow
    assert "--cmake-option ENABLE_CJSON_TEST=OFF" in workflow
    assert "--vulnerable-prepare-run" in workflow
    assert "--fixed-prepare-run" in workflow


def _write_verified_run(run_dir: Path) -> Path:
    plan = PreparedBuildPlan(
        source_snapshot_sha256=SNAPSHOT,
        base_image="gcc:13-bookworm",
        build_system=CBuildSystem.CMAKE,
        descriptor="CMakeLists.txt",
        support_commands=("install pinned packages",),
        install_commands=("cmake --build /opt/vulnhunt/build",),
        test_commands=("ctest --test-dir /opt/vulnhunt/build",),
        verify_commands=("cc --version",),
        compiler="cc",
        compiler_flags=("-fsanitize=address,undefined",),
        sanitizers=("address", "undefined"),
        expected_artifact_roots=("/opt/vulnhunt/build",),
        unsupported_reason=PreparedBuildUnsupportedReason.NONE,
    )
    command = PreparedCommandResult(
        phase="build",
        command=plan.install_commands[0],
        exit_code=0,
        timed_out=False,
        duration_ms=10,
        stdout_sha256="sha256:" + "4" * 64,
        stderr_sha256="sha256:" + "5" * 64,
    )
    test = PreparedCommandResult(
        phase="test",
        command=plan.test_commands[0],
        exit_code=0,
        timed_out=False,
        duration_ms=12,
        stdout_sha256="sha256:" + "6" * 64,
        stderr_sha256="sha256:" + "7" * 64,
    )
    artifact = PreparedArtifact(
        path="/opt/vulnhunt/build/target.o",
        size_bytes=123,
        sha256="sha256:" + "8" * 64,
        sanitizer_markers=("address", "undefined"),
    )
    receipt = PreparedBuildReceipt(
        source_snapshot_sha256=SNAPSHOT,
        plan_sha256=plan.plan_sha256,
        build_system=CBuildSystem.CMAKE,
        base_image=plan.base_image,
        base_image_digest=BASE_DIGEST,
        final_image=plan.image_tag,
        final_image_digest=FINAL_DIGEST,
        package_lock_entries=("cmake=3.25.1-1",),
        package_lock_sha256="sha256:" + "9" * 64,
        compiler_version="cc 13.2.0",
        command_results=(command,),
        test_results=(test,),
        artifacts=(artifact,),
    )
    store = RunStore(run_dir)
    store.save_step("source_snapshot", {"snapshot_artifact": SNAPSHOT})
    store.save_step("prepared_build_plan", plan.to_dict())
    store.save_step("prepared_build_receipt", receipt.to_dict())
    store.save_step("sandbox_prepare", {
        "status": "ready",
        "image": plan.image_tag,
        "image_digest": FINAL_DIGEST,
        "build_plan_sha256": plan.plan_sha256,
        "build_receipt_sha256": receipt.receipt_sha256,
        "build_equivalence_sha256": receipt.equivalence_sha256,
    })
    return run_dir
