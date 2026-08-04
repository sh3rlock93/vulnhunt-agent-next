from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnhunt_agent.macos.binary_analysis import (
    DecompilerHuntStatus,
    ImageIOPilotResult,
    ImageIOPilotStatus,
    load_decompiler_hunt_manifest,
    run_decompiler_hunt_plan,
)

_DIGESTS = {
    "snapshot_sha256": "sha256:" + "1" * 64,
    "image_sha256": "sha256:" + "2" * 64,
    "export_sha256": "sha256:" + "3" * 64,
    "ir_sha256": "sha256:" + "4" * 64,
}


def _tooling(root: Path) -> tuple[Path, Path, Path]:
    ghidra = root / "analyzeHeadless"
    ghidra.write_text("#!/bin/sh\n")
    ghidra.chmod(0o700)
    scripts = root / "scripts"
    scripts.mkdir()
    (scripts / "ExtractDyldImage.java").write_text("// extraction\n")
    (scripts / "ExportImageIOIR.java").write_text("// export\n")
    java = root / "java"
    java.mkdir()
    return ghidra, scripts, java


def _completed_pilot(**kwargs) -> ImageIOPilotResult:
    output = Path(kwargs["output_directory"])
    output.mkdir(mode=0o700)
    for name in (
        "ImageIO.macho",
        "binary-ranking.json",
        "context-plan.json",
        "imageio-ghidra-export.json",
        "input-provenance.json",
        "normalized-ir.json",
        "parser-discovery.json",
        "range-analysis.json",
        "static-analysis.json",
    ):
        (output / name).write_text(json.dumps({"name": name}) + "\n")
        (output / name).chmod(0o600)
    result = ImageIOPilotResult(
        created_at=datetime(2026, 8, 4, tzinfo=UTC),
        status=ImageIOPilotStatus.COMPLETED,
        shared_cache_uuid="157E6D2E-2E5C-39B1-8F2A-8866EE228BED",
        image_uuid="EEB840D5-3559-386F-BBD3-D24AA749D2EC",
        limitation="Static-only fixture",
        **_DIGESTS,
    )
    (output / "pilot-result.json").write_text(
        json.dumps(result.model_dump(mode="json"), default=str) + "\n"
    )
    (output / "pilot-result.json").chmod(0o600)
    return result


def _run(tmp_path: Path, output: Path, **overrides):
    ghidra, scripts, java = _tooling(tmp_path)
    arguments = {
        "cache_path": tmp_path / "cache",
        "output_directory": output,
        "product_version": "26.5.2",
        "build_version": "25F84",
        "ghidra_headless": ghidra,
        "script_directory": scripts,
        "java_home": java,
        "pilot_runner": _completed_pilot,
    }
    arguments.update(overrides)
    return run_decompiler_hunt_plan(**arguments), (ghidra, scripts, java)


def test_static_plan_binds_artifacts_and_zero_execution_counters(tmp_path: Path) -> None:
    output = tmp_path / "private"
    manifest, _ = _run(tmp_path, output)

    assert manifest.status is DecompilerHuntStatus.COMPLETED
    assert manifest.analysis_mode == "decompiler_static_only"
    assert manifest.model_calls == manifest.image_executions == 0
    assert manifest.generated_inputs == manifest.dynamic_experiments == 0
    assert manifest.fuzzer_invocations == 0
    assert {item.name for item in manifest.artifacts}.issuperset(
        {"normalized-ir.json", "parser-discovery.json", "binary-ranking.json"}
    )
    assert (output.stat().st_mode & 0o077) == 0
    assert (output / "decompiler-hunt-manifest.json").stat().st_mode & 0o077 == 0
    assert load_decompiler_hunt_manifest(output) == manifest


def test_resume_is_deterministic_and_does_not_rerun_pilot(tmp_path: Path) -> None:
    output = tmp_path / "private"
    first, tooling = _run(tmp_path, output)
    ghidra, scripts, java = tooling

    def forbidden(**kwargs):
        raise AssertionError(f"pilot reran during resume: {kwargs}")

    second = run_decompiler_hunt_plan(
        cache_path=tmp_path / "cache",
        output_directory=output,
        product_version="26.5.2",
        build_version="25F84",
        ghidra_headless=ghidra,
        script_directory=scripts,
        java_home=java,
        resume=True,
        pilot_runner=forbidden,
    )

    assert second.manifest_sha256 == first.manifest_sha256
    assert second.artifacts == first.artifacts


def test_resume_rejects_configuration_or_artifact_change(tmp_path: Path) -> None:
    output = tmp_path / "private"
    _, tooling = _run(tmp_path, output)
    ghidra, scripts, java = tooling

    with pytest.raises(ValueError, match="configuration"):
        run_decompiler_hunt_plan(
            cache_path=tmp_path / "cache",
            output_directory=output,
            product_version="26.5.2",
            build_version="25F84",
            ghidra_headless=ghidra,
            script_directory=scripts,
            java_home=java,
            max_functions=601,
            resume=True,
        )

    (output / "normalized-ir.json").write_text("changed\n")
    with pytest.raises(ValueError, match="artifacts"):
        run_decompiler_hunt_plan(
            cache_path=tmp_path / "cache",
            output_directory=output,
            product_version="26.5.2",
            build_version="25F84",
            ghidra_headless=ghidra,
            script_directory=scripts,
            java_home=java,
            resume=True,
        )


def test_completed_pilot_missing_required_artifact_fails_closed(tmp_path: Path) -> None:
    ghidra, scripts, java = _tooling(tmp_path)

    def incomplete(**kwargs):
        result = _completed_pilot(**kwargs)
        (Path(kwargs["output_directory"]) / "normalized-ir.json").unlink()
        return result

    with pytest.raises(ValueError, match="missing artifacts"):
        run_decompiler_hunt_plan(
            cache_path=tmp_path / "cache",
            output_directory=tmp_path / "private",
            product_version="26.5.2",
            build_version="25F84",
            ghidra_headless=ghidra,
            script_directory=scripts,
            java_home=java,
            pilot_runner=incomplete,
        )


def test_private_output_rejects_broadened_permissions(tmp_path: Path) -> None:
    output = tmp_path / "private"

    def broad(**kwargs):
        result = _completed_pilot(**kwargs)
        os.chmod(kwargs["output_directory"], 0o755)
        return result

    ghidra, scripts, java = _tooling(tmp_path)
    with pytest.raises(ValueError, match="group or other"):
        run_decompiler_hunt_plan(
            cache_path=tmp_path / "cache",
            output_directory=output,
            product_version="26.5.2",
            build_version="25F84",
            ghidra_headless=ghidra,
            script_directory=scripts,
            java_home=java,
            pilot_runner=broad,
        )
