#!/usr/bin/env python3
"""Run the M14 static-only Ghidra pilot against the local ImageIO binary."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from vulnhunt_agent.macos.binary_analysis import run_imageio_ghidra_pilot

_DEFAULT_CACHE = Path(
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
)
_DEFAULT_GHIDRA = Path("/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless")
_DEFAULT_JAVA = Path("/opt/homebrew/opt/openjdk@21")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Extract and decompile the locally installed Apple ImageIO binary, then run "
            "the deterministic M14 static pipeline. No image input, Hunter, or experiment runs."
        )
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cache", type=Path, default=_DEFAULT_CACHE)
    parser.add_argument("--ghidra-headless", type=Path, default=_DEFAULT_GHIDRA)
    parser.add_argument("--java-home", type=Path, default=_DEFAULT_JAVA)
    parser.add_argument(
        "--script-directory",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "ghidra",
    )
    parser.add_argument("--max-functions", type=int, default=600)
    parser.add_argument("--max-ops-per-function", type=int, default=4000)
    parser.add_argument("--decompile-seconds", type=int, default=3)
    parser.add_argument("--coverage-depth", type=int, default=2)
    parser.add_argument("--max-evidence-functions", type=int, default=2000)
    parser.add_argument("--analysis-timeout-seconds", type=int, default=600)
    parser.add_argument("--process-timeout-seconds", type=int, default=900)
    parser.add_argument("--ghidra-heap", default="8G")
    return parser.parse_args()


def _sw_vers(flag: str) -> str:
    return subprocess.check_output(["/usr/bin/sw_vers", flag], text=True).strip()


def main() -> int:
    if sys.platform != "darwin":
        raise RuntimeError("the real ImageIO pilot requires macOS")
    arguments = parse_arguments()
    result = run_imageio_ghidra_pilot(
        cache_path=arguments.cache,
        output_directory=arguments.output,
        product_version=_sw_vers("-productVersion"),
        build_version=_sw_vers("-buildVersion"),
        ghidra_headless=arguments.ghidra_headless,
        script_directory=arguments.script_directory,
        java_home=arguments.java_home,
        max_functions=arguments.max_functions,
        max_ops_per_function=arguments.max_ops_per_function,
        decompile_seconds=arguments.decompile_seconds,
        coverage_depth=arguments.coverage_depth,
        max_evidence_functions=arguments.max_evidence_functions,
        analysis_timeout_seconds=arguments.analysis_timeout_seconds,
        process_timeout_seconds=arguments.process_timeout_seconds,
        ghidra_heap=arguments.ghidra_heap,
    )
    print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
    return 0 if result.status.value == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
