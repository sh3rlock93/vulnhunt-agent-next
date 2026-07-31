#!/usr/bin/env python3
"""Run one bounded deterministic ImageIO campaign in a disposable UTM clone."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vulnhunt_agent.macos.imageio_fuzzer import (
    ImageIOFuzzBudget,
    PrivateImageIOFuzzStore,
    PrivateImageIOPayloadHistory,
    run_imageio_fuzz_campaign,
)
from vulnhunt_agent.macos.imageio_fuzz_benchmark import assess_imageio_fuzz_benchmark
from vulnhunt_agent.macos.imageio_harness import ImageIOHarnessLimits, ImageIOVMEnvironment
from vulnhunt_agent.macos.imageio_vm_bridge import (
    ImageIOUTMProvisioning,
    SubprocessUTMCLI,
    UTMDisposableImageIOVM,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the M13 deterministic DICOM fuzzer in a networkless UTM clone."
    )
    parser.add_argument("--provisioning", required=True, type=Path)
    parser.add_argument("--bridge", required=True, type=Path)
    parser.add_argument("--seed", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--history", type=Path)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--campaign-seed", required=True)
    parser.add_argument("--product-version", required=True)
    parser.add_argument("--build-version", required=True)
    parser.add_argument("--max-cases", type=int, default=64)
    parser.add_argument("--max-feedback-cases", type=int, default=32)
    parser.add_argument("--max-generations", type=int, default=2)
    parser.add_argument("--max-children-per-novel-input", type=int, default=4)
    parser.add_argument("--max-executions", type=int, default=256)
    parser.add_argument("--wall-time-seconds", type=int, default=20)
    return parser.parse_args()


def main() -> int:
    if sys.platform != "darwin":
        raise RuntimeError("ImageIO fuzz campaigns require a macOS UTM host")
    arguments = parse_arguments()
    provisioning = ImageIOUTMProvisioning.model_validate_json(
        arguments.provisioning.read_text(encoding="utf-8")
    )
    environment = ImageIOVMEnvironment(
        environment_id=f"imageio-vm-{arguments.campaign_id.removeprefix('imageio-fuzz-')}",
        manager="UTM-Apple-Virtualization",
        product_version=arguments.product_version,
        build_version=arguments.build_version,
        image_sha256=provisioning.base_image_sha256,
        clean_snapshot_id=provisioning.clean_snapshot_id,
        disposable_clone_id=arguments.campaign_id,
        harness_guest_path=(
            "/Users/vulnhunt/Library/Application Support/VulnHunt/bin/imageio-harness"
        ),
    )
    store = PrivateImageIOFuzzStore(arguments.output)
    history = (
        PrivateImageIOPayloadHistory(arguments.history)
        if arguments.history is not None
        else None
    )
    budget = ImageIOFuzzBudget(
        max_cases=arguments.max_cases,
        max_feedback_cases=arguments.max_feedback_cases,
        max_generations=arguments.max_generations,
        max_children_per_novel_input=arguments.max_children_per_novel_input,
        max_executions=arguments.max_executions,
    )
    vm = UTMDisposableImageIOVM(
        environment=environment,
        provisioning=provisioning,
        bridge_root=arguments.bridge,
        cli=SubprocessUTMCLI(),
        startup_timeout_seconds=180,
    )
    with vm as runner:
        summary = run_imageio_fuzz_campaign(
            runner=runner,
            environment=environment,
            seed_path=arguments.seed,
            store=store,
            campaign_id=arguments.campaign_id,
            campaign_seed=arguments.campaign_seed,
            budget=budget,
            limits=ImageIOHarnessLimits(
                wall_time_seconds=arguments.wall_time_seconds,
                cpu_time_seconds=min(15, arguments.wall_time_seconds),
            ),
            history=history,
        )
    benchmark = assess_imageio_fuzz_benchmark(
        store_root=store.root,
        summary=summary,
        budget=budget,
        disposable_clone_cleanup_verified=True,
    )
    store.write_benchmark_assessment(benchmark)
    print(json.dumps(summary.model_dump(mode="json"), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
