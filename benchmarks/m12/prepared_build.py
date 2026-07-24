"""Prepare and verify native benchmark images through the production path."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any, Iterable

from vulnhunt_agent.core.events import EventBus
from vulnhunt_agent.core.run_store import RunStore
from vulnhunt_agent.pipeline.sandbox_prepare import run_prepare
from vulnhunt_agent.pipeline.source_snapshot import run_source_snapshot
from vulnhunt_agent.sandbox.prepared_build import (
    PREPARED_BUILD_PLAN_POLICY,
    verify_prepared_build_receipt,
)

VERIFIED_PREPARED_RUN_POLICY = "verified-prepared-run-v1"


async def prepare_native_benchmark(
    repo: Path,
    run_dir: Path,
    *,
    cmake_options: tuple[str, ...] = (),
    configure_options: tuple[str, ...] = (),
) -> dict[str, Any]:
    repo = repo.resolve()
    run_dir = run_dir.resolve()
    if not repo.is_dir():
        raise ValueError(f"native benchmark repository does not exist: {repo}")
    if run_dir.exists() and any(run_dir.iterdir()):
        raise ValueError(f"prepared benchmark run directory is not empty: {run_dir}")
    store = RunStore(run_dir)
    store.save_config({
        "repo_path": str(repo),
        "environment": "c:gcc-13",
        "prepare_mode": "auto",
        "native_cmake_options": list(cmake_options),
        "native_configure_options": list(configure_options),
    })
    bus = EventBus(store.dir / "events.jsonl")
    await run_source_snapshot(store, bus)
    await run_prepare(store, bus)
    return load_verified_prepared_run(run_dir)


def load_verified_prepared_run(run_dir: Path) -> dict[str, Any]:
    store = RunStore(run_dir.resolve())
    snapshot = _required_step(store, "source_snapshot")
    plan = _required_step(store, "prepared_build_plan")
    receipt = _required_step(store, "prepared_build_receipt")
    prepared = _required_step(store, "sandbox_prepare")
    verify_prepared_build_receipt(receipt)

    if plan.get("policy_version") != PREPARED_BUILD_PLAN_POLICY:
        raise ValueError("prepared benchmark plan policy is invalid")
    if not plan.get("supported"):
        raise ValueError("prepared benchmark plan is unsupported")
    if prepared.get("status") != "ready":
        raise ValueError("prepared benchmark sandbox is not ready")
    links = {
        "source_snapshot": (
            snapshot.get("snapshot_artifact"),
            plan.get("source_snapshot_sha256"),
            receipt.get("source_snapshot_sha256"),
        ),
        "plan": (
            plan.get("plan_sha256"),
            receipt.get("plan_sha256"),
            prepared.get("build_plan_sha256"),
        ),
        "receipt": (
            receipt.get("receipt_sha256"),
            prepared.get("build_receipt_sha256"),
        ),
        "equivalence": (
            receipt.get("equivalence_sha256"),
            prepared.get("build_equivalence_sha256"),
        ),
        "image_reference": (
            receipt.get("images", {}).get("final", {}).get("reference"),
            prepared.get("image"),
        ),
        "image_digest": (
            receipt.get("images", {}).get("final", {}).get("digest"),
            prepared.get("image_digest"),
        ),
    }
    for name, values in links.items():
        if not values[0] or len(set(values)) != 1:
            raise ValueError(f"prepared benchmark {name} linkage is invalid")

    return {
        "schema_version": 1,
        "policy_version": VERIFIED_PREPARED_RUN_POLICY,
        "status": "verified",
        "run_dir": str(store.dir),
        "build_system": plan["build_system"],
        "source_snapshot_sha256": plan["source_snapshot_sha256"],
        "plan_sha256": plan["plan_sha256"],
        "receipt_sha256": receipt["receipt_sha256"],
        "equivalence_sha256": receipt["equivalence_sha256"],
        "image": prepared["image"],
        "image_digest": prepared["image_digest"],
        "artifact_count": len(receipt["artifacts"]),
        "sanitizer_artifact_count": len(
            receipt["sanitizer_provenance"]["artifacts"]
        ),
    }


def resolve_reproduction_image(
    *,
    image: str,
    prepared_run: Path | None,
    label: str,
) -> tuple[str, dict[str, Any] | None]:
    if bool(image) == bool(prepared_run):
        raise ValueError(
            f"{label} reproduction requires exactly one image or verified prepare run"
        )
    if prepared_run is None:
        return image, None
    summary = load_verified_prepared_run(prepared_run)
    return str(summary["image"]), summary


def _required_step(store: RunStore, name: str) -> dict[str, Any]:
    value = store.load_step(name)
    if not isinstance(value, dict):
        raise ValueError(f"prepared benchmark step is missing: {name}")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--repo", type=Path, required=True)
    prepare.add_argument("--run-dir", type=Path, required=True)
    prepare.add_argument("--cmake-option", action="append", default=[])
    prepare.add_argument("--configure-option", action="append", default=[])
    verify = subparsers.add_parser("verify")
    verify.add_argument("--run-dir", type=Path, required=True)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "prepare":
            result = asyncio.run(prepare_native_benchmark(
                args.repo,
                args.run_dir,
                cmake_options=tuple(args.cmake_option),
                configure_options=tuple(args.configure_option),
            ))
        else:
            result = load_verified_prepared_run(args.run_dir)
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
