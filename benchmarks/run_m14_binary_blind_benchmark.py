#!/usr/bin/env python3
"""Run the frozen M14 binary benchmark and load oracles only after analysis."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulnhunt_agent.macos.binary_analysis import (
    BlindBenchmarkOracle,
    freeze_blind_benchmark,
    run_blind_binary_benchmark,
)


def parse_arguments() -> argparse.Namespace:
    default_root = Path(__file__).resolve().parent / "m14_blind"
    parser = argparse.ArgumentParser(description="Run the M14 static binary blind benchmark")
    parser.add_argument("--corpus", type=Path, default=default_root)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def _load_oracles(path: Path) -> tuple[BlindBenchmarkOracle, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("M14 oracle file must contain an array")
    return tuple(BlindBenchmarkOracle.model_validate(item) for item in payload)


def main() -> int:
    arguments = parse_arguments()
    exports = arguments.corpus / "exports"
    cases: dict[str, tuple[Path, str]] = {}
    for path in sorted(exports.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        cases[path.stem] = (path, str(payload["snapshot_sha256"]))
    manifest = freeze_blind_benchmark(cases)
    result = run_blind_binary_benchmark(
        manifest,
        export_directory=exports,
        oracle_loader=lambda: _load_oracles(arguments.corpus / "oracles.json"),
    )
    rendered = json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result.false_negatives == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
