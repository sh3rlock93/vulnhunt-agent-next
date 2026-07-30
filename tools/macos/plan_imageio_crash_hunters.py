#!/usr/bin/env python3
"""Rank private ImageIO crash clusters into existing Hunter work items."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulnhunt_agent.domain.schemas import BudgetPolicy
from vulnhunt_agent.macos.imageio_crashes import build_imageio_crash_hunter_plan


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Normalize and rank ImageIO crash evidence, then emit bounded "
            "HunterWorkItem records without calling a model."
        )
    )
    parser.add_argument("--store", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-snapshot", required=True)
    parser.add_argument("--max-hunter-sessions", type=int, default=12)
    parser.add_argument("--max-input-tokens", type=int, default=2_000_000)
    parser.add_argument("--max-output-tokens", type=int, default=200_000)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    plan = build_imageio_crash_hunter_plan(
        store_root=arguments.store,
        run_id=arguments.run_id,
        source_snapshot=arguments.source_snapshot,
        budget=BudgetPolicy(
            max_hunter_sessions=arguments.max_hunter_sessions,
            max_input_tokens=arguments.max_input_tokens,
            max_output_tokens=arguments.max_output_tokens,
        ),
    )
    eligible = [cluster for cluster in plan.clusters if cluster.hunter_eligible]
    print(
        json.dumps(
            {
                "schema_version": "imageio-crash-hunter-plan-summary-v1",
                "policy_version": plan.routing.policy_version,
                "crash_clusters": len(plan.clusters),
                "hunter_eligible_clusters": len(eligible),
                "deduplicated_observations": sum(
                    len(cluster.observations) - 1 for cluster in plan.clusters
                ),
                "scheduled_work_items": len(plan.routing.work_items),
                "admitted_work_items": len(plan.admitted_work_items),
                "deferred_work_items": len(plan.allocation.deferred),
                "admitted_work_ids": list(plan.allocation.admitted_work_ids),
                "model_calls": 0,
                "manifest": str(arguments.store.expanduser().resolve() / "hunter-plan.json"),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
