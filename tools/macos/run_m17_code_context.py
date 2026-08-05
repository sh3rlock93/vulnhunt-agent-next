#!/usr/bin/env python3
"""Continue M17 Hunter roots using only bounded slices from frozen IR."""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from vulnhunt_agent.core import settings
from vulnhunt_agent.core.llm import LLMClient
from vulnhunt_agent.core.provider_preflight import preflight_model_client
from vulnhunt_agent.domain.schemas import BudgetPolicy, BudgetUsage
from vulnhunt_agent.macos.binary_analysis import (
    BinaryCodeContextPolicy,
    DecompilerContextRunResult,
    DecompilerHunterAssessment,
    DecompilerHunterPacket,
    NormalizedBinaryIR,
    continue_decompiler_hunter_session,
    resolve_binary_code_context,
    select_context_continuation_roots,
)
from vulnhunt_agent.macos.binary_analysis.code_context import (
    DecompilerContinuationModelClient,
    _terminal_result_can_resume,
)
from vulnhunt_agent.scheduling.budget import (
    BudgetController,
    BudgetedLLMClient,
    BudgetExceededError,
)

_MAX_ARTIFACT_BYTES = 768 * 1024
_MAX_IR_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class _Root:
    packet: DecompilerHunterPacket
    assessment: DecompilerHunterAssessment
    usage: BudgetUsage


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve M17 code-context requests from an existing normalized-ir.json. "
            "This command does not run Ghidra, an image, a VM, a fuzzer, or a network search."
        )
    )
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument(
        "--source-store",
        type=Path,
        help="private store containing completed M17-4 Hunter artifacts (default: evidence)",
    )
    parser.add_argument(
        "--store",
        type=Path,
        help="private output store for the immutable context chain (default: source store)",
    )
    parser.add_argument("--work-id", action="append", default=[])
    parser.add_argument("--model", default=settings.DEFAULT_MODEL.model_id)
    parser.add_argument("--max-roots", type=int, default=6)
    parser.add_argument("--max-continuations", type=int, default=3)
    parser.add_argument("--max-evidence-kib", type=int, default=384)
    parser.add_argument("--max-input-tokens", type=int, default=1_000_000)
    parser.add_argument("--max-output-tokens", type=int, default=100_000)
    parser.add_argument("--max-wall-clock-minutes", type=int, default=90)
    parser.add_argument("--plan-only", action="store_true")
    return parser.parse_args()


def _read_model(path: Path, model_type, *, maximum: int = _MAX_ARTIFACT_BYTES):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise RuntimeError(f"missing, unsafe, or oversized frozen artifact: {path}")
    return model_type.model_validate_json(path.read_bytes())


def _load_roots(store: Path) -> tuple[_Root, ...]:
    roots = []
    for directory in sorted((store / "hunters").glob("work_*/decompiler-analysis")):
        try:
            root = _Root(
                packet=_read_model(directory / "packet.json", DecompilerHunterPacket),
                assessment=_read_model(directory / "assessment.json", DecompilerHunterAssessment),
                usage=_read_model(directory / "usage.json", BudgetUsage),
            )
        except RuntimeError:
            continue
        roots.append(root)
    return tuple(sorted(roots, key=lambda item: item.packet.admission_rank))


async def _main() -> int:
    arguments = parse_arguments()
    evidence = arguments.evidence.expanduser().resolve(strict=True)
    source_store = (arguments.source_store or evidence).expanduser().resolve(strict=True)
    store = (arguments.store or source_store).expanduser().resolve(strict=True)
    ir = _read_model(evidence / "normalized-ir.json", NormalizedBinaryIR, maximum=_MAX_IR_BYTES)
    policy = BinaryCodeContextPolicy(
        maximum_roots_per_run=arguments.max_roots,
        maximum_continuations_per_root=arguments.max_continuations,
        maximum_total_evidence_bytes=arguments.max_evidence_kib * 1024,
    )
    roots = _load_roots(source_store)
    requested = set(arguments.work_id)
    if requested:
        roots = tuple(item for item in roots if item.packet.work_id in requested)
        missing = requested.difference(item.packet.work_id for item in roots)
        if missing:
            raise RuntimeError("unknown completed Hunter work IDs: " + ", ".join(sorted(missing)))
    assessments = tuple(item.assessment for item in roots)
    admitted_ids, deferred_ids = select_context_continuation_roots(assessments, policy=policy)
    by_id = {item.packet.work_id: item for item in roots}
    admitted = tuple(by_id[item] for item in admitted_ids)
    plan_rows: list[dict[str, object]] = []
    for item in admitted:
        if len(item.assessment.context_requests) != 1:
            plan_rows.append(
                {
                    "work_id": item.packet.work_id,
                    "root_id": item.packet.root_id,
                    "status": "reviewer_inconclusive",
                    "reason": "exactly one typed request is required",
                }
            )
            continue
        response = resolve_binary_code_context(
            ir=ir,
            packet=item.packet,
            request=item.assessment.context_requests[0],
            policy=policy,
        )
        plan_rows.append(
            {
                "work_id": item.packet.work_id,
                "root_id": item.packet.root_id,
                "admission_rank": item.packet.admission_rank,
                "request_kind": response.request.kind.value,
                "resolution_status": response.status.value,
                "rejection": response.rejection.value if response.rejection else None,
                "response_sha256": response.response_sha256,
                "additional_evidence_bytes": response.evidence_bytes,
            }
        )
    if arguments.plan_only:
        print(
            json.dumps(
                {
                    "schema_version": "decompiler-context-cli-plan-v1",
                    "admitted": plan_rows,
                    "deferred_work_ids": deferred_ids,
                    "model_calls": 0,
                    "image_executions": 0,
                    "decompiler_invocations": 0,
                    "fuzzer_invocations": 0,
                    "vm_boots": 0,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if not admitted:
        print(
            json.dumps(
                {
                    "schema_version": "decompiler-context-cli-result-v1",
                    "completed": [],
                    "deferred_work_ids": deferred_ids,
                    "message": "no completed Hunter roots currently need code context",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    results: list[DecompilerContextRunResult] = []
    pending: list[tuple[_Root, bool]] = []
    for item in admitted:
        persisted = (
            store
            / "hunters"
            / item.packet.work_id
            / "decompiler-analysis"
            / "code-context"
            / "result.json"
        )
        if persisted.exists():
            persisted_result = _read_model(persisted, DecompilerContextRunResult)
            if _terminal_result_can_resume(persisted_result, policy=policy):
                pending.append((item, True))
            else:
                results.append(persisted_result)
        else:
            pending.append((item, False))
    extended_continuation_used = any(len(item.entries) >= 3 for item in results)
    client = None
    if pending:
        client = LLMClient(arguments.model)
        preflight = await preflight_model_client(client, model_probe=False)
        if not preflight.ready:
            print(json.dumps(preflight.model_dump(mode="json"), indent=2, sort_keys=True))
            return 2
    budget = BudgetPolicy(
        max_hunter_sessions=arguments.max_roots,
        max_input_tokens=arguments.max_input_tokens,
        max_output_tokens=arguments.max_output_tokens,
        max_wall_clock_minutes=arguments.max_wall_clock_minutes,
    )
    controller = BudgetController(
        budget,
        [item.usage for item, _ in pending],
        soft_input_token_stop=budget.max_input_tokens,
    )
    budget_deferred: list[dict[str, str]] = []
    for item, resuming in pending:
        assert client is not None
        budgeted = BudgetedLLMClient(client, controller, work_id=item.packet.work_id)
        root_policy = (
            policy
            if resuming
            else policy.for_remaining_root(
                extended_continuation_used=extended_continuation_used
            )
        )
        try:
            result = await continue_decompiler_hunter_session(
                store_root=store,
                ir=ir,
                packet=item.packet,
                initial_assessment=item.assessment,
                initial_usage=item.usage,
                client=cast(DecompilerContinuationModelClient, budgeted),
                policy=root_policy,
            )
            results.append(result)
            extended_continuation_used = extended_continuation_used or len(result.entries) >= 3
        except BudgetExceededError as exc:
            budget_deferred.append(
                {
                    "work_id": item.packet.work_id,
                    "reason": exc.reason,
                }
            )
            break
        finally:
            controller.finish_work(item.packet.work_id)
    summary = {
        "schema_version": "decompiler-context-cli-result-v1",
        "completed": [
            {
                "work_id": item.work_id,
                "root_id": item.root_id,
                "terminal_status": item.terminal_status.value,
                "terminal_disposition": item.terminal_assessment.disposition.value,
                "continuations": len(item.entries),
                "chain_sha256": item.chain_sha256,
                "sessions": item.sessions,
                "model_calls": item.model_calls,
                "input_tokens": item.input_tokens,
                "output_tokens": item.output_tokens,
                "total_evidence_bytes": item.total_evidence_bytes,
            }
            for item in results
        ],
        "deferred_work_ids": deferred_ids,
        "budget_deferred": budget_deferred,
        "image_executions": 0,
        "decompiler_invocations": 0,
        "fuzzer_invocations": 0,
        "vm_boots": 0,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 3 if budget_deferred else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
