#!/usr/bin/env python3
"""Run the independent M17 Code Reviewer over completed Hunter hypotheses."""

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
    BinaryCodeReviewRunResult,
    BinaryCodeReviewerModelClient,
    BinaryCodeReviewerPolicy,
    DecompilerContextChainEntry,
    DecompilerContextRunResult,
    DecompilerHunterAssessment,
    DecompilerHunterPacket,
    NormalizedBinaryIR,
    StaticReportabilityStatus,
    build_binary_code_reviewer_packet,
    run_binary_code_review,
    select_code_reviewer_hypotheses,
)
from vulnhunt_agent.scheduling.budget import BudgetController, BudgetedLLMClient

_MAX_ARTIFACT_BYTES = 1024 * 1024
_MAX_IR_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class _ReviewCandidate:
    packet: DecompilerHunterPacket
    assessment: DecompilerHunterAssessment
    entries: tuple[DecompilerContextChainEntry, ...]
    context_chain_sha256: str | None
    hypothesis_id: str


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Review completed M17 code hypotheses using decompiler evidence only. "
            "This command does not execute an image, fuzzer, VM, or dynamic experiment."
        )
    )
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--hunter-store", type=Path)
    parser.add_argument("--context-store", type=Path)
    parser.add_argument("--store", required=True, type=Path)
    parser.add_argument("--product-version", required=True)
    parser.add_argument("--build-version", required=True)
    parser.add_argument("--run-id", default="m17-code-review")
    parser.add_argument("--model", default=settings.DEFAULT_MODEL.model_id)
    parser.add_argument("--max-hypotheses", type=int, default=6)
    parser.add_argument("--max-input-tokens", type=int, default=1_000_000)
    parser.add_argument("--max-output-tokens", type=int, default=100_000)
    parser.add_argument("--max-wall-clock-minutes", type=int, default=90)
    parser.add_argument("--plan-only", action="store_true")
    return parser.parse_args()


def _read_model(path: Path, model_type, *, maximum: int = _MAX_ARTIFACT_BYTES):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise RuntimeError(f"missing, unsafe, or oversized frozen artifact: {path}")
    return model_type.model_validate_json(path.read_bytes())


def _load_candidates(
    hunter_store: Path,
    context_store: Path,
) -> tuple[_ReviewCandidate, ...]:
    candidates: list[_ReviewCandidate] = []
    for directory in sorted((hunter_store / "hunters").glob("work_*/decompiler-analysis")):
        try:
            packet = _read_model(directory / "packet.json", DecompilerHunterPacket)
            assessment = _read_model(directory / "assessment.json", DecompilerHunterAssessment)
        except RuntimeError:
            continue
        context_path = (
            context_store / "hunters" / packet.work_id / "decompiler-analysis"
            / "code-context" / "result.json"
        )
        entries: tuple[DecompilerContextChainEntry, ...] = ()
        chain: str | None = None
        if context_path.exists():
            context = _read_model(context_path, DecompilerContextRunResult)
            assessment = context.terminal_assessment
            entries = context.entries
            chain = context.chain_sha256
        for hypothesis in assessment.hypotheses:
            candidates.append(_ReviewCandidate(
                packet=packet,
                assessment=assessment,
                entries=entries,
                context_chain_sha256=chain,
                hypothesis_id=hypothesis.hypothesis_id,
            ))
    return tuple(sorted(
        candidates,
        key=lambda item: (item.packet.admission_rank, item.hypothesis_id),
    ))


def _result_path(store: Path, reviewer_packet) -> Path:
    return (
        store / "reviewers" / reviewer_packet.work_id
        / reviewer_packet.hypothesis.hypothesis_id
        / reviewer_packet.reviewer_session_id / "result.json"
    )


async def _main() -> int:
    arguments = parse_arguments()
    evidence = arguments.evidence.expanduser().resolve(strict=True)
    hunter_store = (arguments.hunter_store or evidence).expanduser().resolve(strict=True)
    context_store = (arguments.context_store or hunter_store).expanduser().resolve(strict=True)
    store = arguments.store.expanduser().resolve(strict=True)
    ir = _read_model(evidence / "normalized-ir.json", NormalizedBinaryIR, maximum=_MAX_IR_BYTES)
    policy = BinaryCodeReviewerPolicy(
        maximum_hypotheses_per_run=arguments.max_hypotheses,
    )
    candidates = _load_candidates(hunter_store, context_store)
    assessments = tuple({
        item.packet.work_id: item.assessment for item in candidates
    }.values())
    admitted_pairs, _ = select_code_reviewer_hypotheses(assessments, policy=policy)
    admitted_set = set(admitted_pairs)
    admitted = tuple(
        item for item in candidates
        if (item.packet.work_id, item.hypothesis_id) in admitted_set
    )
    deferred = tuple(
        (item.packet.work_id, item.hypothesis_id)
        for item in candidates if item not in admitted
    )
    packets = tuple(build_binary_code_reviewer_packet(
        ir=ir,
        hunter_packet=item.packet,
        hunter_assessment=item.assessment,
        context_entries=item.entries,
        context_chain_sha256=item.context_chain_sha256,
        hypothesis_id=item.hypothesis_id,
        product_version=arguments.product_version,
        build_version=arguments.build_version,
    ) for item in admitted)
    if arguments.plan_only:
        print(json.dumps({
            "schema_version": "m17-code-reviewer-cli-plan-v1",
            "queue_scope": "decompiler-code-reviewer",
            "admitted": tuple({
                "work_id": packet.work_id,
                "hypothesis_id": packet.hypothesis.hypothesis_id,
                "reviewer_session_id": packet.reviewer_session_id,
                "packet_sha256": packet.packet_sha256,
            } for packet in packets),
            "deferred": deferred,
            "model_calls": 0,
            "image_executions": 0,
            "fuzzer_invocations": 0,
            "vm_boots": 0,
            "dynamic_experiments": 0,
        }, indent=2, sort_keys=True))
        return 0
    pending = tuple(
        (candidate, packet)
        for candidate, packet in zip(admitted, packets, strict=True)
        if not _result_path(store, packet).exists()
    )
    client = LLMClient(arguments.model)
    if pending:
        preflight = await preflight_model_client(client, model_probe=False)
        if not preflight.ready:
            print(json.dumps(preflight.model_dump(mode="json"), indent=2, sort_keys=True))
            return 2
    prior_usage: list[BudgetUsage] = []
    results: list[BinaryCodeReviewRunResult] = []
    for candidate, packet in zip(admitted, packets, strict=True):
        path = _result_path(store, packet)
        if path.exists():
            result = _read_model(path, BinaryCodeReviewRunResult)
            results.append(result)
            prior_usage.append(result.usage)
    budget = BudgetPolicy(
        max_hunter_sessions=arguments.max_hypotheses,
        max_input_tokens=arguments.max_input_tokens,
        max_output_tokens=arguments.max_output_tokens,
        max_wall_clock_minutes=arguments.max_wall_clock_minutes,
    )
    controller = BudgetController(budget, prior_usage, soft_input_token_stop=budget.max_input_tokens)
    for candidate, packet in pending:
        budgeted = BudgetedLLMClient(client, controller, work_id=packet.work_id)
        result = await run_binary_code_review(
            store_root=store,
            ir=ir,
            hunter_packet=candidate.packet,
            hunter_assessment=candidate.assessment,
            context_entries=candidate.entries,
            context_chain_sha256=candidate.context_chain_sha256,
            hypothesis_id=candidate.hypothesis_id,
            product_version=arguments.product_version,
            build_version=arguments.build_version,
            run_id=arguments.run_id,
            client=cast(BinaryCodeReviewerModelClient, budgeted),
            policy=policy,
        )
        results.append(result)
        controller.finish_work(packet.work_id)
    results.sort(key=lambda item: (item.decision.work_id, item.decision.hypothesis_id))
    print(json.dumps({
        "schema_version": "m17-code-reviewer-cli-result-v1",
        "completed": tuple({
            "work_id": item.decision.work_id,
            "hypothesis_id": item.decision.hypothesis_id,
            "reviewer_session_id": item.reviewer_session_id,
            "status": item.decision.status.value,
            "decision_sha256": item.decision.decision_sha256,
            "report_sha256": item.report.report_sha256,
            "calls": item.usage.calls,
            "input_tokens": item.usage.input_tokens,
            "output_tokens": item.usage.output_tokens,
        } for item in results),
        "reportable_static": sum(
            item.decision.status is StaticReportabilityStatus.REPORTABLE_STATIC
            for item in results
        ),
        "deferred": deferred,
        "image_executions": 0,
        "generated_inputs": 0,
        "fuzzer_invocations": 0,
        "vm_boots": 0,
        "dynamic_experiments": 0,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
