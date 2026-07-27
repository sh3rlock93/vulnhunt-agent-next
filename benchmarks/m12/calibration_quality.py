"""Post-freeze knowledge-quality metrics for the M12.2 recovery cohort.

The existing ``benchmark-metrics-v1`` reducer remains the authority for recall,
precision, and cost.  This module adds a separate, deterministic audit of the
generalized knowledge projection and its current-source evidence boundary.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from benchmarks.run_libtiff_blind_benchmark import BenchmarkContractError
from vulnhunt_agent.domain.compat import candidate_from_legacy

KNOWLEDGE_METRICS_POLICY = "knowledge-quality-metrics-v1"


def reduce_knowledge_quality(
    cohort_root: Path,
    runs: Sequence[Mapping[str, Any]],
    *,
    ledger_path: Path,
) -> dict[str, Any]:
    """Reduce frozen context and Hunter artifacts without opening an oracle."""
    ledger_tokens = _ledger_identity_tokens(ledger_path)
    per_run = [
        _run_metrics(
            cohort_root,
            raw,
            ledger_tokens=ledger_tokens,
        )
        for raw in sorted(runs, key=lambda item: str(item["run_id"]))
    ]
    selected = sum(int(item["selected_card_count"]) for item in per_run)
    converted = sum(int(item["converted_card_count"]) for item in per_run)
    canonical = sum(int(item["canonical_candidate_count"]) for item in per_run)
    canonical_records = sum(
        int(item["canonical_candidate_record_count"]) for item in per_run
    )
    executions = sum(int(item["hunter_finding_execution_count"]) for item in per_run)
    missing_source = sum(
        int(item["findings_without_current_source_evidence"])
        for item in per_run
    )
    reportable_missing_source = sum(
        int(item["reportable_without_current_source_evidence"])
        for item in per_run
    )
    falsified = sum(int(item["falsified_card_count"]) for item in per_run)
    leaks = sorted(
        leak
        for item in per_run
        for leak in item["ledger_identity_leaks"]
    )
    return {
        "schema_version": 1,
        "policy_version": KNOWLEDGE_METRICS_POLICY,
        "run_count": len(per_run),
        "selected_card_count": selected,
        "selected_pattern_ids": sorted({
            pattern_id
            for item in per_run
            for pattern_id in item["selected_pattern_ids"]
        }),
        "card_to_obligation_conversion": _rate(converted, selected),
        "candidate_yield": {
            "canonical_candidate_count": canonical,
            "hunter_finding_execution_count": executions,
            "selected_card_count": selected,
            "canonical_candidates_per_selected_card": (
                canonical / selected if selected else None
            ),
        },
        "falsified_card_count": falsified,
        "findings_without_current_source_evidence": missing_source,
        "reportable_without_current_source_evidence": reportable_missing_source,
        "ledger_identity_leaks": leaks,
        "duplicate_accounting": {
            "canonical_candidate_count": canonical,
            "canonical_candidate_record_count": canonical_records,
            "hunter_finding_execution_count": executions,
            "duplicate_execution_count": max(0, executions - canonical),
            "logical_findings_count_once": all(
                bool(item["logical_findings_count_once"])
                for item in per_run
            ),
        },
        "per_run": per_run,
    }


def _run_metrics(
    cohort_root: Path,
    raw: Mapping[str, Any],
    *,
    ledger_tokens: tuple[str, ...],
) -> dict[str, Any]:
    run_id = str(raw["run_id"])
    frozen = _resolve_frozen(cohort_root, str(raw["freeze_root"]))
    plan = _load_json(frozen / "plan.json", "frozen hunt plan")
    final_findings = _load_json(frozen / "findings.json", "frozen findings")
    discovery = _load_json(frozen / "discovery.json", "frozen discovery")
    if (
        not isinstance(plan, dict)
        or not isinstance(final_findings, list)
        or not isinstance(discovery, dict)
    ):
        raise BenchmarkContractError(f"knowledge-quality artifacts are invalid: {run_id}")
    internal_run_id = str(
        (discovery.get("run_identity") or {}).get("run_id") or ""
    )
    if not internal_run_id:
        raise BenchmarkContractError(f"knowledge-quality run identity is missing: {run_id}")

    contexts = []
    context_paths = {
        *sorted((frozen / "contexts").glob("*.json")),
        *sorted(
            (frozen / internal_run_id / "cache" / "context").glob("*.json")
        ),
    }
    for path in sorted(context_paths):
        payload = _load_json(path, "frozen knowledge context")
        if not isinstance(payload, dict):
            raise BenchmarkContractError(f"knowledge context is invalid: {run_id}")
        contexts.append(payload)

    selections: set[tuple[str, str]] = set()
    converted: set[tuple[str, str]] = set()
    patterns_by_obligation: dict[str, set[str]] = {}
    selected_patterns: set[str] = set()
    leaks: list[dict[str, str]] = []
    for context in contexts:
        cache_key = str(context.get("cache_key") or "")
        knowledge = context.get("vulnerability_knowledge") or {}
        cards = knowledge.get("cards") if isinstance(knowledge, dict) else None
        if not isinstance(cards, list):
            continue
        encoded_knowledge = json.dumps(
            knowledge,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).casefold()
        for token in ledger_tokens:
            if token.casefold() in encoded_knowledge:
                leaks.append({
                    "run_id": run_id,
                    "cache_key": cache_key,
                    "token": token,
                })
        obligation_ids = {
            str(item.get("obligation_id") or "")
            for item in context.get("invariant_obligations") or []
            if isinstance(item, dict) and item.get("obligation_id")
        }
        for card in cards:
            if not isinstance(card, dict) or not card.get("pattern_id"):
                continue
            pattern_id = str(card["pattern_id"])
            selected_patterns.add(pattern_id)
            selection = (cache_key, pattern_id)
            selections.add(selection)
            if obligation_ids:
                converted.add(selection)
            for obligation_id in obligation_ids:
                patterns_by_obligation.setdefault(obligation_id, set()).add(pattern_id)

    work_items = {
        str(item.get("work_id")): item
        for item in plan.get("work_items") or []
        if isinstance(item, dict) and item.get("work_id")
    }
    raw_by_work = _raw_hunter_results(frozen, internal_run_id)
    finding_executions = sum(
        len(payload.get("findings") or [])
        for payload in raw_by_work.values()
    )
    missing_source_work = {
        work_id
        for work_id, payload in raw_by_work.items()
        if payload.get("findings") and not _has_current_source_read(payload)
    }
    missing_source_findings = sum(
        len(raw_by_work[work_id].get("findings") or [])
        for work_id in missing_source_work
    )
    work_by_fingerprint: dict[str, set[str]] = {}
    for work_id, payload in raw_by_work.items():
        for raw_finding in payload.get("findings") or []:
            if not isinstance(raw_finding, dict):
                raise BenchmarkContractError(
                    f"invalid frozen Hunter finding: {run_id}/{work_id}"
                )
            candidate = candidate_from_legacy(
                raw_finding,
                run_id=run_id,
                task_key=f"hunter:{work_id}",
            )
            work_by_fingerprint.setdefault(candidate.fingerprint, set()).add(work_id)
    reportable_missing_source = 0
    for finding in final_findings:
        if not isinstance(finding, dict) or finding.get("state") != "reportable":
            continue
        task_key = str(finding.get("task_key") or "")
        linked_work = {task_key} if task_key in raw_by_work else set()
        verified = re.fullmatch(r"verified:([0-9a-f]{64})", task_key)
        if verified is not None:
            linked_work.update(work_by_fingerprint.get(verified.group(1), set()))
        if not linked_work:
            raise BenchmarkContractError(
                f"reportable finding has no Hunter work provenance: {run_id}"
            )
        if linked_work <= missing_source_work:
            reportable_missing_source += 1

    falsified: set[tuple[str, str]] = set()
    for work_id, payload in raw_by_work.items():
        if not _has_current_source_read(payload):
            continue
        work = work_items.get(work_id) or {}
        allowed = {str(value) for value in work.get("obligation_ids") or []}
        for disposition in payload.get("target_dispositions") or []:
            if not isinstance(disposition, dict) or disposition.get("status") != "no_finding":
                continue
            target_id = str(disposition.get("target_id") or "")
            if target_id not in allowed:
                continue
            falsified.update(
                (pattern_id, target_id)
                for pattern_id in patterns_by_obligation.get(target_id, set())
            )

    candidate_ids = [
        str(item.get("candidate_id") or "")
        for item in final_findings
        if isinstance(item, dict) and item.get("candidate_id")
    ]
    return {
        "run_id": run_id,
        "selected_card_count": len(selections),
        "selected_pattern_ids": sorted(selected_patterns),
        "converted_card_count": len(converted),
        "canonical_candidate_count": len(set(candidate_ids)),
        "canonical_candidate_record_count": len(candidate_ids),
        "logical_findings_count_once": len(candidate_ids) == len(set(candidate_ids)),
        "hunter_finding_execution_count": finding_executions,
        "falsified_card_count": len(falsified),
        "findings_without_current_source_evidence": missing_source_findings,
        "reportable_without_current_source_evidence": reportable_missing_source,
        "ledger_identity_leaks": sorted(
            leaks,
            key=lambda item: (item["cache_key"], item["token"]),
        ),
    }


def _raw_hunter_results(frozen: Path, run_id: str) -> dict[str, dict[str, Any]]:
    run_root = frozen / run_id / "hunters"
    results: dict[str, dict[str, Any]] = {}
    for path in sorted(run_root.glob("*/hunts/*/findings.json")):
        relative = path.relative_to(run_root)
        if len(relative.parts) != 4:
            raise BenchmarkContractError(f"invalid frozen Hunter path: {path}")
        work_id = relative.parts[0]
        payload = _load_json(path, "frozen Hunter result")
        if not isinstance(payload, dict):
            raise BenchmarkContractError(f"invalid frozen Hunter result: {path}")
        if work_id in results:
            raise BenchmarkContractError(
                f"multiple Hunter result artifacts for one work item: {work_id}"
            )
        results[work_id] = payload
    return results


def _has_current_source_read(payload: Mapping[str, Any]) -> bool:
    for item in payload.get("source_reads") or []:
        if (
            isinstance(item, dict)
            and str(item.get("path") or "")
            and int(item.get("bytes", 0) or 0) > 0
        ):
            return True
    return False


def _ledger_identity_tokens(path: Path) -> tuple[str, ...]:
    payload = _load_json(path, "vulnerability finding ledger")
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise BenchmarkContractError("vulnerability finding ledger is invalid")
    tokens: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        for key in ("finding_id", "project", "source_repository", "source_revision"):
            value = str(record.get(key) or "").strip()
            if len(value) >= 8:
                tokens.add(value)
        tokens.update(
            value
            for value in (str(item).strip() for item in record.get("locations") or [])
            if len(value) >= 8
        )
    return tuple(sorted(tokens, key=lambda value: (value.casefold(), value)))


def _resolve_frozen(root: Path, reference: str) -> Path:
    path = (root.resolve() / reference).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_dir():
        raise BenchmarkContractError(f"frozen run reference is invalid: {reference}")
    return path


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkContractError(f"{label} is unreadable") from exc


def _rate(numerator: int, denominator: int) -> dict[str, int | float | None]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": numerator / denominator if denominator else None,
    }
