"""Bind high-confidence invariant obligations to existing Hunter clusters."""
from __future__ import annotations

from collections import defaultdict

from ..analysis.models import CAnalysisGraph, InvariantObligation
from ..domain.schemas import MAX_HUNTER_OBLIGATIONS, HunterWorkItem
from .shadow import work_id_for

OBLIGATION_ADMISSION_POLICY = "invariant-obligation-admission-v1"
_UNSAFE_GUARDS = {"absent", "partial", "unknown"}


def supported_invariant_obligations(
    graph: CAnalysisGraph,
) -> tuple[InvariantObligation, ...]:
    """Return source-backed obligations that still require model closure."""
    return tuple(
        obligation
        for obligation in graph.invariant_obligations
        if obligation.confidence == "high"
        and _guard_state(obligation) in _UNSAFE_GUARDS
        and obligation.evidence_ranges
        and obligation.required_hunters
    )


def bind_invariant_obligations(
    work_items: tuple[HunterWorkItem, ...],
    graph: CAnalysisGraph,
) -> tuple[HunterWorkItem, ...]:
    """Reserve obligations inside matching clusters without adding sessions.

    A binding changes only the semantic identity and priority of an existing
    work item. It never creates another file/Hunter pair, so the session ceiling
    and context topology remain unchanged.
    """
    pool = list(work_items)
    assignments: dict[str, set[str]] = defaultdict(set)
    for obligation in supported_invariant_obligations(graph):
        for hunter in obligation.required_hunters:
            eligible = [
                item
                for item in pool
                if item.hunter == hunter and _shares_cluster(item, obligation)
            ]
            if not eligible:
                templates = [
                    item for item in pool if _shares_cluster(item, obligation)
                ]
                if not templates:
                    continue
                template = min(
                    templates,
                    key=lambda item: _binding_order(item, obligation),
                )
                eligible = [_specialist_clone(template, hunter)]
                pool.extend(eligible)
            selected = min(
                eligible,
                key=lambda item: _binding_order(item, obligation),
            )
            assignments[selected.work_id].add(obligation.obligation_id)

    bound = []
    for item in pool:
        obligation_ids = tuple(sorted(assignments.get(item.work_id, ())))
        if not obligation_ids:
            bound.append(item)
            continue
        obligation_ids = obligation_ids[:MAX_HUNTER_OBLIGATIONS]
        reasons = tuple(sorted({
            *item.routing_reasons,
            f"obligation-policy:{OBLIGATION_ADMISSION_POLICY}",
            *(f"obligation:{item_id}" for item_id in obligation_ids),
        }))
        work_id = work_id_for(
            source_snapshot=item.source_snapshot,
            planning_policy=item.planning_policy,
            slice_ids=item.slice_ids,
            files=item.files,
            hunter=item.hunter,
            pass_index=item.pass_index,
            target_node_ids=item.target_node_ids,
            target_signal_ids=item.target_signal_ids,
            obligation_ids=obligation_ids,
            changed_line_ranges=item.changed_line_ranges,
            scan_scope_digest=item.scan_scope_digest,
        )
        bound.append(item.model_copy(update={
            "work_id": work_id,
            "obligation_ids": obligation_ids,
            "required": True,
            "risk": max(4, item.risk),
            "routing_reasons": reasons,
        }))
    return tuple(sorted(bound, key=_stable_work_order))


def _specialist_clone(item: HunterWorkItem, hunter: str) -> HunterWorkItem:
    """Create a candidate in the same cluster; admission replaces other work."""
    work_id = work_id_for(
        source_snapshot=item.source_snapshot,
        planning_policy=item.planning_policy,
        slice_ids=item.slice_ids,
        files=item.files,
        hunter=hunter,
        pass_index=item.pass_index,
        target_node_ids=item.target_node_ids,
        target_signal_ids=item.target_signal_ids,
        changed_line_ranges=item.changed_line_ranges,
        scan_scope_digest=item.scan_scope_digest,
    )
    return item.model_copy(update={
        "work_id": work_id,
        "hunter": hunter,
        "routing_reasons": tuple(sorted({
            *item.routing_reasons,
            "required:invariant-obligation-specialist",
        })),
    })


def _shares_cluster(
    item: HunterWorkItem,
    obligation: InvariantObligation,
) -> bool:
    target_overlap = bool(
        set(item.target_node_ids) & set(obligation.target_node_ids)
        or set(item.target_signal_ids) & set(obligation.target_signal_ids)
    )
    evidence_paths = {evidence.path for evidence in obligation.evidence_ranges}
    return target_overlap or bool(set(item.files) & evidence_paths)


def _binding_order(
    item: HunterWorkItem,
    obligation: InvariantObligation,
) -> tuple[int, int, int, str]:
    target_overlap = len(
        set(item.target_node_ids) & set(obligation.target_node_ids)
    ) + len(set(item.target_signal_ids) & set(obligation.target_signal_ids))
    evidence_overlap = len(
        set(item.files) & {evidence.path for evidence in obligation.evidence_ranges}
    )
    return (-target_overlap, -evidence_overlap, -item.risk, item.work_id)


def _guard_state(obligation: InvariantObligation) -> str:
    return next(
        (
            fact.removeprefix("guard=")
            for fact in obligation.structural_facts
            if fact.startswith("guard=")
        ),
        "unknown",
    )


def _stable_work_order(item: HunterWorkItem) -> tuple[str, str, int, str]:
    return item.seed_file, item.hunter, item.pass_index, item.work_id
