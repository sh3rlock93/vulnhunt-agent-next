"""Collapse routed file work into bounded, overlapping AnalysisSlice work."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from ..analysis.models import AnalysisSlice, CoveragePlan
from ..domain.schemas import HunterRoutingPlan, HunterWorkItem
from .shadow import work_id_for

SLICE_WORK_POLICY = "c-slice-work-v1"
MAX_CONTEXT_FILES = 8


@dataclass(frozen=True)
class SliceGroup:
    group_id: str
    slice_ids: tuple[str, ...]
    files: tuple[str, ...]
    risk: int


def build_slice_work_items(
    routing: HunterRoutingPlan,
    analysis: dict | None,
) -> tuple[HunterWorkItem, ...]:
    coverage = CoveragePlan.model_validate(
        (analysis or {}).get("coverage_plan") or {}
    )
    slices = {item.slice_id: item for item in coverage.slices}
    components = _routed_components(routing.work_items)

    out: list[HunterWorkItem] = []
    for component in components:
        hunters = sorted({item.hunter for item in component})
        for hunter in hunters:
            routed_members = [
                item for item in component if item.hunter == hunter
            ]
            for work_members in _member_batches(routed_members):
                slice_ids = tuple(sorted({
                    slice_id
                    for item in work_members
                    for slice_id in item.slice_ids
                }))
                component_files = tuple(sorted({
                    path
                    for slice_id in slice_ids
                    if slice_id in slices
                    for path in slices[slice_id].files
                } | {
                    path for item in work_members for path in item.files
                }))
                group_digest = hashlib.sha256(
                    "\0".join(slice_ids or component_files).encode()
                ).hexdigest()[:20]
                ordered_members = sorted(
                    work_members,
                    key=lambda item: (-int(item.required), -item.risk, item.seed_file),
                )
                seed = ordered_members[0].seed_file
                files = _bounded_files(component_files, ordered_members, seed)
                source = ordered_members[0]
                reasons = tuple(sorted({
                    reason
                    for item in ordered_members
                    for reason in item.routing_reasons
                } | {f"slice-component:{group_digest}"}))
                out.append(HunterWorkItem(
                    work_id=work_id_for(
                        source_snapshot=source.source_snapshot,
                        planning_policy=SLICE_WORK_POLICY,
                        slice_ids=slice_ids,
                        files=files,
                        hunter=hunter,
                    ),
                    run_id=source.run_id,
                    source_snapshot=source.source_snapshot,
                    planning_policy=SLICE_WORK_POLICY,
                    slice_ids=slice_ids,
                    seed_file=seed,
                    files=files,
                    hunter=hunter,
                    risk=max(item.risk for item in work_members),
                    required=any(item.required for item in ordered_members),
                    routing_reasons=reasons,
                ))
    return tuple(sorted(out, key=lambda item: (-item.risk, item.work_id)))


def _routed_components(
    work_items: tuple[HunterWorkItem, ...],
) -> list[list[HunterWorkItem]]:
    """Connected components over routed items that share an AnalysisSlice."""
    ordered = sorted(work_items, key=lambda item: item.work_id)
    remaining = set(range(len(ordered)))
    components: list[list[HunterWorkItem]] = []
    while remaining:
        start = min(remaining)
        remaining.remove(start)
        indexes = {start}
        frontier = [start]
        while frontier:
            current = frontier.pop()
            current_slices = set(ordered[current].slice_ids)
            connected = [
                index for index in sorted(remaining)
                if (
                    bool(current_slices & set(ordered[index].slice_ids))
                    or (
                        not current_slices
                        and not ordered[index].slice_ids
                        and ordered[current].seed_file == ordered[index].seed_file
                    )
                )
            ]
            for index in connected:
                remaining.remove(index)
                indexes.add(index)
                frontier.append(index)
        components.append([ordered[index] for index in sorted(indexes)])
    return components


def _member_batches(
    members: list[HunterWorkItem],
) -> list[list[HunterWorkItem]]:
    """Keep every routed seed file while enforcing the eight-file boundary."""
    ordered = sorted(
        members,
        key=lambda item: (-int(item.required), -item.risk, item.seed_file),
    )
    batches: list[list[HunterWorkItem]] = []
    for item in ordered:
        if (
            not batches
            or len({
                member.seed_file for member in batches[-1]
            } | {item.seed_file}) > MAX_CONTEXT_FILES
        ):
            batches.append([])
        batches[-1].append(item)
    return batches


def group_overlapping_slices(plan: CoveragePlan) -> tuple[SliceGroup, ...]:
    """Greedily merge overlapping slices while keeping context at eight files."""
    buckets: list[list[AnalysisSlice]] = []
    for item in sorted(plan.slices, key=lambda value: (-value.risk, value.slice_id)):
        choices = [
            (index, bucket)
            for index, bucket in enumerate(buckets)
            if _overlaps(item, bucket)
            and (
                _same_sink(item, bucket)
                or len(set(item.files) | {
                    path for existing in bucket for path in existing.files
                }) <= MAX_CONTEXT_FILES
            )
        ]
        if choices:
            index, _ = min(
                choices,
                key=lambda choice: (
                    len({path for member in choice[1] for path in member.files}),
                    tuple(member.slice_id for member in choice[1]),
                ),
            )
            buckets[index].append(item)
        else:
            buckets.append([item])

    groups = []
    for bucket in buckets:
        slice_ids = tuple(sorted(item.slice_id for item in bucket))
        files = tuple(sorted({
            path for item in bucket for path in item.files
        }))
        groups.append(SliceGroup(
            group_id="group:" + "+".join(slice_ids),
            slice_ids=slice_ids,
            files=files,
            risk=max(item.risk for item in bucket),
        ))
    return tuple(sorted(groups, key=lambda item: item.group_id))


def _overlaps(item: AnalysisSlice, bucket: list[AnalysisSlice]) -> bool:
    nodes = set(item.node_ids)
    edges = set(item.edge_ids)
    return any(
        bool(nodes & set(existing.node_ids))
        or bool(edges & set(existing.edge_ids))
        or (
            item.sink_signal_id is not None
            and item.sink_signal_id == existing.sink_signal_id
        )
        for existing in bucket
    )


def _same_sink(item: AnalysisSlice, bucket: list[AnalysisSlice]) -> bool:
    return item.sink_signal_id is not None and any(
        item.sink_signal_id == existing.sink_signal_id
        for existing in bucket
    )


def _bounded_files(
    group_files: tuple[str, ...],
    members: list[HunterWorkItem],
    seed: str,
) -> tuple[str, ...]:
    member_files = [
        item.seed_file for item in members if item.seed_file != seed
    ]
    ordered = [seed, *sorted(set(member_files)), *sorted(group_files)]
    return tuple(dict.fromkeys(ordered))[:MAX_CONTEXT_FILES]
