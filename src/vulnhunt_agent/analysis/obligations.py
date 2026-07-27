"""Repository-agnostic invariant obligations derived from current graph facts."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .models import (
    CAnalysisGraph,
    CapacityRiskChain,
    CursorTransitionChain,
    InvariantObligation,
    InvariantObligationKind,
    ObligationEvidenceRange,
    RiskChain,
)

INVARIANT_OBLIGATION_POLICY = "invariant-obligation-v1"

_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class _ObligationSeed:
    kind: InvariantObligationKind
    structural_facts: tuple[str, ...]
    evidence_ranges: tuple[ObligationEvidenceRange, ...]
    required_hunters: tuple[str, ...]
    source_fact_ids: tuple[str, ...]
    target_node_ids: tuple[str, ...]
    target_signal_ids: tuple[str, ...]
    confidence: str
    rationale: str


def build_invariant_obligations(graph: CAnalysisGraph) -> tuple[InvariantObligation, ...]:
    """Derive obligations only from graph facts; knowledge cards are not inputs."""
    optional_seeds = [
        *(_capacity_seed(chain) for chain in graph.capacity_risk_chains),
        *(_cursor_seed(chain) for chain in graph.cursor_transition_chains),
    ]
    seeds = [
        *(_risk_seed(chain) for chain in graph.risk_chains),
        *(seed for seed in optional_seeds if seed is not None),
    ]
    grouped: dict[str, list[_ObligationSeed]] = {}
    for seed in seeds:
        grouped.setdefault(_obligation_id(seed.kind, seed.structural_facts), []).append(seed)

    obligations = []
    for obligation_id, matches in sorted(grouped.items()):
        first = matches[0]
        obligations.append(InvariantObligation(
            obligation_id=obligation_id,
            kind=first.kind,
            structural_facts=first.structural_facts,
            evidence_ranges=_unique_ranges(matches),
            required_hunters=tuple(sorted({
                hunter for seed in matches for hunter in seed.required_hunters
            })),
            source_fact_ids=tuple(sorted({
                fact_id for seed in matches for fact_id in seed.source_fact_ids
            })),
            target_node_ids=tuple(sorted({
                node_id for seed in matches for node_id in seed.target_node_ids
            })),
            target_signal_ids=tuple(sorted({
                signal_id for seed in matches for signal_id in seed.target_signal_ids
            })),
            confidence=min(
                (seed.confidence for seed in matches),
                key=lambda value: _CONFIDENCE_RANK[value],
            ),
            rationale=first.rationale,
        ))
    return tuple(obligations)


def _risk_seed(chain: RiskChain) -> _ObligationSeed:
    transforms = tuple(
        "transform=" + ",".join((
            *_operation_classes(step.operations),
            f"wrap={int(step.narrowing_or_wrap)}",
            "types=" + ",".join(sorted(_type_class(item) for item in step.operand_types)),
        ))
        for step in chain.transform_steps
    )
    structural = (
        f"guard={chain.guard_state.value}",
        f"source_present={int(bool(chain.source_signal_ids))}",
        f"source_count={len(chain.source_signal_ids)}",
        f"allocation_count={len(chain.allocation_signal_ids)}",
        f"access_count={len(chain.sink_signal_ids) or len(chain.sink_lines)}",
        *transforms,
    )
    evidence = [
        *(_ranges(chain.path, chain.source_lines, "source")),
        *(
            ObligationEvidenceRange(
                path=chain.path,
                line=step.line,
                end_line=step.line,
                structural_role="transform",
            )
            for step in chain.transform_steps
        ),
        *(_ranges(chain.path, chain.guard_lines, "guard")),
        *(_ranges(chain.path, chain.sink_lines, "access")),
    ]
    return _ObligationSeed(
        kind=InvariantObligationKind.INTEGER_MEMORY_RELATION,
        structural_facts=structural,
        evidence_ranges=_dedupe_ranges(evidence),
        required_hunters=("c-bounds-integers",),
        source_fact_ids=tuple(sorted({
            chain.chain_id,
            *chain.source_signal_ids,
            *chain.allocation_signal_ids,
            *chain.sink_signal_ids,
        })),
        target_node_ids=(chain.node_id,),
        target_signal_ids=tuple(sorted({
            *chain.allocation_signal_ids,
            *chain.sink_signal_ids,
        })),
        confidence=chain.confidence,
        rationale=(
            "Prove that the validated numeric domain used for allocation covers "
            "the independent value controlling the later memory access."
        ),
    )


def _capacity_seed(chain: CapacityRiskChain) -> _ObligationSeed | None:
    structural = (
        f"guard={chain.guard_state.value}",
        f"priority={chain.priority_class.value}",
        "missing=" + ",".join(sorted({
            _missing_class(item) for item in chain.missing_elements
        })),
        f"node_hops={len(chain.node_ids)}",
        f"call_hops={len(chain.call_ids)}",
        f"write_count={len(chain.write_fact_ids)}",
        f"advance_count={len(chain.pointer_advance_fact_ids)}",
        f"return_count={len(chain.return_consumption_call_ids)}",
        f"safe_growth_count={len(chain.safe_growth_fact_ids)}",
        f"entrypoint_reachable={int(chain.entrypoint_reachable)}",
    )
    evidence = _dedupe_ranges([
        ObligationEvidenceRange(
            path=path,
            line=int(line),
            end_line=int(line),
            structural_role="relation",
        )
        for path, lines in chain.evidence_lines.items()
        for line in lines
    ])
    if not evidence:
        return None
    return _ObligationSeed(
        kind=InvariantObligationKind.CAPACITY_RELATION,
        structural_facts=structural,
        evidence_ranges=evidence,
        required_hunters=("c-bounds-integers",),
        source_fact_ids=tuple(sorted({
            chain.chain_id,
            *chain.fact_ids,
            *chain.call_ids,
            *chain.summary_ids,
        })),
        target_node_ids=tuple(sorted(set(chain.node_ids))),
        target_signal_ids=tuple(sorted({
            *chain.source_signal_ids,
            *chain.allocation_signal_ids,
            *chain.write_signal_ids,
        })),
        confidence=chain.confidence,
        rationale=(
            "Prove that capacity, pointer movement, and write extent remain in "
            "one unit across aliases and call boundaries."
        ),
    )


def _cursor_seed(chain: CursorTransitionChain) -> _ObligationSeed | None:
    structural = (
        f"guard={chain.guard_state.value}",
        f"required_access_index={chain.required_access_index}",
        "observed_guard_index=" + (
            "none" if chain.observed_guard_index is None
            else str(chain.observed_guard_index)
        ),
        f"cross_file={int(len(set(chain.paths)) > 1)}",
        f"fact_count={len(chain.fact_ids)}",
    )
    evidence = _dedupe_ranges([
        ObligationEvidenceRange(
            path=path,
            line=int(line),
            end_line=int(line),
            structural_role="relation",
        )
        for path, lines in chain.evidence_lines.items()
        for line in lines
    ])
    if not evidence:
        return None
    return _ObligationSeed(
        kind=InvariantObligationKind.CURSOR_LENGTH_RELATION,
        structural_facts=structural,
        evidence_ranges=evidence,
        required_hunters=("c-bounds-integers", "c-parser-state"),
        source_fact_ids=tuple(sorted({
            chain.chain_id,
            *chain.fact_ids,
            *chain.guard_fact_ids,
        })),
        target_node_ids=tuple(sorted({chain.caller_node_id, chain.reader_node_id})),
        target_signal_ids=(),
        confidence=chain.confidence,
        rationale=(
            "Prove that a dominating remaining-input guard covers the largest "
            "post-mutation dereference index across the parser boundary."
        ),
    )


def _obligation_id(
    kind: InvariantObligationKind,
    structural_facts: tuple[str, ...],
) -> str:
    canonical = json.dumps(
        {
            "policy_version": INVARIANT_OBLIGATION_POLICY,
            "kind": kind.value,
            "structural_facts": structural_facts,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "obligation_" + hashlib.sha256(canonical.encode()).hexdigest()[:20]


def _ranges(
    path: str,
    lines: tuple[int, ...],
    role: str,
) -> tuple[ObligationEvidenceRange, ...]:
    return tuple(
        ObligationEvidenceRange(
            path=path,
            line=int(line),
            end_line=int(line),
            structural_role=role,
        )
        for line in lines
    )


def _unique_ranges(matches: list[_ObligationSeed]) -> tuple[ObligationEvidenceRange, ...]:
    return _dedupe_ranges([
        evidence for seed in matches for evidence in seed.evidence_ranges
    ])


def _dedupe_ranges(
    ranges: list[ObligationEvidenceRange],
) -> tuple[ObligationEvidenceRange, ...]:
    unique = {_range_key(item): item for item in ranges}
    return tuple(unique[key] for key in sorted(unique))


def _range_key(item: ObligationEvidenceRange) -> tuple[str, int, int, str]:
    return item.path, item.line, item.end_line, item.structural_role


def _operation_classes(operations: tuple[str, ...]) -> tuple[str, ...]:
    classes = []
    for operation in operations:
        lowered = operation.lower()
        if "*" in lowered or "mul" in lowered:
            classes.append("multiply")
        elif "+" in lowered or "add" in lowered:
            classes.append("add")
        elif "-" in lowered or "sub" in lowered:
            classes.append("subtract")
        elif "shift" in lowered or "<<" in lowered or ">>" in lowered:
            classes.append("shift")
        elif "cast" in lowered or "convert" in lowered:
            classes.append("convert")
        else:
            classes.append("other")
    return tuple(classes)


def _type_class(value: str) -> str:
    lowered = value.lower()
    sign = (
        "unsigned"
        if "unsigned" in lowered or re.search(r"\buint(?:8|16|32|64)?_t\b", lowered)
        else "signed"
    )
    pointer = "pointer" if "*" in value else "scalar"
    width = next((item for item in ("8", "16", "32", "64") if item in lowered), "native")
    return f"{sign}-{pointer}-{width}"


def _missing_class(value: str) -> str:
    lowered = value.lower()
    for token in ("source", "write", "guard", "advance", "growth", "return", "call"):
        if token in lowered:
            return token
    return "other"
