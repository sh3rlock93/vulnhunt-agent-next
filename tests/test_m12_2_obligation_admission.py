from __future__ import annotations

from pathlib import Path

import pytest

from vulnhunt_agent.analysis import (
    CAnalysisGraph,
    InvariantObligation,
    InvariantObligationKind,
    ObligationEvidenceRange,
)
from vulnhunt_agent.analysis.context_cache import SharedContextCache
from vulnhunt_agent.agents.hunter import (
    _expected_target_ids,
    _focused_source_requirements,
    _has_focused_source_read,
)
from vulnhunt_agent.domain.schemas import BudgetPolicy, BudgetUsage, HunterWorkItem
from vulnhunt_agent.scheduling import (
    HUNTER_INPUT_SOFT_STOP,
    BudgetController,
    BudgetExceededError,
    RecyclableAdmissionLedger,
    allocate_work_items,
    bind_invariant_obligations,
    work_id_for,
)

SNAPSHOT = "sha256:" + "a" * 64


def _obligation(
    index: int,
    kind: InvariantObligationKind,
    hunters: tuple[str, ...],
    *,
    guard: str = "absent",
) -> InvariantObligation:
    path = f"src/case-{index}.c"
    return InvariantObligation(
        obligation_id=f"obligation_{index:020x}",
        kind=kind,
        structural_facts=(f"guard={guard}", f"case_class={kind.value}"),
        evidence_ranges=(ObligationEvidenceRange(
            path=path,
            line=10 + index,
            end_line=11 + index,
            structural_role="relation",
        ),),
        required_hunters=hunters,
        source_fact_ids=(f"fact-{index}",),
        target_node_ids=(f"node-{index}",),
        confidence="high",
        rationale="Prove the current-source relation.",
    )


def _work(
    index: int,
    path: str,
    hunter: str,
    *,
    obligation_ids: tuple[str, ...] = (),
    signal_id: str = "",
) -> HunterWorkItem:
    signals = (signal_id,) if signal_id else ()
    work_id = work_id_for(
        source_snapshot=SNAPSHOT,
        planning_policy="test-obligation-plan-v1",
        slice_ids=(),
        files=(path,),
        hunter=hunter,
        target_signal_ids=signals,
        obligation_ids=obligation_ids,
    )
    return HunterWorkItem(
        work_id=work_id,
        run_id="run-obligation",
        source_snapshot=SNAPSHOT,
        planning_policy="test-obligation-plan-v1",
        target_signal_ids=signals,
        obligation_ids=obligation_ids,
        seed_file=path,
        files=(path,),
        hunter=hunter,
        risk=2,
        required=False,
        routing_reasons=("test:obligation",),
    )


def _four_calibration_obligations() -> tuple[InvariantObligation, ...]:
    return (
        _obligation(
            1,
            InvariantObligationKind.FORMATTED_OUTPUT_EXPANSION,
            ("c-bounds-integers", "c-injection-format"),
        ),
        _obligation(
            2,
            InvariantObligationKind.STATEFUL_OUTPUT_CAPACITY,
            ("c-bounds-integers",),
        ),
        _obligation(
            3,
            InvariantObligationKind.CURSOR_LENGTH_RELATION,
            ("c-bounds-integers", "c-parser-state"),
        ),
        _obligation(
            4,
            InvariantObligationKind.INTEGER_MEMORY_RELATION,
            ("c-bounds-integers",),
        ),
    )


def test_four_obligations_replace_low_priority_work_inside_twelve_sessions() -> None:
    obligations = _four_calibration_obligations()
    specialist_work = tuple(
        _work(index * 10 + hunter_index, f"src/case-{index}.c", hunter)
        for index, obligation in enumerate(obligations, start=1)
        for hunter_index, hunter in enumerate(obligation.required_hunters)
    )
    unrelated = tuple(
        _work(100 + index, f"src/unrelated-{index}.c", "c-memory-lifetime")
        for index in range(10)
    )
    original = (*specialist_work, *unrelated)
    graph = CAnalysisGraph(invariant_obligations=obligations)

    bound = bind_invariant_obligations(original, graph)
    allocation = allocate_work_items(
        bound,
        BudgetPolicy(max_hunter_sessions=12, max_retries_per_work_item=1),
        invariant_obligations=obligations,
        native_full_scan=True,
    )

    assert len(bound) == len(original)
    assert len(allocation.admitted_work_ids) <= 12
    expected_pairs = {
        (obligation.obligation_id, hunter)
        for obligation in obligations
        for hunter in obligation.required_hunters
    }
    assert {
        (record.obligation_id, record.hunter)
        for record in allocation.obligation_admissions
        if record.disposition == "admitted"
    } == expected_pairs
    assert allocation.obligation_required_slots == len(specialist_work)
    assert all(record.evidence_ranges for record in allocation.obligation_admissions)
    assert len(allocation.admitted_work_ids) < len(bound)


def test_safe_or_low_confidence_obligation_does_not_claim_a_session() -> None:
    safe = _obligation(
        5,
        InvariantObligationKind.CURSOR_LENGTH_RELATION,
        ("c-parser-state",),
        guard="dominates",
    )
    low = _obligation(
        6,
        InvariantObligationKind.INTEGER_MEMORY_RELATION,
        ("c-bounds-integers",),
    ).model_copy(update={"confidence": "low"})
    work = (
        _work(1, "src/case-5.c", "c-parser-state"),
        _work(2, "src/case-6.c", "c-bounds-integers"),
    )

    assert bind_invariant_obligations(
        work,
        CAnalysisGraph(invariant_obligations=(safe, low)),
    ) == work


def test_missing_specialist_is_cloned_in_cluster_and_replaces_other_work() -> None:
    obligation = _obligation(
        9,
        InvariantObligationKind.FORMATTED_OUTPUT_EXPANSION,
        ("c-bounds-integers", "c-injection-format"),
    )
    original = (_work(1, "src/case-9.c", "c-bounds-integers"),)

    bound = bind_invariant_obligations(
        original,
        CAnalysisGraph(invariant_obligations=(obligation,)),
    )
    allocation = allocate_work_items(
        bound,
        BudgetPolicy(max_hunter_sessions=2, max_retries_per_work_item=0),
        invariant_obligations=(obligation,),
        native_full_scan=True,
    )

    assert len(bound) == 2
    assert {item.hunter for item in bound} == {
        "c-bounds-integers", "c-injection-format"
    }
    assert len(allocation.admitted_work_ids) == 2
    assert all(
        record.disposition == "admitted"
        for record in allocation.obligation_admissions
    )


def test_duplicate_deferred_requires_the_same_obligation_identity() -> None:
    obligation = _obligation(
        7,
        InvariantObligationKind.INTEGER_MEMORY_RELATION,
        ("c-bounds-integers",),
    )
    first = _work(
        1,
        "src/case-7.c",
        "c-bounds-integers",
        obligation_ids=(obligation.obligation_id,),
    )
    second = first.model_copy(update={
        "work_id": work_id_for(
            source_snapshot=SNAPSHOT,
            planning_policy="test-obligation-plan-v1",
            slice_ids=("alternate",),
            files=first.files,
            hunter=first.hunter,
            obligation_ids=first.obligation_ids,
        ),
        "slice_ids": ("alternate",),
    })
    nonsemantic = (
        _work(3, "src/a.c", "c-memory-lifetime", signal_id="same"),
        _work(4, "src/b.c", "c-memory-lifetime", signal_id="same"),
    )
    allocation = allocate_work_items(
        (first, second, *nonsemantic),
        BudgetPolicy(max_hunter_sessions=2, max_retries_per_work_item=0),
        invariant_obligations=(obligation,),
        native_full_scan=True,
    )

    duplicate_records = [
        record for record in allocation.ranking
        if record.disposition == "duplicate_deferred"
    ]
    assert len(duplicate_records) == 1
    assert duplicate_records[0].obligation_ids == (obligation.obligation_id,)
    assert all(
        record.disposition != "duplicate_deferred"
        for record in allocation.ranking
        if not record.obligation_ids
    )


def test_ledger_closes_obligations_or_preserves_typed_source_backed_deferral() -> None:
    obligations = _four_calibration_obligations()[:2]
    work = bind_invariant_obligations(
        tuple(
            _work(index, f"src/case-{index}.c", obligation.required_hunters[0])
            for index, obligation in enumerate(obligations, start=1)
        ),
        CAnalysisGraph(invariant_obligations=obligations),
    )
    allocation = allocate_work_items(
        work,
        BudgetPolicy(max_hunter_sessions=1, max_retries_per_work_item=0),
        invariant_obligations=obligations,
        native_full_scan=True,
    )
    ledger = RecyclableAdmissionLedger(allocation)
    admitted = allocation.admitted_work_ids[0]
    ledger.mark_provider_started(admitted)
    ledger.finish(admitted, status="done")

    dispositions = ledger.snapshot()["obligation_dispositions"]
    assert {item["state"] for item in dispositions} == {"done", "budget_deferred"}
    assert all(item["source_evidence"] for item in dispositions)
    assert next(
        item for item in dispositions if item["state"] == "budget_deferred"
    )["reason"] == "max_hunter_sessions"


def test_input_soft_stop_prevents_new_calls_before_the_hard_limit() -> None:
    prior = BudgetUsage(
        run_id="run-obligation",
        work_id="work_" + "1" * 64,
        scope="hunter",
        model_id="test-model",
        transport="test",
        input_tokens=HUNTER_INPUT_SOFT_STOP - 10,
    )
    controller = BudgetController(
        BudgetPolicy(max_input_tokens=2_000_000),
        [prior],
    )

    with pytest.raises(BudgetExceededError, match="soft_input_token_stop"):
        controller.reserve_call(
            input_upper_bound=11,
            requested_output_tokens=10,
        )
    assert controller.snapshot()["input_tokens"] < 2_000_000


def test_context_packet_names_obligation_and_hydrates_its_evidence(tmp_path: Path) -> None:
    obligation = _obligation(
        8,
        InvariantObligationKind.STATEFUL_OUTPUT_CAPACITY,
        ("c-bounds-integers",),
    )
    source = tmp_path / "src" / "case-8.c"
    source.parent.mkdir()
    source.write_text("\n".join(f"line {line}" for line in range(1, 40)))
    work = _work(
        1,
        "src/case-8.c",
        "c-bounds-integers",
        obligation_ids=(obligation.obligation_id,),
    )
    analysis = {
        "language": "c",
        "graph": CAnalysisGraph(
            invariant_obligations=(obligation,),
        ).model_dump(mode="json"),
        "coverage_plan": {},
    }

    packet = SharedContextCache(
        tmp_path / "cache",
        tmp_path,
        source_snapshot=SNAPSHOT,
        analysis=analysis,
    ).get(work)

    assert packet["obligation_ids"] == [obligation.obligation_id]
    assert packet["invariant_obligations"][0]["obligation_id"] == (
        obligation.obligation_id
    )
    assert _expected_target_ids(packet) == (obligation.obligation_id,)
    requirements = _focused_source_requirements(packet)
    assert requirements == {"src/case-8.c": (18, 19)}
    assert not _has_focused_source_read([], requirements)
    assert _has_focused_source_read([{
        "path": "src/case-8.c",
        "start": 18,
        "end": 18,
        "bytes": 7,
    }], requirements)
    assert packet["selected_ranges"]["src/case-8.c"] == [[18, 19]]
    assert any(
        excerpt["path"] == "src/case-8.c" and "line 18" in excerpt["content"]
        for excerpt in packet["source_excerpts"]
    )
