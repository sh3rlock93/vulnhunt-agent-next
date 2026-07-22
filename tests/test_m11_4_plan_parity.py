from __future__ import annotations

from dataclasses import replace

from tests.factories import HASH_A
from vulnhunt_agent.analysis import build_c_analysis_graph, build_coverage_plan
from vulnhunt_agent.domain.schemas import BudgetPolicy
from vulnhunt_agent.scheduling import (
    NATIVE_PLAN_CONTRACT_POLICY,
    allocate_native_work_plan,
    build_native_work_plan,
)


def _analysis(tmp_path):
    repo = tmp_path / "plan-parity"
    repo.mkdir()
    (repo / "decode.c").write_text(
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "int decode(unsigned count) {\n"
        "  char *dst = malloc(count);\n"
        "  char src[8] = {0};\n"
        "  memcpy(dst, src, count);\n"
        "  return dst == 0;\n"
        "}\n",
        encoding="utf-8",
    )
    graph = build_c_analysis_graph(repo, ["decode.c"])
    coverage = build_coverage_plan(graph)
    return coverage, {
        "language": "c",
        "graph": graph.model_dump(mode="json"),
        "coverage_plan": coverage.model_dump(mode="json"),
        "incremental_scope": {"mode": "full"},
    }


def test_native_plan_contract_ignores_run_identity(tmp_path) -> None:
    coverage, analysis = _analysis(tmp_path)
    inputs = {
        "source_snapshot": HASH_A,
        "selected_files": list(coverage.selected_files),
        "enabled_hunters": ["c-bounds-integers", "c-memory-lifetime"],
        "analysis": analysis,
    }
    first_work = build_native_work_plan(run_id="deterministic", **inputs)
    second_work = build_native_work_plan(run_id="authenticated", **inputs)
    policy = BudgetPolicy(max_hunter_sessions=4, max_retries_per_work_item=1)

    first = allocate_native_work_plan(first_work, policy)
    second = allocate_native_work_plan(second_work, policy)

    assert first.contract == second.contract
    assert first.contract["policy_version"] == NATIVE_PLAN_CONTRACT_POLICY
    assert len(first.contract["semantic_sha256"]) == 64
    assert first.allocation == second.allocation
    assert [item.work_id for item in first.work_items] == [
        item.work_id for item in second.work_items
    ]
    assert {item.run_id for item in first.work_items} == {"deterministic"}
    assert {item.run_id for item in second.work_items} == {"authenticated"}


def test_normalized_plan_contract_ignores_snapshot_specific_ids(tmp_path) -> None:
    coverage, analysis = _analysis(tmp_path)
    inputs = {
        "run_id": "same-run",
        "selected_files": list(coverage.selected_files),
        "enabled_hunters": ["c-bounds-integers", "c-memory-lifetime"],
        "analysis": analysis,
    }
    first_work = build_native_work_plan(source_snapshot=HASH_A, **inputs)
    second_work = build_native_work_plan(
        source_snapshot="sha256:" + "b" * 64,
        **inputs,
    )
    policy = BudgetPolicy(max_hunter_sessions=4, max_retries_per_work_item=1)

    first = allocate_native_work_plan(first_work, policy)
    second = allocate_native_work_plan(second_work, policy)

    assert first.contract["semantic_sha256"] != second.contract["semantic_sha256"]
    assert first.contract["normalized_semantic_sha256"] == (
        second.contract["normalized_semantic_sha256"]
    )
    assert first.allocation.admitted_work_ids != second.allocation.admitted_work_ids


def test_normalized_plan_contract_ignores_scope_identity_digest(tmp_path) -> None:
    coverage, analysis = _analysis(tmp_path)
    inputs = {
        "run_id": "same-run",
        "source_snapshot": HASH_A,
        "selected_files": list(coverage.selected_files),
        "enabled_hunters": ["c-bounds-integers"],
        "analysis": analysis,
    }
    first_work = build_native_work_plan(**inputs)
    second_work = replace(
        first_work,
        work_items=tuple(
            item.model_copy(update={"scan_scope_digest": "sha256:" + "b" * 64})
            for item in first_work.work_items
        ),
    )
    policy = BudgetPolicy(max_hunter_sessions=4, max_retries_per_work_item=0)

    first = allocate_native_work_plan(first_work, policy)
    second = allocate_native_work_plan(second_work, policy)

    assert first.contract["semantic_sha256"] != second.contract["semantic_sha256"]
    assert first.contract["normalized_semantic_sha256"] == (
        second.contract["normalized_semantic_sha256"]
    )


def test_native_plan_contract_records_hunter_selection(tmp_path) -> None:
    coverage, analysis = _analysis(tmp_path)
    policy = BudgetPolicy(max_hunter_sessions=4, max_retries_per_work_item=0)

    def contract(hunters: list[str]):
        work = build_native_work_plan(
            run_id="same-run",
            source_snapshot=HASH_A,
            selected_files=list(coverage.selected_files),
            enabled_hunters=hunters,
            analysis=analysis,
        )
        return allocate_native_work_plan(work, policy).contract

    bounds = contract(["c-bounds-integers"])
    both = contract(["c-bounds-integers", "c-memory-lifetime"])

    assert bounds["enabled_hunters"] == ["c-bounds-integers"]
    assert both["enabled_hunters"] == [
        "c-bounds-integers",
        "c-memory-lifetime",
    ]
    assert bounds["semantic_sha256"] != both["semantic_sha256"]


def test_native_plan_contract_records_capacity_policy(tmp_path) -> None:
    coverage, analysis = _analysis(tmp_path)
    work = build_native_work_plan(
        run_id="same-run",
        source_snapshot=HASH_A,
        selected_files=list(coverage.selected_files),
        enabled_hunters=["c-bounds-integers"],
        analysis=analysis,
    )
    policy = BudgetPolicy(max_hunter_sessions=4, max_retries_per_work_item=0)

    enabled = allocate_native_work_plan(work, policy)
    disabled = allocate_native_work_plan(
        work,
        policy,
        include_capacity_chains=False,
    )

    assert enabled.contract["semantic_sha256"] != disabled.contract["semantic_sha256"]
    assert enabled.contract["capacity_units"] == [
        {
            "unit_id": unit.unit_id,
            "policy_version": unit.policy_version,
            "root_cause_group": unit.root_cause_group,
            "priority_class": unit.priority_class,
            "representative_chain_id": unit.representative_chain_id,
            "representative_work_id": unit.representative_work_id,
            "chain_ids": unit.chain_ids,
            "work_ids": unit.work_ids,
            "required_paths": unit.required_paths,
            "evidence_lines": unit.evidence_lines,
        }
        for unit in enabled.allocation.capacity_units
    ]
    assert disabled.contract["capacity_units"] == []
