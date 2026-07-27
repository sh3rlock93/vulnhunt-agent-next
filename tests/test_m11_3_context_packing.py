from __future__ import annotations

import json

from vulnhunt_agent.analysis.context_cache import (
    MAX_CONTEXT_BYTES,
    MIN_EVIDENCE_EXCERPT_BYTES,
    _fit_packet,
    _packet_digest,
)


def _truncation() -> dict:
    return {
        "max_context_bytes": MAX_CONTEXT_BYTES,
        "omitted": [],
        "trimmed": [],
        "packet_fit_applied": False,
        "removed_slices": 0,
        "removed_risk_chains": 0,
        "removed_capacity_risk_chains": 0,
        "compacted_capacity_risk_chains": 0,
        "removed_selected_range_files": 0,
        "removed_related_nodes": 0,
        "removed_constraints": 0,
    }


def test_packet_fit_discards_supporting_metadata_before_focus_source() -> None:
    focus_id = "risk_aaaaaaaaaaaaaaaaaaaa"
    packet = {
        "cache_key": "context_" + "a" * 64,
        "source_snapshot": "a" * 64,
        "context_policy": "c-context-v8",
        "focus_chain_ids": [focus_id],
        "risk_chains": [
            {
                "chain_id": focus_id,
                "path": "focus.c",
                "rationale": "focus evidence",
            },
            {
                "chain_id": "risk_bbbbbbbbbbbbbbbbbbbb",
                "path": "support.c",
                "rationale": "S" * 7_000,
            },
        ],
        "capacity_risk_chains": [],
        "slices": [{"rationale": "X" * 7_000}],
        "related_nodes": [{"path": "support.c", "detail": "R" * 5_000}],
        "constraint_facts": [{"path": "support.c", "evidence": "C" * 5_000}],
        "source_excerpts": [
            {
                "path": "focus.c",
                "kind": "target",
                "truncated": False,
                "content": "F" * 4_000,
            },
            {
                "path": "support.c",
                "kind": "related",
                "truncated": False,
                "content": "U" * 5_000,
            },
        ],
        "truncation": _truncation(),
    }

    fitted = _fit_packet(packet)
    fitted["packet_digest"] = _packet_digest(fitted)
    encoded = (json.dumps(
        fitted,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n").encode()

    focus_excerpt = next(
        item for item in fitted["source_excerpts"] if item["path"] == "focus.c"
    )
    assert len(encoded) <= MAX_CONTEXT_BYTES
    assert len(focus_excerpt["content"].encode()) >= MIN_EVIDENCE_EXCERPT_BYTES
    assert fitted["risk_chains"] == [{
        "chain_id": focus_id,
        "path": "focus.c",
        "rationale": "focus evidence",
    }]
    assert fitted["slices"] == []
    assert fitted["truncation"]["evidence_excerpt_guaranteed"] is True
    assert fitted["truncation"]["packet_fit_applied"] is True


def test_packet_fit_falls_back_to_nonempty_target_without_focus_chain() -> None:
    packet = {
        "focus_chain_ids": [],
        "risk_chains": [{
            "chain_id": "risk_cccccccccccccccccccc",
            "path": "target.c",
            "rationale": "legacy direct-call focus",
        }],
        "capacity_risk_chains": [],
        "slices": [{"rationale": "X" * 30_000}],
        "related_nodes": [],
        "constraint_facts": [],
        "source_excerpts": [{
            "path": "target.c",
            "kind": "target",
            "truncated": False,
            "content": "int main(void) { return 0; }",
        }],
        "truncation": _truncation(),
    }

    fitted = _fit_packet(packet)

    assert fitted["source_excerpts"][0]["content"] == "int main(void) { return 0; }"
    assert fitted["risk_chains"][0]["chain_id"] == "risk_cccccccccccccccccccc"
    assert fitted["truncation"]["evidence_excerpt_guaranteed"] is True


def test_packet_fit_compacts_one_large_focus_capacity_chain_before_source() -> None:
    focus_id = "capacity_risk_" + "d" * 20
    packet = {
        "focus_chain_ids": [focus_id],
        "risk_chains": [],
        "capacity_risk_chains": [{
            "chain_id": focus_id,
            "policy_version": "c-capacity-risk-chain-v3",
            "root_cause_group": "capacity_group_" + "e" * 20,
            "root_path": "decode.c",
            "root_function": "decode",
            "base": "output",
            "element_count": "capacity",
            "element_size": "1",
            "paths": ["decode.c", "write.c"],
            "fact_ids": [f"capacity_{index:020x}" for index in range(2_000)],
            "call_ids": [f"capacity_call_{index:020x}" for index in range(50)],
            "summary_ids": [f"capacity_summary_{index:020x}" for index in range(50)],
            "pointer_advance_fact_ids": ["capacity_" + "1" * 20],
            "write_fact_ids": ["capacity_" + "2" * 20],
            "guard_fact_ids": [],
            "guard_state": "absent",
            "missing_elements": ["source"],
            "evidence_lines": {"decode.c": [10], "write.c": [20]},
            "priority_class": "complete_unchecked_capacity_path",
            "score": 100,
            "confidence": "high",
            "entrypoint_reachable": True,
            "evidence_facts": [{
                "fact_id": "capacity_" + "3" * 20,
                "kind": "write",
                "path": "write.c",
                "line": 20,
                "write_extent": "row_width",
                "evidence": "memcpy writes row_width bytes",
            }],
            "rationale": "complete cross-file capacity path",
        }],
        "slices": [],
        "related_nodes": [],
        "constraint_facts": [],
        "source_excerpts": [{
            "path": "decode.c",
            "kind": "target",
            "truncated": False,
            "content": "F" * 4_000,
        }],
        "truncation": _truncation(),
    }

    fitted = _fit_packet(packet)
    encoded = (json.dumps(
        {**fitted, "packet_digest": "sha256:" + "0" * 64},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n").encode()
    chain = fitted["capacity_risk_chains"][0]

    assert len(encoded) <= MAX_CONTEXT_BYTES
    assert chain["chain_id"] == focus_id
    assert chain["paths"] == ["decode.c", "write.c"]
    assert chain["evidence_lines"] == {"decode.c": [10], "write.c": [20]}
    assert chain["write_count"] == 1
    assert chain["evidence_facts"][0]["write_extent"] == "row_width"
    assert "fact_ids" not in chain
    assert len(fitted["source_excerpts"][0]["content"]) == 4_000
    assert fitted["truncation"]["compacted_capacity_risk_chains"] == 1


def test_packet_fit_removes_non_focus_selected_range_fanout() -> None:
    focus_id = "risk_" + "f" * 20
    packet = {
        "focus_chain_ids": [focus_id],
        "risk_chains": [{
            "chain_id": focus_id,
            "path": "focus.c",
            "rationale": "focused risk chain",
        }],
        "capacity_risk_chains": [],
        "slices": [],
        "related_nodes": [],
        "constraint_facts": [],
        "selected_ranges": {
            "focus.c": [[line, line] for line in range(1, 80)],
            **{
                f"support_{index}.c": [
                    [line, line] for line in range(1, 80)
                ]
                for index in range(40)
            },
        },
        "source_excerpts": [{
            "path": "focus.c",
            "kind": "target",
            "truncated": False,
            "content": "F" * 4_000,
        }],
        "truncation": _truncation(),
    }

    fitted = _fit_packet(packet)
    encoded = (json.dumps(
        {**fitted, "packet_digest": "sha256:" + "0" * 64},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n").encode()

    assert len(encoded) <= MAX_CONTEXT_BYTES
    assert "focus.c" in fitted["selected_ranges"]
    assert len(fitted["selected_ranges"]) < 41
    assert len(fitted["source_excerpts"][0]["content"]) == 4_000
    assert fitted["truncation"]["removed_selected_range_files"] > 0


def test_packet_fit_caps_oversized_focus_selected_ranges() -> None:
    focus_id = "risk_" + "1" * 20
    packet = {
        "focus_chain_ids": [focus_id],
        "risk_chains": [{"chain_id": focus_id, "path": "focus.c"}],
        "capacity_risk_chains": [],
        "slices": [],
        "related_nodes": [],
        "constraint_facts": [],
        "selected_ranges": {
            "focus.c": [[line, line] for line in range(1, 4_000)],
        },
        "source_excerpts": [{
            "path": "focus.c",
            "kind": "target",
            "truncated": False,
            "content": "F" * 4_000,
        }],
        "truncation": _truncation(),
    }

    fitted = _fit_packet(packet)

    assert len(fitted["selected_ranges"]["focus.c"]) == 32
    assert len(fitted["source_excerpts"][0]["content"]) == 4_000
    assert fitted["truncation"]["trimmed_selected_ranges"] == 3_967


def test_packet_fit_compacts_single_focus_proof_metadata_before_failing() -> None:
    risk_id = "risk_" + "2" * 20
    cursor_id = "cursor_transition_" + "3" * 20
    packet = {
        "focus_chain_ids": [risk_id],
        "risk_chains": [{
            "chain_id": risk_id,
            "path": "focus.c",
            "transform_steps": [{
                "path": "focus.c",
                "line": 10,
                "operation": "X" * 20_000,
                "operations": ["Y" * 5_000] * 10,
                "narrowing_or_wrap": True,
            }],
            "rationale": "R" * 20_000,
        }],
        "capacity_risk_chains": [],
        "cursor_transition_chains": [{
            "chain_id": cursor_id,
            "paths": ["focus.c"],
            "guard_state": "absent",
            "evidence_lines": {"focus.c": list(range(1, 500))},
            "rationale": "C" * 20_000,
        }],
        "vulnerability_knowledge": {"cards": [{
            "pattern_id": "vpattern_test",
            "weakness_family": "bounds",
            "matched_semantic_tags": ["write"],
            "invariant": "I" * 10_000,
            "investigation_steps": ["S" * 10_000] * 8,
            "required_evidence": ["E" * 10_000] * 6,
            "falsifiers": ["F" * 10_000] * 6,
        }]},
        "slices": [],
        "related_nodes": [],
        "constraint_facts": [],
        "source_excerpts": [{
            "path": "focus.c",
            "kind": "target",
            "truncated": False,
            "content": "source evidence\n" * 300,
        }],
        "truncation": _truncation(),
    }

    fitted = _fit_packet(packet)
    encoded = (json.dumps(
        {**fitted, "packet_digest": "sha256:" + "0" * 64},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n").encode()

    assert len(encoded) <= MAX_CONTEXT_BYTES
    assert fitted["risk_chains"][0]["chain_id"] == risk_id
    assert fitted["cursor_transition_chains"][0]["chain_id"] == cursor_id
    assert fitted["vulnerability_knowledge"]["cards"][0]["pattern_id"] == (
        "vpattern_test"
    )
    assert len(fitted["source_excerpts"][0]["content"].encode()) >= (
        MIN_EVIDENCE_EXCERPT_BYTES
    )
