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
        "removed_related_nodes": 0,
        "removed_constraints": 0,
    }


def test_packet_fit_discards_supporting_metadata_before_focus_source() -> None:
    focus_id = "risk_aaaaaaaaaaaaaaaaaaaa"
    packet = {
        "cache_key": "context_" + "a" * 64,
        "source_snapshot": "a" * 64,
        "context_policy": "c-context-v6",
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
        "risk_chains": [],
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
    assert fitted["truncation"]["evidence_excerpt_guaranteed"] is True
