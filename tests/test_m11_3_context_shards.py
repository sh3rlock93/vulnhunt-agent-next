from __future__ import annotations

from pathlib import Path

from tests.factories import HASH_A
from vulnhunt_agent.analysis import SharedContextCache, context_for_work_item
from vulnhunt_agent.analysis.context_cache import MAX_CONTEXT_BYTES
from vulnhunt_agent.domain.schemas import HunterWorkItem
from vulnhunt_agent.scheduling import work_id_for


def _chain(index: int, *, rationale_bytes: int) -> dict:
    suffix = format(index, "020x")
    return {
        "chain_id": f"capacity_risk_{suffix}",
        "policy_version": "c-capacity-risk-chain-v3",
        "root_cause_group": f"capacity_group_{suffix}",
        "allocation_fact_id": f"capacity_{suffix}",
        "root_node_id": "decode.c::decode@1",
        "root_path": "decode.c",
        "root_function": "decode",
        "base": "output",
        "element_count": f"count_{index}",
        "element_size": "sizeof(*output)",
        "node_ids": ["decode.c::decode@1"],
        "paths": ["decode.c"],
        "fact_ids": [f"capacity_{suffix}"],
        "source_signal_ids": [],
        "allocation_signal_ids": ["sig-shard-allocation"],
        "write_signal_ids": [f"sig-write-{index}"],
        "write_fact_ids": [f"capacity_{suffix}"],
        "guard_state": "absent",
        "missing_elements": ["source"],
        "evidence_lines": {"decode.c": [index * 10]},
        "priority_class": "partial_capacity_path",
        "score": 80 - index,
        "confidence": "medium",
        "entrypoint_reachable": True,
        "rationale": "R" * rationale_bytes,
    }


def _work(chain_ids: tuple[str, ...]) -> HunterWorkItem:
    work_id = work_id_for(
        source_snapshot=HASH_A,
        planning_policy="c-slice-work-v4",
        slice_ids=("slice-shard",),
        files=("decode.c",),
        hunter="c-bounds-integers",
        target_signal_ids=("sig-shard-allocation",),
    )
    return HunterWorkItem(
        work_id=work_id,
        run_id="run-context-shards",
        source_snapshot=HASH_A,
        planning_policy="c-slice-work-v4",
        slice_ids=("slice-shard",),
        target_signal_ids=("sig-shard-allocation",),
        focus_chain_ids=chain_ids,
        seed_file="decode.c",
        files=("decode.c",),
        hunter="c-bounds-integers",
        risk=5,
        required=True,
        routing_reasons=("context shard fixture",),
    )


def _fixture(tmp_path: Path, *, rationale_bytes: int) -> tuple[Path, dict, HunterWorkItem]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "decode.c").write_text(
        "\n".join(f"int value_{line} = {line};" for line in range(1, 81)) + "\n"
    )
    chains = tuple(_chain(index, rationale_bytes=rationale_bytes) for index in range(1, 5))
    work = _work(tuple(chain["chain_id"] for chain in chains))
    analysis = {
        "language": "c",
        "graph": {
            "schema_version": 2,
            "nodes": [],
            "signals": [],
            "risk_chains": [],
            "capacity_risk_chains": list(chains),
        },
        "coverage_plan": {"policy_version": "fixture", "slices": []},
    }
    return repo, analysis, work


def test_oversized_focus_context_materializes_one_bounded_packet_per_chain(
    tmp_path: Path,
) -> None:
    repo, analysis, work = _fixture(tmp_path, rationale_bytes=9_000)
    compact = context_for_work_item(analysis, work)
    assert [
        chain["chain_id"] for chain in compact["capacity_risk_chains"]
    ] == list(work.focus_chain_ids)

    cache = SharedContextCache(
        tmp_path / "cache",
        repo,
        source_snapshot=HASH_A,
        analysis=analysis,
    )
    shards = cache.get_shards(work)

    assert len(shards) == len(work.focus_chain_ids)
    assert [packet["focus_chain_ids"][0] for packet in shards] == list(
        work.focus_chain_ids
    )
    assert {
        chain["chain_id"]
        for packet in shards
        for chain in packet["capacity_risk_chains"]
    } >= set(work.focus_chain_ids)
    assert all(
        any(excerpt["content"] for excerpt in packet["source_excerpts"])
        for packet in shards
    )
    assert all(
        (tmp_path / "cache" / f"{packet['cache_key']}.json").stat().st_size
        <= MAX_CONTEXT_BYTES
        for packet in shards
    )
    stats = cache.stats()
    assert stats["sharded_work_items"] == 1
    assert stats["shard_packets"] == 4


def test_small_multi_chain_context_stays_in_one_packet(tmp_path: Path) -> None:
    repo, analysis, work = _fixture(tmp_path, rationale_bytes=32)
    cache = SharedContextCache(
        tmp_path / "cache-small",
        repo,
        source_snapshot=HASH_A,
        analysis=analysis,
    )

    shards = cache.get_shards(work)

    assert len(shards) == 1
    assert set(work.focus_chain_ids) <= {
        chain["chain_id"] for chain in shards[0]["capacity_risk_chains"]
    }
    assert cache.stats()["sharded_work_items"] == 0


def test_capacity_context_preserves_ranked_formula_evidence(tmp_path: Path) -> None:
    repo, analysis, work = _fixture(tmp_path, rationale_bytes=32)
    first_chain = analysis["graph"]["capacity_risk_chains"][0]
    allocation_id = first_chain["allocation_fact_id"]
    derivation_id = "capacity_" + "f" * 20
    first_chain["fact_ids"] = [allocation_id, derivation_id]
    analysis["graph"]["capacity_facts"] = [
        {
            "fact_id": allocation_id,
            "kind": "allocation",
            "path": "decode.c",
            "line": 10,
            "function": "decode",
            "subject": "output",
            "base": "output",
            "element_count": "plane_size(width, height)",
            "offset": "0",
            "remaining_capacity": "plane_size(width, height)",
            "write_extent": "",
            "evidence": "output allocated by malloc(plane_size(width, height))",
        },
        {
            "fact_id": derivation_id,
            "kind": "write",
            "path": "decode.c",
            "line": 20,
            "function": "decode",
            "subject": "plane_width",
            "base": "output",
            "element_count": "",
            "offset": "row * stride",
            "remaining_capacity": "",
            "write_extent": "PAD(width, sampling) / sampling",
            "evidence": "memcpy writes PAD(width, sampling) / sampling bytes",
        },
    ]

    packet = context_for_work_item(analysis, work)
    evidence = packet["capacity_risk_chains"][0]["evidence_facts"]

    assert [item["fact_id"] for item in evidence] == [
        allocation_id,
        derivation_id,
    ]
    assert evidence[1]["write_extent"] == "PAD(width, sampling) / sampling"
