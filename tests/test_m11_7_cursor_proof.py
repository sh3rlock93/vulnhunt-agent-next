from __future__ import annotations

import json
from typing import Any, cast

from vulnhunt_agent.agents.cursor_proof import validate_cursor_proofs
from vulnhunt_agent.agents.hunter import HunterAgent
from vulnhunt_agent.core.llm import LLMResponse

TARGET = "sig-cursor"
CHAIN = "cursor_transition_" + "a" * 20


def _context() -> dict:
    return {
        "change_focus": {"target_signal_ids": [TARGET]},
        "cursor_transition_chains": [{
            "chain_id": CHAIN,
            "target_signal_ids": [TARGET],
            "guard_state": "partial",
            "observed_guard_index": 0,
            "required_access_index": 1,
            "advance_delta": 1,
            "dereference_index": 0,
            "evidence_requirements": [
                {"role": "read", "path": "parser.c", "line": 14},
                {"role": "advance", "path": "parser.c", "line": 20},
                {"role": "call", "path": "parser.c", "line": 21},
                {"role": "guard", "path": "parser.c", "line": 24},
            ],
        }],
    }


def _proof(*, conclusion: str = "safe_proved", attempted: bool = False) -> dict:
    return {
        "policy_version": "c-cursor-proof-v1",
        "chain_id": CHAIN,
        "pre_guard_relation": "position + 0 < length before the loop body",
        "observed_guard_index": 0,
        "cursor_mutation": "position increments by one",
        "cursor_delta": 1,
        "post_mutation_relation": "position may equal length",
        "callee_entry_precondition": "read_label receives the incremented position",
        "dereference_relation": "CURRENT(view)[0] reads data[position]",
        "dereference_index": 0,
        "required_guard_index": 1,
        "minimum_boundary_case": "length-position=1 becomes zero after increment",
        "maximum_boundary_case": "the largest accepted position has the same gap",
        "conclusion": conclusion,
        "boundary_attempt": {
            "status": "executed" if attempted else "not_available",
            "execution_index": 1 if attempted else None,
            "rationale": "ASan boundary run" if attempted else "sandbox unavailable",
        },
    }


def _disposition(*, status: str = "no_finding", proof: dict | None = None) -> dict:
    item: dict[str, Any] = {
        "target_id": TARGET,
        "status": status,
        "finding_indices": [0] if status == "finding" else [],
        "rationale": "cursor boundary was analyzed",
    }
    if proof is not None:
        item["cursor_proof"] = proof
    return item


def _reads() -> list[dict]:
    return [{"path": "parser.c", "start": 12, "end": 24, "bytes": 800}]


def test_complete_source_grounded_proof_closes_without_sandbox() -> None:
    error = validate_cursor_proofs(
        _context(),
        [_disposition(proof=_proof())],
        expected_targets=(TARGET,),
        source_reads=_reads(),
        executions=[],
        written_pocs=[],
        sandbox_available=False,
    )

    assert error == ""


def test_missing_or_contradicted_proof_fails_closed() -> None:
    missing = validate_cursor_proofs(
        _context(),
        [_disposition()],
        expected_targets=(TARGET,),
        source_reads=_reads(),
        executions=[],
        written_pocs=[],
        sandbox_available=False,
    )
    contradicted = _proof()
    contradicted["required_guard_index"] = 0
    contradiction = validate_cursor_proofs(
        _context(),
        [_disposition(proof=contradicted)],
        expected_targets=(TARGET,),
        source_reads=[],
        executions=[],
        written_pocs=[],
        sandbox_available=False,
    )
    overbroad_read = validate_cursor_proofs(
        _context(),
        [_disposition(proof=_proof())],
        expected_targets=(TARGET,),
        source_reads=[{
            "path": "parser.c", "start": 1, "end": 500, "bytes": 20_000,
        }],
        executions=[],
        written_pocs=[],
        sandbox_available=False,
    )

    assert "incomplete cursor proof" in missing
    assert "proof contradicts required_guard_index" in contradiction
    assert "source reads missing" in contradiction
    assert "source reads missing" in overbroad_read


def test_available_sandbox_requires_runtime_bound_to_written_poc() -> None:
    missing_attempt = validate_cursor_proofs(
        _context(),
        [_disposition(status="finding", proof=_proof(
            conclusion="unsafe_reachable",
        ))],
        expected_targets=(TARGET,),
        source_reads=_reads(),
        executions=[],
        written_pocs=[],
        sandbox_available=True,
    )
    executions = [
        {"argv": ["cc", "/workspace/cursor.c", "-o", "/workspace/exec/poc"]},
        {"argv": ["/workspace/exec/poc"], "exit_code": 1},
    ]
    valid_attempt = validate_cursor_proofs(
        _context(),
        [_disposition(status="finding", proof=_proof(
            conclusion="unsafe_reachable",
            attempted=True,
        ))],
        expected_targets=(TARGET,),
        source_reads=_reads(),
        executions=executions,
        written_pocs=["cursor.c"],
        sandbox_available=True,
    )

    assert "unsafe boundary hypothesis was not executed" in missing_attempt
    assert valid_attempt == ""


def _response(payload: dict) -> LLMResponse:
    text = json.dumps(payload)
    return LLMResponse(
        text=text,
        input_tokens=10,
        output_tokens=5,
        cache_read_tokens=0,
        cache_write_tokens=0,
        stop_reason="end_turn",
        content_blocks=[{"text": text}],
    )


class ProofClient:
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.calls = 0
        self.messages: list[list[dict]] = []

    async def chat(self, *, messages, **kwargs) -> LLMResponse:
        self.calls += 1
        self.messages.append(list(messages))
        return _response(self.payload)


class ProofTools:
    sandbox = None
    source_reads = _reads()
    execution_records: list[dict] = []
    written_pocs: list[str] = []
    tool_calls = 0
    repeated_reads = 0
    poc_write_calls = 0


async def test_hunter_repairs_once_then_defers_an_unproved_cursor_target() -> None:
    client = ProofClient({
        "target_dispositions": [_disposition()],
        "findings": [],
    })
    result = await HunterAgent(
        client=cast(Any, client),
        tools=cast(Any, ProofTools()),
        arch={"language": "c", "environment": "c:gcc-13"},
        hunter_prompt="Review the cursor target.",
        max_iterations=3,
    ).hunt("parser.c", _context())

    assert client.calls == 2
    assert result.cursor_proof_retries == 1
    assert result.stopped == "cursor_proof_incomplete"
    assert result.budget_reason == "cursor_proof_incomplete"
    assert result.findings == []
    assert result.incomplete_target_ids == [TARGET]
    assert result.target_dispositions[0]["status"] == "deferred"
    retry = client.messages[1][-1]["content"][0]["text"]
    assert "Cursor proof gate blocked finalization" in retry
    assert "guard/mutation/call/dereference" in retry


async def test_hunter_accepts_a_complete_cursor_proof() -> None:
    client = ProofClient({
        "target_dispositions": [_disposition(proof=_proof())],
        "findings": [],
    })
    result = await HunterAgent(
        client=cast(Any, client),
        tools=cast(Any, ProofTools()),
        arch={"language": "c", "environment": "c:gcc-13"},
        hunter_prompt="Review the cursor target.",
        max_iterations=2,
    ).hunt("parser.c", _context())

    assert client.calls == 1
    assert result.stopped == "final_json"
    assert result.incomplete_target_ids == []
    assert result.target_dispositions[0]["cursor_proof"]["chain_id"] == CHAIN


async def test_failed_cursor_proof_preserves_and_reindexes_other_target_findings() -> None:
    context = _context()
    context["change_focus"]["target_signal_ids"].append("sig-other")
    client = ProofClient({
        "target_dispositions": [
            {
                "target_id": TARGET,
                "status": "finding",
                "finding_indices": [0],
                "rationale": "unproved cursor candidate",
            },
            {
                "target_id": "sig-other",
                "status": "finding",
                "finding_indices": [1],
                "rationale": "independent finding",
            },
        ],
        "findings": [{"title": "cursor"}, {"title": "other"}],
    })
    result = await HunterAgent(
        client=cast(Any, client),
        tools=cast(Any, ProofTools()),
        arch={"language": "c", "environment": "c:gcc-13"},
        hunter_prompt="Review mixed targets.",
        max_iterations=3,
    ).hunt("parser.c", context)

    assert result.findings == [{"title": "other"}]
    assert result.target_dispositions == [
        {
            "target_id": TARGET,
            "status": "deferred",
            "finding_indices": [],
            "rationale": "cursor proof or boundary evidence was incomplete",
        },
        {
            "target_id": "sig-other",
            "status": "finding",
            "finding_indices": [0],
            "rationale": "independent finding",
        },
    ]
    assert result.incomplete_target_ids == [TARGET]
