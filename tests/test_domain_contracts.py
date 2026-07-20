from __future__ import annotations

import pytest
from pydantic import ValidationError

from tests.factories import HASH_A, HASH_B, HASH_C, candidate
from vulnhunt_agent.domain.compat import candidate_from_legacy
from vulnhunt_agent.domain.schemas import (
    CandidateFinding,
    CodeLocation,
    Evidence,
    EvidenceKind,
    OracleResult,
    ReviewVerdict,
    Verdict,
)
from vulnhunt_agent.domain.states import (
    FINDING_TRANSITIONS,
    RUN_TRANSITIONS,
    FindingState,
    RunState,
    StateTransitionError,
    require_finding_transition,
    require_run_transition,
)
from vulnhunt_agent.reporting.policy import StrictReportPolicy


def test_candidate_schema_rejects_unknown_fields_and_unsafe_locations() -> None:
    raw = candidate().model_dump()
    raw["invented"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        CandidateFinding.model_validate(raw)
    with pytest.raises(ValidationError, match="traverse parents"):
        CodeLocation(path="../secret", line=1)
    with pytest.raises(ValidationError, match="less than or equal to 1"):
        CandidateFinding.model_validate({**candidate().model_dump(), "confidence": 1.1})


def test_reproduction_evidence_requires_complete_machine_readable_contract() -> None:
    with pytest.raises(ValidationError, match="missing required fields"):
        Evidence(
            evidence_id="ev-incomplete",
            run_id="run-1",
            kind=EvidenceKind.REPRODUCTION,
            producer="reproducer",
        )

    evidence = _reproduction()
    assert evidence.oracle is not None
    assert evidence.oracle.result == "passed"
    with pytest.raises(ValidationError, match="must be produced by reproducer"):
        _reproduction(producer="hunter")


def test_review_verdict_enforces_cvss_by_verdict() -> None:
    with pytest.raises(ValidationError, match="requires a CVSS"):
        ReviewVerdict(
            candidate_id="cand-1",
            verdict=Verdict.REAL,
            notes="Reachable sink",
            reviewer="reviewer-1",
        )
    with pytest.raises(ValidationError, match="must not carry"):
        ReviewVerdict(
            candidate_id="cand-1",
            verdict=Verdict.FALSE_POSITIVE,
            notes="Blocked upstream",
            reviewer="reviewer-1",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        )


def test_transition_tables_accept_only_declared_edges() -> None:
    for run_current in RunState:
        for run_target in RunState:
            if run_target in RUN_TRANSITIONS[run_current]:
                require_run_transition(run_current, run_target)
            else:
                with pytest.raises(StateTransitionError):
                    require_run_transition(run_current, run_target)
    for finding_current in FindingState:
        for finding_target in FindingState:
            if finding_target in FINDING_TRANSITIONS[finding_current]:
                require_finding_transition(finding_current, finding_target)
            else:
                with pytest.raises(StateTransitionError):
                    require_finding_transition(finding_current, finding_target)


def test_legacy_confirmed_string_never_becomes_reproduced_or_reportable() -> None:
    legacy = {
        "title": "SSRF",
        "type": "ssrf",
        "status": "confirmed",
        "entry_file": "app.py",
        "entry_line": 4,
        "sink_file": "app.py",
        "sink_line": 5,
        "description": "URL reaches urlopen",
        "attack": "Control URL",
        "poc_file": "/workspace/poc.py",
        "exec_output": "LEAKED_SECRET=1",
    }
    converted = candidate_from_legacy(legacy, run_id="run-1", task_key="app.py::ssrf")
    assert converted.state is FindingState.POC_READY
    assert converted.evidence_ids == ()
    decision = StrictReportPolicy().evaluate(
        converted,
        run_snapshot=HASH_A,
        evidence=[],
        verdict=None,
    )
    assert not decision.allowed
    assert "independent reproduction evidence is missing" in decision.reasons


def test_strict_policy_promotes_only_snapshot_matched_reproduction() -> None:
    finding = candidate(
        state=FindingState.REVIEWER_VERIFIED,
        evidence_ids=("ev-repro-1", "ev-repro-2"),
    )
    verdict = ReviewVerdict(
        candidate_id=finding.candidate_id,
        verdict=Verdict.REAL,
        notes="Data flow and reproduction agree",
        reviewer="reviewer-1",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    )
    policy = StrictReportPolicy()
    mismatch = policy.evaluate(
        finding,
        run_snapshot=HASH_B,
        evidence=[_reproduction(attempt=1), _reproduction(attempt=2)],
        verdict=verdict,
    )
    assert not mismatch.allowed
    assert (
        "no deterministic two-attempt reproduction matches the run snapshot"
        in mismatch.reasons
    )

    one_attempt = policy.evaluate(
        finding,
        run_snapshot=HASH_A,
        evidence=[_reproduction(attempt=1)],
        verdict=verdict,
    )
    assert not one_attempt.allowed

    failed_third = _reproduction(attempt=3).model_copy(
        update={
            "oracle": OracleResult(
                type="regex",
                expression="LEAKED_SECRET=",
                result="failed",
            )
        }
    )
    mixed_finding = finding.model_copy(
        update={"evidence_ids": ("ev-repro-1", "ev-repro-2", "ev-repro-3")}
    )
    mixed = policy.evaluate(
        mixed_finding,
        run_snapshot=HASH_A,
        evidence=[
            _reproduction(attempt=1),
            _reproduction(attempt=2),
            failed_third,
        ],
        verdict=verdict,
    )
    assert not mixed.allowed

    promoted = policy.promote(
        finding,
        run_snapshot=HASH_A,
        evidence=[_reproduction(attempt=1), _reproduction(attempt=2)],
        verdict=verdict,
    )
    assert promoted.state is FindingState.REPORTABLE


def _reproduction(*, attempt: int = 1, producer: str = "reproducer") -> Evidence:
    return Evidence(
        evidence_id=f"ev-repro-{attempt}",
        run_id="run-1",
        candidate_id="cand-1",
        kind=EvidenceKind.REPRODUCTION,
        producer=producer,
        reproduction_group="repro-1",
        attempt=attempt,
        source_snapshot=HASH_A,
        image_digest=HASH_B,
        command=("python", "/workspace/poc.py"),
        exit_code=0,
        stdout_artifact=HASH_C,
        stderr_artifact=HASH_B,
        oracle=OracleResult(type="regex", expression="LEAKED_SECRET=", result="passed"),
    )
