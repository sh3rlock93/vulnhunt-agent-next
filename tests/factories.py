from __future__ import annotations

from vulnhunt_agent.domain.schemas import CandidateFinding, CodeLocation, Precondition
from vulnhunt_agent.domain.states import FindingState

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
HASH_C = "sha256:" + "c" * 64


def candidate(
    *,
    candidate_id: str = "cand-1",
    state: FindingState = FindingState.HYPOTHESIS,
    evidence_ids: tuple[str, ...] = (),
) -> CandidateFinding:
    return CandidateFinding(
        candidate_id=candidate_id,
        run_id="run-1",
        task_key="insecure_app/app.py::ssrf-network",
        title="Unvalidated outbound URL",
        weakness="CWE-918",
        state=state,
        entrypoint=CodeLocation(path="insecure_app/app.py", line=6, symbol="fetch_url"),
        sink=CodeLocation(path="insecure_app/app.py", line=8, symbol="urlopen"),
        dataflow=(CodeLocation(path="insecure_app/app.py", line=7),),
        preconditions=(
            Precondition(kind="input", description="Attacker controls target_url"),
        ),
        attacker_capability="Supply an outbound URL",
        impact=("Read internal HTTP resources",),
        evidence_ids=evidence_ids,
        confidence=0.9,
    )
