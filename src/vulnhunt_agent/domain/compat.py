"""Compatibility adapters for pre-V2 JSON findings."""
from __future__ import annotations

import hashlib

from .schemas import CandidateFinding, CodeLocation, Precondition
from .states import FindingState


def candidate_from_legacy(raw: dict, *, run_id: str, task_key: str) -> CandidateFinding:
    """Validate and conservatively map a legacy Hunter finding.

    A legacy ``status=confirmed`` string never maps to ``reproduced`` or
    ``reportable``. At most it means a PoC is ready for an independent run.
    """
    status = str(raw.get("status", "unverified"))
    has_poc_claim = bool(raw.get("poc_file")) and bool(raw.get("exec_output"))
    state = (
        FindingState.POC_READY
        if status == "confirmed" and has_poc_claim
        else FindingState.STATICALLY_SUPPORTED
    )
    entrypoint = _location(raw, "entry")
    assert entrypoint is not None
    sink = _location(raw, "sink", required=False)
    files = [str(path) for path in raw.get("files_touched", []) if path]
    dataflow = tuple(
        CodeLocation(path=path, line=1)
        for path in files
        if path not in {entrypoint.path, sink.path if sink else None}
    )
    candidate_id = _legacy_id(run_id, task_key, raw)
    attack = str(raw.get("attack") or "Legacy finding did not structure attacker capability")
    impact = (str(raw.get("description") or raw.get("title") or "Unspecified impact"),)

    return CandidateFinding(
        candidate_id=candidate_id,
        run_id=run_id,
        task_key=task_key,
        title=str(raw.get("title") or "Untitled legacy finding"),
        weakness=str(raw.get("type") or "unknown"),
        state=state,
        entrypoint=entrypoint,
        sink=sink,
        dataflow=dataflow,
        preconditions=(
            Precondition(
                kind="legacy-import",
                description="Preconditions require review after legacy import",
            ),
        ),
        attacker_capability=attack,
        impact=impact,
        confidence=0.75 if state is FindingState.POC_READY else 0.45,
    )


def _location(raw: dict, prefix: str, *, required: bool = True) -> CodeLocation | None:
    path = str(raw.get(f"{prefix}_file") or "")
    if not path:
        if required:
            path = "unknown"
        else:
            return None
    line_raw = raw.get(f"{prefix}_line", 1)
    line = line_raw if isinstance(line_raw, int) and line_raw > 0 else 1
    return CodeLocation(path=path, line=line)


def _legacy_id(run_id: str, task_key: str, raw: dict) -> str:
    identity = "\0".join(
        [
            run_id,
            task_key,
            str(raw.get("type", "unknown")),
            str(raw.get("entry_file", "unknown")),
            str(raw.get("entry_line", 1)),
            str(raw.get("sink_file", "")),
            str(raw.get("sink_line", "")),
        ]
    )
    return "cand_legacy_" + hashlib.sha256(identity.encode()).hexdigest()[:24]
