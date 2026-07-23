"""Fail-closed proof contract for structurally identified cursor targets."""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

CURSOR_PROOF_POLICY = "c-cursor-proof-v1"


class CursorBoundaryAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["executed", "not_available"]
    execution_index: int | None = Field(default=None, ge=0)
    rationale: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def validate_execution_index(self) -> "CursorBoundaryAttempt":
        if self.status == "executed" and self.execution_index is None:
            raise ValueError("executed boundary attempt requires execution_index")
        if self.status == "not_available" and self.execution_index is not None:
            raise ValueError("unavailable boundary attempt cannot cite an execution")
        return self


class CursorStateProof(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_version: Literal["c-cursor-proof-v1"]
    chain_id: str = Field(pattern=r"^cursor_transition_[0-9a-f]{20}$")
    pre_guard_relation: str = Field(min_length=1, max_length=2000)
    observed_guard_index: int | None = Field(default=None, ge=0)
    cursor_mutation: str = Field(min_length=1, max_length=2000)
    cursor_delta: int
    post_mutation_relation: str = Field(min_length=1, max_length=2000)
    callee_entry_precondition: str = Field(min_length=1, max_length=2000)
    dereference_relation: str = Field(min_length=1, max_length=2000)
    dereference_index: int = Field(ge=0)
    required_guard_index: int = Field(ge=0)
    minimum_boundary_case: str = Field(min_length=1, max_length=2000)
    maximum_boundary_case: str = Field(min_length=1, max_length=2000)
    conclusion: Literal["unsafe_reachable", "safe_proved"]
    boundary_attempt: CursorBoundaryAttempt


def cursor_target_ids(
    context: dict | None,
    expected_targets: tuple[str, ...],
) -> tuple[str, ...]:
    expected = set(expected_targets)
    targeted = {
        str(target_id)
        for chain in (context or {}).get("cursor_transition_chains") or ()
        for target_id in chain.get("target_signal_ids") or ()
        if str(target_id) in expected
    }
    return tuple(target_id for target_id in expected_targets if target_id in targeted)


def validate_cursor_proofs(
    context: dict | None,
    dispositions: list[dict],
    *,
    expected_targets: tuple[str, ...],
    source_reads: object,
    executions: object,
    written_pocs: object,
    sandbox_available: bool,
) -> str:
    """Validate closed cursor dispositions against immutable context and ledgers."""
    cursor_targets = cursor_target_ids(context, expected_targets)
    if not cursor_targets:
        return ""
    chains = _chains_by_target(context or {}, set(cursor_targets))
    dispositions_by_target = {
        str(item.get("target_id", "")): item for item in dispositions
    }
    errors: list[str] = []
    for target_id in cursor_targets:
        disposition = dispositions_by_target.get(target_id)
        if disposition is None or disposition.get("status") == "deferred":
            continue
        chain = chains.get(target_id)
        if chain is None:
            errors.append(f"{target_id}: cursor chain context is missing")
            continue
        try:
            proof = CursorStateProof.model_validate(disposition.get("cursor_proof"))
        except ValidationError as exc:
            errors.append(f"{target_id}: incomplete cursor proof ({exc.errors()[0]['msg']})")
            continue
        errors.extend(_proof_contradictions(target_id, disposition, proof, chain))
        missing_reads = _missing_source_evidence(chain, source_reads)
        if missing_reads:
            errors.append(
                f"{target_id}: source reads missing " + ", ".join(missing_reads)
            )
        attempt_error = _boundary_attempt_error(
            proof,
            chain,
            executions=executions,
            written_pocs=written_pocs,
            sandbox_available=sandbox_available,
        )
        if attempt_error:
            errors.append(f"{target_id}: {attempt_error}")
    return "; ".join(errors)


def _chains_by_target(context: dict, target_ids: set[str]) -> dict[str, dict]:
    selected: dict[str, dict] = {}
    for chain in context.get("cursor_transition_chains") or ():
        for target_id in chain.get("target_signal_ids") or ():
            target = str(target_id)
            if target in target_ids and target not in selected:
                selected[target] = chain
    return selected


def _proof_contradictions(
    target_id: str,
    disposition: dict,
    proof: CursorStateProof,
    chain: dict,
) -> list[str]:
    expected = {
        "chain_id": str(chain.get("chain_id", "")),
        "observed_guard_index": chain.get("observed_guard_index"),
        "cursor_delta": int(chain.get("advance_delta", 0)),
        "dereference_index": chain.get("dereference_index"),
        "required_guard_index": int(chain.get("required_access_index", 0)),
    }
    actual = {
        "chain_id": proof.chain_id,
        "observed_guard_index": proof.observed_guard_index,
        "cursor_delta": proof.cursor_delta,
        "dereference_index": proof.dereference_index,
        "required_guard_index": proof.required_guard_index,
    }
    errors = [
        f"{target_id}: proof contradicts {field}"
        for field, value in expected.items()
        if actual[field] != value
    ]
    expected_conclusion = (
        "unsafe_reachable"
        if disposition.get("status") == "finding"
        else "safe_proved"
    )
    if proof.conclusion != expected_conclusion:
        errors.append(f"{target_id}: proof conclusion contradicts disposition")
    return errors


def _missing_source_evidence(chain: dict, source_reads: object) -> list[str]:
    required_roles = {"guard", "advance", "call", "read"}
    requirements = [
        item
        for item in chain.get("evidence_requirements") or ()
        if item.get("role") in required_roles
    ]
    present_roles = {str(item.get("role", "")) for item in requirements}
    missing = [
        role for role in ("advance", "call", "read") if role not in present_roles
    ]
    if not isinstance(source_reads, list):
        return [*missing, "recorded source ranges"]
    for item in requirements:
        path = str(item.get("path", ""))
        line = int(item.get("line", 0))
        if not any(_read_covers(record, path, line) for record in source_reads):
            missing.append(f"{item.get('role')}@{path}:{line}")
    return list(dict.fromkeys(missing))


def _read_covers(record: object, path: str, line: int) -> bool:
    if not isinstance(record, dict) or str(record.get("path", "")) != path:
        return False
    if int(record.get("bytes", 0)) <= 0:
        return False
    start = max(1, int(record.get("start", 1)))
    end = record.get("end")
    if end is None:
        return False
    bounded_end = int(end)
    return (
        bounded_end >= start
        and bounded_end - start <= 96
        and start <= line <= bounded_end
    )


def _boundary_attempt_error(
    proof: CursorStateProof,
    chain: dict,
    *,
    executions: object,
    written_pocs: object,
    sandbox_available: bool,
) -> str:
    unsafe_hypothesis = str(chain.get("guard_state", "unknown")) != "dominates"
    if not sandbox_available or not unsafe_hypothesis:
        return ""
    attempt = proof.boundary_attempt
    if attempt.status != "executed" or attempt.execution_index is None:
        return "unsafe boundary hypothesis was not executed in the available sandbox"
    if not isinstance(executions, list) or attempt.execution_index >= len(executions):
        return "boundary attempt cites a missing execution ledger entry"
    execution = executions[attempt.execution_index]
    if not isinstance(execution, dict):
        return "boundary attempt cites an invalid execution ledger entry"
    argv = execution.get("argv") or []
    if not isinstance(argv, list) or not argv:
        return "boundary attempt execution has no argv"
    command = PurePosixPath(str(argv[0])).name
    if command in {"cc", "gcc", "clang", "c++", "g++", "clang++"}:
        return "boundary attempt cites compilation rather than trigger execution"
    if not _poc_is_bound_to_execution(
        written_pocs,
        executions,
        runtime_index=attempt.execution_index,
    ):
        return "boundary attempt is not bound to a written PoC or prior compilation"
    return ""


def _poc_is_bound_to_execution(
    written_pocs: object,
    executions: list[object],
    *,
    runtime_index: int,
) -> bool:
    if not isinstance(written_pocs, list) or not written_pocs:
        return False
    names = {str(path).lstrip("/") for path in written_pocs if str(path)}
    for index, record in enumerate(executions):
        if index > runtime_index or not isinstance(record, dict):
            continue
        argv = [str(item).lstrip("/") for item in record.get("argv") or ()]
        if any(
            argument.endswith(name) or name.endswith(argument)
            for argument in argv
            for name in names
            if argument
        ):
            return True
    return False
