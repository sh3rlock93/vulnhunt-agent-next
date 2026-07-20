# Milestone 1 — Domain contracts and durable state

Status: Complete

## Scope

- Add strict Pydantic V2 models for runs, findings, evidence, review verdicts, and artifacts.
- Enforce explicit run and finding state machines in repository transactions.
- Persist validated domain objects in a SQLite WAL repository with idempotent task and transition keys.
- Deduplicate findings deterministically within a run and task.
- Store immutable blobs in a SHA-256 content-addressed artifact store.
- Preserve JSONL event compatibility through a validated append/read adapter.
- Import legacy `RunStore` directories conservatively without treating `confirmed` text as reproduction.
- Provide machine-readable, read-only `runs`, `status`, and `findings` CLI commands.
- Enforce a strict report policy that requires matching independent reproduction evidence.

## Acceptance criteria

- [x] Invalid or tampered finding models are revalidated and rejected at the persistence boundary.
- [x] Every undeclared run and finding transition is rejected by exhaustive unit tests.
- [x] Replaying a task or candidate does not create a duplicate finding.
- [x] Transition idempotency keys replay safely and reject conflicting reuse.
- [x] SQLite operates in WAL mode and foreign-key enforcement is enabled.
- [x] Artifact reads verify their content hash and reject path traversal or tampering.
- [x] Legacy `confirmed` results import no higher than `poc_ready`.
- [x] Findings without matching reproduction evidence fail the strict report policy.
- [x] Existing baseline pipeline and Hunter contract tests remain green.
- [x] CI passes on Python 3.11, 3.12, and 3.13.

## Verification commands

```bash
python -m ruff check src tests
python -m mypy
python -m pytest --cov=vulnhunt_agent --cov-report=term-missing \
  --cov-report=xml --cov-fail-under=45
```

Local forward-compatibility run on Python 3.14.5: 31 tests passed with 57.51% branch
coverage, and Ruff and mypy reported no findings. The supported-version CI matrix remains
the release authority for Python 3.11–3.13.
GitHub Actions runs `29491833405` and `29491851917` passed all three matrix jobs.

## Explicit boundary

This milestone models reproduction evidence and blocks unverified reporting, but it does not
execute an independent reproduction. Immutable source snapshots, hardened build/hunt/reproduce
sandboxes, success oracles, and repeated PoC execution are Milestone 2 release gates.
