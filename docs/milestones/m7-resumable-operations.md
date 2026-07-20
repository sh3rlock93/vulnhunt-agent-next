# M7 — Resumable operations with leases and heartbeats

Status: Complete

## Outcome

V2 tasks now have durable, fenced worker ownership instead of relying on a
`running` status string. A worker must atomically acquire a lease before doing
reproduction work, renew it with a heartbeat, and present the same secret token
to finish. Expired work can be reclaimed without changing the task key or
discarding already persisted evidence.

```text
pending
  → lease(worker A, attempt 1) → running
      ├─ heartbeat → extended running
      ├─ finish(token A) → terminal
      └─ worker disappears
           → expiry → lease(worker B, attempt 2) → resume
```

## Storage migration

Opening a writable V1 SQLite database performs an in-place, transactional schema
migration to V2. The task table gains:

- lease owner and an unlisted random lease token;
- acquisition, heartbeat, and expiry timestamps;
- last error and completion timestamp;
- the existing attempt counter as the retry fence.

The migration preserves runs, tasks, payloads, attempts, findings, and evidence.
A binary refuses a database whose schema is newer than it supports. Read-only
task listing remains compatible with an unmigrated V1 database.

## Lease contract

`BEGIN IMMEDIATE` serializes claims across SQLite connections. Only a pending
task or an expired running task may be acquired. A live lease prevents a second
worker from executing the same task.

Every lease carries a cryptographically random token. Heartbeat and finish
operations verify all of:

- run, task type, and stable task key;
- worker ID and token;
- attempt number;
- `running` status;
- a deadline that has not elapsed.

An expired worker is fenced even if no replacement worker has claimed the task
yet. This prevents delayed output from an old process from overwriting the newer
attempt. Lease tokens are never returned by `list_tasks`, the CLI, or the UI.

## Recovery and attempt limits

Expired tasks can be acquired directly by another worker, or explicitly
requeued:

```bash
vulnhunt --db .vulnhunt/state.db recover RUN_ID --max-attempts 3
vulnhunt --db .vulnhunt/state.db tasks RUN_ID
vulnhunt --db .vulnhunt/state.db tasks RUN_ID --status failed
```

Recovery retains the original `(run_id, task_type, task_key)` idempotency
identity and increments the attempt. Once the configured attempt ceiling is
reached, the task becomes `failed` with a durable error instead of looping
forever.

The Streamlit evidence panel shows task type, key, status, attempt, lease owner,
expiry, and last error. It does not expose the token.

## Reproducer integration

`ReproducerService` now leases each reproduction task. Its deadline covers all
native setup commands and the trigger, and is renewed before each independent
attempt and before promotion.

Reproduction evidence remains content-addressed and is written after every
attempt. If a process disappears after attempt 1:

1. the candidate remains `reproduction_pending`;
2. attempt-1 evidence remains immutable;
3. another worker cannot start before lease expiry;
4. the next worker acquires attempt 2;
5. it skips stored attempt-1 evidence and runs only the missing attempt;
6. deterministic evidence is attached and the task finishes normally.

Ordinary sandbox errors still produce `environment_blocked`. Process death or
cancellation leaves the lease to expire, which is the signal for safe recovery.

## Acceptance gates

- [x] A V1 database migrates in place without losing its task payload.
- [x] Only one worker can hold a live task lease.
- [x] Heartbeats extend the deadline.
- [x] Wrong-token, expired, and superseded workers cannot finish.
- [x] Expired claims retain task identity and increment the attempt.
- [x] Attempt ceilings terminate poison tasks.
- [x] Lease tokens are absent from read APIs and UI data.
- [x] CLI can inspect tasks and recover expired work.
- [x] Reproducer resumes from persisted evidence rather than rerunning it.
- [x] Existing strict report and real Docker contracts remain green.

## Verification

```bash
python -m ruff check src tests benchmarks
python -m mypy
python -m pytest --cov=vulnhunt_agent --cov-report=term-missing \
  --cov-report=xml --cov-fail-under=45
VULNHUNT_RUN_DOCKER_TESTS=1 \
  python -m pytest tests/test_docker_sandbox_integration.py
```

On 2026-07-20, local validation passed 80 standard tests at 68% branch coverage
and all four real Docker contracts.
