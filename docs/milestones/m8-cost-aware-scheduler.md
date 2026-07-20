# M8 — Cost-aware slice scheduling

Status: In progress (PR 3 of 6 complete)

## Goal

Replace the legacy `selected file × enabled Hunter` Cartesian product with a
deterministic, coverage-preserving slice scheduler. The completed milestone
must substantially reduce model sessions while never silently omitting a
detected critical sink.

```text
immutable snapshot
  → C analysis graph
  → analysis slices
  → overlap deduplication
  → signal-aware routing
  → budget scheduler
  → leased Hunter work
  → verified evidence and strict reports
```

## PR 1 — Contracts, metrics, and shadow mode

The first increment deliberately preserves execution behavior. It materializes
the legacy Cartesian plan as stable `HunterWorkItem` objects, stores that plan
under the run, and measures actual Hunter consumption:

- sessions, model calls, and iterations;
- input, output, cache-read, and cache-write tokens;
- tool calls, repeated reads, PoC writes, and sandbox executions;
- wall-clock time and optional USD estimates for priced API models.

Codex subscription runs retain token/session/time accounting but do not invent
a dollar conversion. Usage records are validated and stored in SQLite schema
V3, keyed by run, stable work ID, and scope. The UI reads the durable metrics
and falls back to legacy artifact totals for old runs.

The stable work ID hashes the immutable source snapshot, planning policy,
analysis slices, files, Hunter, and pass number. File and slice order therefore
cannot perturb identity.

## Remaining increments

1. Hard budgets and adaptive iteration limits.
2. Shared immutable context cache.
3. Git-diff incremental scanning and final benchmark gates.

## PR 1 acceptance gates

- [x] Current file × Hunter execution is unchanged in shadow mode.
- [x] Work planning is deterministic under reordered inputs.
- [x] SQLite V2 migrates to V3 without losing tasks.
- [x] Usage records never expose provider credentials.
- [x] API pricing is optional and subscription usage remains unpriced.
- [x] Repeated reads and PoC/sandbox activity are measured.

## PR 2 — Signal-aware Hunter router

The signal router replaces the Cartesian product in active execution. It scores
file-local graph signals, grammar boundaries, and cross-file slice context
against the six native specialists:

- indexed writes, copies, sizes, and integer conversions → Bounds & Integers;
- allocation/release and ownership signals → Memory Lifetime;
- Flex/Bison files and parser-flow context → Parser State;
- formats, commands, paths, environment, and dynamic loading → Injection & Format;
- concurrency-state signals → Concurrency & Global State;
- error-contract signals → Error Contracts.

An ordinary file receives one primary specialist. A risk-5 cross-file sink may
receive one secondary specialist when a second discipline is materially
relevant. Critical specialists are forced even when they were not manually
enabled, and a critical sink file omitted by an upstream selector is put back
into the plan. Unknown critical categories receive a deterministic fallback.
The hunt step refuses to start if the resulting plan reports any uncovered
critical sink.

On the parser-to-index-write regression fixture, routing reduces nine legacy
sessions to four while preserving 100% of detected critical-sink coverage.

## PR 2 acceptance gates

- [x] Reordered files and enabled Hunters produce the same plan and work IDs.
- [x] Every detected critical sink maps to at least one scheduled work item.
- [x] A disabled but required critical specialist is automatically included.
- [x] The libcue-shaped regression schedules Bounds and Parser specialists.
- [x] The regression reduces Hunter sessions by more than 50%.
- [x] The UI reports legacy sessions, scheduled sessions, reduction, and coverage.

## PR 3 — Bounded slice work and durable leases

File-routed work is now collapsed by overlapping AnalysisSlice nodes, edges,
and sink identity. Each resulting work item contains one to eight ordered
context files, exact slice IDs, the routed specialist, risk, and critical-work
flag. Its directory is exactly `hunters/<work_id>/`, so restarting a process
does not create timestamp-derived artifact paths.

New runs no longer create or update `hunters/_queue.json`. Each work item is a
V2 SQLite `hunter` task whose key is the stable work ID. The M7 lease contract
now applies to Hunter execution:

- acquisition is atomic across workers;
- a background heartbeat renews long model sessions;
- expired work retains its work ID and increments its attempt;
- a live lease prevents duplicate execution;
- the final findings write is preceded by a fenced heartbeat;
- only the current lease token can mark work done or failed;
- tokens remain absent from CLI and UI task data.

Per-work `task.json`, traces, PoCs, findings, and clustering artifacts remain
available for crash recovery and verification. The old JSON queue implementation
is retained solely for reading and importing legacy runs. The hunt UI
automatically chooses the durable queue when SQLite work items are present.

On the parser-to-index-write fixture, four routed file sessions collapse to two
slice sessions: one Bounds session and one Parser session, both receiving the
same bounded three-file path.

## PR 3 acceptance gates

- [x] Overlap grouping and work IDs are deterministic.
- [x] Context contains at most eight files and the seed file is always present.
- [x] New Hunter work creates no `_queue.json`.
- [x] Only one worker can hold a live Hunter task lease.
- [x] Expired Hunter work resumes under the same work ID at the next attempt.
- [x] Completed subtask metadata survives process replacement.
- [x] Lease tokens are absent from read APIs and UI data.
- [x] End-to-end hunt execution completes through the SQLite slice queue.
- [x] Legacy JSON queue tests and importer behavior remain supported.
