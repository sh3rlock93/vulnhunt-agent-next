# M8 — Cost-aware slice scheduling

Status: In progress (PR 2 of 6 complete)

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

1. Slice queue and M7 lease integration.
2. Hard budgets and adaptive iteration limits.
3. Shared immutable context cache.
4. Git-diff incremental scanning and final benchmark gates.

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
