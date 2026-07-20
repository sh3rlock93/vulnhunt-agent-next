# M8 — Cost-aware slice scheduling

Status: In progress (PR 1 of 6 complete)

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

1. Signal-aware Hunter router.
2. Slice queue and M7 lease integration.
3. Hard budgets and adaptive iteration limits.
4. Shared immutable context cache.
5. Git-diff incremental scanning and final benchmark gates.

## PR 1 acceptance gates

- [x] Current file × Hunter execution is unchanged in shadow mode.
- [x] Work planning is deterministic under reordered inputs.
- [x] SQLite V2 migrates to V3 without losing tasks.
- [x] Usage records never expose provider credentials.
- [x] API pricing is optional and subscription usage remains unpriced.
- [x] Repeated reads and PoC/sandbox activity are measured.
