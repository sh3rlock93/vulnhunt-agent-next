# M8 — Cost-aware slice scheduling

Status: Complete (6 of 6 increments)

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

## PR 4 — Hard budgets and adaptive Hunter depth

Hunter execution now has provider-neutral hard limits for sessions, input
tokens (including cache reads/writes), output tokens, wall-clock time, and
retries. The same limits apply to API and Codex subscription transports;
subscription usage remains unpriced but is not unmetered.

Session admission is deterministic. The scheduler aims to reserve 60% for
required critical work, 30% for non-critical high-risk work, and 10% for
retries. Empty reservations may be borrowed in risk order so small scans are
not artificially deferred. If the configured limit cannot cover every item,
the omitted work is stored as the terminal `budget_deferred` state rather than
being mislabeled as a Hunter failure.

A shared call controller reserves a conservative input upper bound and the
remaining output allowance before a provider request starts. Concurrent
Hunters therefore cannot independently spend the same remaining tokens.
Provider calls are capped to the remaining output tokens and cancelled at the
wall-clock deadline. Usage already persisted for a resumed run reduces the
remaining budget.

Hunter depth is selected per item and then bounded by the operator's existing
`hunter_max_iterations` cap:

- ordinary work: 8 iterations;
- required or risk-4/5 work: 30 iterations;
- a retry or work with existing PoC evidence: 100 iterations.

The Hunt plan records admitted/deferred counts and allocation classes. The Hunt
summary records every unanalysed work ID, and both the Hunt and Final Report
views display an explicit incomplete-analysis warning when budget deferral
occurred.

The default configuration keys are:

```text
budget_max_hunter_sessions = 100
budget_max_input_tokens = 2000000
budget_max_output_tokens = 200000
budget_max_wall_clock_minutes = 60
budget_max_retries_per_work_item = 1
```

## PR 4 acceptance gates

- [x] Critical work is admitted before high-risk and ordinary work.
- [x] Concurrent model calls reserve shared input and output allowances.
- [x] A call cannot start after the wall-clock deadline.
- [x] Output tokens passed to the provider never exceed the remaining budget.
- [x] Iteration depth follows deterministic 8/30/100 tiers.
- [x] Retry attempts are capped by the budget policy.
- [x] Budget deferral is durable and distinct from failure.
- [x] Unanalysed and critical-unanalysed work is visible in artifacts and UI.

## PR 5 — Shared immutable context cache

Hunter sessions that cover the same source snapshot, graph version, slice set,
and bounded file set now reuse one content-addressed context packet. Hunter
identity is deliberately absent from the key, so Bounds and Parser specialists
following the same path receive byte-identical starting context.

Each packet contains:

- compact graph paths, signals, sink metadata, and slice rationale;
- bounded, line-numbered source excerpts around relevant graph nodes;
- complete bounded excerpts for Flex/Bison sources;
- directly included local headers;
- up to two root build descriptors such as `CMakeLists.txt`, `meson.build`, or
  `Makefile`;
- an explicit instruction that the packet is a starting point, not a read
  boundary.

Packets live under `cache/context/context_<sha256>.json`. The key includes the
source snapshot digest, graph schema, coverage policy, exact slice IDs, context
files, and excerpt policy limits. A different source snapshot always produces
a different key. Each packet also has a canonical payload digest; corrupted or
partially written entries are rebuilt instead of being trusted.

Writes use a temporary file followed by atomic replacement. The Hunt step
materializes packets before concurrent model execution, records the work-to-key
mapping, and publishes entries/hits/misses/bytes in both the Hunt plan and
summary. The existing `read_file`, `grep`, and sibling-file exploration tools
are unchanged, so the cache cannot hide context that was not preloaded.

## PR 5 acceptance gates

- [x] Cross-Hunter work with identical slices reuses one packet.
- [x] Reordered work does not change the cache key or packet content.
- [x] Snapshot changes cannot hit an older packet.
- [x] Graph, slice, file-bound, and excerpt-policy changes affect identity.
- [x] C source, parser, local-header, and build context is bounded and included.
- [x] Packet corruption is detected and rebuilt.
- [x] Cache writes complete before parallel Hunter execution.
- [x] Arbitrary follow-up `read_file` and `grep` exploration remains available.
- [x] Cache hit/miss evidence is visible in durable artifacts and the UI.

## PR 6 — Git-diff incremental scanning and final benchmark gates

Incremental C scans compare the merge base of `base-ref` and `head-ref` with
the checked-out head. Changed line ranges seed overlapping functions, then the
scope expands through callers, callees, parser-flow edges, local header
consumers, and overlapping analysis slices. Only critical sinks inside that
expanded scope are required and scheduled.

Safety takes priority over reduction. The scanner records a reason and falls
back to full coverage when refs cannot be resolved, the checkout is dirty or
does not match `head-ref`, the merge base or diff is unavailable, build
configuration changed, a C source was deleted, or a changed header has unknown
consumers. Python and C scans without refs preserve the existing full-scan
artifact shape.

The same pipeline is exposed through the CLI:

```bash
vulnhunt scan /path/to/repo \
  --base-ref main --head-ref HEAD --plan-only

vulnhunt scan /path/to/repo \
  --base-ref main --head-ref HEAD
```

The UI and durable Hunt plan show changed and impacted files, planned
incremental sessions, the equivalent full-scan session count, actual
consumption, and reduction. A zero-work diff completes Hunt planning without
initializing a model provider.

GitHub CI now checks the pinned libcue regression at both the vulnerable
revision (`1b0f3917b8f908c81bb646ce42f29cf7c86443a1`) and fixed revision
(`cfb98a060fd79dbc3463d85f0f29c3c335dfa0ea`). The vulnerable fixture must
retain Bounds and Parser specialists, cover every scoped critical sink, and
reduce the 36-session legacy plan to at most 14 sessions. The fixed fixture
must retain both lower- and upper-bound guard recognition.

## PR 6 acceptance gates

- [x] Changed lines seed their containing C functions.
- [x] Callers, callees, parser-flow paths, and overlapping slices expand scope.
- [x] Changed local headers expand to known consumers.
- [x] Every changed header must have a known consumer or the scan falls back.
- [x] Unchanged unrelated critical sinks are not scheduled.
- [x] Every scoped critical sink remains covered by a scheduled specialist.
- [x] Unsafe or ambiguous Git states visibly fall back to full scanning.
- [x] Python and ref-free full scans remain backward compatible.
- [x] CLI plan and execution use the same persisted pipeline as the UI.
- [x] UI reports incremental planned, full equivalent, and actual sessions.
- [x] The vulnerable libcue gate reduces 36 sessions to 9 (75%).
- [x] Vulnerable and fixed libcue revisions are both enforced in CI.
