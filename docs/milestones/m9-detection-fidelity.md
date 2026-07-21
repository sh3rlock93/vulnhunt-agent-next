# M9 — Detection fidelity and closed-loop verification

Status: In progress (4 of 6 increments)

## Goal

Make incremental native scans focus on the code that actually changed, require
an explicit disposition for every critical target, and automatically close any
follow-up reproduction requested by evidence reviewers. The milestone is gated
by a vulnerable/fixed zlib MiniZip regression for CVE-2023-45853.

## PR 1 — Routing-plan integrity

Critical cross-file work can prefer a required specialist that is not the
highest-scoring route. The previous secondary selection used a positional slice
of the ranking and could append that preferred specialist a second time,
producing identical stable work IDs and invalidating both incremental plans and
their full-scan baseline.

Secondary selection now chooses the highest-ranked specialist not already in
the plan and performs a final stable de-duplication. The strict routing-plan
validator remains in place as a fail-closed contract.

## PR 1 acceptance gates

- [x] A lower-ranked required specialist is never scheduled twice.
- [x] A materially relevant secondary specialist is retained.
- [x] Work IDs remain deterministic and unique.
- [x] Existing critical-sink coverage and reduction tests remain green.

## PR 2 — Macro-aware C graph and deletion anchors

Tree-sitter can preserve a long macro-decorated C function as a structured
parse-error region rather than a normal `function_definition`. The graph and
repository index now recover such a function only when the region contains a
function declarator, an opening body brace, body nodes, and an isolated closing
brace. This recovers zlib's `zipOpenNewFileInZip4_64` without treating arbitrary
error nodes or prototypes as executable functions.

Native allocation macros named `ALLOC` are recorded as allocation-size sinks.
Deletion-only Git hunks now anchor both sides of the removed range so a guard
deletion at a function boundary cannot silently produce an empty changed-node
set.

## PR 2 acceptance gates

- [x] The MiniZip-shaped macro function appears in both repository and graph indexes.
- [x] Calls and security signals inside a recovered body remain attributed to it.
- [x] Deletion-only diffs select the recovered function in the head graph.
- [x] Real zlib maps the changed function and its `ALLOC` signal.
- [x] Existing ordinary C and parser graph contracts remain green.

## PR 3 — Change-focused bounded scheduling and context

Incremental routing now carries the exact changed nodes, directly affected
critical signals, and changed line ranges into the durable Hunter work
contract. Slice work prioritizes a directly changed function before expanded
callers or ordinary entrypoints and keeps at most six high-value slices, four
target nodes, and six target signals in one prompt.

Shared context packets use a versioned 24 KB hard limit. Changed ranges are
selected before surrounding graph ranges, the seed file is emitted first, and
the packet cache key includes all change-focus metadata. This preserves cache
sharing across Hunters only when they actually receive identical evidence.

## PR 3 acceptance gates

- [x] A deletion-only MiniZip diff schedules `zipOpenNewFileInZip4_64` first.
- [x] The recovered function's `ALLOC` signal is an explicit Hunter target.
- [x] Work never contains more than 6 slices, 4 target nodes, or 6 target signals.
- [x] Persisted context packets never exceed 24,000 bytes.
- [x] Real zlib collapses 7 routed sessions into 3 bounded Hunter sessions.
- [x] Existing M8 scheduling, cache reuse, and native-analysis tests remain green.

## PR 4 — Per-target completion and lower amplification

Every bounded Hunter session now has a versioned target-completion contract.
The final response must assign each target signal (or target node when no signal
exists) exactly one `finding`, `no_finding`, or `deferred` disposition with a
reason and valid finding references. Missing, duplicate, unknown, and invalid
dispositions cannot silently complete a durable task.

The agent makes at most one format-repair call. A second invalid response or an
explicitly deferred target persists a deferred disposition and leaves the work
budget-deferred. The former 8/30/100 iteration tiers are reduced to 6/18/40,
and output tokens are sized from the bounded target count rather than repository
size. Run summaries expose finding/no-finding/deferred/missing target counts.

## PR 4 acceptance gates

- [x] Every explicit target has exactly one validated disposition.
- [x] `finding` dispositions reference existing findings; safe targets explain why.
- [x] Missing completion stops after one repair instead of consuming the full loop.
- [x] Deferred and budget-exhausted targets remain visible and resumable.
- [x] Durable summaries fail the completion flag for missing/deferred targets.
- [x] Vulnerable and fixed libcue gates retain 72.22% session reduction.

## Remaining increments

5. Leased reproduction-variant execution and automatic re-review.
6. Pinned zlib vulnerable/fixed benchmark and final operational gates.
