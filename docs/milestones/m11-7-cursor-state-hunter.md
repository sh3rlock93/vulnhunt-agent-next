# M11.7 — Cursor-state Hunter recovery

Status: implemented; authenticated recovery and protected release gates satisfied

## Goal

Recover blind detection of a bounded-input parser bug that is already admitted
and read by a Hunter, but is missed because the dangerous operation is an input
read reached after a cursor mutation rather than a conventional write/copy
sink.

The motivating target is cJSON issue 800.  On a non-NUL-terminated input ending
in a comma, `parse_object` proves only that the comma at index zero is
accessible, advances `input_buffer->offset` to `length`, and calls
`parse_string`, whose first `buffer_at_offset(input_buffer)[0]` read is one byte
out of bounds.  The upstream fix adds an index-one accessibility check before
the advance.

M11.7 changes the target formation and Hunter proof contract, not the existing
file ranking formula.  It must preserve current session, token, context, retry,
and parallelism ceilings.

## Root cause

The trace-audited M11.6 cJSON run reached both `parse_string` and
`parse_object`, so file admission and context availability were not the direct
cause.  Detection still failed because:

- the analysis graph emitted write/copy/format targets but no critical target
  for the macro-backed input read;
- no `c-parser-state` work was planned for a handwritten parser in a `.c` file;
- the Bounds Hunter proved UTF output capacity while never proving the input
  cursor invariant across `guard -> advance -> call -> read`;
- a NUL-requiring fuzz harness was not distinguished from the public
  explicit-length API contract; and
- no boundary counterexample was required before a cursor-related target could
  receive `no_finding`.

## Release rule

The strict recovery target is vulnerable cJSON commit
`98f9eb0412067a852ec107c68e49180fe4e472dc`, tree
`5e10bc6289cb29afd1847278a89359e3e9d5e1f2`.  This revision predates the
regression test.  Its production `cJSON.c`, `cJSON.h`, `cJSON_Utils.c`, and
`cJSON_Utils.h` bytes are identical to upstream fix-parent commit
`826cd6f842ae7e46ee38bbc097f9a34f2947388d`.

Discovery receives only the pinned vulnerable tree, an oracle-free scan
manifest, and ordinary repository source.  The trigger, issue identifier,
expected lines, fixed revision, and patch are withheld until discovery
artifacts are frozen.  After freezing, the evaluator requires the matching
candidate and two vulnerable/two fixed sanitizer attempts.

The target begins as `recovery_target`.  It becomes `must_detect` only after
authenticated blind discovery and differential reproduction pass.  Existing
`must_detect` entries may not be removed, demoted, deferred beyond their locked
rank, or matched by a different weakness.

## Production contracts

### Cursor-bound access signal

`c-cursor-access-v1` recognizes read-side memory accesses only when structural
evidence connects the base expression to a cursor-like offset/position and an
explicit bound.  Function-like macros are expanded only for local fact
extraction; arbitrary preprocessing or repository-specific names are not
introduced.

The compact signal records:

- the read expression and source line;
- cursor subject, bound subject, and constant/dynamic access index;
- macro expansion provenance when applicable;
- the nearest guard and whether a mutation invalidates it; and
- confidence and the evidence ranges needed by a Hunter.

Unqualified array reads do not become critical sinks.  This prevents a broad
signal-count and session-cost increase.

### Cursor transition chain

`c-cursor-transition-v1` binds caller and callee facts into the ordered proof
obligation:

`bounded input -> guard -> cursor mutation -> call -> input read`

A guard for access index `n` cannot prove safety after a positive cursor delta
unless it also covers `n + delta`.  A transition whose guard is absent,
partial, or invalidated is critical and includes both caller and callee in its
AnalysisSlice.

### Handwritten-parser routing

`c-signal-router-v4` routes a cursor-transition target to
`c-parser-state` even when all files are `.c` or `.h`.  Routing is based on the
structural signal/chain, not repository names, parser function names, CVE data,
or extensions alone.  Bounds remains eligible as supporting coverage, but the
parser specialist is the required owner for this target family.

### Hunter state proof

`c-cursor-proof-v1` requires the assigned Hunter to return a compact state
ledger for every cursor target:

- pre-guard relation;
- cursor mutation and resulting relation;
- callee entry precondition;
- dereference relation; and
- a minimum/maximum boundary counterexample or a concrete proof that none is
  reachable.

A cursor target cannot be closed as `no_finding` without this ledger and source
reads covering the mutation, call, and dereference.  Missing evidence becomes
`deferred`, not a fabricated safe result.  When sandbox execution is available,
an unsafe boundary hypothesis must be attempted before finalization.

## PR sequence

1. Freeze the strict cJSON scan manifest, withheld oracle, evaluator, synthetic
   vulnerable/fixed fixtures, and `recovery_target` registry entry.
2. Add bounded macro-aware cursor access facts and caller-to-callee transition
   chains, with deterministic IDs and negative fixtures that suppress ordinary
   guarded array reads.
3. Route transition targets to the Parser-State Hunter within the unchanged
   budget and preserve every protected specialist/admission contract.
4. Enforce the cursor state ledger, source-evidence gate, and boundary-attempt
   requirement for `finding`, `no_finding`, and `deferred` dispositions.
5. Run the complete protected matrix, then perform authenticated strict blind
   cJSON discovery and two-vulnerable/two-fixed reproduction before promotion.

Each PR runs its targeted tests and the full deterministic suite.  It is merged
only after its own diff review and checks pass; the next PR starts from the
newly merged `main`.

## Acceptance gates

- [x] The vulnerable neutral fixture emits one stable cursor-transition chain;
      the guarded fixture emits no critical chain.
- [x] The cJSON vulnerable snapshot produces a critical read target whose
      evidence covers `parse_object` and `parse_string` without using oracle
      strings in production.
- [x] A handwritten `.c` parser receives required `c-parser-state` work.
- [x] A NUL-only harness does not narrow an explicit-length public API contract.
- [x] `no_finding` is rejected when the state ledger or boundary analysis is
      absent, incomplete, or contradicted by the recorded source.
- [x] No new repository/path/symbol/trigger signature appears in `src/` or
      `prompts/`.
- [x] Planned/admitted sessions and context bytes remain within existing caps.
- [x] Every existing `must_detect` release job remains present in the protected
      release matrix and must pass before merge.
- [x] Strict blind discovery matches cJSON issue 800, followed by two failing
      vulnerable and two passing fixed sanitizer executions.
- [x] Targeted, full, lint, and type-check suites pass.

## Recovery evidence

The authenticated blind run used the Codex subscription adapter with
`gpt-5.6-sol` and received only the pinned vulnerable tree plus the oracle-free
scan manifest.  It admitted the required Parser-State work at rank 6 with
22,088 bytes of context.  The Hunter returned an `unsafe_reachable` cursor
ledger for signal `sig_609c03cb553078b84d7f`, executed a boundary PoC, and
observed the one-byte sanitizer read at `cJSON.c:787` through the caller frame
at `cJSON.c:1666`.

The frozen discovery root is
`2984ebf579b40af9db27dc0c1cec3bae0d98e20a82762cb91c3594026bea009c`.
Evaluation accepted the confirmed reportable candidate
`cand_verified_3f59aa2bebb8d1b2bc979873b6`, reproduced the vulnerable heap
buffer overflow twice, and observed two clean `rejected` executions on fixed
commit `3ef4e4e730e5efd381be612df41e1ff3f5bb3c32`.  The run stayed within the
unchanged caps: 12 sessions, 1,191,295 input tokens, 329,472 cache-read tokens,
27,099 output tokens, and a maximum context below 24,000 bytes.

An earlier negative-control run used a source-baked image without the declared
build artifacts.  The Parser-State Hunter correctly refused to close the cursor
target and returned `cursor_proof_incomplete`; that run was not used for the
promotion receipt.

## Non-goals

- changing generic file-ranking weights;
- treating every C array read as a critical sink;
- adding an unbounded symbolic executor or general-purpose preprocessor;
- increasing model/session/token budgets to hide a reasoning gap;
- encoding cJSON names, lines, trigger bytes, issue data, or patch contents in
  production logic or prompts;
- weakening evidence, reproduction, or historical-detection gates; or
- expanding M11.7 into unrelated vulnerability families.

## Rollback conditions

Stop the sequence before the next PR if any change:

- displaces or demotes a protected detection;
- increases critical targets primarily through ordinary safe array reads;
- requires repository-specific production logic;
- closes a cursor target safely without a complete proof ledger; or
- can pass the cJSON evaluator using an unrelated finding.
