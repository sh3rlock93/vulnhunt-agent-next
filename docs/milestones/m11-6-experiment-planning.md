# M11.6 — Capability-aware experiment planning

Status: implemented and locally verified

## Goal

Prevent a Reviewer-requested experiment from being recorded as executed when
the existing PoC cannot implement the requested behavior.  The planning layer
sits between the evidence-only Reviewer and the sandboxed Reproducer:

`Reviewer request → Experiment Planner → Variant Compiler → Reproducer → re-review`

The planner is deterministic and fail-closed.  It binds each request to the
immutable PoC artifact and chooses one of four strategies:

- argument-only variant;
- environment-only variant;
- separately synthesized harness; or
- separately approved fixed-revision snapshot.

Only the first two strategies are executable in this milestone.  A request for
a new transport topology, a PoC that does not consume argv, or a fixed revision
is preserved as a typed deferral instead of being approximated by meaningless
command-line arguments.

## Triggering incident

A blind libmodbus run reproduced an ASan heap-buffer-overflow in the prepared
target.  The reachability Reviewer requested an end-to-end TCP server/client
experiment.  The old variant compiler was only authorized to change argv, so
it appended `--transport tcp` to a `main(void)` PoC.  The PoC ignored the
arguments and directly called `modbus_reply`; the same crash was then
incorrectly counted as a completed variant.  Two re-reviews repeated the same
cycle and the candidate ended as generic `review_inconclusive` with no stored
verdict.

## Contracts

- `experiment-planning-v1` produces an immutable, persisted plan for every
  executable or deferred Reviewer request.
- Argument variants require source evidence that the PoC consumes argv.
- End-to-end transport requests require both a client path and a server receive
  path in the existing PoC; otherwise they require a new harness.
- Compiled variants are checked against the approved strategy before sandbox
  execution. Newly compiled option names and environment controls must be
  consumed by the immutable PoC source.
- Planning deferral executes no sandbox job and records
  `experiment_plan_unsupported`, including the missing capability and remaining
  requirement.
- Existing argument-aware and environment-aware controls retain their bounded
  two-attempt behavior.

## Acceptance gates

- [x] A `main(void)` PoC cannot implement an alternate trigger by appended argv.
- [x] A real-TCP request cannot reuse a direct-call harness without transport
  client and receive-path capabilities.
- [x] Unsupported plans persist as `experiment_plan` tasks and execute zero
  variant jobs.
- [x] Candidate resolution uses the typed planning reason rather than generic
  review inconclusiveness.
- [x] An argument-aware safe-input variant still executes twice and returns to
  automatic re-review.
- [x] A compiler cannot introduce an option that is absent from the immutable
  PoC and call the result conforming.
- [x] Targeted, full, lint, and type-check suites pass.
- [x] A fresh blind-repository benchmark completes without a planning-contract
  regression.

## Deferred scope

Generating a brand-new network harness is deliberately not hidden inside the
argv compiler.  It requires a separate synthesis strategy with an immutable
harness artifact, source-aware conformance review, and explicit authorization
for changed setup commands.  This milestone exposes that requirement without
weakening the existing reproduction provenance boundary.

## Fresh trace-audited blind baseline

The post-change baseline used vulnerable cJSON commit
`826cd6f842ae7e46ee38bbc097f9a34f2947388d` without the issue, patch, target
location, or PoC in discovery.  The run completed normally and exercised no
Reviewer variant, so it exposed no experiment-planning regression.  It did not,
however, find upstream issue #800: the bounds Hunters read the relevant
`parse_object` region but failed to connect the length-bounded parser state to
the one-byte read in `parse_string`.  Oracle disclosure after discovery showed
the vulnerable revision failing ASan twice at `cJSON.c:787` and the fixed
revision passing twice.  This is a separate Hunter reasoning gap, not a passing
detection benchmark, and must not be reported as scanner success.

This run is trace-audited rather than a strict process-enforced blind result.
The source tree contained the upstream regression test, although selection and
Hunter traces show that the scanner never opened it.  A future strict fixture
must pin parent commit `98f9eb0412067a852ec107c68e49180fe4e472dc`, whose
production cJSON source is byte-identical but predates the regression test, and
must use the formal withheld-oracle freeze workflow.
