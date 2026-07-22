# M11 — Reliable bounded scans and candidate falsification on live repositories

Status: PR 1–6 implemented and verified; PR 7 pending

## Goal

Make a blind scan of a current, widely used C repository operationally valid,
cost-bounded, and resistant to avoidable false positives. M11 does not promise
to find a zero-day in every clean upstream revision. It promises that:

- an invalid provider execution is never reported as a clean scan;
- operators can bound discovery to declared files or components without making
  analysis-only source copies;
- one dense file cannot consume the useful discovery budget;
- selected work can still use caller, callee, and global constraint context
  from the complete immutable source snapshot;
- theoretically suspicious arithmetic is checked for input and resource
  reachability before it is promoted; and
- every candidate and every admitted target ends in an auditable terminal
  state.

The default full-scan behavior remains coverage-preserving and compatible with
M10. Bounded scope is an explicit operator choice and must report incomplete
repository coverage rather than pretending to be a full scan.

## Evidence from the libexpat live-repository run

The baseline used upstream commit
`7d93af0965eee44fde42d9e9ec8761ae2894e8e8` without CVE, advisory, patch, or
fix-diff input. The tree contained 81 C-family files and 40,113 lines. The
prepared GCC 13 image passed its ASan/UBSan build and the available CTest gate.

The run exposed five general problems:

1. The source snapshot rejected a repository-internal README symlink, requiring
   a manually dereferenced analysis copy.
2. A Codex subscription launch failed because the execution environment could
   not write the Codex state database. Ten tasks were initially labelled as
   authentication or internal model failures even though no model tokens or
   tools ran.
3. A 12-session full-scan budget admitted ten work items, all seeded from
   `expat/lib/xmlparse.c`. Seven completed, three became target-deferred, 54
   work items were budget-deferred, and the remaining selected files received
   no useful coverage. The completed calls used 1,095,795 input tokens and
   15,243 output tokens.
4. Saving a five-file selection did not constrain execution because the router
   correctly reintroduced critical sinks from the full graph. A second manual
   source view was needed to obtain a true four-file tokenizer plan.
5. The bounded tokenizer run completed 11 of 11 work items and all 48 targets,
   but proposed an `int nAtts` overflow in `xmltok_impl.c`. Full caller analysis
   refuted it: the only public path retains the whole start tag in an
   `int`-bounded buffer, while each attribute needs at least five input bytes,
   so the attribute counter cannot approach `INT_MAX`. The scoped Hunter did
   not receive that caller-side constraint and the verifier left the candidate
   as merely `statically_supported` with no executable recipe.

These are scanner reliability defects and cost-quality gaps. They do not
establish a vulnerability in libexpat.

## Design principles

- **Full snapshot, bounded scheduling:** scope limits model work, not the source
  truth available for context and verification.
- **Explicit incompleteness:** out-of-scope and budget-deferred work remain
  visible and cannot be counted as no-finding coverage.
- **Fail closed on invalid execution:** zero executed model calls is not a
  successful zero-finding scan.
- **Falsification before escalation:** cheap caller constraints and numeric
  bounds run before expensive PoC synthesis.
- **No target signatures:** policies are expressed using general source,
  buffer, type, and resource relationships.
- **Blindness remains process-enforced:** scope manifests and real-tree
  benchmarks contain no vulnerability oracle.

## Versioned contracts

M11 introduces these versioned policies so historical artifacts remain
explainable:

- `source-snapshot-v3`: safe repository-internal symlink normalization and
  provenance;
- `scan-scope-v1`: full, bounded-file, and bounded-component scope semantics;
- `c-context-v5`: full-snapshot caller/callee and constraint hydration;
- `c-budget-v3`: seed-file diversity, quota borrowing, and slot recycling;
- `native-feasibility-v1`: input-size, resource, and numeric reachability
  evidence;
- `run-outcome-v1`: complete, budget-limited, invalid, and interrupted outcome
  classification.

## PR 1 — Safe source intake and symlink provenance

Allow ordinary repository-internal file symlinks to be snapshotted without
requiring an analysis copy. The snapshotter resolves a symlink only when its
canonical target remains inside the immutable repository root and is a regular
file. The snapshot records the link path, textual target, resolved relative
path, content digest, and normalization policy.

Escaping, absolute, dangling, cyclic, directory, socket, device, and FIFO links
remain rejected. The canonical snapshot digest must be independent of host
absolute paths and must change when either the link mapping or resolved content
changes.

Expected changes:

- `src/vulnhunt_agent/intake/snapshot.py`
- source snapshot schemas and provenance export
- intake fixtures for safe and unsafe symlinks

### PR 1 acceptance gates

- [x] The libexpat README symlink is accepted without copying the repository.
- [x] Repository-external, dangling, cyclic, and special-file links are rejected.
- [x] Link provenance and resolved-content SHA-256 are persisted.
- [x] Reordered directory traversal produces the same snapshot identity.
- [x] Changing a link target or its content changes the snapshot identity.
- [x] Existing no-symlink snapshots remain readable and deterministic.

## PR 2 — Provider readiness preflight and actionable failure taxonomy

Run a transport-specific readiness check before Hunter admission. For the Codex
subscription adapter this verifies the executable and version, required feature
flags, login state, state-store accessibility in the actual execution context,
temporary output paths, and in-process app-server initialization. A separately
requested model probe may perform one minimal structured response, but the
default local readiness check must not consume model tokens.

Classify failures using stable codes such as:

- `state_store_read_only`;
- `app_server_init_denied`;
- `authentication_required`;
- `model_unavailable`;
- `unsupported_cli_feature`;
- `provider_protocol_error`; and
- `provider_transport_error`.

Persist a redacted stderr fingerprint and remediation text. Do not expose
credentials, prompts, tokens, or arbitrary command payloads. A preflight
failure sets the run outcome to `invalid_execution` and prevents Hunter budget
admission.

Expected changes:

- `src/vulnhunt_agent/core/codex_client.py`
- provider-neutral preflight result schemas
- CLI/UI run-start and diagnostics surfaces
- adapter failure-classification fixtures

### PR 2 acceptance gates

- [x] A read-only Codex state database is reported as `state_store_read_only`.
- [x] App-server initialization denial is not mislabelled as authentication.
- [x] No Hunter task is admitted after a terminal preflight failure.
- [x] A zero-call failed run cannot display a zero-finding success result.
- [x] API, Codex subscription, and fake test providers share one result contract.
- [x] Diagnostics are redacted and contain a concrete remediation.
- [x] Existing M10 protocol-repair and retry tests remain green.

## PR 3 — First-class bounded scan scope

Add an immutable scope manifest instead of overloading the UI file selector.
The CLI and UI support:

```text
--scope-mode full|files|component
--include-path <path>       # repeatable
--exclude-path <path>       # repeatable
--scope-manifest <file>
```

`full` preserves the M10 rule that every detected critical sink must be routed
or budget-deferred. `files` and `component` limit mandatory scheduling to the
declared scope. Critical signals outside that scope receive the durable state
`scope_deferred`; they are not suppressed, no-finding, or silently dropped.
The final result must say that repository-wide coverage is incomplete.

Scope is applied to the full immutable snapshot and full analysis graph. It
must never require deleting files, making a curated source tree, or changing
the prepared target image. Stable work IDs include the canonical scope digest.

Expected changes:

- CLI scan arguments and UI scope controls
- `src/vulnhunt_agent/analysis/incremental.py`
- `src/vulnhunt_agent/scheduling/router.py`
- scope schemas, artifacts, and coverage summaries

### PR 3 acceptance gates

- [x] A four-file libexpat tokenizer scope schedules only those seed files.
- [x] `xmlparse.c` is not forced into an explicit tokenizer-only scope.
- [x] Out-of-scope critical signals are counted as `scope_deferred`.
- [x] Full mode retains M10's no-uncovered-critical-sink guarantee.
- [x] Relative-path normalization rejects traversal and nonexistent paths.
- [x] Equivalent reordered scope manifests produce the same digest and work IDs.
- [x] Reports distinguish scoped completeness from repository completeness.

## PR 4 — Full-snapshot context and constraint hydration

Keep scheduling bounded while hydrating each context packet from the complete
snapshot. Starting from the selected target, the context builder adds bounded
caller and callee ranges, type definitions, input-buffer construction, and
dominant validation or resource constraints even when those files are outside
the execution scope.

Add general `ConstraintFact` records for relationships such as:

- an API parameter or allocation is bounded by `INT_MAX`, `SIZE_MAX`, or a
  checked application limit;
- a complete token must fit in a bounded parser buffer;
- each loop iteration or parsed item consumes a known minimum number of bytes;
- a guard dominates the sink through an immediate caller; and
- a count, length, or allocation value is narrowed before use.

Context remains subject to a hard byte limit. Exact target ranges come first,
then constraints capable of proving or disproving reachability, then other
callers and callees. The cache key includes the full snapshot, scope digest,
constraint policy, selected ranges, and truncation decisions.

Expected changes:

- `src/vulnhunt_agent/analysis/context.py`
- C graph caller/callee and constraint extraction
- context cache schema and prompt rendering
- cross-scope context tests

### PR 4 acceptance gates

- [x] Scoped work can read context from outside its scheduling scope.
- [x] The libexpat `getAtts` packet includes its `storeAtts` caller and buffer-size constraint.
- [x] Oracle files, external paths, and non-snapshot content remain inaccessible.
- [x] No context packet exceeds the configured byte limit.
- [x] Truncation decisions are deterministic and visible in the artifact.
- [x] Snapshot, scope, constraint, or excerpt changes invalidate the cache key.
- [x] Existing M10 chain-first context tests remain green.

## PR 5 — Dense-file fairness and recyclable budget quotas

Extend risk-chain admission with seed-file diversity. Component diversity alone
is insufficient when many high-risk files share one directory or package. Add
a deterministic seed-file quota and a per-file early-round cap. Before the
diversity quota is satisfied, one seed file may not consume more than the
configured cap unless it owns every eligible critical chain; any exception is
persisted with its score and reason.

The default 12-session live-repository policy reserves:

- 6 chain-critical sessions;
- 3 distinct-seed diversity sessions;
- 2 high-risk secondary sessions; and
- 1 retry or reviewer-requested session.

Unused reservations are borrowed before execution in the listed order. A
target-deferred or terminally invalid item cannot strand an otherwise usable
reservation. Started calls still count against session and token limits, while
unstarted admissions are returned to the queue. Coverage-group deduplication
prevents equivalent slices from repeatedly consuming the same seed budget.

Expected changes:

- `src/vulnhunt_agent/scheduling/budget.py`
- routing coverage groups and seed-family calculation
- durable admission, cancellation, and usage accounting
- scheduler metrics and result summaries

### PR 5 acceptance gates

- [x] A 12-session libexpat plan admits at least three distinct critical seed files when eligible.
- [x] `xmlparse.c` cannot consume all useful sessions before diversity admission.
- [x] Unused retry and class reservations are borrowed deterministically.
- [x] Unstarted cancelled work returns its reservation without inventing usage.
- [x] Started or cancelled provider calls retain their actual token and time usage.
- [x] Duplicate coverage groups do not consume multiple general slots.
- [x] Admission remains identical under input and filesystem reordering.
- [x] M8 and M10 budget behavior remains compatible outside the new policy version.

## PR 6 — Resource-feasibility proofs and terminal candidate resolution

Insert a falsification stage between Hunter output and reproduction. It derives
and records lower and upper bounds for the claimed trigger:

- minimum iterations, objects, or parsed items required to cross a type limit;
- minimum attacker-controlled bytes and memory required;
- maximum bytes or objects reachable through the public entrypoint;
- relevant type, buffer, allocator, and application limits; and
- the source ranges and arithmetic supporting each bound.

The result is one of `feasible`, `logically_infeasible`,
`environmentally_extreme`, or `unknown`. Only a proven contradiction can mark
a finding `statically_refuted` or `resource_infeasible`. A merely expensive but
possible trigger remains a candidate with reduced exploitability confidence.

For surviving candidates, the verifier performs one bounded full-context
re-review and attempts to synthesize a reproduction recipe against the prepared
target. `statically_supported` becomes an intermediate state, not a terminal
reporting state. Final states are:

- `confirmed`;
- `statically_refuted`;
- `resource_infeasible`;
- `reproduction_rejected`; or
- `verification_deferred` with a typed reason and remaining requirement.

Expected changes:

- feasibility models and C numeric-bound analysis
- verification pipeline and recipe synthesis
- finding-state transition policy
- report and UI candidate-resolution views

### PR 6 acceptance gates

- [x] The libexpat `nAtts` candidate is refuted using caller and minimum-input bounds.
- [x] A nearby synthetic candidate with a reachable smaller limit remains feasible.
- [x] Large but logically possible resource-exhaustion findings are not auto-refuted.
- [x] Every inferred bound cites immutable source ranges and checked arithmetic.
- [x] A supported candidate gets one bounded recipe-synthesis attempt.
- [x] Standalone model code still cannot confirm prepared-target vulnerability.
- [x] No candidate remains silently terminal at `statically_supported`.
- [x] Legacy findings remain readable without retroactive confidence promotion.

## PR 7 — Real-world benchmark and honest outcome reporting

Add a libexpat operational benchmark that is separate from vulnerability
oracles. Its deterministic tier checks source intake, full planning, bounded
scope, context hydration, fair admission, feasibility proof, and run-outcome
classification. It does not assert that the latest upstream tree is free of
unknown vulnerabilities.

The optional authenticated tier runs the pinned tree under a 12-session Codex
subscription or API budget. It records:

- provider preflight and model identity;
- selected, scope-deferred, budget-deferred, admitted, and completed targets;
- distinct seed files and maximum per-file session share;
- input, output, cache, tool, and wall-clock usage;
- candidates by confirmed, refuted, rejected, and deferred outcome;
- tokens per completed target and time to first supported candidate; and
- full-snapshot and scope-manifest digests.

Introduce explicit run outcomes:

- `valid_complete`: all in-scope work reached terminal dispositions;
- `valid_budget_limited`: execution was valid but declared work was deferred;
- `invalid_execution`: provider, snapshot, sandbox, or protocol setup prevented
  trustworthy analysis; and
- `interrupted`: operator or process cancellation left resumable work.

A zero-finding label is shown only for a valid outcome and only with its exact
scope and deferred counts.

Expected changes:

- `benchmarks/libexpat-live-scan.toml`
- deterministic fixtures for the libexpat-shaped false-positive chain
- benchmark runner, freeze manifest, and metrics exporter
- CLI/UI/result-card outcome rendering
- authenticated benchmark documentation

### PR 7 acceptance gates

- [ ] Deterministic CI requires no provider credentials or network access.
- [ ] Safe symlink, provider failure, scope, fairness, and feasibility fixtures pass.
- [ ] The real-tree plan uses the pinned source and contains no CVE or patch oracle.
- [ ] The authenticated run respects 12 sessions and all token/time ceilings.
- [ ] Every admitted target has one terminal disposition.
- [ ] Invalid and interrupted runs cannot be presented as clean scans.
- [ ] The report always shows exact scope and all deferred categories.
- [ ] M8–M10, Docker, evidence-provenance, and legacy-artifact regressions remain green.

## Verification matrix

| Layer | Purpose | Required gate |
| --- | --- | --- |
| Unit | symlinks, scopes, failure codes, quotas, bounds, state transitions | every PR |
| Synthetic integration | reachable and unreachable integer/resource chains | PR 4–6 |
| Real-tree deterministic | pinned libexpat plan, scope, context, admission | PR 1–7 |
| Provider fixture | Codex state, app-server, auth, model, and protocol failures | PR 2 and 7 |
| Sandbox integration | prepared-target recipe and provenance enforcement | PR 6 and 7 |
| Authenticated blind run | cost and outcome-quality measurement | PR 7 release gate |
| Regression | M8 scheduler, M9 native cases, M10 LibTIFF, domain, Docker | every PR |

Each PR is merged only after its acceptance gates pass. A later PR may not
weaken full-scan critical-sink coverage, the blind oracle boundary, or
prepared-target evidence requirements to make the live benchmark pass.

## Stop conditions requiring a design decision

Implementation proceeds sequentially unless one of these conditions occurs:

- bounded-scope semantics would silently change existing full-scan behavior;
- a required source symlink resolves outside the pinned repository root;
- fair admission would exclude the only known critical risk chain under the
  existing fixed budget;
- a feasibility proof depends on an assumption that cannot be tied to source or
  build evidence;
- a provider readiness check cannot distinguish local setup failure without a
  billable model request; or
- a finding requires host privileges, network access, or an execution policy
  expansion for reproduction.

Ordinary implementation defects, deterministic test failures with local fixes,
and optional authenticated credentials do not stop the sequence.

## Definition of done

M11 is complete when all seven PRs are merged and a fresh pinned libexpat run
demonstrates that:

- the original repository is accepted without a dereferenced source copy;
- Codex subscription setup failures fail before Hunter budget admission with a
  correct, actionable category;
- full mode preserves critical-sink coverage while a declared bounded scope
  schedules only its intended seed files;
- bounded work receives relevant caller and resource constraints from the full
  immutable snapshot;
- a dense file cannot monopolize the fixed live-repository budget;
- the observed impossible attribute-count candidate is deterministically
  refuted without a target-specific signature;
- surviving candidates receive actual-target verification or a typed deferred
  requirement; and
- final output distinguishes valid complete, valid budget-limited, invalid,
  and interrupted runs with complete usage and coverage accounting.
