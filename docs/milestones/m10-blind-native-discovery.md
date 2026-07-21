# M10 — Blind native vulnerability discovery at repository scale

Status: In progress — PR 5 complete

## Goal

Find and independently reproduce a real memory-safety vulnerability in a
100,000+ line C repository without giving the scanner a CVE identifier, fixing
diff, vulnerable file, function, line, or proof of concept. M10 turns the
LibTIFF blind-scan miss into a repository-scale discovery benchmark rather than
adding a target-specific signature.

The milestone is complete only when the frozen discovery output finds
CVE-2023-41175 in vulnerable LibTIFF, reproduces it against the prepared target
twice, and then fails to confirm the same defect in the post-freeze fixed-tree
negative control.

## Baseline and problem statement

The M9 blind evaluation used LibTIFF commit
`cb88a5b6bf1757060ec4d50055fa852fd7830cfe`, the parent of fixing commit
`6e2dac5f904496d127c92ddc4e56eccfca25c2ee`.

The target contains 139 C-family files and 107,694 lines. Static analysis
created 1,446 nodes, 7,173 edges, 389 entrypoints, 1,634 critical signals, and
1,964 slices. The plan selected 91 files, but the integrated run failed before
Hunter execution because one routed item contained 148 target signals while
`HunterWorkItem` permits at most 128. Other dense files contained 216 and 293
signals. The later slice stage already chunks signals, but validation occurs
before that stage.

A separate blind component scan spent 46 Codex iterations and approximately
1.77 million input tokens. It inspected `tools/raw2tiff.c` but prioritized an
unrelated thumbnail issue. A post-evaluation file-only run found the exact
integer-overflow-to-buffer-overflow chain in six iterations and reproduced it
with AddressSanitizer. This establishes that the remaining gap is discovery,
routing, and prioritization rather than basic reasoning or PoC generation.

The evaluation also exposed two correctness problems:

- A standalone reimplementation under `/workspace` could be labelled
  `confirmed` even when no target source or binary appeared in the sanitizer
  trace.
- Invalid JSON escapes in Codex tool arguments could terminate otherwise useful
  work instead of requesting one bounded protocol repair.

## Blindness contract

M10 separates scanner input from evaluation-only knowledge. The contract is
enforced by process boundaries and an access audit, not by prompt wording.

### Scanner-visible inputs

- Pinned vulnerable source snapshot and its build metadata.
- Language and toolchain declaration, such as `c:gcc-13`.
- Deterministic graph, signals, slices, and risk chains derived from that tree.
- Fixed execution, session, token, and wall-clock budgets.
- General native vulnerability taxonomies and non-target-specific prompts.

### Withheld oracle inputs

- CVE identifier and description.
- Fix commit, patch, diff, and fixed source tree.
- Vulnerable file, function, line range, and expected weakness class.
- Known trigger values, PoC, sanitizer output, and expected finding text.

The oracle must not be present in the target checkout, environment variables,
settings, prompt cache, analysis database, or discovery command. Benchmark
execution has three phases:

1. `discover` runs in an oracle-free subprocess and emits candidate findings,
   target dispositions, reproduction evidence, metrics, and an access log.
2. `freeze` writes a SHA-256 manifest for every discovery artifact and closes
   the discovery process. Frozen artifacts are immutable evaluation inputs.
3. `evaluate` starts separately, verifies the manifest, loads the withheld
   oracle, and calculates success or failure. It cannot resume Hunter work.

Manual file selection, a target-specific rule, or inspecting the fix before the
freeze invalidates the benchmark run.

```text
pinned source -> graph/signals -> risk chains -> bounded target batches
              -> quota scheduler -> targeted Hunter -> actual-target evidence
              -> freeze + hashes
                                      withheld oracle -> post-freeze evaluation
```

## Non-goals

- Proving that all 1,634 critical signals are vulnerability-free.
- Naming a CVE during discovery.
- General interprocedural symbolic execution or whole-program path proof.
- Unlimited Hunter sessions or repeated model calls until the oracle matches.
- Treating standalone model code as proof that the prepared target is vulnerable.

## Versioned contracts

M10 introduces the following policy versions so old runs remain explainable:

- `c-signal-router-v3`: validates bounded batches before work-item creation.
- `c-risk-chain-v1`: records source, arithmetic transform, guard, and sink links.
- `c-slice-work-v4`: ranks and chunks work using risk-chain membership.
- `c-context-v4`: serializes a chain-first packet under the 24,000-byte limit.
- `native-evidence-v2`: records what executable and source produced evidence.
- `blind-oracle-v1`: freezes discovery before evaluation knowledge is loaded.

Legacy evidence may deserialize with `execution_subject=unknown`, but it cannot
be promoted to target-confirmed evidence without a new reproduction.

## PR 1 — Pre-validation target batching and plan integrity

Full-scan routing must never construct an invalid `HunterWorkItem`. The router
first creates an internal `RoutingTargetBatch`, orders target signals
deterministically, and chunks them to at most six signals before schema
validation. Slice expansion may reduce or enrich a batch but cannot merge it
past the bound.

No signal is silently truncated. Every critical signal must map to one of:

- an admitted Hunter work item;
- a durable budget-deferred work item;
- an explicitly suppressed signal with policy and reason.

Duplicate coverage is allowed only when two distinct specialists are required;
both work items then reference the same audited coverage group. Stable work IDs
include the routing policy, seed, specialist, target IDs, and change focus.

Expected changes:

- `src/vulnhunt_agent/scheduling/router.py`
- `src/vulnhunt_agent/scheduling/slices.py`
- `src/vulnhunt_agent/domain/schemas.py`
- routing-plan and M8 scheduler tests

### PR 1 acceptance gates

- [x] Full LibTIFF planning completes with the 293-, 216-, and 148-signal files.
- [x] No final work item contains more than six target signals.
- [x] All 1,634 baseline critical signals have an auditable terminal route.
- [x] Reordering parser output does not change stable batches or work IDs.
- [x] No truncation, duplicate work ID, or Pydantic validation escape is possible.
- [x] M9 incremental routing semantics and zlib gates remain green.

## PR 2 — SSA-lite integer and size risk chains

Individual source and sink signals are too numerous to rank effectively. Add a
bounded intraprocedural data-flow pass that links security-relevant operations
inside one function. It is intentionally SSA-lite: it follows local
assignments, simple aliases, casts, and expression use without claiming a full
C memory model.

`RiskChain` contains:

- `chain_id`, `policy_version`, `file`, and `function_node_id`;
- ordered source, transform, guard, allocation, and sink signal IDs;
- source and sink line ranges;
- arithmetic operations, operand types, and narrowing or wrap risk;
- guard state: `absent`, `partial`, `dominates`, or `unknown`;
- deterministic score, confidence, and human-readable rationale.

The first pass recognizes general patterns:

- external values from arguments, option parsing, integer conversion, file
  reads, format tags, and function parameters;
- multiplication, addition, shifts, signed/unsigned conversion, and narrowing;
- allocation sizes, copy lengths, indexes, and loop bounds;
- mismatches where a derived or wrapped size controls allocation but an
  unbounded original value later controls a copy or loop.

M10 does not add `raw2tiff`, LibTIFF, or CVE-specific names to production
analysis. Synthetic fixtures encode the same data-flow shape with neutral
identifiers, including a guarded negative case.

Expected changes:

- new `src/vulnhunt_agent/analysis/risk_chains.py`
- graph models and persisted analysis artifacts
- C graph and signal export integration
- focused synthetic and real-tree tests

### PR 2 acceptance gates

- [x] A source-to-arithmetic-to-allocation-to-copy chain is emitted deterministically.
- [x] The chain records whether the later copy or loop uses a different bound.
- [x] A dominating overflow guard lowers or suppresses the dangerous-chain score.
- [x] Alias, cast, and nested multiplication fixtures retain ordered provenance.
- [x] IDs and scores are stable across runs and filesystem ordering.
- [x] The vulnerable LibTIFF tree produces a high-priority chain for the target path without oracle input.
- [x] The fixed tree records its new guard and lowers that chain after evaluation only.

## PR 3 — Diverse, budget-aware admission

Replace file-risk-only admission with deterministic risk-chain admission. Dense
files cannot monopolize the session budget. The default LibTIFF benchmark has a
24-logical-item ceiling divided into concrete reservable quotas:

- 14 chain-critical items;
- 5 critical items from components not yet represented;
- 3 high-risk non-chain items;
- 2 retry or reviewer-requested item reservations.

This is the integer form of an approximately 60/20/10/10 allocation. A retry
retains its logical work ID and consumes its reservation plus the original
token and wall-clock budget; it does not become a 25th admitted item. Unused
quota may be borrowed in that order after each scheduling round. Before
all eligible top-level components receive one critical admission, no seed file
may consume more than four sessions. Within a quota, ordering uses risk-chain
score, guard state, sink severity, entrypoint reachability, component novelty,
and stable ID.

Admission decisions persist the score components, quota, rank, and reason.
Work beyond the budget remains resumable and visible as `budget_deferred`; it is
never dropped from coverage metrics.

Expected changes:

- `src/vulnhunt_agent/scheduling/budget.py`
- routing metrics and durable run summaries
- plan artifact and CLI/UI summary fields
- M8 scheduler and LibTIFF admission tests

### PR 3 acceptance gates

- [x] The vulnerable target chain is admitted within the first 24 sessions without oracle data.
- [x] No single dense file consumes the benchmark before component coverage occurs.
- [x] Every admission exposes rank, quota, score breakdown, and policy version.
- [x] Deferred critical work remains countable and resumable.
- [x] Repeated runs produce identical admission order from identical artifacts.
- [x] Existing M8 60/30/10 operational behavior remains compatible outside M10 full native scans.

## PR 4 — Chain-first Hunter context and target completion

Full native scans no longer send a generic repository-root target. Each admitted
Hunter receives one bounded work item containing one to six exact target
signals, their risk-chain rationale, and only the source ranges needed to
reason about that chain.

Context order is:

1. external source and parse/conversion site;
2. arithmetic and type transforms;
3. guard or missing-guard region;
4. allocation site;
5. copy, index, or loop-bound sink;
6. immediate callers or callees when space remains.

The serialized packet retains the 24,000-byte hard cap. The prompt asks the
Hunter to compare allocation size with the independent copy, loop, or index
bound and to prove reachability before escalating. It does not mention the
benchmark target.

M9 target completion remains mandatory: every admitted signal receives exactly
one `finding`, `no_finding`, or `deferred` disposition. An empty finding array
cannot complete work when target dispositions are missing.

Expected changes:

- `src/vulnhunt_agent/analysis/context.py`
- Hunter prompt and result validation
- `src/vulnhunt_agent/pipeline/hunt/`
- context cache and completion tests

### PR 4 acceptance gates

- [x] Native full-scan work uses exact targets rather than `.` as the analysis unit.
- [x] The target chain's source, arithmetic, allocation, and sink ranges fit one packet.
- [x] No persisted context packet exceeds 24,000 bytes.
- [x] The context cache key changes when chain members or policy versions change.
- [x] Every admitted target receives exactly one valid disposition.
- [x] The target session inspects relevant source ranges without manual file selection.
- [x] Synthetic vulnerable and guarded fixtures produce finding and no-finding dispositions respectively.

## PR 5 — Actual-target evidence provenance

Reproduction confidence must describe what actually executed. Extend evidence
with:

- `execution_subject`: `prepared_binary`, `linked_target_harness`,
  `standalone_model`, or `unknown`;
- prepared snapshot and build identity;
- executed binary and linked target artifacts;
- normalized sanitizer frames and source roots;
- attempt count, clean-environment IDs, and oracle outcome.

A memory-safety finding may become `confirmed` only when both clean attempts
exercise the prepared target:

- the prepared target binary itself crashes with a matching sanitizer frame; or
- a bounded harness links the prepared target library and the sanitizer trace
  reaches source below `/code` or the pinned target artifact.

A PoC that copies or reimplements source under `/workspace` is useful
hypothesis evidence, but remains `unverified`. Text output, exit status, and a
standalone sanitizer failure cannot impersonate target execution. The existing
two-attempt and snapshot-match requirements remain mandatory.

Expected changes:

- evidence schemas and tool ledger
- Reproducer oracle and policy service
- consensus/reporting confidence rules
- Docker sandbox integration tests

### PR 5 acceptance gates

- [x] Standalone reimplementation evidence cannot confirm a target finding.
- [x] A prepared binary or linked target harness records verifiable target provenance.
- [x] Sanitizer frames are normalized and matched to the pinned source root.
- [x] Both clean attempts must agree on subject, snapshot, and failure class.
- [x] Legacy `unknown` evidence remains readable but cannot gain confirmation.
- [x] The prior archive snippet result is downgraded to unverified by policy.
- [x] The LibTIFF target binary reproduction is confirmable when executed twice.

## PR 6 — Codex protocol repair and durable retries

Malformed tool arguments are a protocol error, not authorization to guess and
execute a repaired command. The Codex adapter first performs strict JSON and
tool-schema validation. On failure it returns a typed
`tool_arguments_invalid` event to the Hunter, including the allowed schema and
a redacted validation reason. The Hunter may request exactly one model repair;
no tool runs before the repaired payload validates.

Durable work may retry once for a classified transient transport or protocol
failure while retaining the same logical work ID. Completed tool calls and
completed targets are not replayed. Authentication, authorization, missing
model, and budget failures are terminal rather than retried.

Metrics distinguish invalid arguments, repair success, rate limits, timeouts,
transport failures, and terminal configuration errors. Raw prompts, tokens,
credentials, and unsafe tool payloads are not logged.

Expected changes:

- `src/vulnhunt_agent/core/codex_client.py`
- Hunter loop and durable pipeline retry policy
- structured events and run metrics
- protocol and replay tests

### PR 6 acceptance gates

- [ ] Invalid JSON escapes never reach tool execution.
- [ ] One valid model repair can resume the original logical work item.
- [ ] A second malformed payload terminates as an explicit deferred disposition.
- [ ] Retry count, token cost, and elapsed time are charged to the original budget.
- [ ] Completed calls and target dispositions are not replayed after retry.
- [ ] Auth and configuration failures fail immediately with actionable categories.
- [ ] The previously observed invalid-escape scenario is covered by a deterministic test.

## PR 7 — Withheld-oracle LibTIFF benchmark

Add a reproducible benchmark with scanner and oracle manifests kept logically
and operationally separate:

- `benchmarks/libtiff-blind-scan.toml` contains only repository, vulnerable
  commit, build environment, policies, and budgets.
- `benchmarks/oracles/libtiff-cve-2023-41175.toml` contains the evaluation-only
  fix, location, weakness, and reproduction expectations.
- `benchmarks/run_libtiff_blind_benchmark.py` exposes separate `discover`,
  `freeze`, and `evaluate` commands and refuses mixed-phase options.

The discovery process receives a restricted filesystem view containing the
installed scanner, scan manifest, writable artifact directory, and vulnerable
target only. The oracle directory and fixed tree are not mounted. The evaluator
runs after process exit with a separate view containing read-only frozen
artifacts and the oracle. An input manifest and denied-access audit make the
separation machine-checkable even though both manifests are versioned in the
development repository.

The deterministic CI tier requires no LLM credentials. It verifies the pinned
trees, full-plan validity, risk-chain creation, admission rank, context bounds,
actual-target evidence policy, oracle isolation, and vulnerable/fixed static
differential. The authenticated benchmark tier runs locally or in an approved
nightly environment with either the OpenAI API or Codex subscription adapter;
it is not a required GitHub-hosted PR check when credentials are unavailable.

The authenticated budget is:

- at most 24 Hunter sessions;
- at most 2,000,000 input tokens and 200,000 output tokens;
- at most 60 minutes wall time;
- one format repair and one transient retry per logical item;
- complete dispositions for all admitted targets.

Evaluation succeeds only when the frozen vulnerable run contains a finding in
the oracle range with an integer-size mismatch leading to memory corruption,
and two clean actual-target attempts produce matching AddressSanitizer evidence.
The same reproduction against the fixed tree must be rejected or complete
without sanitizer failure, and the fixed discovery result must not contain the
same confirmed finding.

Reported benchmark metrics include top-k target admission, time and tokens to
first valid finding, disposition completeness, confirmed versus unverified
findings, evidence subject, deferred critical targets, and oracle-access audit.

### PR 7 acceptance gates

- [ ] The vulnerable and fixed Git trees match their pinned upstream commits.
- [ ] Discovery completes without opening or receiving the oracle manifest.
- [ ] Frozen artifacts and their SHA-256 manifest verify before evaluation.
- [ ] The vulnerable target is found within 24 sessions and the fixed budget.
- [ ] Two clean attempts reproduce the defect in the prepared target binary.
- [ ] The fixed tree rejects the trigger or runs without matching sanitizer evidence.
- [ ] The post-freeze fixed-tree negative control has no equivalent confirmed result.
- [ ] Deterministic CI runs without API or subscription credentials.
- [ ] Authenticated results record adapter, model, policies, cost, and run identity.
- [ ] All M8, M9, Docker, and domain-contract regressions remain green.

## Verification matrix

| Layer | Purpose | Required gate |
| --- | --- | --- |
| Unit | batching, stable IDs, risk chains, guards, quotas, evidence policy | every PR |
| Synthetic integration | vulnerable/guarded neutral C fixtures | PR 2–5 |
| Real-tree deterministic | pinned LibTIFF plan, rank, context, static differential | PR 1–7 |
| Sandbox integration | prepared binary, linked harness, two clean attempts | PR 5 and 7 |
| Authenticated blind run | end-to-end model discovery under fixed budget | PR 7 release gate |
| Regression | M8 scheduler, M9 zlib, libcue, domain, Docker | every PR |

Each PR is merged only after its acceptance gates pass. A later PR may not
weaken an earlier bound to make the final benchmark pass. PR 7 is the only
place where the oracle is interpreted, and only after discovery artifacts have
been frozen.

## Stop conditions requiring a design decision

Implementation proceeds sequentially unless one of these conditions occurs:

- The target cannot be admitted within 24 sessions without a target-specific
  feature; increasing the budget or accepting a signature requires approval.
- A proposed reproduction requires network access, host privileges, or a
  sandbox escape beyond the existing execution policy.
- The fixed revision still produces matching actual-target sanitizer evidence,
  which would invalidate the chosen oracle or PoC.
- A schema change cannot preserve legacy artifacts without a data migration.
- Authenticated model variance prevents repeatable success under the agreed
  budget; changing the release criterion requires approval.

Ordinary implementation defects, flaky tests with a known local fix, and
missing optional credentials do not stop the sequence. They are fixed or the
authenticated tier is run in the documented supported environment.

## Definition of done

M10 is complete when all seven PRs are merged and a fresh benchmark run proves:

- no CVE, diff, vulnerable location, trigger, or fixed source was available
  before artifact freeze;
- full LibTIFF planning is bounded, deterministic, and coverage-auditable;
- the vulnerable chain is admitted and analyzed within the fixed budget;
- every admitted target has a valid terminal disposition;
- two clean executions confirm the finding in the prepared target, not copied
  model code;
- the fixed tree supplies the expected negative control;
- frozen artifacts, access logs, model usage, and policy versions are sufficient
  for an independent audit;
- all existing regression suites remain green.
