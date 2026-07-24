# M12 — Measured zero-day readiness

Status: in progress; M12.0 measurement contract is active

## Goal

Move the scanner from a strong research prototype to a measurable internal beta
for C memory-safety research.  M12 does not promise that every current
repository contains or yields a zero-day.  It establishes whether the scanner
reliably detects previously unseen historical vulnerabilities, how often it
does so, what it costs, how many reportable results are false, and whether the
same operating procedure can be used on current upstream revisions.

M12 is deliberately sequential.  Only one sub-milestone may be active.  The
next sub-milestone starts only after the current one has its release report,
all protected detections are green, and every rollback condition is cleared.
Later work may not be pulled into an earlier PR for convenience.

## Scope and claims

The primary release claim is limited to the C vulnerability families already
represented by protected detection contracts:

- bounded writes, size calculations, and capacity propagation;
- bounded parser reads and cursor-state transitions; and
- integer or signedness transitions that reach memory access.

Lifetime errors, races, authentication, injection, cryptographic defects, and
business logic are outside the primary M12 recall denominator unless a later,
separately reviewed Hunter milestone adds them.  Challenge cases from an
unsupported family may be recorded, but they cannot improve or reduce the
primary score by being silently mixed into it.

## Evaluation partitions

Every benchmark case belongs to exactly one immutable partition:

1. `protected`: the existing `must_detect` regressions.  They prevent old
   detections from disappearing but do not measure generalization.
2. `calibration`: new cases whose oracles may be inspected after a run and may
   guide a narrowly scoped fix.  They never count as holdout evidence again.
3. `negative`: fixed revisions and safe near-miss repositories used to measure
   false escalation and report precision.
4. `sealed_holdout`: cases never used for prompts, ranking, Hunter logic, tests,
   or threshold selection.  Opening an oracle permanently retires that case
   from future holdout use if implementation changes follow.
5. `prospective`: current upstream snapshots without a known vulnerability
   oracle.  A no-finding result is not a claim that the repository is safe.

Repository names, paths, symbols, trigger values, patch text, issue numbers,
and fixed revisions remain unavailable to discovery.  The evaluator opens
them only after discovery artifacts are frozen and hash-verified.

## Metric definitions

Metrics are calculated from frozen artifacts; benchmark runners may not infer
success from console text.

Recall is reported at `k = 3, 6, 12` sessions.  Binomial rates include a 95%
Wilson interval so a small pilot cannot be presented with false precision.

- `valid_run_rate`: valid completed or valid budget-limited runs divided by all
  requested runs.  Invalid and interrupted runs are failures, not no-findings.
- `admission_at_k`: whether the oracle-matching target and required Hunter were
  admitted within the first `k` sessions.
- `hunter_detection_at_k`: whether a matching raw Hunter finding with required
  source evidence appeared within `k` sessions.
- `reportable_detection_at_k`: whether the matching vulnerability reached one
  canonical `reportable` candidate within `k` sessions.
- `case_success_rate`: successful repeated runs divided by valid repeated runs
  for one benchmark case.
- `reportable_precision`: manually or oracle-adjudicated real reportable
  candidates divided by all adjudicated reportable candidates.
- `fixed_target_false_positive_rate`: fixed revisions incorrectly matched to
  their paired vulnerable oracle divided by valid fixed-revision runs.
- `false_escalation_rate`: candidates from the negative partition that reached
  reportable status and were then adjudicated false divided by valid negative
  runs.
- `tokens_per_valid_run`: input plus cache-read plus cache-write tokens.  Output
  tokens are reported separately.
- `tokens_per_reportable`: total model tokens divided by unique real reportable
  candidates.  When there are none, the result is `undefined`, never zero.
- `time_to_first_reportable`: wall time from accepted run start to the first
  canonical reportable candidate.

Duplicate Hunter findings for the same root cause count once in precision and
recall, while their individual execution costs remain in the cost denominator.
All metrics include numerator, denominator, confidence interval, source run
IDs, model identity, policy versions, and snapshot hashes.

## M12.0 — Measurement contract and baseline freeze

### Single objective

Make performance claims reproducible before running or changing another
Hunter.  This milestone changes benchmark and reporting code only.  It does not
change ranking, routing, prompts, Hunter behavior, reviewer behavior, sandbox
execution, or budgets.

### PR sequence

1. Add a versioned `benchmark-case-v1` manifest describing partition, source
   identity, supported family, required Hunter, budget, repetition index, and
   evaluator reference.  The discovery view excludes oracle-only fields.
2. Add a `benchmark-metrics-v1` reducer that consumes closed freeze manifests,
   authenticated receipts, canonical candidates, and adjudications.  It emits
   JSON plus a compact Markdown table with exact denominators.
3. Freeze the M11.7 main commit and current six `must_detect` results as the M12
   baseline.  Add leakage and status-demotion checks, but no new vulnerability
   target.

### Acceptance gates

- Reordering input cases or runs produces byte-identical metrics.
- Missing, invalid, interrupted, or unverified runs cannot become detections.
- A duplicate candidate counts once for recall and precision but retains all
  token usage.
- Zero reportable findings produce an undefined cost-per-reportable value.
- Every metric links to immutable run, source, model, policy, and freeze IDs.
- No production source, prompt, ranking, Hunter, or budget file changes.
- The complete protected release matrix remains green.

### Stop conditions

- Existing artifacts lack enough provenance to distinguish invalid execution
  from a valid miss.
- A metric requires subjective interpretation that cannot be represented by a
  versioned adjudication record.
- The reducer would need oracle data before freeze verification.

## M12.1 — Prepared-build verification and provenance

### Single objective

Turn the existing CMake, Meson, Autotools, and Make preparation path into a
verifiable benchmark input.  The project already selects these layouts and
creates source-baked images; this milestone does not replace that logic or add
another build framework.  It adds a stable plan, verifies the artifacts that
Hunters will actually use, and records enough provenance to reproduce the
preparation.  Detection, scheduling, review, and candidate policy do not
change.

### PR sequence

1. Refactor the existing layout selection into a serializable,
   `prepared-build-plan-v1` record.  It captures a source-relative descriptor,
   normalized commands, compiler and sanitizer settings, expected artifact
   roots, and a typed unsupported reason.  Image identity is derived from the
   source snapshot, base toolchain, and plan—not an absolute host path.
2. Verify the approved plan's real outputs before a hunt can start.  Emit a
   `prepared-build-v1` receipt containing source and plan hashes, base-image
   digest, compiler version, command results, tests, verified readable
   artifacts, sanitizer provenance, and final image digest.  A compiler-version
   check alone is insufficient.  Hunt and reproduction remain network-disabled
   and immutable.
3. Move benchmark fixtures that still depend on hand-prepared images onto the
   verified existing preparation path.  Prove equivalent protected results on
   cJSON plus one CMake, one Autotools/Make, and one generated-parser project;
   do not add support for a new build layout in this PR.

### Acceptance gates

- Supported repositories require no hand-written per-repository Docker step.
- Repeated preparation of the same source and toolchain yields the same plan
  and equivalent receipt; unavoidable image metadata is excluded explicitly.
- Missing `/opt/vulnhunt/build` artifacts fail before Hunter admission with a
  typed preparation error.
- Failed build or test output cannot be reported as a clean scan.
- Dependency or toolchain network use during preparation is declared in the
  receipt; undeclared or unpinned downloads fail closed.  Hunt and reproduction
  never receive network access.
- Build commands cannot access host mounts, Docker socket, credentials, or
  another run's artifacts.
- Every protected vulnerable/fixed reproduction still has target-source
  sanitizer provenance.
- No ranking, signal, routing, Hunter, reviewer, or token-budget changes.

### Stop conditions

- A protected repository needs network-fetched dependencies not pinned by the
  source or base image.
- The build requires a capability outside the existing sandbox threat model.
- Automatic artifact selection would guess between multiple non-equivalent
  targets without a source-backed rule.

## Cost staging

Authenticated model spend is unlocked only after the preceding deterministic
gates pass:

- M12.0 and M12.1 use no authenticated analysis calls.
- M12.2 spends 12 calibration runs and is the first stop/go decision.
- M12.3 replays frozen artifacts and adds no benchmark calls.
- M12.4 spends 18 negative runs only after calibration and canonicalization
  pass.
- M12.5 spends 30 primary holdout runs in small cohorts; the six optional
  challenge runs execute only after the primary beta decision.
- M12.6 spends three prospective runs, one repository at a time.

No later allocation is pre-authorized by an earlier success.  Its preceding
release report must show the stated quality and cost gates first.

## M12.2 — Small calibration corpus and repeated-run pilot

### Single objective

Measure stochastic reliability and cost on a small new development corpus
before spending the sealed holdout.  This milestone introduces no broad Hunter
upgrade.

### Corpus

- Four previously unused vulnerable/fixed pairs from four repositories.
- At least one bounded write/capacity case, one parser OOB-read case, and one
  integer/signedness-to-memory case.
- Repository size is capped so one run stays within the existing 12-session,
  2,000,000-input-token, 200,000-output-token, 60-minute, and 24,000-context-byte
  ceilings.
- Regression tests, issue text, PoCs, trigger bytes, and fixes are excluded from
  discovery; vulnerable source predating a regression test is preferred.

### PR sequence

1. Add four calibration manifests, withheld oracles, fixed controls, and
   process-enforced leakage tests.  Do not add them to `must_detect` yet.
2. Add a cohort runner that performs three independent authenticated runs per
   vulnerable case, freezes each run separately, and evaluates only afterward.
   It never retries a valid miss under the same repetition ID.
3. Publish the 12-run reliability and cost report.  Promote a case to protected
   only if it succeeds in at least two of three runs and differential
   reproduction passes.

### Acceptance gates

- All 12 requested runs have unique run IDs and immutable receipts.
- `valid_run_rate` is 100%; otherwise infrastructure is fixed and the cohort is
  rerun under a new report version.
- At least three of four target Hunters are admitted within 12 sessions.
- Aggregate `hunter_detection_at_12` is at least 75%.
- Aggregate `reportable_detection_at_12` is at least 50%.
- No supported family has zero detections across all three repetitions.
- Median tokens per valid run do not exceed 1,500,000 including cache traffic;
  no run exceeds the existing 2,000,000-token contract.
- Existing protected detections remain green.

If a threshold fails because of one coherent reasoning gap, work stops and one
small `M12.2.x` recovery milestone is designed for that gap using calibration
cases only.  Other missing families and the sealed holdout remain untouched.

## M12.3 — Canonical findings and reviewer consensus

### Single objective

Prevent duplicate Hunters and severity disagreements from corrupting
reportability and precision.  This milestone does not add vulnerability
signals or improve ranking.

### PR sequence

1. Add `canonical-finding-v1`, keyed by source snapshot, normalized weakness
   family, target sanitizer frame or exact sink, root-cause chain, and trigger
   equivalence.  Same-sink findings with different root causes must remain
   separate.
2. Merge duplicate evidence while preserving every Hunter, PoC, execution,
   reviewer, and cost record.  Canonicalization is deterministic and reversible
   from provenance.
3. Separate reviewer consensus into `validity` and `severity`.  A unanimous
   `real` validity verdict can become reportable even when CVSS attack vector or
   impact differs; the disagreement remains explicit and severity is marked
   unresolved.

### Acceptance gates

- The authenticated cJSON duplicate becomes one canonical vulnerability with
  both Hunter evidence trails retained.
- CVSS disagreement alone cannot turn unanimous real evidence into
  `review_inconclusive`.
- One real and one false reviewer verdict still fail closed.
- Different root causes sharing a sink do not merge.
- Recall and precision reducers count the canonical candidate once, while cost
  includes all work.
- Every current report remains readable and no protected candidate disappears.
- No signal, ranking, routing, prompt, or budget changes.

### Stop conditions

- Canonical identity depends on free-form title similarity alone.
- Merging would discard contradictory evidence or original candidate IDs.
- Validity cannot be separated from severity without changing historical
  verdict meaning.

## M12.4 — Negative corpus and precision gate

### Single objective

Measure how often the verified pipeline escalates safe code.  This milestone
does not attempt to improve recall.

### Corpus

- Six negative cases in total: four fixed repository revisions paired with
  calibration or retired historical vulnerabilities, plus two structurally
  similar safe near-miss repositories where the
  critical guard, capacity relation, or cursor invariant is present.
- Three independent authenticated runs per negative case.
- Any unexpected reportable candidate receives human adjudication.  A genuine
  unrelated vulnerability is recorded as real and is not counted as a false
  positive merely because the repository was in the negative partition.

### PR sequence

1. Freeze negative manifests, absence oracles for the paired target, and human
   adjudication records.  No repository is labelled globally vulnerability
   free.
2. Execute the negative cohort and produce fixed-target, false-escalation,
   candidate-volume, and reviewer-disagreement metrics.
3. Add a precision release gate.  If one structural false-positive family
   dominates, stop and design one `M12.4.x` falsification milestone for that
   family only.

### Acceptance gates

- `fixed_target_false_positive_rate` is 0%.
- No candidate without actual-target evidence reaches reportable status.
- `reportable_precision` on the combined calibration and negative corpus is at
  least 80%, with every candidate adjudicated.
- False escalation is reported per run and per canonical candidate.
- Non-reportable suspicious candidates remain visible as workload/noise and
  are not reclassified as false vulnerabilities.
- Existing protected recall gates remain green.

## M12.5 — Sealed historical holdout

### Single objective

Measure generalization once, without tuning on the answers.

### Corpus

- Ten primary cases from at least eight repositories, all within the declared
  C memory-safety families and unused by protected or calibration work.
- Two optional challenge cases from adjacent memory-safety families, scored
  separately.
- Each case pins vulnerable and fixed commits, source trees, an oracle, and a
  differential reproduction, but discovery receives only the vulnerable tree
  and oracle-free scan manifest.
- Three independent authenticated runs per case.  Cases are opened in cohorts
  of three to cap spend, but no scanner code, prompt, threshold, or budget may
  change between cohorts.

### PR sequence

1. Freeze the corpus registry, partition proof, evaluator hashes, and leakage
   audit before the first authenticated run.  A reviewer confirms no case was
   used during development.
2. Execute four sequential cohorts and publish receipts after each.  A cohort
   may stop the campaign for infrastructure invalidity or budget exhaustion,
   but not because recall is disappointing.
3. Publish the final report and beta decision.  Missed cases may guide later
   work only after being retired from the holdout and replaced in the next
   evaluation version.

### Beta thresholds

- `valid_run_rate` is at least 95% across requested primary runs.
- Primary `admission_at_12` is at least 90%.
- Primary `hunter_detection_at_12` is at least 70%.
- Primary `reportable_detection_at_12` is at least 50%.
- At least 70% of primary cases succeed in two or more of three runs at the raw
  Hunter level.
- Adjudicated `reportable_precision` is at least 80%.
- Median model input including cache is at most 1,500,000 tokens per valid run;
  no run exceeds the declared 2,000,000-input-token ceiling.
- Every detected case passes vulnerable/fixed differential reproduction.
- All protected detections remain green; none may be demoted to improve the
  holdout score.

Passing permits the claim “internal beta for the declared C memory-safety
families.”  It does not permit a claim of complete C vulnerability coverage.

## M12.6 — Prospective current-repository campaign

### Single objective

Demonstrate the same bounded process on current upstream code without a known
answer.  No production feature is added in this milestone.

### Campaign

- Select three current, popular, small-to-medium C repositories with automatic
  prepared builds and clear private disclosure channels.
- Pin the exact commit and date before analysis.  Open issues, advisories,
  security patches, and future diffs are not discovery input.
- Scan one repository at a time under the unchanged 12-session, 2,000,000-input
  token, 60-minute, and sandbox limits.
- Every reportable candidate receives an independent source review, repeated
  actual-target reproduction, current-version confirmation, and responsible
  disclosure assessment.  Public exploit development is outside this gate.

### PR sequence

1. Add prospective manifests containing only source, scope, budget, build, and
   disclosure-policy metadata.
2. Execute and freeze the three scans sequentially.  Do not change scanner code
   between repositories; an infrastructure failure creates a new campaign
   version.
3. Publish an operational report.  Private vulnerability details remain in a
   restricted evidence package until coordinated disclosure permits release.

### Acceptance gates

- All three repositories build automatically and produce valid run outcomes.
- All admitted targets have terminal dispositions or typed deferrals.
- Every reportable candidate is adjudicated; none remains pending in the final
  campaign report.
- Cost, time, coverage, deferred work, candidate volume, and reviewer outcomes
  are reported for each repository.
- A no-finding result states exact scope and deferred counts and makes no safety
  claim.
- A novel confirmed finding is reported only after actual-target reproduction
  and current-version confirmation; CVE assignment is not required for the
  campaign to be operationally complete.

## Sequential execution rule

The implementation order is fixed:

`M12.0 → M12.1 → M12.2 → M12.3 → M12.4 → M12.5 → M12.6`

For every PR:

1. start from the newly merged `main`;
2. implement only the named PR scope;
3. run targeted tests, the full deterministic suite, lint, type checking,
   sandbox gates when relevant, and the complete protected detection matrix;
4. inspect the diff for repository-specific production signatures and
   unrelated feature changes;
5. open a draft PR, wait for every required check, then squash-merge; and
6. begin the next PR only after the merge is verified locally and remotely.

## Global rollback and decision conditions

Stop and request a design decision if a milestone would:

- expose or use a sealed oracle before discovery freeze;
- tune code on a case still counted as holdout;
- raise session, token, context, retry, network, or sandbox privilege ceilings;
- introduce repository-specific behavior into production analysis or prompts;
- demote, remove, or weaken a protected detection;
- count invalid, duplicate, deferred, or unadjudicated output as a successful
  detection;
- call an unexpected real vulnerability a false positive because it appeared
  in a negative repository; or
- require a new vulnerability family to meet the primary M12 score.

Ordinary implementation defects, test failures with an in-scope fix, and a
valid measured miss do not authorize expanding the current milestone.  A miss
is recorded honestly and any recovery work receives its own later milestone.

## Definition of done

M12 is complete only when all sub-milestones are merged and the evidence shows:

- reproducible metrics with exact denominators and costs;
- verified automatic prepared builds with immutable provenance for the
  evaluation corpus;
- three-run reliability measurements on calibration and sealed cases;
- canonical findings with validity consensus independent of severity scoring;
- an adjudicated negative-corpus precision measurement;
- a passing sealed-holdout beta report for the declared C families; and
- three bounded prospective current-repository scans with honest outcomes.
