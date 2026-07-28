# M12.2 calibration recovery release report

Status: the post-recovery calibration is complete with failed release gates.
M12.3 remains blocked.

## Immutable cohort

- Cohort: `cohort_1ce8e6d4043746ab`
- Snapshot: `sha256:c73a52b952e79b917e5f1d5cb6c959a6b9938c5219966ebd80468286b172d4fa`
- Catalog: `sha256:4deabae6642c31c267473308bd85ef9ee6700a86a4eab0e9b9e447e41020a9aa`
- Plan: `sha256:0473954ece73178d53ca4adba3fd88cad32ca20799fe683863994f55d588db00`
- Metrics: `sha256:3d700f6326a0a6ddff11315b8650c0c39da7084b1aed471d80c20f02de2cd17d`
- Knowledge metrics: `sha256:afbe371da54adde4d4e517fb029b3a3141ccb5cfc71819dde02fd3b2dc7cbddb`
- Differential controls: `sha256:5476dd7a902f8d90a8319c82773743ae3548626761c2e15c853c96332b79ddfe`
- Model: `gpt-5.6-sol` through the Codex subscription adapter
- Repetitions: three independent runs for each of four calibration cases
- Valid receipts: 12 of 12
- Infrastructure failures in the accepted cohort: 0

Every discovery run used a unique run ID and state database. Each run was
frozen before the calibration oracle was opened. A real Codex transport timeout
occurred once and recovered without leaving an orphan process or invalidating
the run. No abandoned predecessor cohort was reused.

## Gate result

| Gate | Actual | Required | Result |
|---|---:|---:|---|
| `valid_run_rate` | 12/12 (100%) | 100% | PASS |
| target Hunters admitted in at least 2/3 runs | 4/4 | at least 3/4 | PASS |
| `hunter_detection_at_12` | 5/12 (41.67%) | at least 75% | FAIL |
| `reportable_detection_at_12` | 1/12 (8.33%) | at least 50% | FAIL |
| supported families with a target detection | 3/3 | 3/3 | PASS |
| cases with target detection in at least 2/3 runs | 2/4 | 4/4 | FAIL |
| paired vulnerable/fixed controls | 1/4 | 4/4 | FAIL |
| median input tokens including cache | 1,472,356 | at most 1,500,000 | PASS |
| maximum input tokens including cache | 1,479,682 | at most 2,000,000 | PASS |

The campaign retained 17,748,988 model tokens across input, cache reads, and
output. Because only one target became reportable, tokens per reportable target
were also 17,748,988.

## Case result

| Case | Historical target | Target admission | Target Hunter detection | Target reportable | Differential pair |
|---|---|---:|---:|---:|---:|
| `case_793a704d3845b63e` | WavPack signed sample-rate under-allocation | 3/3 | 2/3 | 0/3 | FAIL |
| `case_82b3a769de36034c` | Mini-XML unbounded float formatting | 3/3 | 2/3 | 1/3 | PASS |
| `case_e9366d85b7c31f73` | libcoap option extension OOB read | 3/3 | 1/3 | 0/3 | FAIL |
| `case_f521543734c7e34a` | uriparser ampersand capacity omission | 3/3 | 0/3 | 0/3 | FAIL |

These values use the unchanged benchmark reducer. Findings that described the
right weakness but did not satisfy the sealed location and Hunter contract are
not counted as target detections.

## Diagnosis

The recovery fixed admission and cost, but did not close the full
finding-to-reportable path:

- All four target Hunters were admitted in all three repetitions. Ranking and
  session admission are no longer the primary blocker.
- Seven candidates matched the sealed target oracle after freeze. All seven
  were adjudicated `real`; six remained `review_inconclusive` and only one
  became reportable. WavPack lacked a validated actual-target reproduction,
  two Mini-XML repetitions retained reproduction or review uncertainty, and
  libcoap required an input-consuming harness that the experiment plan could
  not synthesize.
- The uriparser Hunter described the omitted query separator in all three
  repetitions. It attributed the terminal write to `src/UriEscape.c`, while the
  sealed oracle identifies the missing capacity guard in `src/UriQuery.c` as
  the sink. The reducer therefore correctly scored 0/3 under its exact current
  contract. This is a root-cause/terminal-write provenance mismatch, not
  evidence that the candidate was absent.
- The paired controls were fully valid only for Mini-XML. WavPack's vulnerable
  side reproduced but the fixed-side expected result did not; libcoap and
  uriparser did not reproduce on their vulnerable prepared images. These
  control failures remain separate from Hunter detections and block promotion.

The failures are downstream of ranking and are not one safe change: target
location equivalence, actual-target experiment synthesis, reviewer consensus,
and prepared differential controls have distinct contracts. They must not be
collapsed into a reportability shortcut.

## Decision

Decision: `stop_and_design_m12_2_x`.

No new calibration case is promoted to the protected set. M12.3 is not started
because both detection thresholds and the paired-control gate failed. The next
work must be a narrowly scoped M12.2.x design that preserves exact oracle
isolation, current budgets, existing protected recall, and fail-closed
reportability.

## Reproduction

After the 12-run cohort is closed, verify and evaluate it with:

```console
python -m benchmarks.m12.calibration_cohort verify \
  --plan /path/to/cohort/cohort-plan.json
python -m benchmarks.m12.calibration_cohort evaluation-ready \
  --plan /path/to/cohort/cohort-plan.json
python -m benchmarks.m12.calibration_evaluation \
  --plan /path/to/cohort/cohort-plan.json \
  --controls /path/to/cohort/differential-controls.json \
  --output /path/to/cohort/evaluation
```

The evaluator verifies the cohort freeze first, binds generated adjudications
to the sealed oracle SHA-256, and emits `metrics.json`, `metrics.md`,
`release-report.json`, and `release-report.md` without modifying frozen
discoveries.
