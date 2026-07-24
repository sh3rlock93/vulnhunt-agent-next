# M12.2 calibration pilot release report

Status: completed with failed release gates. M12.3 is blocked.

## Immutable cohort

- Cohort: `cohort_73223b4875a348b8`
- Snapshot: `sha256:7ff07fc61631d7bedc78638a6a46873e25626b3454920c6f9b852a533e3400f8`
- Catalog: `sha256:4a238160877b0d9bc66f14df3841ab8b72a21cec69db663bc76f09ae11947e96`
- Metrics: `sha256:b93d6e5ae4af0f8f41a52ba102b0ea88e1efcef9d7e190185702deb9f7895460`
- Model: `gpt-5.6-sol` through the Codex subscription adapter
- Repetitions: three independent runs for each of four calibration cases
- Valid receipts: 12 of 12
- Infrastructure failures in the accepted cohort: 0

The accepted campaign used one serialized Codex transport call at a time. This
removed the intermittent login failure seen in the discarded campaign without
changing session, token, wall-clock, context, ranking, prompt, or detection
policy. Every run was frozen before the calibration oracle was opened.

## Gate result

| Gate | Actual | Required | Result |
|---|---:|---:|---|
| `valid_run_rate` | 12/12 (100%) | 100% | PASS |
| target Hunters admitted in at least 2/3 runs | 3/4 | at least 3/4 | PASS |
| `hunter_detection_at_12` | 0/12 (0%) | at least 75% | FAIL |
| `reportable_detection_at_12` | 0/12 (0%) | at least 50% | FAIL |
| supported families with a target detection | 0/3 | 3/3 | FAIL |
| median input tokens including cache | 1,825,891 | at most 1,500,000 | FAIL |
| maximum input tokens including cache | 1,978,866 | at most 2,000,000 | PASS |

## Case result

| Case | Historical target | Target admission | Target Hunter detection | Target reportable |
|---|---|---:|---:|---:|
| `case_793a704d3845b63e` | WavPack signed sample-rate under-allocation | 2/3 | 0/3 | 0/3 |
| `case_82b3a769de36034c` | Mini-XML unbounded float formatting | 3/3 | 0/3 | 0/3 |
| `case_e9366d85b7c31f73` | libcoap option extension OOB read | 0/3 | 0/3 | 0/3 |
| `case_f521543734c7e34a` | uriparser ampersand capacity omission | 3/3 | 0/3 | 0/3 |

The Hunters produced 29 canonical candidates, including five candidates in
the scanner's `reportable` state. None matched both the sealed oracle entry and
sink ranges. Those five are therefore recorded as non-target, unadjudicated
candidates and do not count as calibration detections or precision evidence.
In particular, uriparser produced a separately reportable signed-size overflow
in query composition, not the historical one-byte ampersand accounting bug.

## Diagnosis

The result separates admission from reasoning:

- WavPack, Mini-XML, and uriparser received target-covering work in at least
  two repetitions but the Hunters reasoned toward different bugs or no bug.
- libcoap never admitted a work item covering both `src/pdu.c` and
  `src/option.c`, so its failure begins in routing/admission.
- Most runs consumed close to the two-million-token ceiling even when they
  missed the target. The median exceeded the release budget by 325,891 tokens.

This is not an infrastructure failure and retrying the same run IDs would be
invalid. The coherent product gap is oracle-blind invariant completion inside
already selected target file clusters: capacity/state pairs and parser
length-before-read relations are not being closed before budget is spent on
unrelated high-risk sinks. A recovery milestone must address that gap on the
calibration corpus only and must also reduce deferred, non-target sessions.

## Decision

Decision: `stop_and_design_m12_2_x`.

No calibration case is promoted to the protected set, because none achieved a
target detection in two of three repetitions. M12.3, the negative corpus, and
the sealed holdout remain unopened. Existing protected detections must pass the
normal release matrix before this report is merged.

## Reproduction

After a 12-run cohort is closed, the report is regenerated with:

```console
python -m benchmarks.m12.calibration_evaluation \
  --plan /path/to/cohort/cohort-plan.json \
  --output evaluation-v2
```

The evaluator verifies the cohort freeze first, copies exact-hash evaluator
dependencies into the self-contained cohort evidence root, binds generated
adjudications to the original oracle SHA-256, and emits `metrics.json`,
`metrics.md`, `release-report.json`, and `release-report.md` without modifying
the frozen discoveries.
