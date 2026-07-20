# M6 — Immutable, independently verified pipeline

Status: Complete

## Outcome

The Streamlit workflow now connects the C Hunter portfolio to the V2 evidence
and reporting services. A model's `status=confirmed` claim is no longer enough
to reach the final report. The complete promotion path is:

```text
Immutable snapshot → C graph and Hunter portfolio
  → recorded PoC and exact command recipe
  → two clean Reproducer containers
  → evidence-only dual review
  → strict JSON, Markdown, and SARIF
```

The final UI prefers these strict reports and does not present quarantined
legacy reviews as verified findings.

## Immutable run input

The first UI step creates a deterministic tar and manifest in the content
addressed artifact store and attaches its digest to the SQLite run record.
Prepare uses that tar rather than copying the live checkout. Analysis, prepare,
and hunt re-hash the source and stop if it changed after the snapshot was
created. Continuing with modified source requires a new run.

## Hunter execution ledger

Every `write_poc` path and every sandbox `exec` call is retained with:

- exact argv, cwd, and timeout;
- exit code and timeout state;
- bounded stdout and stderr;
- execution duration.

A confirmed finding must provide an ordered setup command list, final trigger,
working directory, timeout, and non-trivial oracle. The verifier accepts it only
when the PoC exists in the Hunter mirror, all commands match recorded calls in
order, and the oracle passes against the recorded final result. Unsafe working
directories and fabricated or altered recipes are rejected.

Native recipes are translated from the Hunter layout to the independent
Reproducer layout: `/code` becomes the read-only source snapshot and a Hunter
PoC under `/workspace` becomes `/workspace/poc`. Native binaries are built only
under the executable `/workspace/exec` tmpfs; its parent workspace and `/tmp`
remain `noexec`.

## Independent verification

An accepted recipe creates a conservative V2 hypothesis and advances only
through explicit finding states. `ReproducerService` starts two disposable,
networkless, non-root containers. Each container:

1. extracts the same immutable source snapshot read-only;
2. streams the content-addressed PoC;
3. runs every setup argv without a shell;
4. runs the trigger only if setup succeeded;
5. evaluates the declared oracle and stores immutable evidence.

Both attempts must use one image digest and agree on setup commands, trigger,
snapshot, and passing oracle. Two distinct Reviewer configurations must cite
the reproduction evidence for high or critical findings. Only then can
`StrictReportService` emit a report.

The verifier is replay-safe. Re-running a completed verification does not
repeat sandbox jobs, reviews, or overwrite a different report. If the same
deterministic candidate ID resolves to changed immutable candidate data, replay
fails instead of silently replacing evidence.

## Acceptance gates

- [x] A run snapshot is created before filtering and cannot drift later.
- [x] Prepare consumes the stored snapshot rather than the mutable checkout.
- [x] Hunter PoC writes and exec calls are stored as an exact ledger.
- [x] Fabricated, reordered, unsafe, or oracle-failing recipes are rejected.
- [x] Native setup commands compile inside each clean Reproducer container.
- [x] The trigger runs only after all setup commands succeed.
- [x] Two deterministic reproductions are required before review.
- [x] High/critical findings require two evidence-citing Reviewer variants.
- [x] Final UI output comes from strict Markdown/JSON/SARIF bundles.
- [x] Completed verification resumes without duplicate executions.

## Verification

```bash
python -m ruff check src tests
python -m mypy
python -m pytest --cov=vulnhunt_agent --cov-report=term-missing \
  --cov-report=xml --cov-fail-under=45
VULNHUNT_RUN_DOCKER_TESTS=1 \
  python -m pytest tests/test_docker_sandbox_integration.py
```

On 2026-07-20, local validation passed 75 standard tests at 66% branch
coverage and all four real Docker contracts. The added native contract compiled
an ASan/UBSan PoC in `/workspace/exec`, triggered it independently, and observed
the expected AddressSanitizer evidence.
