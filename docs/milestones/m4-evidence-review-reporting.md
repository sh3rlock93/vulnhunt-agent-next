# M4 — Evidence review, consensus, and reporting

Status: Implementation complete; CI pending

## Outcome

Only a finding backed by an immutable source snapshot, a deterministic
two-attempt reproduction, and evidence-citing Reviewer consensus can become
`reportable`. Reports are rendered from validated domain data rather than
free-form model prose.

## Review boundary

- The Reviewer receives a redacted, integrity-checked packet containing the
  candidate, repository identity, source snapshot, reproduction metadata,
  oracle results, and evidence IDs.
- It has no host tools and cannot execute a command. An `unclear` verdict may
  request only a declarative `safe_input`, `config_toggle`, `fixed_revision`, or
  `alternate_trigger` experiment.
- A variant request becomes an idempotent `reproduction_variant` task. It does
  not contain `argv` and must be compiled into a new trusted
  `ReproductionSpec` by the Reproducer path.
- A `real` verdict must cite stored reproduction evidence and provide a valid
  CVSS 3.1 vector and allow-listed CWE.
- High and critical findings require two named Reviewers with distinct model or
  prompt configurations. A second name using the same configuration does not
  satisfy the policy.
- Verdict, CVSS, or CWE disagreement transitions the finding to `unclear`;
  disagreement is never promoted automatically.

## Strict export

`strict-v2` rechecks the source snapshot, attached evidence, artifact hashes,
two-attempt reproduction, and `consensus-v1` immediately before export. It
then writes deterministic:

- `report.md`
- `report.json` (the canonical report)
- `report.sarif` (SARIF 2.1.0)
- `provenance.json`

Every security result carries the candidate fingerprint, source snapshot,
reviewer identities, policy versions, and evidence IDs. Existing output may be
replayed only when its bytes match; an attempt to overwrite it with different
content fails closed.

```bash
vulnhunt --db /path/to/state.db export RUN_ID \
  --artifacts /path/to/artifacts \
  --output /path/to/output
```

The Streamlit run page automatically shows a read-only evidence/state/consensus
panel when the selected run contains `state.db`. A custom location can be
provided as `v2_db_path` in that run's `config.json`.

## Acceptance gates

- [x] Review packets verify artifact hashes and redact common secret formats.
- [x] Reviewers cannot run commands or directly mutate evidence.
- [x] Variant requests are declarative, idempotent Reproducer tasks.
- [x] Real verdicts require evidence citations, CVSS 3.1, and an allow-listed CWE.
- [x] High/critical findings require two distinct model/prompt configurations.
- [x] Reviewer disagreement becomes `unclear`, never `reportable`.
- [x] Markdown, canonical JSON, SARIF, and provenance are deterministic.
- [x] A report can be traced back to attached evidence IDs and an immutable
  source snapshot.
- [x] The emitted SARIF passes the local profile and the complete official
  OASIS SARIF 2.1.0 JSON schema.
- [x] Streamlit exposes finding state, evidence count, Reviewer count, and
  consensus without granting state-transition authority to the UI.
- [ ] GitHub Actions passes on supported Python versions.

## Verification

```bash
python -m ruff check src tests benchmarks
python -m mypy
python -m pytest --cov=vulnhunt_agent --cov-report=term-missing \
  --cov-report=xml --cov-fail-under=45

curl -L --fail \
  -o /tmp/sarif-schema-2.1.0.json \
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
VULNHUNT_SARIF_SCHEMA_PATH=/tmp/sarif-schema-2.1.0.json \
  python -m pytest \
  tests/test_m4_review_reporting.py::test_sarif_passes_complete_oasis_2_1_0_schema
```

The complete OASIS schema is downloaded only for the explicit conformance test.
Normal offline tests validate the deliberately small SARIF profile emitted by
this project.

On 2026-07-20, the local validation passed 66 automated tests at 63.74% branch
coverage, all three real Docker isolation contracts, the complete OASIS schema,
and a live evidence-packet review through Codex CLI 0.144.1 using the logged-in
ChatGPT subscription.
