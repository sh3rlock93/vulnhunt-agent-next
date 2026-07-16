# Milestone 0 — Baseline and CI

Status: Local gates passed; GitHub Actions verification pending

## Scope

- Preserve the current five-step pipeline order and JSON contracts.
- Add an intentionally vulnerable Python fixture with machine-readable ground truth.
- Exercise Filter → Rank → Selector without external LLM or Docker dependencies.
- Exercise the Hunter tool loop with deterministic fake model and tool adapters.
- Add regression tests for CVSS, JSON extraction, persistent queue state, prompts, and report materialization.
- Run lint, type checking, and tests on Python 3.11, 3.12, and 3.13 in GitHub Actions.

## Acceptance criteria

- [x] `ruff` passes for `src` and `tests`.
- [x] `mypy` passes for the analysis engine and tests under the baseline configuration.
- [x] `pytest` passes locally with branch coverage enabled.
- [x] Analysis-engine coverage is at least 45%; UI and process entry points are excluded.
- [x] Golden Filter → Rank → Selector output is stable.
- [x] The vulnerable fixture proves attacker input reaches the expected sink without network access.
- [ ] CI passes on Python 3.11, 3.12, and 3.13.
- [x] Existing `main` history remains available as `upstream/main` and `origin/main`.

## Local verification

Verified on Python 3.14.5 as an additional forward-compatibility check:

```bash
python -m ruff check src tests
python -m mypy
python -m pytest --cov=vulnhunt_agent --cov-report=term-missing \
  --cov-report=xml --cov-fail-under=45
```

Result: 17 tests passed, 45.38% branch coverage, and no Ruff or mypy findings.
The CI matrix remains the release authority for the supported Python 3.11–3.13 range.

## Explicit boundary

Milestone 0 does not claim Docker isolation or real LLM quality. Hardened sandbox and
independent PoC reproduction are Milestone 2 release gates. The fake adapters in this
milestone lock orchestration contracts so those components can be replaced safely later.
