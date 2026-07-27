# Vulnerability knowledge database

This directory is the provenance ledger for vulnerabilities and security defects
encountered during development. It is deliberately separate from the runtime
prompt database in `src/vulnhunt_agent/knowledge/patterns-v1.json`.

- `finding-ledger-v1.json` preserves repository, revision, path, validation, and
  current-upstream status for audit and regression ownership.
- `patterns-v1.json` contains only generalized invariants, investigation steps,
  required evidence, and falsifiers. It is the only part supplied to Hunters.
- Runtime packet selection uses structural graph facts and remains identical
  across specialists so the existing context cache is reusable. Hunter system
  prompts provide role specialization. Neither layer compares repository names,
  paths, symbols, line numbers, commits, CVEs, titles, or literal trigger values.
- Candidate-only ledger records do not create active runtime patterns until they
  receive an independent validation decision.

The split is intentional: the ledger answers “what did we observe?”, while the
runtime database asks “which broadly applicable invariant should be tested here?”
