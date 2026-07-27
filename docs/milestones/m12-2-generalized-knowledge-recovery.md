# M12.2.x — Generalized knowledge and missed-target recovery

Status: knowledge foundation implemented locally; recovery PRs not started.

## Objective

Turn previously validated findings into reusable, repository-agnostic security
invariants, then recover the four missed calibration targets without increasing
the 12-session, 2,000,000-input-token, 24,000-context-byte, or 60-minute limits.

This milestone does not treat a historical finding as a signature. Runtime
analysis may receive an invariant, investigation steps, required evidence, and
falsifiers. It must never receive the originating repository, path, symbol,
line, commit, CVE, patch, PoC input, or literal trigger from the finding ledger.

## Knowledge architecture

The database has two deliberately separate layers:

1. `knowledge/finding-ledger-v1.json` is the auditable source ledger. It records
   exact provenance, root-cause deduplication, validation maturity, and whether
   current upstream was revalidated. It is not loaded by Hunters.
2. `src/vulnhunt_agent/knowledge/patterns-v1.json` is the runtime projection.
   Structural graph facts select at most four generalized cards in a shared
   cross-Hunter context packet; existing specialist prompts provide role focus.
   A card is a hypothesis checklist, never evidence.

New knowledge follows this promotion path:

`candidate → independent validation → root-cause deduplication → generalized
invariant review → identity-leakage test → active runtime card`

Candidate-only records remain in the ledger but cannot create active cards.

## Sequential PR plan

Only one PR may be active. Each PR starts from the newly merged `main`, passes
its focused tests and the complete protected detection matrix, and is merged
before the next PR begins.

### PR 1 — General invariant-obligation contract

Add a deterministic `invariant-obligation-v1` model containing an obligation
kind, structural source facts, evidence ranges, required Hunter roles, closure
states, and a stable semantic identity. Knowledge cards may suggest an
obligation family but cannot create or close an obligation without current graph
facts. Admission and ranking do not change in this PR.

Acceptance:

- renaming repositories, files, symbols, and variables preserves semantic
  obligation classification;
- changing guard, arithmetic, or state-transition structure changes the
  obligation identity;
- every obligation has `proved_safe`, `candidate`, or
  `unresolved_with_evidence` closure semantics;
- no calibration oracle or fixed-tree data enters production input.

### PR 2 — Formatted-output expansion obligation

Recover the missed fixed-buffer formatting case. Detect fixed or caller-bounded
destinations, classify bounded and unbounded formatting operations, and model
maximum representation expansion including precision, sign, exponent, locale,
and terminator. Route the same obligation to bounds and format specialists when
both are enabled; this is complementary coverage, not duplicate work.

Acceptance:

- the Mini-XML calibration target is admitted and its exact formatting
  obligation is closed in at least two of three runs;
- bounded formatting with a checked return is proved safe and does not become
  reportable;
- the existing libcue formatted-output detection remains green;
- no function name, format literal, or buffer size from either repository is
  hard-coded.

### PR 3 — Stateful output-capacity obligation

Recover the missed delimiter-accounting case. Model capacity as state across
loop iterations and branches: data bytes, prefixes, separators, escapes,
terminators, pointer movement, and remaining space. Deduplication must preserve
distinct state-transition obligations even when they share one allocation or
destination.

Acceptance:

- the uriparser calibration target's second-iteration one-byte deficit is
  represented and closed in at least two of three runs;
- first-item, empty-list, exact-fit, and extra-capacity controls remain safe;
- the historical signed-length overflow stays separately detectable and is not
  merged with the stateful delimiter root cause;
- cJSON, zlib, libjpeg, and libwebp protected detections remain green.

### PR 4 — Cross-file length-before-read obligation

Recover the missed parser extension-byte read. Extend cursor facts so a caller's
remaining length, cursor mutation, callee precondition, and indexed read form one
cross-file obligation even when no write or allocation signal exists. A
post-mutation check must be distinguished from a pre-mutation check.

Acceptance:

- the libcoap caller/callee target is admitted and closed in at least two of
  three runs;
- zero-, one-, and maximum-extension boundary cases are explicitly analyzed;
- a dominating length check in a fixed control closes as safe;
- the protected cJSON cursor detection remains green and same-file performance
  does not regress.

### PR 5 — Signed source-to-allocation-to-write obligation

Recover the missed signed sample-rate allocation relation. Join an externally
influenced signed value to its final validated domain, allocation expression,
independent copy or loop bound, and write unit across the full function cluster.
The obligation must survive when the source and sink are hundreds of lines apart.

Acceptance:

- the WavPack calibration target is represented before model execution and
  closed in at least two of three runs;
- negative, zero, boundary, narrowing, and overflow cases are included;
- checked arithmetic and a source-backed non-negative domain close safe;
- zlib, libtiff, and libwebp integer/capacity regressions do not disappear.

### PR 6 — Obligation-level admission and completion reserve

Replace file-level admission accounting with obligation-level accounting. Each
supported high-confidence obligation receives one required specialist session
inside its existing cluster before unrelated lower-priority work. Do not add a
session or token; replace the lowest-ranked non-required work and enforce a
1,500,000-token soft stop. `duplicate_deferred` may apply only when semantic
obligation identities match.

Acceptance:

- admission metrics name the exact obligation and Hunter, not just a file;
- every admitted obligation receives a terminal disposition or typed budget
  deferral with source evidence;
- all four calibration obligations are admitted within 12 sessions;
- median input including cache remains at or below 1,500,000 tokens and no run
  crosses the current hard limit.

### PR 7 — Differential calibration and knowledge quality gate

Run a new four-by-three vulnerable cohort and the paired fixed controls under new
run IDs. Evaluate with the unchanged M12 metrics reducer. Add knowledge-specific
metrics: selected-card count, card-to-obligation conversion, candidate yield,
falsified-card count, and findings produced without current-source evidence.

Acceptance:

- `hunter_detection_at_12 >= 75%` and
  `reportable_detection_at_12 >= 50%`;
- no supported family has zero detections;
- each recovered case succeeds in at least two of three runs and its fixed
  counterpart does not reproduce;
- all protected detections remain green;
- no finding becomes reportable solely because a knowledge card was selected;
- no source identity from the ledger appears in a discovery artifact;
- duplicate logical findings count once while all execution cost is retained.

## Stop and rollback conditions

Stop and request a design decision if a PR would require a repository-specific
production rule, an oracle-derived location or literal, a larger model budget,
a weaker protected detection, or a reportability shortcut. An honest miss or an
ordinary in-scope implementation failure is recorded and repaired in the same
PR; it does not authorize broadening the next PR.
