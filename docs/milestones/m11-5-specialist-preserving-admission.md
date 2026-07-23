# M11.5 specialist-preserving admission

M11.5 restores the withheld-oracle libcue parser-to-bounds target without
regressing detections that are green on the current scanner. A capacity root
cause is evidence-sharing metadata; it is not proof that two different Hunter
specialists are interchangeable.

## Release rule

The historical detection registry has three states:

- `must_detect`: removal, demotion, or end-to-end detection failure blocks merge;
- `recovery_target`: this milestone must promote the target after a blind pass;
- `known_gap`: planning and admission may not degrade while restoration remains
  explicit work.

The registry and every oracle are evaluation-only inputs. Discovery accepts
only the pinned vulnerable tree and an audited scan manifest. The fixed tree,
known trigger, vulnerability identifier, and expected sink become readable only
after discovery artifacts are frozen and hash-verified.

## PR sequence

1. Freeze the registry, libcue scan contract, independent oracle, and evaluator.
2. Preserve distinct specialist coverage during capacity canonicalization.
3. Admit required critical specialists within the existing session budget.
4. Complete the parser-to-sink blind finding without repository signatures.
5. Run every protected regression and promote libcue after differential proof.

Each PR runs the full deterministic matrix before the next PR starts. The final
release additionally runs authenticated blind discovery for protected targets.
Session, input, output, context, retry, and parallelism ceilings are not raised.

## Non-goals

- new Hunter agents or vulnerability families;
- repository, path, symbol, patch, CVE, or trigger signatures in production;
- broad prompt rewrites;
- weakening or deleting a protected regression;
- treating an unrelated finding as a pass for a missing historical target.

## PR4 authenticated result

The 2026-07-23 Codex-subscription blind run completed all 10 admitted work
items with no failed or deferred sessions. It used 420,807 new input tokens,
134,912 cache-read tokens, and 8,309 output tokens, all within the locked
budget. The `c-parser-state` work ran fourth and produced a candidate spanning
`cue_scanner.l`, `cue_parser.y`, and the `cd.c:347` write sink. Discovery did
not receive the oracle or fixed tree.

After the discovery root was frozen as
`7ba3e4e7ea6bc66aeaf3fd46e1ca1772e51bf5471c20b1dc0f5b5d4e652cf17e`,
the withheld evaluator matched exactly one of three candidates. Two clean
vulnerable-image attempts crashed under ASan in `track_set_index`, while two
fixed-image attempts completed without a sanitizer finding and emitted the
expected rejection. All authenticated release checks passed.

## PR5 no-regression release matrix

The final release matrix is closed over every `must_detect` registry entry.
Each protected detection names the exact CI job that proves its deterministic
admission contract; an omitted, skipped, cancelled, or failed job fails the
aggregate gate. Authenticated receipts are source-pinned and must match the
expected Hunter and paths. A gate that requires differential reproduction
cannot be declared without an authenticated receipt containing that proof.

`libcue-cve-2023-43641` is promoted to `must_detect` only after the PR4 blind
candidate and two vulnerable/two fixed reproduction attempts passed. A fresh
credential-free run retained the historical `time.c` formatting finding at
rank 3 and the parser-to-`cd.c` finding at rank 4. Re-evaluating the frozen
authenticated run matched both model candidates, verified the discovery root,
and repeated the CVE differential reproduction successfully.

The aggregate CI gate covers these protected detections:

- zlib CVE-2023-45853;
- libjpeg-turbo issue 387;
- libwebp CVE-2023-4863;
- the libcue `time.c` global-buffer-overflow finding;
- libcue CVE-2023-43641.
