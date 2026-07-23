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
