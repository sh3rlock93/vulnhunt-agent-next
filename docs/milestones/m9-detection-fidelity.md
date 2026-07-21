# M9 — Detection fidelity and closed-loop verification

Status: In progress (1 of 6 increments)

## Goal

Make incremental native scans focus on the code that actually changed, require
an explicit disposition for every critical target, and automatically close any
follow-up reproduction requested by evidence reviewers. The milestone is gated
by a vulnerable/fixed zlib MiniZip regression for CVE-2023-45853.

## PR 1 — Routing-plan integrity

Critical cross-file work can prefer a required specialist that is not the
highest-scoring route. The previous secondary selection used a positional slice
of the ranking and could append that preferred specialist a second time,
producing identical stable work IDs and invalidating both incremental plans and
their full-scan baseline.

Secondary selection now chooses the highest-ranked specialist not already in
the plan and performs a final stable de-duplication. The strict routing-plan
validator remains in place as a fail-closed contract.

## PR 1 acceptance gates

- [x] A lower-ranked required specialist is never scheduled twice.
- [x] A materially relevant secondary specialist is retained.
- [x] Work IDs remain deterministic and unique.
- [x] Existing critical-sink coverage and reduction tests remain green.

## Remaining increments

2. Macro-decorated C functions and deletion-diff anchoring.
3. Change-focused bounded scheduling and context packets.
4. Per-target Hunter completion with lower token amplification.
5. Leased reproduction-variant execution and automatic re-review.
6. Pinned zlib vulnerable/fixed benchmark and final operational gates.
