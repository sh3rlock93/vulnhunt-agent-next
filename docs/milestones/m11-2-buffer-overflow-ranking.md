# M11.2 — Capacity-aware buffer-overflow ranking

Status: complete; all 7 PRs implemented and release-gated

## Goal

Improve which C buffer-overflow candidates reach the existing fixed Hunter
budget. The milestone keeps the 12-session and token limits unchanged and does
not add Hunters, prompts, provider behavior, sandbox behavior, or target-specific
signatures.

The release gate is a blind scan of the vulnerable libwebp tree for
CVE-2023-4863. The affected capacity chain must rank within the first six
admissions without advisory, patch, diff, vulnerable symbol, or magic-constant
input. Existing LibTIFF and synthetic ranking regressions must remain green.

## Sequential PRs

1. Persist the complete pre-admission ranking, score components, linked risk
   chains, missing chain elements, guard states, and terminal admission reason.
2. Extract bounded capacity facts for allocation, pointer position, remaining
   capacity, write extent, and capacity guards.
3. Summarize capacity behavior across direct function calls with bounded depth.
4. Assemble and categorically rank cross-file capacity risk chains.
5. Recognize dominating capacity guards and safe growth paths.
6. Admit and deduplicate logical capacity chains while retaining fixed budgets.
7. Freeze and evaluate the blind libwebp release gate on vulnerable and fixed
   revisions.

## PR 1 acceptance gates

- [x] Every candidate receives a deterministic pre-admission rank and record ID.
- [x] Both admitted and deferred candidates persist a typed disposition and reason.
- [x] Static score components are distinct from dynamic admission novelty.
- [x] Linked risk-chain IDs, missing elements, and guard states are visible.
- [x] Reversing work-item and risk-chain input order produces identical output.
- [x] Existing admission IDs, quotas, and ordering do not change.

## PR 2 acceptance gates

- [x] Allocation base, element count, and element size are structured facts.
- [x] Pointer aliases, offsets, advances, remaining capacity, and writes are linked.
- [x] Explicit capacity comparisons are retained without claiming dominance.
- [x] Allocator wrappers and `count * sizeof(element)` forms are recognized.
- [x] Alias traversal stops after 8 hops and transformations stop after 12.
- [x] Repeated and reordered analysis is byte-for-byte deterministic.

## PR 3 acceptance gates

- [x] Direct call arguments, result variables, and resolved targets are persisted.
- [x] Pointer parameters written by a function carry symbolic write extents.
- [x] Consumed/required and pass-through return behavior is explicit.
- [x] Parameter writes and return behavior propagate through at most five calls.
- [x] External and function-pointer calls remain unresolved and do not propagate.
- [x] The generic libwebp Huffman call path is linked end to end.

## PR 4 acceptance gates

- [x] Allocation, alias, call binding, returned consumption, advance, and write
  evidence form one deterministic cross-file chain.
- [x] Calls and aliases remain bounded by the PR 2/3 limits.
- [x] Chains are classified as complete unchecked, complete unknown-guard,
  partial, or isolated before their numeric score is considered.
- [x] Allocation and write signals both map scheduling work to the same chain.
- [x] Chain paths and exact evidence lines are included in bounded Hunter context.
- [x] Existing M10 risk-chain ordering remains unchanged without capacity evidence.

## PR 5 acceptance gates

- [x] Rejecting `required > remaining` and `used + required > capacity` guards
  lower complete chains below critical admission.
- [x] Checked realloc/grow followed by failure termination is a safe path end.
- [x] Overflow-safe rejecting checks are recognized without target signatures.
- [x] Non-dominating or directionally ambiguous comparisons remain unknown, not safe.
- [x] Unrelated parser, metadata, and public-limit checks do not mask a capacity path.
- [x] Relevant guard and safe-growth fact IDs remain auditable in chain artifacts.

## PR 6 acceptance gates

- [x] One capacity root-cause group is one admission unit across files and signals.
- [x] Bounds work is selected before lifetime work for the same capacity chain.
- [x] Equivalent allocation/write work is explicitly duplicate-deferred.
- [x] Complete capacity classes qualify without a fixed numeric threshold.
- [x] Partial capacity evidence cannot become chain-critical from raw score alone.
- [x] The 12-session, 24k context, retry, seed-cap, and parallelism limits are unchanged.
- [x] Libwebp affected work remains top six and existing LibTIFF gates remain green.

## PR 7 acceptance gates

- [x] Discovery runs in a separate process without oracle, fixed tree, patch,
  diff, CVE identifier, or PoC input.
- [x] Discovery artifacts are closed with per-file and root SHA-256 hashes
  before the evaluator opens withheld ground truth.
- [x] Vulnerable and fixed source commits and trees are pinned independently.
- [x] The affected complete unchecked capacity chain is admitted within the
  first six positions under the unchanged 12-session budget.
- [x] The admitted 24 KB context contains both the allocation and write files.
- [x] The fixed tree has no equivalent unsafe capacity chain.
- [x] Two clean vulnerable-image attempts reproduce the target ASan class and
  two clean fixed-image attempts reject the same input without sanitizer output.
- [x] An authenticated Codex-subscription blind run emits a model candidate
  matching the withheld allocation-to-write root cause.
- [x] CI repeats the credential-free discover, freeze, and evaluate gates.

## Release evidence

The release run used vulnerable commit
`7ba44f80f3b94fc0138db159afea770ef06532a0` and fixed commit
`902bc9190331343b2017211debcec8d2ab87e17a`. The scanner manifest contains
neither the advisory identifier nor oracle locations.

- Deterministic and authenticated evaluations both passed every gate.
- The target chain ranked 3rd and its context was 23,457 bytes.
- The authenticated `gpt-5.6-sol` Codex-subscription run used 6 Hunter
  sessions, 773,173 input tokens, 96,256 cache-read tokens, and 15,101 output
  tokens. It produced two candidates; the strict post-freeze matcher accepted
  one as the target root cause.
- The target PoC is fixed by SHA-256
  `f2281261ab7c6426eab9e62ac569244994d2fa563d3e2b1de4a0c7abcc00b3e6`.
  Both vulnerable attempts reported `heap-buffer-overflow` from
  `ReplicateValue` at `src/utils/huffman_utils.c:59`, with allocation at
  `src/dec/vp8l_dec.c:432`. Both fixed attempts returned `BITSTREAM_ERROR`
  without a sanitizer failure.

The first pre-gate run placed the target at rank 8 because equal categorical
scores fell back to work identity. The released tie-break is repository-agnostic:
it records and prefers cross-file capacity evidence, returned consumption,
pointer advance, and a linked write. This moved the target to rank 3 without
changing session, token, retry, context, or parallelism limits.

Run the credential-free tier with:

```bash
python benchmarks/run_libwebp_capacity_benchmark.py discover \
  --repo /path/to/pinned-vulnerable-libwebp \
  --scan-manifest benchmarks/libwebp-blind-scan.toml \
  --output /tmp/libwebp-discovery --mode deterministic
python benchmarks/run_libwebp_capacity_benchmark.py freeze \
  --discovery /tmp/libwebp-discovery --frozen /tmp/libwebp-frozen
python benchmarks/run_libwebp_capacity_benchmark.py evaluate \
  --frozen /tmp/libwebp-frozen \
  --oracle benchmarks/oracles/libwebp-cve-2023-4863.toml \
  --scan-manifest benchmarks/libwebp-blind-scan.toml \
  --vulnerable-repo /path/to/pinned-vulnerable-libwebp \
  --fixed-repo /path/to/pinned-fixed-libwebp \
  --output /tmp/libwebp-evaluation
```

## Non-goals

- Session, token, context, or parallelism increases
- New vulnerability families or new Hunter agents
- Prompt, verifier, UI, provider, sandbox, or intake changes
- Generic symbolic execution or whole-program points-to analysis
- Repository, file, function, constant, CVE, patch, or diff signatures
