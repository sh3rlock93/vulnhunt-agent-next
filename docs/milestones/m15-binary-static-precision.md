# M15 — Binary Static-Analysis Precision

## Goal

Reduce decompiler-induced false positives without changing ranking, Hunter,
fuzzer, or dynamic experiment behavior. Every precision rule must preserve the
supported deterministic vulnerability fixtures before it is admitted.

## Sequential scope

1. **M15-1 — Pointer provenance and explicit taint boundary**: distinguish
   address formation from integer size arithmetic, require an explicit input
   source, and preserve unique SSA value identity.
2. **M15-2 — Input API source propagation**: propagate typed data, length, and
   offset sources from supported ImageIO/CoreFoundation provider APIs.
3. **M15-3 — Typed memory-sink semantics**: distinguish address, allocation
   size, copy length, and stored value operands.
4. **M15-4 — CFG dominance and range guards**: replace same-block comparison
   suppression with bounded dominance evidence.
5. **M15-5 — Blind binary regression gate**: expand the corpus and establish
   measured promotion thresholds before Binary Hunter admission.

Implemented through M15-5. M15 is complete.

## M15-1 implementation

Status: implemented and locally verified on 2026-07-31.

### Root-cause evidence

The M14 ImageIO pilot emitted 424 `integer_overflow` static candidates:

- 218 `add → store` chains;
- 198 `add → load` chains;
- 8 `subtract → store` chains.

They were caused by three independent normalization errors:

1. Ghidra `PTRADD` and `PTRSUB` were mapped to generic integer add/subtract.
2. Every function parameter was tainted even without an `input_*` marker.
3. Distinct high-p-code SSA values named `UNNAMED` collapsed into one variable.

### Change boundary

- The Ghidra exporter adds `pointer_arithmetic` to `PTRADD`/`PTRSUB` while
  retaining their normalized add/subtract operation for dataflow.
- Pointer arithmetic may still produce `offset_length_oob` when both explicit
  `input_offset` and `input_length` evidence reaches a memory access. It cannot
  become a generic `integer_overflow` solely because it forms an address.
- A parameter becomes a taint source only when it has an explicit `input_*`
  tag. `decoder_entry` is discovery evidence, not attacker-control evidence.
- Named high variables retain their names. Generic `UNNAMED` values receive a
  deterministic identity from address space, storage offset, size, and defining
  p-code sequence, preventing unrelated SSA values from aliasing.
- Exported p-code text now begins with its source mnemonic for auditability.

No ranking score, context budget, Hunter prompt, model call, corpus mutation,
fuzzer route, or experiment policy changed.

## Regression requirements

- Ordinary input-derived multiply/add reaching a size sink still emits
  `integer_overflow`.
- Explicit pointer `offset + length` reaching a load still emits
  `offset_length_oob`.
- Allocation/copy mismatch and same-block use-after-free fixtures remain
  detected.
- Untagged and `decoder_entry`-only parameters do not acquire taint.
- Pointer field/index formation without offset-plus-length evidence emits no
  generic integer-overflow candidate.
- The frozen M14 blind corpus remains TP=1, FP=0, FN=0.

## Same-image A/B result

Both runs used:

- snapshot `sha256:47ad3755368140434c7821c0aa030c5631e5157dc50d7efc082440392c1c7adf`;
- ImageIO UUID `EEB840D5-3559-386F-BBD3-D24AA749D2EC`;
- 600 exported functions and 2,500 operations per function;
- 500 parser candidates, 200 ranked functions, and 64 context packs;
- zero model calls, tokens, image executions, and experiments.

Observed static-candidate counts:

| Stage | Candidates | Change from M14 baseline |
|---|---:|---:|
| M14 baseline | 424 | — |
| Pointer provenance | 50 | -88.2% |
| Explicit parameter taint | 1 | -99.8% |
| Unique SSA identity (final M15-1) | 0 | -100% |

Zero final candidates is not evidence that ImageIO is vulnerability-free. It
shows that every M14 candidate in this bounded slice depended on a demonstrated
normalization error. M15-2 below recovers real input influence from a bounded
set of supported API calls.

## M15-2 implementation

Status: implemented and locally verified on 2026-07-31.

### Typed API sources

The Ghidra exporter now uses a closed result-source allowlist:

| API result | Dataflow tag | Provenance tag |
|---|---|---|
| `CFDataGetLength` | `input_length` | `source_api:cf_data_length` |
| `CGDataProviderGetSize` | `input_length` | `source_api:image_provider_length` |
| `CGImageProviderGetSize` | `input_length` | `source_api:image_provider_length` |
| `CFDataGetBytePtr` | `input_data` | `source_api:cf_data_bytes` |
| `CGDataProviderGetBytePointer` | `input_data` | `source_api:data_provider_bytes` |

Matching is performed on a canonicalized callee and requires an exact supported
suffix. Generic names such as `getSize`, `length`, or `getBytes` do not become
sources. APIs that write into an output argument are also excluded because this
PR models return-value provenance only.

The analyzer admits a `CALL` result as a source only when the normalized
instruction carries an explicit `input_*` tag. The source then propagates
through the existing assign, cast, phi, bitwise, and arithmetic rules. Untagged
and `decoder_entry`-only calls kill any previous taint attached to their result.
Propagation remains bounded to the analyzer's current basic-block scope; CFG
joins and dominance are reserved for M15-4.

### Regression requirements

- A typed `CFDataGetLength` result propagated through a cast and multiply to an
  allocation still emits `integer_overflow`.
- A typed provider length combined with explicit `input_offset` pointer
  arithmetic still emits `offset_length_oob`.
- Name-only, untagged, and `decoder_entry`-only call results emit no finding.
- All M15-1 pointer, parameter-taint, allocation/copy, and UAF fixtures remain
  unchanged.

### Same-image result

The end-to-end pilot used the same snapshot, ImageIO UUID, 600-function limit,
and 2,500-operation limit as M15-1. The exporter identified 24 typed API return
sources:

- 8 `source_api:cf_data_bytes`;
- 14 `source_api:cf_data_length`;
- 2 `source_api:image_provider_length`.

Those values had 75 direct normalized-IR uses, including compares, calls, phi,
casts, assignments, bitwise masks, and two additions. None formed an unguarded
supported arithmetic-to-memory chain, so the deterministic analyzer emitted
zero findings. This is a valid negative result, not source-discovery failure.
The parser discovery report retained 38 API-call evidence entries.

## M15-3 implementation

Status: implemented and locally verified on 2026-07-31.

### Typed sink roles

The analyzer now interprets memory operands by normalized operation and a
closed callee table instead of treating every operand as a sink:

| Operation/API | Address or destination | Size or length | Explicitly excluded |
|---|---|---|---|
| Ghidra `LOAD` | operand 1 | — | address-space operand 0 |
| Ghidra `STORE` | operand 1 | — | address-space operand 0 and stored value 2 |
| `memcpy` / `memmove` families | operand 0 | operand 2 | source operand 1 |
| `bcopy` | operand 1 | operand 2 | source operand 0 |
| `malloc`, `malloc_type_malloc` | — | operand 0 | malloc type cookie |
| `malloc_zone_malloc` | — | operand 1 | zone operand 0 |
| `realloc`, `reallocf`, `malloc_type_realloc` | — | operand 1 | prior pointer and type cookie |
| `malloc_zone_realloc` | — | operand 2 | zone and prior pointer |
| `CFAllocatorAllocate` | — | operand 1 | allocator and hint |
| `__ImageIO_Malloc` | — | operand 0 | remaining metadata arguments |

One-operand `LOAD` and two-operand `STORE` remain accepted for normalized IR
adapters that omit Ghidra's address-space operand. Unknown copy and allocator
names do not inherit a role from a substring or argument position.

`__ImageIO_Malloc` is admitted as an exact canonical name because the frozen
ImageIO decompilation shows its first parameter being aligned, overflow-checked,
and passed as the `_mmap` size. The similarly named
`__ImageIO_Malloc.cold.1` helper does not match the allowlist.

`calloc` and its zone/type variants are deliberately excluded from single-size
reasoning. Their capacity is `count * element_size`; selecting either argument
as the complete size would manufacture a false relationship. Composite
capacity tracking remains a future isolated rule.

### Regression requirements

- Arithmetic in a Ghidra `STORE` stored-value operand does not become a memory
  address finding.
- Ghidra `LOAD`/`STORE` address operands and a `bcopy` destination retain
  explicit offset-plus-length OOB detection.
- Supported malloc/realloc/CF allocator size operands retain integer-overflow
  detection while type cookies, allocator objects, and old pointers do not.
- `bcopy` allocation/copy comparison uses its second operand as destination.
- Unsupported `calloc` composite capacity and similarly named cold helpers do
  not acquire guessed semantics.
- All prior M14/M15 analyzer fixtures and the frozen blind corpus remain green.

### Same-image result

The already exported M15-2 ImageIO IR was reanalyzed without another Ghidra
run because this milestone changes only deterministic Python analysis. Its 600
functions and 500 parser candidates contain:

- 4,008 loads;
- 1,564 stores;
- 29 copy calls;
- 87 allocation calls, including 30 exact `__ImageIO_Malloc`, 21
  `malloc_type_malloc`, 34 composite `malloc_type_calloc`, one `reallocf`, and
  one excluded cold helper.

The typed rules emitted zero findings, preserving the M15-2 valid negative
result. The frozen blind corpus remained TP=1, FP=0, FN=0, precision=1.0, and
recall=1.0 with zero model calls or tokens. The complete local suite passed 630
tests with 8 environment-dependent skips; Ruff and mypy also passed.

## M15-4 implementation

Status: implemented and locally verified on 2026-07-31.

### Root cause and change boundary

The former guard rule suppressed a candidate whenever any comparison mentioning
the arithmetic result or one of its inputs appeared earlier in the same basic
block. It did not require a conditional branch, identify the safe branch,
validate the bound, or reject a path that bypassed the comparison. It also
discarded taint and arithmetic provenance at every basic-block boundary.

M15-4 replaces that heuristic with bounded CFG evidence:

- Ghidra comparisons carry an exact normalized predicate tag for equality,
  unsigned/signed less-than, and unsigned/signed less-or-equal.
- Every `CBRANCH` carries `conditional_branch` and its concrete true-target
  address. The analyzer also supports the frozen pre-M15-4 text/operand form.
- Taint and arithmetic origins are propagated across reachable CFG blocks with
  a bounded forward fixed point. Reassignment behavior inside a block remains
  unchanged.
- Block dominators are computed only over entry-reachable blocks.
- A guard suppresses a sink only when the selected safe successor dominates
  the sink and that successor has the guard block as its sole predecessor. A
  bypass path, shared entry into the safe block, or same-block comparison fails
  closed and retains the finding.

Ranking, context packing, Hunter prompts, model execution, fuzzer behavior, and
dynamic experiments were not changed.

### Typed range rules

Only unsigned `<` and `<=` comparisons can prove a memory-size bound. Signed
comparisons, equality checks, and unrelated variables do not suppress a
candidate.

For multiply, shift-left, and add-with-constant, a precondition is admitted
only when the operation width and constant derive a concrete maximum safe input
and the branch threshold is no larger. For example, a 64-bit `length * 4`
requires `length <= UINT64_MAX / 4` or a stricter bound; comparing the wrapped
result with a generic maximum is insufficient.

The other admitted patterns are deliberately narrow:

- unsigned add wrap checks where the safe path rejects `result < addend`;
- direct offset-plus-length result bounds for memory access;
- `copy_length <= allocation_size`, including the reversed
  `allocation_size < copy_length` reject-edge form.

### Regression requirements

- A comparison with no consuming conditional branch remains reportable.
- A correct width-derived bound on the dominating safe edge suppresses the
  integer-overflow candidate.
- An oversized threshold, irrelevant variable, signed comparison, or CFG
  bypass retains the finding.
- Both true-edge and false-edge copy guards use the correct branch direction.
- Cross-block parameter/API taint reaches arithmetic and memory sinks.
- All M15-1 through M15-3 fixtures and the frozen blind corpus remain green.

### Real ImageIO result

A fresh end-to-end Ghidra pilot used the same cache snapshot and ImageIO UUID:

- snapshot `sha256:47ad3755368140434c7821c0aa030c5631e5157dc50d7efc082440392c1c7adf`;
- ImageIO UUID `EEB840D5-3559-386F-BBD3-D24AA749D2EC`;
- export `sha256:dab9b50ddd59285011bc65bafb2297b4e763572453de379eb2938c28d67caf24`;
- normalized IR `sha256:54fa1385d9f358232a6a71ab9e731c9cf14a3f870f90e7756023545df7ba8b57`.

The 600-function export contains 4,213 tagged comparisons and 4,182 tagged
conditional branches with true targets. The normalized analyzer paired 3,294
comparison/branch guards across 353 functions, with at most 72 guards in one
function. Analysis of 500 parser candidates emitted zero findings, preserving
the M15-2/M15-3 valid negative result. The full static pipeline completed with
64 context packs and no Hunter calls, tokens, image executions, experiments,
or estimated cost.

The frozen blind corpus remained TP=1, FP=0, FN=0, precision=1.0, and
recall=1.0. The complete local suite passed 637 tests with 8
environment-dependent skips; Ruff and mypy also passed.

## M15-5 implementation

Status: implemented and locally verified on 2026-07-31.

### Gate contract

The original M14 blind runner analyzed every case before loading its separate
oracle, but its command failed only on a false negative. M15-5 preserves the
M14 result schema for compatibility and adds a fail-closed gate with the
following default policy:

| Requirement | Default |
|---|---:|
| Minimum frozen cases | 10 |
| Required vulnerability classes | all 4 supported classes |
| Expected findings per required class | at least 1 |
| Recall per required class | 1.0 |
| Overall precision | 1.0 |
| Maximum false positives | 0 |
| Maximum false negatives | 0 |
| Determinism runs | 2 |
| Model calls, tokens, and estimated cost | 0 |

Both deterministic runs complete before the oracle loader is invoked. The
observation digest binds each case's finding keys and complete binary-ranking
digest, so a finding or ranking-order change fails determinism even if aggregate
counts remain equal. Export hashes are revalidated before every run.

Gate failure reasons are structured and independently testable: insufficient
case count, missing class coverage, class recall regression, overall precision
regression, excessive FP/FN, and nondeterministic results. The CLI exits nonzero
whenever any reason is present.

### Frozen corpus

The M15 corpus uses 12 opaque case IDs. Oracles remain in a separate file and
are not passed to freezing, normalization, discovery, static analysis, or
ranking. Six vulnerable cases cover:

- two integer-overflow paths, including a correct-looking guard with a CFG
  bypass;
- one offset-plus-length OOB memory access;
- two allocation/copy mismatches covering `memcpy` and `bcopy` operand order;
- one same-block use-after-free.

Six negative controls cover direct safe allocation, a valid dominating range
guard, arithmetic used only as a `STORE` value, ordinary pointer-field/index
formation, allocation and copy using the same length, and unsupported composite
`calloc` capacity. These controls bind the M15-1 through M15-4 precision fixes.

### Measured result

The default gate passed:

- manifest `sha256:29dcd48ca675457031dab3c6ae7342456fd30f70cf0cdcc4bd7f3cf8d50cf503`;
- 12 cases and 6 expected findings;
- TP=6, FP=0, FN=0;
- overall recall=1.0 and precision=1.0;
- per-class recall=1.0 for integer overflow, offset/length OOB,
  allocation/copy mismatch, and use-after-free;
- identical two-run finding/ranking observation digest
  `sha256:84e4a0cdbbf6b44c689a259c579ef57f475e8064bcad549b3b68adec783795a4`;
- zero model calls, tokens, dynamic experiments, and estimated cost.

A dedicated GitHub Actions workflow runs lint, type checking, all binary
pipeline tests, and the gate for relevant changes. Local verification passed
94 binary pipeline tests and the complete project suite passed 641 tests with
8 environment-dependent skips. Ruff and mypy also passed.

### Limitation

The frozen M15 cases are compact normalized-IR regression fixtures. They prove
that implemented semantics do not regress; they do not measure decompiler
recovery quality or real-world zero-day recall. Promotion beyond this gate
should next add independently sourced, Ghidra-produced historical vulnerable
and patched binaries without providing patch diffs to the analyzer.
