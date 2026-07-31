# M16 — Composite-Range and Uninitialized-Disclosure Recovery

## Goal

Recover ImageIO vulnerabilities whose individual fields pass validation but
whose combined range is invalid, and distinguish the non-crashing disclosure
case where a short input read leaves a buffer partially initialized before a
decoder consumes the full declared length.

CVE-2026-20634 is the first real benchmark, not a hard-coded signature. The
general invariants implemented by M16 are:

```text
0 <= offset <= capacity
0 <= length <= capacity - offset
```

and:

```text
bytes_initialized >= bytes_consumed
```

The milestone is complete only when a blind run over a vulnerable historical
ImageIO build finds the generalized defect, a patched build and benign input
remain negative, and every pre-M16 binary regression remains green.

## Evidence motivating the milestone

The frozen macOS 26.5.2 ImageIO pilot contains:

- the UTI string `com.sgi.sgi-image`;
- the string `decodeSGI_RLEcompressed` at `0x18d941fc8`;
- code references to that string at `0x18d777cfc`, `0x18d777d2c`, and
  `0x18d777d4c`.

None of those reference addresses belongs to one of the 600 functions exported
by the bounded Ghidra run. Only `CreateReader_SGI` was exported as an SGI
function. Parser discovery admitted it with score 4, but it did not enter the
final 200-function ranking. The 500 analyzed candidates emitted zero static
findings.

The existing `offset_length_oob` analyzer also requires an offset/length
arithmetic result to exist before it can identify an unchecked sink. The
vulnerable form of CVE-2026-20634 omits the combined operation and guard, so the
current rule cannot represent the root cause even if the function is exported.

## Non-goals

- Do not hard-code the vulnerable SGI function address, patch bytes, PoC
  offsets, output hash, or CVE identifier into production detection logic.
- Do not build a general adjacent-build patch-diff engine in M16.
- Do not provide patch deltas or oracle labels to discovery, static analysis,
  ranking, or the Hunter during a blind benchmark.
- Do not broaden fuzzing to every ImageIO format. SGI is the only new structured
  mutator in this milestone.
- Do not claim that a static candidate is a confirmed vulnerability.
- Do not execute malformed images on the host or weaken SIP, hardened runtime,
  VM isolation, or network controls.
- Do not add exploit development, code execution, persistence, evasion, public
  disclosure, or automatic external submission.
- Do not rewrite the M14/M15 ranking or context-budget policy unless a measured
  M16 coverage failure requires a narrowly scoped scoring component.

## Implementation precondition

M16 implementation starts only from a committed M15 baseline with:

1. the M15 blind binary regression gate passing twice deterministically;
2. the complete test suite, Ruff, and mypy passing;
3. the macOS 26.5.2 snapshot and M15 pilot digests recorded;
4. no unrelated uncommitted files in the PR worktree.

At design time the current worktree still contains uncommitted M13–M15 changes.
Those changes must be separated and committed before opening M16-1 so that each
M16 PR has an auditable diff and can be reverted independently.

## Global admission rules

Every PR follows the same gate:

1. Implement only that PR's declared scope.
2. Run focused unit and contract tests.
3. Run the M15 blind regression gate twice.
4. Run the complete project suite, Ruff, and mypy.
5. Run the PR-specific actual-ImageIO check when listed.
6. Inspect the diff for unrelated changes and generated/private artifacts.
7. Commit, push, open a PR, verify CI, and merge only after every required gate
   passes.
8. Start the next PR from the updated default branch.

A failed gate is repaired in the same PR. The next PR does not start while a
required test, determinism check, or actual-target assertion is failing.

The standard local gate uses the project virtual environment:

```bash
.venv/bin/python benchmarks/run_m15_binary_regression_gate.py \
  --output /private/tmp/m15-gate-run-1.json
.venv/bin/python benchmarks/run_m15_binary_regression_gate.py \
  --output /private/tmp/m15-gate-run-2.json
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check src tests benchmarks
.venv/bin/python -m mypy
```

The two gate outputs must have the same finding/ranking observation digest.
PR-focused tests run before this standard gate and are added to CI in the same
PR that introduces their behavior.

Historical Apple binaries, dyld caches, decompiler projects, raw PoCs, decoded
pixels, crash logs, and canary output remain in a private directory outside the
Git worktree. Git stores only code, synthetic fixtures, digest-bound manifests,
and reproduction instructions.

## Sequential PR plan

1. **M16-1 — Decoder coverage census and xref-guided export**
2. **M16-2 — Input-backed table and scalar provenance**
3. **M16-3 — Composite-range validation-gap analyzer**
4. **M16-4 — Partial-initialization disclosure model and Hunter contract**
5. **M16-5 — Raw-pixel differential and canary oracle**
6. **M16-6 — SGI relational mutator and deep-seed qualification**
7. **M16-7 — Historical blind regression and end-to-end decision gate**

---

## M16-1 — Decoder coverage census and xref-guided export

### Objective

Ensure that a security-relevant decoder cannot disappear merely because its
name scores below a global decompilation cap.

### Scope

- Add a lightweight, all-function census before bounded decompilation. It
  records function identity, address range, symbol/display name, direct string
  references, and bounded call edges without exporting pseudocode for every
  function.
- Derive decoder seeds from:
  - registered ImageIO UTIs captured by the existing inventory;
  - symbol/name tokens such as read, parse, decode, decompress, RLE, and known
    format identifiers;
  - references to decoder, format, malformed-input, and UTI strings;
  - bounded callers and callees of those seeds.
- Select the decompilation set in two explicit tiers:
  1. mandatory evidence seeds and their bounded neighborhood;
  2. the existing parser-score fallback up to the remaining budget.
- Record, for every selected or omitted function, its selection reason and
  tier. Record cap saturation as a visible coverage warning.
- Add SGI as a format value in the typed inventory/discovery boundary, but do
  not use the exact CVE function name as a production allowlist entry.

### Constraints

- The all-function census must not contain pseudocode or unbounded p-code.
- Mandatory seeds cannot be evicted by lower-priority fallback functions.
- Callgraph expansion remains bounded by configurable depth and function count.
- Selection order and coverage manifests must be deterministic and
  digest-bound to the same binary snapshot.

### Focused verification

- A synthetic image with more functions than the export cap still exports a
  low-address and a high-address xref-selected decoder.
- Unreferenced generic functions remain eligible only through the fallback
  tier.
- Changing a UTI, string reference, selection reason, or selected function
  invalidates the coverage digest.
- Repeated selection produces byte-identical ordered manifests.
- A cap-saturated run reports omissions rather than implying full coverage.

### Actual-ImageIO gate

On the frozen macOS 26.5.2 ImageIO image:

- the function containing at least one `decodeSGI_RLEcompressed` string
  reference must enter the export;
- the SGI reader entry and the selected decoder must have an auditable
  selection path;
- the normalized IR must contain that function even if Ghidra retains only a
  generic function name;
- no model or image execution is allowed.

---

## M16-2 — Input-backed table and scalar provenance

### Objective

Carry attacker influence from an input-backed buffer through indexed table
loads, byte-order conversion, assignments, casts, and loop joins without
tainting every memory load.

### Scope

- Add a typed `input_scalar` provenance class distinct from `input_data`,
  `input_offset`, and `input_length`.
- A `LOAD` result becomes input-backed only when its address provenance derives
  from an approved input buffer or a bounded read-session summary.
- Preserve provenance through:
  - pointer index formation;
  - integer width extension and narrowing;
  - byte swap/reverse operations;
  - assignments and PHI nodes;
  - bounded cross-block fixed-point propagation.
- Add normalized IR support for byte-swap and boolean-composition p-code that
  was previously `unknown`.
- Preserve stable SSA identity and the M15 distinction between pointer
  formation and integer size arithmetic.
- Attach role evidence only from use: a scalar may become a range offset,
  range length, capacity, count, or index when it occupies a typed call or
  comparison role. Variable names alone are insufficient.

### Negative controls

- A load through an unrelated object or global pointer is not input-tainted.
- A decoder-entry tag alone does not taint all loads in the function.
- An input pointer copied into a local alias retains provenance, but an
  unrelated reassignment kills it.
- A byte-swapped input scalar remains input-backed without automatically
  becoming a length or offset.

### Focused verification

- Synthetic table load → byte swap → PHI → typed range-call fixtures retain
  source identity.
- Global-table, constant-table, output-buffer, and unrelated-heap fixtures
  remain negative.
- All M15 pointer, API-source, sink-role, and CFG fixtures remain unchanged.

### Actual-ImageIO gate

The selected SGI decoder must expose two distinguishable input-backed scalar
flows into individual file-size comparisons or a typed range-read call. If the
decompiler does not recover enough provenance, the PR records the exact missing
edge and is not declared complete merely because unit tests pass.

---

## M16-3 — Composite-range validation-gap analyzer

### Objective

Detect the absence of a combined range invariant even when no `offset + length`
operation exists in the vulnerable code.

### Scope

- Add a typed range-call summary with the roles:

  ```text
  destination, offset, requested_length, available_capacity, actual_length
  ```

  `available_capacity` may be a companion value recovered from the owning read
  session or a dominating size query; it is not assumed to be a direct call
  operand.

- Model `IIOImageReadSession::getBytesAtOffset` as the first concrete range
  reader. Matching must use a canonical exact method identity, not a broad
  `getBytes` substring.
- Identify two input-backed scalars used as offset and requested length against
  the same capacity.
- Recognize safe dominating forms:
  - `offset + length <= capacity` with a proven non-wrapping addition;
  - `offset <= capacity && length <= capacity - offset`;
  - equivalent strict/reject-edge forms recovered from CFG;
  - boolean AND chains or compiler-lowered conditional comparisons whose safe
    edge dominates the range call.
- Emit a candidate when individual offset and length checks exist but no
  dominating combined range proof covers the call.
- Retain a candidate when a path bypasses one part of the compound guard.
- Include explicit evidence for source, both individual checks, missing
  invariant, range-call roles, and sink address.

### Classification

Introduce `composite_range_gap` as a static relation class. Existing
`offset_length_oob` remains supported for an explicit unchecked arithmetic
result. The M15 gate keeps an explicit frozen list of its original four
required classes so adding M16 classes cannot silently rewrite the M15 oracle.

### False-positive suppressors

- Different capacities for offset and length do not form a combined proof or a
  combined-gap candidate without a demonstrated common range call.
- A clamp that changes the requested length before the call is respected.
- A checked actual-length return may suppress later consumption impact, but it
  does not by itself prove the original input range valid.
- A zeroing operation does not repair the bounds relation; it affects only the
  later disclosure classification.

### Focused verification

At minimum, add paired vulnerable/safe fixtures for:

1. individual checks only;
2. checked `offset + length`;
3. overflow-safe subtraction form;
4. arithmetic wrap before comparison;
5. compound guard with a bypass path;
6. distinct capacity values;
7. clamped length;
8. range-call arguments in reversed or unrelated roles.

### Actual-ImageIO gate

The current patched ImageIO SGI decoder must not emit
`composite_range_gap`. Its recovered combined check must be retained as
negative evidence. A failure to recover the patched guard is a decompiler/IR
coverage failure, not permission to whitelist the function.

---

## M16-4 — Partial-initialization disclosure model and Hunter contract

### Objective

Distinguish a range defect that merely truncates input from one that causes
uninitialized allocation content to reach decoded output.

### Scope

- Add `partial_initialization_disclosure` as a vulnerability class with CWE-908
  metadata.
- Model the chain:

  ```text
  uninitialized allocation
    → range read may initialize fewer than requested bytes
    → actual length is ignored or not used as the consume bound
    → downstream parser/decompressor consumes requested length
    → decoded/output buffer becomes externally observable
  ```

- Add bounded call summaries for allocation, range-read return value, decoder
  consumption length, and output propagation. Interprocedural expansion is
  limited to one caller/callee hop unless a later measured fixture proves that
  depth insufficient.
- Require evidence for allocation capacity, maximum initialized bytes,
  downstream consumed bytes, and an output route. A partial read alone is not
  a disclosure finding.
- Suppress disclosure promotion when:
  - the allocation is fully zero-initialized before the short read;
  - the actual copied length is checked and controls every consumer;
  - the combined range guard proves a full read;
  - the output is not observable or is fully overwritten before observation.
- Add a generalized knowledge entry for “individually valid range fields plus
  partial-fill/full-consume,” without SGI-specific addresses or constants.
- Extend the Binary Hunter schema and prompt to reason about
  `composite_range_gap` and `partial_initialization_disclosure`.
- Add typed experiment requests for raw-output differential and canary
  propagation. They remain non-executable until human review.

### Hunter admission rule

A Hunter disclosure hypothesis must cite:

- one input/reachability evidence item;
- one composite-range or partial-initialization static finding;
- one allocation/initialization evidence item;
- one full-consumption/output evidence item;
- a falsification condition.

The Hunter cannot promote a composite-range candidate directly to reportable.

### Focused verification

- Partial fill followed by full consume and output produces a disclosure
  candidate.
- Return-value checked, fully zeroed, full-overwrite, and non-observable
  controls remain negative.
- Invalid model output cannot invent an unsupported experiment or omit the
  required evidence classes.
- Existing four M14/M15 Hunter classes and experiment kinds remain valid.

---

## M16-5 — Raw-pixel differential and canary oracle

### Objective

Validate non-crashing memory disclosure instead of treating normal process exit
as a negative result.

### Scope

- Add a VM-only raw-pixel route using the decoded image's data provider and a
  bounded data copy. Keep the existing CGContext render route as an independent
  behavioral route.
- Record only bounded evidence by default:
  - decoded byte count;
  - output digest;
  - per-run canary position digest/count;
  - route and build identity.
  Raw pixels remain private outside Git.
- Add a reviewed canary allocator interposer for uninitialized malloc-family
  allocations used by the analyst-controlled harness process. The interposer:
  - has a content digest and fixed source revision;
  - calls the real allocator without recursion;
  - never changes `calloc` zero-initialization semantics;
  - fills only newly allocated non-`calloc` blocks before the program writes
    them;
  - executes only inside the disposable networkless VM;
  - records whether the target allocation family was actually observed.
- Use at least three distinct canary bytes. A positive oracle requires
  positional correlation: the same output positions must track the selected
  canary across runs. A mere count of coincidental byte values is insufficient.
- Require a benign input control under the same canaries and build.
- Classify a canary-correlated disclosure as interesting even when every run
  exits normally and no crash log exists.
- Keep ASan and Guard Malloc for bug classes they can observe, but do not treat
  their silence as negative evidence for uninitialized disclosure.

### Safety and stop condition

If interposition requires weakening host security, changing SIP, executing on
the host, enabling network access, or injecting into a third-party process,
stop and request a design decision. M16 does not work around those controls.

### Focused verification

- Synthetic harness output whose fixed positions follow three canaries passes.
- Random matching bytes, changing positions, constant output, and benign
  canary coincidences fail.
- Normal exit plus a valid leak oracle is retained as interesting.
- Crash, timeout, resource, and infrastructure classifications remain
  unchanged.
- Output and allocator evidence are bound to VM/build/input/interposer digests.

---

## M16-6 — SGI relational mutator and deep-seed qualification

### Objective

Generate small, parser-valid SGI RLE cases that exercise range relationships
instead of random bytes.

### Scope

- Add SGI as one format plugin with a bounded parser for:
  - the 512-byte big-endian header;
  - storage mode, bytes per channel, dimensions, and channel count;
  - start-offset and byte-length tables;
  - file-size and table-count relationships.
- Require a seed to reach source creation, SGI type identification, image
  creation, and raw or rendered pixel materialization before mutation.
- Add relational operators that preserve all unrelated fields:
  - each field individually in range, combined range out of bounds;
  - exact end-of-file range;
  - one-byte combined overrun;
  - truncated available tail with preserved declared length;
  - paired offset/length boundary movement.
- Avoid broad random mutations in this milestone. Existing DICOM mutators are
  untouched.
- Store operator, table index, original values, mutated values, and asserted
  relation in the case manifest.

### Budget

- Maximum 16 generated SGI cases per seed.
- Maximum two decode routes per case during qualification; the final canary
  replay uses only the selected raw-pixel route.
- Zero model calls during generation, qualification, and execution.

### Focused verification

- Every generated payload satisfies its declared individual-field and combined
  relation.
- Endianness, table positions, seed digest, and mutation provenance are
  deterministic.
- Invalid/oversized dimensions, table counts, and seed sizes fail closed.
- Duplicate payloads are removed content-addressably.
- Existing DICOM campaign behavior and fixtures remain byte-for-byte stable.

### Current-build gate

On macOS 26.5.2, a benign SGI seed must reach pixel materialization. Structured
invalid cases may be rejected or produce a uniform/empty result, but must not
produce a canary-correlated disclosure. This is a negative control, not the
historical positive benchmark.

---

## M16-7 — Historical blind regression and end-to-end decision gate

### Objective

Prove that M16 recovers the known vulnerability from vulnerable code without
using the patch diff as analyzer input, while preserving all previous
detections.

### Required local targets

| Role | Target | Expected security state |
|---|---|---|
| Positive | macOS 26.2, build 25C56 ImageIO | vulnerable |
| Patched control | macOS 26.3, build 25D125 ImageIO | fixed |
| Current control | frozen macOS 26.5.2, build 25F84 ImageIO | fixed |

The targets must be lawfully obtained and remain private. If the 26.2 ImageIO
binary and a disposable 26.2 VM are not locally available, implementation may
complete M16-1 through M16-6, but M16 cannot be marked complete. Stop before
downloading or provisioning a new historical system image when user approval
or Apple-account interaction is required.

### Blind protocol

1. Freeze each binary, inventory, harness, seed, interposer, and VM identity by
   digest.
2. Run export, normalization, discovery, static analysis, and ranking on each
   build independently.
3. Do not load vulnerable/patched labels or patch differences until all static
   observations are sealed.
4. Run the Hunter only on admitted ranked evidence, with at most two model
   calls for the benchmark.
5. Load the private oracle and classify static observations.
6. After reviewer approval, execute only the bounded trigger/control matrix in
   disposable networkless VMs.
7. Seal dynamic observations before evaluating expected positive/negative
   outcomes.

### Required matrix

| Binary/input | Static composite gap | Disclosure hypothesis | Canary correlation |
|---|---:|---:|---:|
| 26.2 structured trigger | yes | yes | yes |
| 26.2 benign SGI | no | no | no |
| 26.3 structured trigger | no | no | no |
| 26.3 benign SGI | no | no | no |
| 26.5.2 structured trigger | no | no | no |
| 26.5.2 benign SGI | no | no | no |

If decompiler differences prevent an exact disclosure chain on one build, the
minimum static positive is a correctly evidenced `composite_range_gap` plus a
Hunter request for the canary experiment. The final dynamic positive remains
mandatory for M16 completion.

### Regression requirements

- The M15 12-case gate remains TP=6, FP=0, FN=0 with identical two-run
  observation digest unless an intentionally versioned fixture change is
  documented.
- Add M16 synthetic positives and negatives for both new classes without
  modifying M15 oracle labels.
- All previously supported integer-overflow, explicit offset/length OOB,
  allocation/copy mismatch, and UAF cases remain detected.
- Current/patched SGI functions do not require a name, address, hash, or build
  whitelist to stay negative.
- Two complete M16 blind runs produce identical static findings, ranking, and
  experiment-plan digests.

### Cost and execution ceilings

- Static stages: zero model calls and zero image executions.
- Hunter benchmark: at most two model calls, only after deterministic ranking.
- Dynamic confirmation: at most 12 reviewed canary/control executions per
  historical build and no feedback fuzzing.
- No network device in any malformed-image VM.
- No proprietary binary or raw candidate artifact in Git.

## Milestone completion criteria

M16 is complete only when all of the following are true:

1. All seven PRs are merged in order and their CI checks pass.
2. The actual SGI decoder is present in the bounded exported IR with an
   auditable, generalized selection reason.
3. Input table values retain source provenance through endian conversion and
   loop joins.
4. The vulnerable historical decoder emits `composite_range_gap` without patch
   knowledge.
5. The patched and current decoders expose a dominating combined-range proof
   and remain negative.
6. The partial-fill/full-consume chain can produce an evidence-bound disclosure
   hypothesis.
7. Canary-position correlation is positive only for the vulnerable trigger and
   negative for every patched and benign control.
8. The M15 gate, full tests, Ruff, and mypy remain green.
9. Static candidates are not labeled confirmed/reportable without dynamic and
   human-review evidence.
10. Every test image, binary, VM artifact, decoded output, and temporary
    decompiler project is cleaned up or retained only in the declared private
    content-addressed evidence store.

## Explicit failure interpretation

- **Function absent after M16-1:** coverage/selection failure; do not tune the
  analyzer or ranking yet.
- **Function present but input scalars untainted after M16-2:** provenance or
  call-summary failure; do not add a name-based SGI exception.
- **Vulnerable and patched builds both positive after M16-3:** guard recovery or
  relational false-positive failure.
- **Static gap found but no disclosure chain after M16-4:** keep the result as a
  range hypothesis; do not overstate impact.
- **ASan/Guard Malloc silent:** expected for this class and not a negative
  result.
- **Canary bytes appear without positional correlation or in benign controls:**
  oracle false positive; do not promote.
- **Historical target unavailable:** M16 remains implemented-but-unvalidated,
  not complete.

## Deferred follow-up

After M16 succeeds, a separate milestone may mine adjacent Apple releases for
generalized guard additions using normalized semantic diffing. That future
lane must remain separate from zero-day blind discovery and must suppress
framework-wide compiler hardening noise. It is intentionally not part of M16.
