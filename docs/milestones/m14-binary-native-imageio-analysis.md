# M14 — Binary-Native ImageIO Analysis

## Goal

Add a source-like static-analysis path for Apple ImageIO binaries so discovery is
not dependent on a fuzzer reaching a vulnerable state. Fuzzing remains an
independent dynamic validation signal; M14 does not replace or silently modify
the existing campaign engine.

## Non-goals

- Do not reconstruct Apple's original source code.
- Do not claim a vulnerability from decompiler output alone.
- Do not execute untrusted image input on the host.
- Do not change F1–F5 corpus, mutator, scheduler, or crash triage behavior.

## Sequential PR plan

1. **Binary snapshot and evidence contract** — bind analysis to an immutable
   dyld shared-cache UUID and per-file SHA-256 manifest using read-only access.
2. **Decompiler adapter and normalized IR** — isolate Ghidra/Binary Ninja
   differences behind a versioned function/call/control-flow representation.
3. **ImageIO parser discovery** — identify candidate images and parser entry
   points using symbols, strings, imports, selectors, and call-graph evidence.
4. **Deterministic vulnerability analyzers** — implement bounded integer,
   allocation/copy, offset/length, lifetime, and state-machine checks over IR.
5. **Binary function ranking and context packing** — prioritize reachable,
   input-influenced functions while retaining machine-verifiable evidence.
6. **Binary Hunter and experiment planning** — let the Hunter challenge static
   findings and request the smallest useful dynamic experiment from the fuzzer.
7. **Blind benchmark and ImageIO pilot** — measure known-case recall, false
   positives, runtime, and cost before using the path for zero-day discovery.

Each PR advances only after its focused tests and the repository-wide regression
suite pass. A failure is repaired in the same PR before proceeding.

## PR1 contract

`BinarySnapshot` records only:

- macOS product/build and normalized architecture;
- primary dyld cache magic and UUID;
- primary, numbered subcache, and symbols file names;
- byte lengths and streaming SHA-256 digests;
- a deterministic snapshot digest that excludes capture time.

The collector rejects symlinks, non-regular members, malformed/truncated cache
headers, architecture disagreement, zero UUIDs, changing files, and configured
file/byte limit violations. It does not copy cache bytes, extract Mach-O images,
invoke a decompiler, accept an image, or call ImageIO.

## PR1 exit criteria

- Two captures of unchanged bytes have the same snapshot digest.
- Changing any evidence field invalidates the model digest.
- Cache family ordering is deterministic.
- Persisted manifests are atomic, mode `0600`, and content-addressed.
- Existing fuzzing files are untouched.
- Focused and full regression suites pass.

## Implemented through PR7

### PR2 — Normalized IR and adapters

- Ghidra and Binary Ninja JSON exports are normalized into the same versioned
  image, function, basic-block, instruction, string-reference, and import model.
- Every export must carry the expected binary snapshot digest.
- Unsupported operations remain `unknown` with their source opcode retained;
  the adapter does not guess semantics.
- Normalized IR and pseudocode carry deterministic SHA-256 bindings.

The adapters consume bounded, non-symlink JSON exports. Running Ghidra or Binary
Ninja and extracting dyld images remains outside this PR.

### PR3 — ImageIO parser discovery

- Candidate discovery combines function markers, format strings, input tags,
  ImageIO/data-provider calls, memory sinks, and a bounded internal call graph.
- Isolated generic allocation/copy calls do not become parser candidates.
- Call-graph expansion is bounded by depth and candidate count.
- Discovery output is deterministic and digest-bound to normalized IR.

### PR4 — Deterministic analyzers

- Supported static-candidate classes are unchecked input-derived integer
  arithmetic, offset/length OOB, allocation/copy mismatch, and same-block UAF.
- A finding requires a source-to-sink evidence chain; arithmetic that never
  reaches a memory sink is not emitted.
- Visible intervening comparisons suppress the corresponding same-block alert.
- Results remain explicitly `static_candidate`; they are not reportable or
  confirmed vulnerabilities without later Hunter review and experiments.

### PR5 — Ranking and context packing

- Ranking combines static findings, confidence, parser evidence, input
  reachability, call-graph position, function complexity, and unknown-IR cost.
- Every score is decomposable into typed components.
- Context packing preserves a contiguous prefix of the ranking. It cannot skip
  an oversized high-ranked function to admit a lower-ranked function.
- Oversized functions are reduced around evidence addresses and then truncated
  to a strict UTF-8 byte budget.
- Pack/segment/plan hashes and validators prevent silent reordering or mutation.

## M14 completion status

All seven PR scopes are implemented. PR7 adds a frozen blind corpus, a separate
post-analysis oracle, a bounded Ghidra extractor/exporter, and a static-only
pilot runner. No PR7 path invokes a model, executes image input, starts a
Hunter, or runs a dynamic experiment.

## PR7 — Blind benchmark and real ImageIO pilot

Status: implemented and locally verified

### Blind benchmark contract

- Benchmark exports are hashed into `m14-blind-manifest-v1` before an oracle is
  available to the analysis loop.
- The API accepts an oracle loader callback and calls it only after every frozen
  export has completed normalization, discovery, and static analysis.
- Changed exports and missing, extra, duplicated, or unsorted oracle cases are
  rejected.
- Results record per-case and aggregate true positives, false positives, false
  negatives, recall, precision, runtime, and zero model/token/cost usage.
- The committed smoke corpus contains one known integer-overflow dataflow and
  one known-safe control. The local blind run produced TP=1, FP=0, FN=0,
  recall=1.0, and precision=1.0. This verifies the benchmark mechanism; two
  synthetic cases are not a general accuracy claim.

Run it with:

```bash
.venv/bin/python benchmarks/run_m14_binary_blind_benchmark.py
```

### Ghidra bridge

- `ExtractDyldImage.java` mounts the local split dyld cache read-only and
  extracts exactly one allow-listed ImageIO path to a caller-controlled private
  directory.
- Ghidra's extraction footer is verified and removed from a separate private
  copy so its standard Mach-O loader can consume the already-fixed image.
- `LC_UUID` is parsed directly and bound to the export without loading or
  executing the Mach-O.
- `ExportImageIOIR.java` emits bounded functions, basic blocks, high p-code,
  pseudocode, imports, strings, references, parameters, and API-derived input
  tags in the existing `ghidra-imageio-export-v1` schema.
- P-code is ordered by instruction address and sequence number before export so
  the normalized IR's canonical-order invariant is retained.
- Headless commands use argument arrays, finite heap/time/function/operation
  limits, no stdin, private logs, and no network feature.

Run the real static pilot on Apple Silicon macOS with:

```bash
.venv/bin/python tools/macos/run_m14_imageio_pilot.py \
  --output /private/tmp/vulnhunt-m14-imageio-pilot
```

The output directory must not already exist. It is created with mode `0700`;
evidence files use mode `0600`. Extracted binaries and decompiler exports must
remain outside Git.

### 2026-07-31 local pilot result

Environment: macOS 26.5.2 (25F84), arm64e cache, Ghidra 12.1.2.

- Snapshot: 15 cache-family members, digest-bound to cache UUID
  `157E6D2E-2E5C-39B1-8F2A-8866EE228BED`.
- ImageIO: UUID `EEB840D5-3559-386F-BBD3-D24AA749D2EC`.
- Stage runtime: snapshot 1.93s, extraction 6.45s, Ghidra analysis/export
  70.75s, normalized static pipeline 5.80s.
- Exported functions: 600; discovered candidates: 500 (configured cap);
  ranked functions: 200; context packs: 64.
- Static candidates: 424, all classified as `integer_overflow`.
- Model calls, tokens, estimated cost, image executions, and experiments: zero.
- Confirmed vulnerabilities: zero.

The 424 candidates are deliberately not presented as vulnerabilities. The
candidate cap was saturated and many p-code pointer/addition expressions were
treated as input-derived arithmetic sinks. This is evidence that the real
bridge works end to end, but also that binary-specific taint-source precision,
pointer-arithmetic normalization, dominance, and sink semantics need another
milestone before the result is suitable for zero-day triage. PR7 records that
limitation instead of hiding it behind the synthetic benchmark score.

The first precision repair and same-image A/B result are recorded in
`m15-binary-static-precision.md`; the M14 numbers above remain the immutable
pre-repair baseline.

## PR6 design — Scope-bound Binary Hunter and experiment planning

Status: implemented and locally verified

### Objective

Challenge PR4 static candidates with an evidence-bound Hunter, and translate
only the smallest useful follow-up into a typed, non-executable experiment
request. PR6 does not run a decompiler, execute an image, generate an exploit,
or promote a static candidate to a reportable vulnerability.

The PR consumes the immutable PR1–PR5 chain:

`BinarySnapshot → NormalizedBinaryIR → ParserDiscovery → AnalysisReport → Ranking → ContextPlan`

and produces:

`BinaryHunterAssessment → BinaryExperimentRequest → reviewer-gated plan`

If any digest in that chain does not match, packet construction fails before a
model call.

### Authorized defensive-research scope

Every Hunter packet carries a content-addressed `binary-research-scope-v1`
object. The caller must attest that the binary is lawfully present on an
analyst-controlled macOS installation or VM. The contract fixes these values:

- purpose: defensive vulnerability research;
- target origin: locally installed system binary;
- analysis mode: bounded, read-only static analysis;
- host image execution: false;
- network access: false;
- third-party system access: false;
- credential, persistence, evasion, and weaponization assistance: false;
- public disclosure or external submission: false;
- dynamic experiments: planning only, with separate human review required.

The following block is included verbatim in the Binary Hunter system prompt:

> This task is authorized defensive research over an Apple ImageIO binary
> lawfully present on an analyst-controlled macOS installation or disposable
> VM. Perform bounded, read-only static analysis of the supplied evidence only.
> Do not provide exploit code, arbitrary-code-execution steps, persistence,
> evasion, credential access, network activity, third-party access, or public
> disclosure instructions. Treat every result as a hypothesis. You may request
> only a typed, non-executable experiment supported by the existing networkless
> disposable-VM harness; execution requires independent human review. If the
> requested conclusion cannot be supported inside this scope, return
> `scope_blocked` or `inconclusive` and state the missing evidence.

This statement defines and enforces the actual operating boundary. It must not
be varied, hidden, or rewritten to evade a provider safeguard.

### Contracts

#### `BinaryResearchScope`

- Schema version: `binary-research-scope-v1`.
- Records the fixed permissions above plus a caller-supplied authorization
  basis and the PR1 snapshot digest.
- Has a deterministic `scope_sha256` over canonical JSON.
- Rejects permissive values such as host execution, networking, third-party
  access, automatic experiment execution, or weaponization.

#### `BinaryHunterPacket`

- Schema version and prompt version are explicit.
- Binds `snapshot_sha256`, `ir_sha256`, `discovery_sha256`, `report_sha256`,
  `ranking_sha256`, `context_plan_sha256`, and `scope_sha256`.
- Contains exactly one ranked context pack per Hunter call, its sequence, byte
  length, and content digest.
- Includes machine-readable finding summaries and evidence addresses, but no
  raw dyld-cache bytes and no path outside the private artifact root.
- Preserves PR5 order. A lower-ranked pack cannot be submitted while an
  admitted higher-ranked pack is omitted or pending.
- Has a strict input-byte limit and rejects changed, reordered, or unbound
  context.

#### `BinaryHunterAssessment`

Allowed dispositions are:

- `static_hypothesis`: the evidence supports a bounded root-cause hypothesis;
- `needs_context`: a named function, call edge, or bounded evidence window is
  missing;
- `needs_experiment`: one supported dynamic observation could discriminate the
  hypothesis;
- `not_vulnerable`: visible evidence falsifies the candidate;
- `inconclusive`: evidence is insufficient;
- `scope_blocked`: answering would require a prohibited action.

Each hypothesis must identify the input-controlled value, parser state,
size/allocation/index or lifetime relationship, supporting and contradicting
evidence IDs, a falsification condition, and confidence. The model may cite
only IDs present in the packet. `static_hypothesis` remains non-reportable.

#### `BinaryExperimentRequest`

The Hunter may select only an allow-listed request:

- exact replay through an existing ImageIO API route;
- one structured format-field boundary variation;
- one existing API-route differential;
- one bounded incremental chunk schedule;
- Guard Malloc/allocator diagnostics through an attested harness;
- cross-build replay against a separately approved snapshot;
- one additional bounded binary-context request.

Requests contain no shell command, source snippet, executable payload,
environment override, arbitrary path, or network destination. They bind the
hypothesis, retained input digest or context digest, existing harness route,
maximum execution count, expected observation, and falsification condition.
`auto_execute` is always false.

#### `BinaryExperimentPlan`

The deterministic planner maps a request to one of:

- `review_required`: supported by the current networkless VM harness;
- `requires_context`: needs another bounded PR5 context pack;
- `requires_harness`: needs a separately implemented/attested harness feature;
- `requires_snapshot`: needs explicit approval for another OS build;
- `unsupported`: cannot be represented without broadening scope;
- `scope_blocked`: conflicts with `BinaryResearchScope`.

Only `review_required` can later receive a human approval record. PR6 persists
the request and plan but executes zero experiments. Approval and execution are
separate operations and are not implemented in this PR.

### Hunter behavior

1. Validate the complete digest chain and research-scope object locally.
2. Submit the next contiguous PR5 context pack with typed finding metadata.
3. Require schema-valid JSON; retry once only for serialization failure.
4. Validate all evidence references, function IDs, finding IDs, and experiment
   parameters locally.
5. Persist the packet, raw model response, validated assessment, usage, and
   plans under a private content-addressed artifact directory.
6. Stop on budget exhaustion, invalid provenance, scope conflict, or repeated
   schema failure. Do not silently skip to a lower-ranked pack.

The Hunter must separate decompiler statements from inference. A pseudocode
line alone cannot establish attacker control, reachability, or impact. A
positive hypothesis requires a PR3 input/reachability chain and PR4 evidence;
otherwise the result is `needs_context` or `inconclusive`.

### Reuse and change boundary

- Reuse the existing budget controller, durable Hunter queue, model client,
  private artifact containment, and independent experiment-review concepts.
- Add PR6 models and orchestration under `macos/binary_analysis/`; do not put
  binary-specific conditions into the generic C-source Hunter.
- Reuse ImageIO experiment kinds only where the current harness already
  supports them. Unsupported capabilities remain typed deferrals.
- Do not modify M13 F1–F5 fuzzer scheduling, mutation, corpus, crash triage, or
  execution behavior.
- Do not add dyld image extraction or Ghidra/Binary Ninja execution. PR6 still
  consumes the bounded JSON export contract introduced in PR2.

### Focused verification

Tests use synthetic, non-proprietary IR and fake model clients. Required cases:

1. The packet accepts one fully matching PR1–PR5 digest chain.
2. Mutation of every upstream digest is rejected before the model call.
3. Reordered packs, skipped leading packs, oversized context, unknown evidence
   IDs, and unknown finding/function IDs are rejected.
4. The fixed scope object rejects host execution, networking, third-party
   access, automatic execution, and weaponization.
5. A valid static hypothesis cites both input reachability and PR4 evidence.
6. Pseudocode-only reasoning cannot become `static_hypothesis`.
7. An exploit, command, arbitrary path, or network-bearing response fails local
   validation and produces no experiment plan.
8. Every allowed request maps deterministically to the expected plan status.
9. `review_required` still has `auto_execute=false`; all other statuses have an
   execution limit of zero.
10. Budget exhaustion and two invalid responses persist a typed deferral and
    do not advance the ranking cursor.
11. Successful processing advances exactly one contiguous pack and stores
    model usage once.
12. Existing M13 and M14 PR1–PR5 focused tests plus the full regression suite
    remain unchanged and pass.

### Exit criteria

- The Binary Hunter can accept, challenge, reject, or defer a static candidate
  without claiming a confirmed vulnerability.
- Every model-visible byte is bound to the snapshot/IR/ranking/scope chain.
- No model output can directly invoke a tool or execute an experiment.
- Unsupported or prohibited requests fail closed with an inspectable reason.
- A human can review a minimal plan containing the exact observation and
  falsification condition before any later VM execution work begins.
- PR6 introduces no change to fuzzing behavior and no proprietary binary or
  decompiler export is committed to the repository.

### Explicitly deferred to PR7 or later

- Real ImageIO/dyld benchmark artifacts and blind measurement belong to PR7.
- Automatic dyld image extraction and Ghidra/Binary Ninja invocation require a
  separate, reviewable runner milestone; they are not implicitly authorized by
  the PR2 adapter or by this Hunter.
- Dynamic execution, crash confirmation, exploitability assessment, Apple
  submission material, and public disclosure are outside PR6.
