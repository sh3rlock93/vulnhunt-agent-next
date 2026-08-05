# M17 — Decompiler-First Binary Vulnerability Hunting

## Goal

Turn the existing ImageIO Ghidra pipeline into a code-first vulnerability
discovery workflow. The Hunter must reason over decompiled pseudocode,
normalized p-code, control flow, and call relationships, then an independent
Reviewer must decide whether the cited code proves a security-relevant defect.

M17 does not use fuzzing as a discovery or confirmation mechanism. Its primary
output is a reviewable static-code finding with an address-bound proof, not a
crash, generated input, exploit, or CVE claim.

```text
BinarySnapshot
  -> Ghidra export
  -> NormalizedBinaryIR
  -> parser/decoder discovery
  -> code-first root admission
  -> interprocedural evidence capsule
  -> Decompiler Hunter
  -> bounded code-context continuation
  -> independent Code Reviewer
  -> static reportability decision
```

## Why this milestone is required

M14-M16 provide a real binary-analysis foundation, but they do not yet implement
the requested end-to-end behavior:

- the current static pilot stops after normalization, deterministic analysis,
  ranking, and context packing;
- `BinaryHunterAgent` exists, but the real Ghidra pilot does not construct or
  execute its plan;
- the current Hunter contract requires deterministic `static_finding` evidence
  before it may return `static_hypothesis`, so a bug class not modeled by the
  rule engine cannot be discovered from code alone;
- context packs are function-oriented and may omit the caller, callee, guard,
  or return-value use needed to prove an interprocedural defect;
- the current Hunter can request dynamic experiments, but there is no
  independent code-only Reviewer that can promote or reject a hypothesis;
- F7 and the ImageIO fuzzer are separate dynamic systems and are not part of the
  desired discovery path.

The 2026-08-04 current-build audit is the frozen starting point: 1,112 ImageIO
functions were decompiled, 500 parser candidates were discovered, 200 functions
were ranked, and `decodeSGI_RLEcompressed` ranked second. The run emitted 43
static candidates but made zero model calls and confirmed zero vulnerabilities.
M17 must consume that decompiled evidence instead of starting a fuzz campaign.

## Non-goals

- Do not run, mutate, generate, minimize, or replay image inputs.
- Do not start a VM, native harness, fuzzer, crash triager, canary interposer, or
  dynamic experiment.
- Do not use patch diffs, CVE descriptions, vulnerable function names, fixed
  addresses, binary hashes, or vulnerable/patched labels as discovery input.
- Do not reconstruct or claim to possess Apple's original source code.
- Do not treat decompiler pseudocode as exact source when p-code or control-flow
  evidence contradicts it.
- Do not generate exploit code, weaponization steps, or a submission to Apple.
- Do not redesign the C-source Hunter, repository ranking, F1-F7 fuzzer, or M13
  Apple submission policy.
- Do not add another LLM provider. Reuse the configured API-first provider and
  existing Codex-subscription fallback.
- Do not broaden vulnerability classes merely to increase finding counts.

## Required terminology and states

M17 uses distinct states so a model opinion cannot silently become a
vulnerability:

| State | Meaning |
|---|---|
| `admitted_root` | A decoder/parser function selected for code review. |
| `code_hypothesis` | A Hunter claim tied to a feasible address-level code path. |
| `needs_code_context` | The claim cannot be judged without another frozen IR slice. |
| `reviewer_rejected` | The Reviewer found a guard, infeasible path, missing input control, or unsupported impact. |
| `reviewer_inconclusive` | Required evidence is unavailable or decompiler ambiguity is material. |
| `reportable_static` | The code proof passes every M17 static reportability obligation. |

`reportable_static` means suitable for private expert review and preparation of
a minimal confirmation strategy. It does not mean dynamically reproduced,
exploitable, eligible for a CVE, or ready for submission.

## Static proof obligations

A result can become `reportable_static` only when the immutable evidence proves
all of the following:

1. **Frozen target** — snapshot, Mach-O UUID, export, IR, coverage, and prompt
   versions are digest-bound.
2. **Reachable parser route** — the root is linked to an ImageIO input/parser
   entry route by symbols, strings, imports, or a bounded call path.
3. **Attacker-controlled source** — the exact input-derived value or byte region
   is identified, including width, signedness, and conversion uncertainty.
4. **Feasible path** — the cited source, transformations, guards, and sink form a
   CFG- and callgraph-consistent path.
5. **Security relation** — the violated allocation, size, range, lifetime,
   initialization, type, or state invariant is stated precisely.
6. **Guard analysis** — every dominating and path-controlling comparison in the
   capsule is considered; a merely omitted pseudocode line is not evidence of a
   missing guard.
7. **Security sink and impact** — a concrete read, write, allocation, copy,
   object lifetime, disclosure, or control-state consequence is cited.
8. **Contradiction review** — safe paths, clamps, failure returns, caller
   preconditions, and decompiler uncertainty are recorded.
9. **Independent acceptance** — a separate Reviewer session accepts the proof
   without relying on uncited Hunter prose.

Missing any obligation yields `needs_code_context`, `reviewer_rejected`, or
`reviewer_inconclusive`; confidence alone cannot compensate for missing proof.

## Versioned artifacts

M17 introduces the following content-addressed contracts. Names are normative
unless implementation evidence shows an existing type can be safely versioned
instead.

- `DecompilerHuntManifest` — run identity, stage digests, decompiler limits,
  provider/model identity, budgets, and static-only execution counters.
- `CodeHuntRoot` and `CodeHuntAdmission` — selected root, ranking components,
  format family, entry distance, deterministic findings when present, and
  explicit admission/omission reason.
- `BinaryEvidenceCapsule` — root, bounded callers/callees, pseudocode, p-code,
  CFG edges, sources, sinks, guard facts, omissions, and evidence-address map.
- `BinaryCodeContextRequest` — a request for an existing function, caller,
  callee, basic-block neighborhood, or variable-use slice from the frozen IR.
- `DecompilerHunterHypothesis` and `DecompilerHunterAssessment` — code-only
  claim, path, invariant, impact, contradictions, uncertainty, and citations.
- `BinaryCodeReviewerVerdict` — independently validated proof obligations and
  accepted/rejected/inconclusive decision.
- `StaticReportabilityDecision` — deterministic aggregation of evidence and
  Reviewer verdict; the LLM cannot set this state directly.
- `DecompilerHuntResult` — counts, digests, omissions, usage, and terminal run
  status. It fixes image executions, dynamic experiments, and generated inputs
  to zero.

Every artifact must reject upstream digest changes, duplicate or reordered
evidence, unknown function/address references, and non-canonical serialization.
Raw proprietary binaries, full Ghidra databases, and full decompiler exports
remain in the private evidence store and are never committed.

## Sequential PR plan

Implementation proceeds in order. Each PR is merged only after its focused
tests, the binary-analysis regression gate, and the repository-wide suite pass.
If a gate fails, repair that PR before starting the next one.

### M17-1 — Static-only run contract and real pipeline orchestration

#### Objective

Connect the existing snapshot, extraction, Ghidra export, normalization,
discovery, analysis, ranking, and packing stages behind one resumable M17 run
without yet calling a model.

#### Implementation scope

- Add a binary hunt orchestrator under
  `src/vulnhunt_agent/macos/binary_analysis/` and a dedicated
  `tools/macos/run_m17_decompiler_hunt.py` entry point.
- Reuse `run_imageio_ghidra_pilot` stage functions rather than reimplementing
  extraction or Ghidra invocation.
- Add `--plan-only`, private output directory, resume-by-digest, explicit
  decompiler bounds, and machine-readable terminal status.
- Add provider preflight metadata without making a billable call in
  `--plan-only` mode.
- Fix `analysis_mode` to `decompiler_static_only`; persist
  `image_executions=0`, `generated_inputs=0`, `dynamic_experiments=0`, and
  `fuzzer_invocations=0` as validated literals.
- Fail closed on stale snapshots, partial exports, missing coverage manifests,
  unsupported architecture, digest mismatch, or a non-private evidence path.
- Do not import or invoke `imageio_fuzzer`, `imageio_harness`,
  `imageio_vm_bridge`, `imageio_crashes`, or M13 campaign code.

#### Focused validation

- A synthetic Ghidra export completes all static stages with zero model and
  execution counters.
- Two plan-only runs over identical inputs produce the same stage digests.
- Changing one IR byte or coverage setting invalidates resume.
- A missing/partial Ghidra stage cannot create a Hunter-ready manifest.
- The current ImageIO pilot completes and includes the SGI decoder in IR.

#### Exit criteria

The command produces one validated, resumable `DecompilerHuntManifest` and an
immutable static evidence chain. No Hunter call is possible until M17-2 and
M17-3 admission/context artifacts exist.

### M17-2 — Code-first root admission independent of static findings

#### Objective

Admit promising parser code even when the deterministic analyzers emitted no
finding. Static rules become evidence and prioritization signals, not a gate on
what the Hunter is allowed to inspect.

#### Implementation scope

- Build `CodeHuntAdmission` from existing discovery, coverage, ranking, and IR
  artifacts.
- Preserve the original binary ranking as the primary order; add only a narrow
  admission layer for parser reachability, format-family diversity, source/sink
  presence, decompiler completeness, and duplicate root suppression.
- Permit `finding_ids=()` and record that the root is admitted for semantic code
  review rather than a known rule match.
- Reserve bounded slots across distinct format families and entry routes so one
  large decoder family cannot consume the complete run.
- Exclude thunks, import stubs, empty pseudocode, irrecoverably truncated
  functions, and generic allocators with no parser/input evidence.
- Do not add function-name, CVE, SGI, version, address, or hash allowlists.

#### Focused validation

- A vulnerable fixture with zero deterministic findings is still admitted from
  parser reachability and code evidence.
- A generic allocator with no parser route remains excluded.
- Static findings increase priority but are not required.
- Admission order is deterministic and is the exact Hunter execution order.
- Existing M14 ranking tests and the M15 12-case gate remain unchanged.
- On the frozen current ImageIO export, `decodeSGI_RLEcompressed` remains
  auditable as admitted or has a concrete non-budget omission reason.

#### Exit criteria

At least one no-finding code root can reach the next stage, and every admitted
or omitted parser candidate has a deterministic reason.

### M17-3 — Interprocedural evidence graph and code capsules

#### Objective

Give the Hunter enough code to prove or falsify a defect across function
boundaries without sending the entire ImageIO binary or relying on a 24 KiB
single-function excerpt.

#### Implementation scope

- Build a bounded evidence graph over internal calls, CFG edges, dataflow
  definitions/uses, source APIs, memory/state sinks, and recovered guards.
- For each root, include the root plus only relevant callers, callees, and basic
  blocks. Default bounds are call depth 2, at most 8 functions, and at most 96
  KiB for the initial capsule.
- Pair pseudocode with normalized p-code and address mappings. Pseudocode-only
  statements cannot satisfy a proof obligation when no address/IR evidence
  supports them.
- Preserve full source, guard, and sink neighborhoods before lower-value
  context. If one required neighborhood cannot fit, mark the capsule
  `proof_incomplete` instead of silently truncating it.
- Record omitted functions, blocks, variables, unknown operations, and
  decompiler failures explicitly.
- Deduplicate shared callees by digest while preserving each callsite and return
  use.
- Bind every capsule to the snapshot, IR, discovery, analysis, coverage,
  admission, and context-policy digests.

#### Focused validation

- Interprocedural source -> conversion -> guard -> sink fixtures retain all four
  steps and their function/address identities.
- A caller-side guard is included and prevents a false missing-check claim.
- A callee return used as a size/index in the caller remains connected.
- Recursive and mutually recursive graphs terminate at declared bounds.
- Oversized evidence becomes `proof_incomplete`; it is never silently promoted.
- Repeated capsule construction is byte-for-byte deterministic.

#### Exit criteria

Every admitted root has either a proof-capable capsule or an explicit bounded
reason why code analysis cannot safely proceed.

### M17-4 — Decompiler-native Hunter sessions

#### Objective

Make the model inspect decompiled code for novel vulnerability hypotheses rather
than merely restating deterministic static findings.

#### Implementation scope

- Add a new prompt/schema version dedicated to decompiler-first analysis. Do not
  weaken or silently mutate the M14 `binary-imageio-hunter-v2` contract.
- Remove the requirement that a code hypothesis cite a pre-existing
  `static_finding`; require parser reachability plus cited source, path, guard,
  sink, and invariant evidence instead.
- Require structured fields for attacker control, width/signedness, call path,
  CFG path, guard analysis, security relation, impact, contradicting evidence,
  decompiler uncertainty, confidence, and falsification condition.
- Limit dispositions to `code_hypothesis`, `needs_code_context`,
  `not_vulnerable`, `inconclusive`, and `scope_blocked`.
- Replace dynamic experiment requests with `BinaryCodeContextRequest`. The
  Hunter may request only evidence already present in the frozen IR.
- Reuse the configured OpenAI-compatible API client by default and
  `CodexSubscriptionClient` when the existing provider configuration selects
  subscription mode. Do not read Codex credentials directly.
- Preserve durable queue, work ID, prefix order, provider preflight, token
  accounting, retry, and resume behavior.
- Initial campaign profile: at most 16 root sessions, one initial call per root,
  strict aggregate token/wall-clock limits, and no automatic expansion beyond
  the next PR's continuation budget.

#### Focused validation

- A model response can identify a supported code defect without any
  deterministic finding ID.
- An unsupported source, invented address, missing guard analysis, or unknown
  function reference is rejected before persistence.
- `not_vulnerable` requires cited guard/failure-path evidence, not an empty
  assertion.
- Model JSON repair does not reorder work or bypass the budget controller.
- Both API and Codex-subscription fake clients satisfy the same protocol.
- No Hunter output can request image generation, execution, fuzzing, VM access,
  shell commands, URLs, or exploit content.

#### Exit criteria

The real M17 orchestrator can execute admitted code roots and persist
schema-valid, address-bound Hunter assessments with complete usage accounting.

### M17-5 — Bounded code-context continuation

#### Objective

Allow a Hunter to resolve one missing caller, callee, guard, or variable-use
question without starting a new broad scan or losing the original ranking
position.

#### Implementation scope

- Add a deterministic local context broker that resolves only
  `BinaryCodeContextRequest` objects against the already frozen IR.
- Supported requests are: exact function, direct caller, direct callee,
  basic-block neighborhood, definition/use chain, and callsite return-use.
- Reject arbitrary text searches, filesystem paths, decompiler reruns, network
  requests, unknown addresses, and functions outside the frozen image.
- Preserve the same `work_id` and root session across continuations; append a
  hash chain of request, response capsule, and assessment.
- Permit at most two context continuations for at most six roots per run. Total
  evidence supplied to one root is capped at 192 KiB.
- Stop with `reviewer_inconclusive` when the requested proof cannot be recovered
  inside the bounds. Do not skip to a lower-ranked root as a substitute for a
  failed continuation.

#### Focused validation

- A missing caller guard is requested, supplied, and causes the Hunter to
  withdraw a false hypothesis.
- A missing callee sink is supplied and completes a valid code hypothesis.
- Repeated, circular, out-of-image, arbitrary-file, and over-budget requests are
  rejected deterministically.
- Resume continues from the exact context-chain digest without repeating paid
  calls.
- Context continuations do not create additional Hunter sessions; calls and
  tokens are still charged to the originating session.

#### Exit criteria

A bounded multi-function question can be resolved from frozen decompiler output
without invoking Ghidra again or executing an image.

### M17-6 — Independent Code Reviewer and static reportability gate

#### Objective

Prevent the Hunter from grading its own hypothesis and turn only complete code
proofs into private `reportable_static` findings.

#### Implementation scope

- Add a separate Reviewer prompt, schema, queue scope, raw response store, and
  usage ledger. It may use the same configured model but must run in a fresh
  session with no Hunter conversation history.
- Supply the Reviewer with the immutable evidence capsule, structured
  hypothesis, context-chain hashes, and deterministic facts. Do not supply
  uncited free-form Hunter reasoning as evidence.
- Evaluate every static proof obligation independently with
  `proven|disproven|unknown` and cited address-level evidence.
- Require the Reviewer to seek dominating guards, caller preconditions, safe
  failure paths, integer-promotion behavior, alias uncertainty, and decompiler
  contradictions before acceptance.
- Permit one bounded Reviewer context request through the same local broker;
  never permit a dynamic experiment request.
- Compute `StaticReportabilityDecision` deterministically. The Reviewer may
  recommend acceptance, but cannot directly set `reportable_static`.
- Generate a private report containing target UUID/build, affected function and
  address, decompiled excerpt, p-code path, input-control proof, violated
  invariant, guard analysis, impact boundary, contradictions, limitations, and
  all artifact digests.
- Keep `dynamic_reproduction=false`, `exploitability=unknown`, and
  `apple_submission_ready=false` fixed in every M17 report.

#### Focused validation

- A valid vulnerable fixture passes all obligations and becomes
  `reportable_static`.
- A patched fixture with a dominating combined-range guard is rejected.
- An infeasible CFG path, unproven attacker control, ambiguous alias, or
  pseudocode-only sink cannot become reportable.
- Flipping a Reviewer verdict without matching cited proof does not change the
  deterministic reportability decision.
- Hunter and Reviewer usage, prompts, raw responses, and evidence digests remain
  separately auditable.
- Existing M4 reporting and M13 Apple CVE policy tests remain unchanged.

#### Exit criteria

The system can produce a private, code-evidence-complete static finding while
explicitly refusing unsupported dynamic or CVE claims.

### M17-7 — Blind code-only benchmark and real ImageIO decision gate

#### Objective

Prove that the complete M17 path finds a known vulnerability from decompiled
code alone, rejects its guarded counterpart, and does not regress previously
supported binary defects.

#### Blind protocol

1. Freeze every binary/export, coverage policy, prompt, model, budget, and
   expected case inventory by digest.
2. Assign opaque case and build IDs before analysis.
3. Do not expose vulnerability labels, version roles, patch differences, CVE
   text, expected functions, or oracle data to discovery, ranking, Hunter, or
   Reviewer.
4. Run Ghidra, normalization, discovery, admission, capsule construction,
   Hunter, continuation, and Reviewer independently for every case.
5. Seal all observations and usage records before loading the private oracle.
6. Compare vulnerable, patched, and safe-control outcomes only after sealing.
7. Repeat the complete code-only run once with the same configuration to measure
   stability. No image is executed in either run.

#### Required cohorts

- The unchanged M15 12-case gate: six supported positives and six safe controls
  covering integer overflow, offset/length OOB, allocation/copy mismatch, and
  UAF.
- M16 composite-range and partial-initialization positive/negative fixtures.
- At least two code-first positives deliberately invisible to deterministic
  analyzers so M17 is not merely testing rule restatement.
- One lawfully held historical vulnerable ImageIO build, its patched control,
  and the current build. The first target is the M16 SGI case if the required
  private binaries are available.

Historical binaries and exports remain private. If the vulnerable and patched
ImageIO targets are unavailable, M17-1 through M17-6 may be implemented and
merged, but M17 cannot be marked effectiveness-complete.

#### Acceptance thresholds

- M15 deterministic gate remains exactly TP=6, FP=0, FN=0 with its unchanged
  observation digest.
- Every supported positive is admitted; every omission has a non-silent bounded
  reason.
- Both code-first positives produce a code hypothesis in both runs despite
  having no deterministic finding.
- No safe or patched control becomes `reportable_static`.
- The historical vulnerable ImageIO target becomes `reportable_static` from
  code-only evidence; patched and current controls remain negative or
  explicitly inconclusive for evidence quality, never falsely reportable.
- Static stage digests, admission order, evidence capsules, and context-broker
  responses are identical across repeated runs.
- Hunter/Reviewer model variance is reported per case; a positive that appears
  in only one run fails the stability gate.
- The complete benchmark performs zero image executions, generated inputs,
  fuzzer invocations, VM boots, and dynamic experiments.

#### Cost ceiling for the first real run

- At most 16 Hunter root sessions.
- At most six roots receive context continuation, with at most two continuation
  calls each.
- At most six hypotheses enter Reviewer sessions; each gets at most one Reviewer
  context continuation.
- Aggregate maximum: 34 successful model calls, 1,000,000 input tokens, 100,000
  output tokens, and 90 wall-clock minutes. Schema-repair retries must fit the
  same ceilings and never expand them.
- `--plan-only` and all deterministic stages remain zero-call operations.

These are hard ceilings, not targets. A lower-ranked root is not admitted after
the budget prefix is exhausted.

### M17-8 — Bounded third proof-closure continuation

#### Trigger

The first current-ImageIO SGI run recovered the 32-bit row-byte multiplication
and its later 64-bit allocation use, but exhausted the 192 KiB per-root evidence
cap before resolving the already typed destination-pointer request. The frozen
capsule and first two responses consumed 196,294 bytes; the final deterministic
pointer/stride slice requires another 98,040 bytes. This is an evidence-closure
failure, not a ranking or Hunter-session failure.

An initial third-continuation trial remained inconclusive after 195,564 bytes:
the model named allocation variables and destination addresses together in its
rationale, while the v1 broker structurally selected only the single primary
variable. Repeating one-dimensional slices is therefore not an acceptable
recovery mechanism.

#### Implementation scope

- Permit one proof-bearing root per run to receive a third continuation from
  the same frozen IR and hash chain.
- Extend a definition/use request with sorted, bounded
  `supporting_variables` and `supporting_addresses`. The broker must select and
  retain every structured anchor; prose in `rationale` never changes evidence
  selection.
- Raise that root's total evidence ceiling to 288 KiB while retaining the
  existing 96 KiB response ceiling.
- Keep all remaining roots at two continuations and 192 KiB after the single
  third-continuation allowance is consumed.
- Do not add Hunter sessions, decompiler invocations, image executions,
  generated inputs, fuzzing, VM boots, network search, or shell access.
- Preserve the M17-7 aggregate ceiling of 12 Hunter continuation calls, 34
  successful model calls, 1,000,000 input tokens, 100,000 output tokens, and 90
  wall-clock minutes.

#### Exit criteria

The SGI root either reaches a schema-valid code hypothesis supported by the
allocation and destination-pointer chains, or terminates with a more specific
evidence-backed safe/inconclusive result. A third continuation cannot be spent
on a second root in the same run, and a multi-anchor request cannot silently
omit one of its declared variables or addresses.

#### Current-ImageIO observation

The bounded real run against macOS 26.5.2 build 25F84 completed after two
continuations and produced the first schema-valid code hypothesis for the SGI
root. It retained 195,897 evidence bytes, used one Hunter session and four model
calls, and performed zero image executions, fuzzing invocations, VM boots, or
decompiler reruns. The independent Reviewer admitted exactly that hypothesis
but returned `reviewer_inconclusive` after two calls: the frozen single-function
chain did not prove metadata provenance, the exact format dispatch, or the
allocation-to-store alias. Manual inspection of the already frozen IR found a
KTX `initialize` function with an explicit checked-width sequence, so this
hypothesis must not be reported until cross-function field provenance proves or
falsifies the apparent guard. M17-8 therefore validates bounded proof closure;
it does not claim a vulnerability.

### M17-9 — Object-field provenance and PHI-origin closure

#### Trigger

The M17-8 KTX hypothesis depended on decoder-state fields whose writers and
validators live outside `decodeImageImp`. The previous broker could recover a
single function's definition/use chain, but it could neither name object-field
offsets structurally nor retain both incoming definitions of a loop PHI. The
Reviewer therefore could not distinguish an actual allocation/write mismatch
from state validation performed by `prepareGeometry`, `willDecode`, or
`initialize`.

#### Implementation scope

- Add sorted, bounded `supporting_field_offsets` only to
  `definition_use_chain` requests. Natural-language field names still select
  no evidence.
- Select the minimum lifecycle/owner-matched frozen functions that directly
  access every requested object offset; unrelated classes with the same offset
  are excluded.
- Retain exact object-field accesses, enum/range guards, requested variables and
  addresses, and every direct incoming definition of a requested PHI.
- Deduplicate instructions and facts already present in the immutable context
  chain so a broader continuation spends bytes only on new evidence.
- Prioritize exact targets inside large p-code blocks and keep the 96 KiB
  serialized response ceiling. The root preselection allowance rises from 256
  to 320 instructions solely to prevent a selected guard block from being
  dropped before response compaction.
- Return the exact validation error to a Reviewer schema-repair attempt and
  explicitly prohibit mixing caller-edge requests with definition/use-only
  selectors.
- Do not invoke a decompiler, image, fuzzer, VM, generated input, network
  search, or dynamic experiment.

#### Exit criteria

A deterministic replay over the frozen KTX root must return a resolved response
that includes `decodeImageImp`, `prepareGeometry`, `willDecode`, and
`initialize`; retains the loop's initial PHI pointer definition and the
`0x140b` format dispatch; and stays within 96 KiB. Repeating a broader request
must reuse prior chain evidence and fit the model-declared response budget.
Synthetic tests must also prove that a late field guard in a large p-code block
survives compaction and that unrelated owner functions are not selected.

#### Current-ImageIO observation

The deterministic frozen-IR replay resolved at 98,235 bytes and retained both
the initial PHI pointer and the `0x140b` dispatch. The real Codex continuation
then completed in one Hunter session, three model calls, 330,780 input tokens,
8,188 output tokens, and 195,413 total evidence bytes. It requested eight
numeric field offsets and received a 65,015-byte second response containing the
four expected functions. All dynamic counters remained zero.

The Hunter kept the KTX row-byte-wrap claim as a conditional
`code_hypothesis`. The independent Reviewer did not accept it: it requested a
schema-valid direct-caller slice, and the frozen IR contained no matching call
edge. The deterministic gate therefore returned `reviewer_inconclusive`, with
`reportable_static=0` and `apple_submission_ready=false`. The remaining defect
is caller/parser-route recovery and dominance linkage, not field-provenance
selection. This observation is not a vulnerability claim.

### M17-10 — Virtual caller route and CFG-dominance recovery

#### Trigger

The M17-9 Reviewer asked for a direct caller of KTX `decodeImageImp`, but the
normalized IR represents the relevant C++ virtual call as a register-targeted
`CALLIND`. Exact function-name and address resolution therefore returned no
edge even though the frozen IR retained `IIOReadPlugin::callDecodeImage`, its
`0xd8` vtable-slot calculation, the indirect callsite, and the surrounding
CFG. A later Reviewer request also mixed one `willDecode` address into a
`decodeImageImp` definition/use request, so the broker rejected the entire
slice instead of giving the model its existing schema-repair opportunity.

#### Implementation scope

- Recover a caller edge only when the requested target has a class-qualified
  selector declaration, the frozen caller names the same selector, the call is
  explicitly represented as `CALLIND`, and receiver-plus-argument arity
  matches. Do not treat arbitrary indirect calls as resolved targets.
- Mark recovered edges as `virtual_selector`, preserve the selector and total
  compatible implementation count, and forbid the Hunter or Reviewer from
  treating that edge alone as a unique runtime receiver binding.
- Compute strict CFG dominators for the indirect call block and retain at most
  eight address-backed guard blocks. Protect the call instruction and its
  immediately preceding vtable-slot derivation from response compaction.
- Preload one bounded root-caller route response into the independent Reviewer
  packet without consuming the Reviewer's single optional context request.
- Require every address, block, variable, and supporting-address selector on a
  `definition_use_chain` Reviewer request to belong to `function_id`. Return
  the exact ownership error through the existing one-repair model path;
  cross-method state selection remains offset-based.
- Keep all route and provenance evidence bound to the existing snapshot, IR,
  capsule, work, root, and context-chain digests. Do not execute an image,
  decompiler, fuzzer, VM, generated input, shell experiment, or network search.

#### Exit criteria

A deterministic replay over the frozen KTX root must resolve
`callDecodeImage` at callsite `0x18d6f6968`, retain the `0xd8` slot derivation,
label the edge as non-unique virtual dispatch, and include its CFG-derived
dominating guard blocks within 32 KiB. A synthetic negative must reject an
indirect caller that lacks a frozen selector hint, while ordinary direct calls
must retain exact-edge semantics. The independent Reviewer must receive this
route before its optional request, repair a foreign-address definition/use
request, and finish with all dynamic counters at zero.

#### Current-ImageIO observation

The packet-bound route baseline resolved to 32,675 bytes. It retained
`callDecodeImage`, the `0xd8` vtable-slot calculation, the indirect call at
`0x18d6f6968`, five dominating guard blocks, and a visible candidate count of
25 `decodeImageImp` implementations. The Reviewer then repaired its first
cross-function address error and received a 65,157-byte provenance response
covering `willDecode`, `prepareGeometry`, `createImageBlock`,
`extractDecodeOptions`, and `initialize`.

The final independent review used one subscription session, three model calls,
517,326 input tokens, and 8,823 output tokens. It remained
`reviewer_inconclusive`, with `reportable_static=0` and
`apple_submission_ready=false`; every image, fuzzer, VM, generated-input, and
dynamic-experiment counter stayed zero. The caller-recovery defect is closed,
but the virtual edge intentionally does not prove which of 25 compatible
implementations owns the runtime receiver. Exact KTX receiver/vtable binding,
file-byte-to-geometry provenance, and the complete allocation-to-row-base
invariant remain separate proof gaps. This observation is not a vulnerability
claim.

### M17-11 — Address-backed C++ vtable binding

#### Trigger

M17-10 recovered the generic `callDecodeImage` dispatch and its `0xd8` slot,
but only selector names and arity were present in normalized IR. That evidence
left 25 compatible `decodeImageImp` implementations and could not establish
that the selected KTX root occupied the recovered slot. Reducing that set from
names alone would have converted decompiler hints into a false exact edge.

#### Implementation scope

- Extend the Ghidra export with bounded Itanium C++ vtable references for
  selected functions. Accept only aligned data references whose closest
  preceding demangled `Owner::vtable` symbol has the same owner as the target
  method; derive the address point as two pointer entries after the table
  symbol and cap slot offsets at 64 KiB.
- Normalize owner, table symbol/address, address point, slot offset, data
  reference address, and target function into a canonically ordered IR record.
  Include non-empty records in the normalized-IR digest while retaining v1/v2
  compatibility when no records exist.
- Promote an indirect edge to `virtual_vtable` only when the call's immediately
  preceding address-backed pointer-add has one aligned slot constant and
  exactly one same-owner vtable record maps that slot to the requested target.
  Otherwise retain the M17-10 `virtual_selector` candidate set.
- Expose the complete binding metadata to Hunter and Reviewer. Treat it as an
  exact static table-to-method mapping, not proof that attacker input selects
  that receiver type at runtime. Do not change reportability rules or execute
  an image, fuzzer, VM, generated input, or dynamic experiment.

#### Exit criteria

Synthetic tests must bind a KTX method only when both the owner and `0xd8`
slot match, retain selector-only semantics on a mismatched slot, preserve old
v1/v2 IR digests, and reject malformed or unaligned table references. A real
ImageIO v3 export must deterministically recover the KTX table symbol, address
point, slot reference, target address, generic callsite, and dominating guards
within the existing 32 KiB route budget. Existing direct and selector-only
edge behavior and all prior binary regression gates must remain unchanged.

#### Current-ImageIO observation

The real v3 export contained 1,200 functions and 260 bounded virtual-method
records. For KTX it recovered `KTXReadPlugin::vtable` at `0x1ee968fd0`, the
Itanium address point at `0x1ee968fe0`, and the `decodeImageImp` data reference
at `0x1ee9690b8`; the resulting slot offset is exactly `0xd8`. The frozen route
then resolved twice to the same digest in 32,160 bytes, promoted callsite
`0x18d6f6968` from 25 selector candidates to one `virtual_vtable` target, and
retained five CFG-dominating guard blocks. All image, input-generation,
dynamic-experiment, fuzzer, and VM counters remained zero.

The first KTX Hunter attempt remained schema-invalid after its repair call and
produced no accepted evidence; the required retry completed in one model call
and requested a
definition/use chain for `sVar23`, allocation/IOSurface capacity, and
`getBytesAtOffset`. That 32 KiB slice could not fit the existing evidence
budget, so the broker returned `evidence_budget_exceeded` and no code
hypothesis or Reviewer reportability decision was produced. M17-11 therefore
closes only the exact static vtable-binding gap. Budgeted definition/use
compaction and attacker-controlled file-byte-to-size provenance remain the
next separate gaps. This observation is not a vulnerability claim.

### M17-12 — Budgeted definition/use proof compaction

#### Trigger

The M17-11 KTX Hunter named four exact SSA values, five code addresses, and
five decoder-state offsets in one valid 32 KiB request, but the broker rejected
the response before the Hunter could continue. A diagnostic replay still lost
one direct PHI origin at 96 KiB. Ghidra had emitted one semantic operation and
up to fourteen `INDIRECT`/`UNKNOWN` side-effect records at the same machine
address; the slicer ranked every co-addressed record equally and the budget
gate protected every downstream use and every field-guard pair.

#### Implementation scope

- Rank semantic instructions ahead of `UNKNOWN` side effects at requested and
  definition/use anchor addresses, while retaining canonical address/index
  order in the emitted slice.
- Protect a minimal deterministic SSA proof core: requested definitions, one
  security-relevant direct use per requested value, all direct PHI origins,
  the best semantic instruction at every explicit address, one address-backed
  field-pointer operation per requested offset, and one representative field
  comparison. Lower-priority uses and duplicate branch-side effects remain
  eligible for budget trimming.
- Account for every omission marker before the final byte-budget decision so a
  resolved response can never exceed its declared maximum after serialization.
- Preserve the existing request schema, evidence identities, field-provenance
  selection, reportability rules, and all static-only execution constraints.
  Do not add vulnerability classes, target allowlists, dynamic experiments, or
  ImageIO-specific matching.

#### Exit criteria

A synthetic function with more than 64 same-address decompiler side effects
and repeated downstream uses must resolve deterministically within 16 KiB,
retain the semantic input call and both PHI origins, and omit most noise. The
unchanged real KTX request must resolve within 32 KiB with all four requested
values having a definition and use, every PHI origin present, all five exact
addresses and all five object offsets retained, and a stable response digest.
All prior M17 and M15 regression gates must remain unchanged.

#### Current-ImageIO observation

The unchanged first KTX request now resolves to 31,943 bytes with 35 new facts:
11 `decodeImageImp` instructions and 24 `willDecode` instructions. It retains
all requested definitions/uses, four direct PHI inputs, five exact addresses,
and five field offsets. A second 32 KiB continuation resolves to 32,510 bytes
and the Hunter terminates with one conditional `allocation_size_mismatch`
hypothesis: an IOSurface-derived 64-bit read length can be paired with a
decoder-field-sized `calloc` destination before `getBytesAtOffset`.

The independent Reviewer used one additional 32,362-byte frozen-IR slice and
proved the frozen target, exact KTX vtable route, and feasible conditional path,
but remained `reviewer_inconclusive` at confidence 0.84. Attacker control of
the relevant geometry/state fields, a satisfiable requested-length versus
effective-capacity inequality, and `getBytesAtOffset` write/capacity semantics
remain unproven. The run used no image execution, generated input, dynamic
experiment, fuzzer invocation, or VM boot. M17-12 therefore closes the context
budget miss and recovers a reviewable code hypothesis; it does not establish a
reportable vulnerability.

### M17-13 — Address-backed range-reader boundary closure

#### Trigger

The M17-12 Reviewer could not determine whether the KTX
`getBytesAtOffset` call writes the requested length, truncates it to destination
capacity, or rejects the destination. The 1,200-function export contained three
same-named `getBytesAtOffset` implementations plus one
`_CGImageReadSessionGetBytesAtOffset`, but all four fell outside the evidence
cap. Name-only call resolution intentionally refused to choose among the three
duplicates.

#### Implementation scope

- Promote only the known ImageIO range-reader boundary identities to mandatory
  export evidence, displacing lower-priority fallback functions without raising
  the 1,200-function cap.
- Add a canonical `callee_address:<hex>` tag to direct Ghidra `CALL` operations.
  Do not assign one to `CALLIND` or infer an address from a duplicated name.
- Resolve direct call edges by that frozen address before the legacy unique-name
  fallback in both evidence-capsule and context-broker graph construction. An
  unknown or conflicting address tag remains unresolved.
- When a definition/use slice explicitly retains a direct callsite, expose its
  exact frozen edge in the same response so the next typed request can name the
  related callee without guessing.
- Also expose bounded direct edges whose callsites are retained inside a newly
  supplied callee slice, allowing a forwarding wrapper to be followed on the
  next existing continuation without broad callgraph expansion.
- Tell Hunter and Reviewer to request the exact direct callee when a
  range-reader's write or clamp behavior is a proof obligation; API names alone
  are not evidence of semantics.
- Preserve prior v1/v2/v3 normalized-IR compatibility, context budgets, static
  reportability thresholds, and every no-execution/no-fuzzing constraint.

#### Exit criteria

Synthetic duplicate-name readers must resolve only with one exact address tag,
while old untagged ambiguous IR remains unavailable. A real capped ImageIO
export must contain all four range-reader implementations as mandatory evidence
and bind the KTX callsite at `0x18d6b6c84` to exactly `0x18d65ec14` in both graph
builders. Focused, binary-regression, full-suite, type, lint, and unchanged M15
blind gates must pass.

#### Current-ImageIO observation

The real 1,200-function export includes all four range-reader functions with
`range_reader_boundary` as their mandatory reason. KTX `initialize` at
`0x18d6b62dc` binds to `0x18d6671f0`; KTX `decodeImageImp` at `0x18d6b6c84`
binds to `0x18d65ec14`. The latter wrapper in turn binds directly to the
`IIOImageRead::getBytesAtOffset` implementation at `0x18d76fa28`, whose frozen
pseudocode validates a non-null destination and positive request, clamps only
against available source bytes, and dispatches to provider/file/CFData copy
helpers. This closes exact callee availability and identity; destination
capacity, attacker-controlled field provenance, and a satisfiable allocation
inequality still require independent proof before reportability. No image,
generated input, fuzzer, VM, or dynamic experiment was invoked.

The completed KTX replay used one Hunter session, five model calls, 513,975
input tokens, 10,045 output tokens, three context responses, and 165,434 total
evidence bytes. The first definition/use response exposed the exact session
wrapper edge, the second exposed the wrapper's exact reader edge, and the third
opened `IIOImageRead::getBytesAtOffset`. The Hunter correctly remained
`needs_code_context`: 17 blocks containing the decisive provider/file/CFData
copy and failure behavior were outside that final 32 KiB slice. This is a
bounded proof-depth limit, not evidence that a destination guard is absent, and
M17-13 does not produce a reportable finding.

### M17-14 — Single-root final-reader proof closure

#### Trigger

The exact M17-13 KTX chain consumed three continuations to reach
`IIOImageRead::getBytesAtOffset`. Its terminal assessment requested one final
definition/use slice for the requested byte count and the omitted provider copy
blocks. The request is address-bound and uses evidence already present in the
frozen IR, but the three-continuation cardinality prevented the broker from
answering it.

#### Implementation scope

- Allow an explicitly configured root to receive a fourth same-session context
  continuation while retaining the default of three.
- Keep the existing 288 KiB total evidence ceiling and 96 KiB per-response
  ceiling; do not increase packet, token, session, or root budgets.
- Permit only one root per CLI run to cross the two-continuation baseline. Once
  an admitted root consumes a third or fourth continuation, all remaining roots
  are capped at two continuations and 192 KiB.
- Extend only the persisted chain cardinalities and ordinals needed to represent
  the fourth response. Preserve all request types, evidence validation,
  reportability thresholds, and static-only constraints.
- Do not add ImageIO names, addresses, vulnerability patterns, generated inputs,
  dynamic experiments, or model instructions that assume a vulnerability.

#### Exit criteria

A synthetic four-step proof must remain in one Hunter session, append exactly
four digest-linked entries, make four continuation calls, and terminate with a
schema-valid hypothesis. At the M17-14 revision, a fifth continuation must be
rejected by policy. The
existing three-step proof and all prior M17/M15 regression gates must remain
unchanged. The real KTX run must answer the final reader request without image
execution, fuzzing, a VM, or another decompiler invocation; its terminal result
is accepted whether vulnerable, safe, or inconclusive only when that conclusion
is supported by the newly supplied frozen evidence.

#### Current-ImageIO observation

The unchanged frozen KTX root completed four same-session responses with one
Hunter session, six total model calls, 643,418 input tokens, 11,403 output
tokens, and 198,025 evidence bytes. The fourth definition/use response confirmed
that the wrapper forwards the destination, offset, and 64-bit requested length
unchanged and recovered the visible underlying-reader range predicates. It did
not expose a write to the destination: the same 17 decisive successor blocks
remained omitted because the request inherited the prior 32 KiB bound.

The terminal assessment therefore remained `needs_code_context` and requested
the same address-bound chain with a 96 KiB response. This is not a Hunter
reasoning miss and is not evidence of a vulnerability or a safe path. M17-14
proves that a fourth bounded continuation works and localizes the remaining gap
to one enlarged final-reader response. The run invoked no image, fuzzer, VM,
dynamic experiment, or decompiler.

### M17-15 — Continuation-aware omitted-block frontier

#### Trigger

Replaying the M17-14 terminal 96 KiB request directly through the deterministic
broker produced only 12,934 bytes and omitted the same 17 blocks as the prior
32 KiB response. The larger byte allowance was ineffective because block
ranking selected the same semantic prefix before deduplication. The remaining
failure was therefore a stagnant context frontier, not a token or session
shortage.

#### Implementation scope

- Permit an explicitly configured root to receive one fifth same-session
  continuation while retaining the default of three and the single extended
  root lease.
- Recognize a refinement only when a later `definition_use_chain` or
  `exact_function` targets the same function. A repeated typed request must
  increase its byte bound and preserve all prior variables and supporting
  addresses; a larger exact request may continue that typed frontier, and a
  typed request may follow a broader same-function slice at an equal or larger
  bound.
- For that refinement only, prioritize previously omitted blocks within each
  semantic priority tier and allow up to the existing schema maxima of 32
  blocks and 512 instructions. Deduplication still removes already supplied
  instructions afterward.
- Keep the total evidence ceiling at 288 KiB, the response ceiling at 96 KiB,
  and every frozen-IR identity, citation, reportability, and no-execution rule.
- Canonically sort only set-like model arrays before validation. For a
  `definition_use_chain` only, discard an unknown optional `block_id` hint and
  retain strict validation of its function, variables, addresses, and evidence;
  block-addressed request kinds still reject unknown blocks.
- Do not use rationale text, function names, ImageIO addresses, parser formats,
  or expected vulnerability classes to activate refinement.

#### Exit criteria

A synthetic wide reader must omit a late write in its first 32 KiB response and
recover it in a strictly larger typed refinement without changing the frozen
IR. Non-refinement requests and the existing three- and four-continuation tests
must remain unchanged, while a sixth continuation is rejected. On the real KTX
chain, the offline final-reader refinement must move beyond the prior 17-block
frontier and expose concrete write-capable calls or fail explicitly without
repeating the same slice. Full, type, lint, M14/M16/M17, and unchanged M15 blind
gates must pass before the actual fifth Hunter judgment is accepted.

#### Current-ImageIO observation

The continuation-aware replay expanded the fifth response from the stagnant
12,934-byte prefix to 55,050 bytes and reduced the omitted reader blocks from
17 to 5. It exposed three feasible transfer-dispatch calls at `0x18d76fb6c`,
`0x18d76fb94`, and `0x18d76fc04`, together with their destination, offset, and
length arguments. The five-entry chain used one Hunter session, six total
model calls, 701,316 input tokens, 12,840 output tokens, and 253,075 evidence
bytes. Every image, generated-input, dynamic-experiment, fuzzer, VM, and new
decompiler counter remained zero.

The terminal judgment correctly remains `needs_code_context`. The dispatched
length is a PHI that can select either the original requested length or a value
defined in one of the five remaining blocks. The visible diagnostic calls do
not terminate their CFG paths, and no destination-capacity invariant has yet
been proved. M17-15 therefore closes the stagnant-frontier defect and reaches
the concrete write boundary, but it does not claim a vulnerability. The next
milestone must recover the final PHI definition and then follow only the exact
write helper required to decide the inequality.

### M17-16 — One-shot final PHI proof closure

#### Trigger

The M17-15 terminal request identifies one exact reader function, one length
PHI, five variables, and eight addresses. Resolving it offline against the same
frozen IR and five immutable chain entries produces a deterministic 41,426-byte
response. That response recovers the PHI at `0x18d76fb44` and fits under the
existing 288 KiB total evidence ceiling by 411 bytes. The broker can answer the
question without changing ranking, token limits, or evidence budgets, but the
five-entry schema prevents the Hunter from judging it.

#### Implementation scope

- Permit one explicitly configured root to receive a sixth same-session
  continuation. Retain the default of three and the existing single extended
  root lease; all remaining roots still fall back to two continuations and 192
  KiB.
- Extend only continuation packet, chain-entry, run-result, and policy
  cardinalities from five to six. Reject a seventh continuation.
- Keep the per-response ceiling at 96 KiB and total evidence ceiling at 288
  KiB. Do not change frontier selection, ranking, prompt content, model retry
  count, evidence validation, or reportability thresholds.
- Reuse the existing frozen IR and immutable five-entry chain. Do not invoke an
  image, generated input, dynamic experiment, fuzzer, VM, or decompiler.

#### Exit criteria

A synthetic root must complete a six-response proof in one Hunter session with
six digest-linked entries and seven total model calls including the initial
assessment. A seventh continuation must fail schema validation, while existing
three-, four-, and five-response behavior remains unchanged. The real sixth
response must retain the deterministic
`sha256:6332affc62f8c54982a424813026d678515b871f2667b6a08ff741ebf32fd0c3`
digest, total no more than 288 KiB, and present the final length PHI to one
Hunter judgment. Full, type, lint, M14/M16/M17, and unchanged M15 blind gates
must pass before that judgment is accepted.

#### Current-ImageIO observation

The sixth response retained the expected
`sha256:6332affc62f8c54982a424813026d678515b871f2667b6a08ff741ebf32fd0c3`
digest and 41,426-byte size. The complete chain used one Hunter session, seven
model calls, 902,477 input tokens, 16,362 output tokens, and 294,501 evidence
bytes, leaving 411 bytes below the unchanged 288 KiB ceiling. It recovered
`lVar3-param_2`, the two PHI inputs, their selection, and the positive-length
dispatch guard. No image, generated input, dynamic experiment, fuzzer, VM, or
decompiler was invoked.

The Hunter correctly remained `needs_code_context` and made no vulnerability
claim. All three destination-transfer call instructions carry exact
`callee_address` tags, but their target functions were omitted from the frozen
1,200-function census by the evidence-neighborhood cap. The failure has moved
from proof depth to export coverage: adding further continuations against this
IR cannot expose bodies that are absent. The next milestone must preserve a
small direct-callee closure for mandatory range-reader boundaries and rerun the
static export before any additional Hunter judgment.

### M17-17 — Mandatory boundary direct-callee closure

#### Trigger

The M17-16 Hunter resolved the range reader's length PHI but could not inspect
the three destination-transfer helpers. Their calls at `0x18d76fb6c`,
`0x18d76fb94`, and `0x18d76fc04` already contain exact `callee_address` tags.
The export census also records the target functions and their caller relation,
but marks all three `evidence_neighborhood_or_fallback_cap_reached`. They are
absent from normalized IR, so neither another context request nor a larger
session allowance can recover their bodies.

#### Implementation scope

- After selecting mandatory range-reader boundaries, promote an internal direct
  callee only when the census proves the boundary is its sole caller. Mark it
  mandatory with an address-backed
  `range_reader_exclusive_callee:seed=<entry>` reason. This excludes shared
  logging and lifecycle hubs whose reverse edges would expand unrelated root
  capsules. Do not match a helper name, parser format, expected sink,
  vulnerability class, or the three observed addresses.
- Perform the closure before the mandatory evidence-cap check. Keep the closure
  bounded by the existing per-function census edge limit and fail explicitly
  if mandatory evidence exceeds the configured maximum.
- Preserve deterministic entry-address ordering, the total 1,200-function
  export cap, 4,000 operations per function, coverage depth two, and all
  normalized-IR identity rules. Mandatory callees displace only lower-priority
  neighborhood or fallback functions.
- Do not alter Hunter ranking, context budgets, continuation counts, prompts,
  reportability, or dynamic execution behavior.

#### Exit criteria

An automated exporter contract test must prove the exclusive direct-callee
closure is applied before the evidence-cap check, excludes shared targets,
marks accepted targets mandatory, and restores deterministic frontier ordering.
All existing adapter, M14/M16/M17, full, type, lint, and unchanged M15 gates
must pass. A new static-only ImageIO export using the frozen M17 settings must
retain 1,200 functions and include all three address-tagged transfer targets
with the new reason. The normalized context
graph must bind each of the three reader callsites to one exact helper function
and expose its bounded body. Only after those checks pass may one admission-rank
one KTX Hunter root run; image execution, generated input, fuzzing, VM boot, and
dynamic experiments remain prohibited.

#### Current-ImageIO observation

The first closure replay promoted every range-reader callee, including the
shared `ImageIOLog` and `debugSendingMessageDone` hubs with 128 bounded callers
each. Their reverse edges expanded several root capsules beyond 96 KiB before
any model call. The implementation was corrected to require exactly one caller.
The accepted export retained 1,200 functions, excluded those shared hubs, and
promoted five exclusive callees: two destination checks and the three transfer
helpers. Each transfer call now binds to one exact frozen function ID, and all
24 admitted capsules materialize within budget; the rank-one KTX capsule is
89,732 bytes.

Two independent rank-one Hunter attempts then produced the same substantive
allocation-size-mismatch analysis, but neither response passed the request
schema after its one repair call. The model selected `direct_callee` without a
packet-supplied related function ID and also attached proof anchors that are
legal only for `definition_use_chain`. Four model calls used 305,765 input and
6,895 output tokens in total; no assessment was accepted and no vulnerability
is claimed. Image execution, generated input, dynamic experiment, fuzzer, and
VM counts remained zero. The remaining defect is the initial Hunter request
contract: when the omitted callee has no packet edge, it must select a
caller-side definition/use slice and receive the concrete validation error on
its bounded repair turn.

### M17-18 — Bounded Hunter validation feedback

#### Trigger

Both M17-17 rank-one Hunter attempts described the same allocation-size
mismatch and requested useful frozen code, but repeated an invalid
`direct_callee` shape on the one permitted repair turn. The validator correctly
rejected supporting proof anchors on that request kind; the repair prompt hid
that exact reason and supplied only generic schema instructions.

#### Implementation scope

- Preserve the existing strict assessment and context-request validators. Do
  not coerce, delete, or reinterpret invalid fields.
- Capture only the most recent model-response validation error, truncate it to
  1,000 characters, and include it in the existing single schema-repair prompt.
  A response without a JSON object receives an equally explicit bounded error.
- Clarify that `direct_callee` cannot carry supporting proof anchors. When no
  exact related call-edge ID exists, the Hunter must not invent one and should
  request a caller-side `definition_use_chain` for the relevant variable.
- Bump the Hunter prompt identity to v3. Do not add model calls, retries,
  sessions, evidence, output tokens, dynamic activity, or reportability paths.

#### Exit criteria

An automated model-contract test must replay the observed invalid
`direct_callee` request, prove that the repair turn contains the precise
validator reason, and accept a corrected request without relaxing validation.
The existing wrong-identity repair test must also prove that validation feedback
is present while call and usage accounting remains two. Focused tests must pass
twice, followed by all M14/M16/M17, full, type, lint, and unchanged M15 blind
gates. Only then may the rank-one KTX Hunter be rerun against the exact frozen
M17-17 export; no new decompilation, image execution, generated input, fuzzing,
VM boot, or dynamic experiment is permitted.

#### Current-ImageIO observation

The first rank-one replay produced a valid caller-side
`definition_use_chain` shape but cited one unknown IR variable. Its conservative
250k input-token reservation stopped before repair after one call and 75,954
input tokens. A fresh replay with a 500k reservation completed on its first call
with a schema-valid request, 75,960 input tokens, 1,391 output tokens, and no
repair. The broker resolved 32,328 bytes from the same frozen IR. The first
continuation recovered the exact forwarding-wrapper call edge, and the second
showed that the wrapper passes destination, offset, and requested length to one
internal reader while the root ignores the wrapper's return value.

The third continuation response then remained invalid after its repair because
it attached definition/use proof anchors to a `direct_callee` request. The
continuation agent records the precise validation error for its terminal
exception but, unlike M17-18's initial Hunter, does not include that error in
its repair prompt. No vulnerability is claimed. All ImageIO execution,
generated-input, dynamic-experiment, fuzzer, VM, and new-decompiler counts
remained zero. The next change must apply the same bounded validation feedback
to continuation repair without changing schemas, retry counts, context budgets,
or reportability.

### M17-19 — Bounded continuation validation feedback

#### Trigger

M17-18 made the initial Hunter request schema-valid and advanced the real KTX
root through two resolved continuation entries. The third continuation attached
definition/use-only proof anchors to a `direct_callee` request on both permitted
attempts. `DecompilerContinuationAgent` already retained the exact validator
message for its terminal exception but did not expose it to the repair turn.

#### Implementation scope

- Add the most recent, already bounded 1,000-character continuation validation
  error to the existing single repair prompt. Use the existing explicit
  no-JSON error when parsing fails.
- Bump the continuation prompt identity to v8 so persisted packet and chain
  evidence reflects the behavior change.
- Preserve request schemas, canonicalization, strict validation, two attempts
  per continuation, six-continuation ceiling, 288 KiB evidence limit, root
  ordering, reportability, and all static-only prohibitions.

#### Exit criteria

A model-contract test must replay a `direct_callee` request carrying a
supporting address, confirm that the repair prompt contains the exact validator
reason, and accept a corrected second response in the same root with two model
calls. Focused tests must pass twice, followed by M14/M16/M17, full, type, lint,
and unchanged M15 blind gates. The interrupted real KTX chain must then be
replayed from the same M17-18 initial assessment and frozen M17-17 IR. No new
decompilation, target execution, generated input, fuzzing, VM, or dynamic
experiment is allowed.

#### Current-ImageIO observation

The interrupted KTX chain resumed from its two persisted entries without
repeating either paid call. M17-19 accepted the third continuation in one call,
and the fourth continuation used its one repair turn successfully before
persisting a valid request. The chain reached all six entries with one root
session, seven total model calls, 860,836 input tokens, 14,297 output tokens,
and 219,742 evidence bytes. It recovered the exact forwarding wrapper, the
underlying reader, destination checks, source-range comparisons, the effective
length selection, and the positive-transfer successor.

The terminal status remained `reviewer_inconclusive`: the fifth response named
the required positive-transfer block but omitted 17 non-selected blocks, and
the model mentioned that block only in rationale rather than setting
`block_id`. The sixth same-variable request therefore selected no new facts and
returned `proof_unavailable` without another model call. No vulnerability is
claimed. Dynamic and new-decompiler counters remained zero. The next change
must preserve newly supplied block IDs through continuation canonicalization and
make exact block targeting explicit, without increasing continuation or
evidence budgets.

### M17-20 — Prior-response block targeting

#### Trigger

The M17-19 Hunter named `bb_acec6d125b307cf0` as the positive-transfer
successor required to close the proof, but encoded it only in request rationale.
The broker therefore repeated a same-variable slice, deduplicated all selected
facts, and returned `proof_unavailable`. Continuation validation accepts blocks
supplied by earlier responses, while pre-validation canonicalization currently
recognizes only blocks from the base capsule and would erase a correct newly
supplied `block_id` hint.

#### Implementation scope

- Build the canonicalizer's known-block set from the immutable union of base
  packet blocks and every block in this continuation packet's prior frozen
  responses.
- Continue dropping an optional definition/use `block_id` only when it is
  outside that union. Do not weaken final continuation validation.
- Instruct the continuation model to encode an exact newly supplied block in
  `block_id`; prose rationale alone does not select evidence.
- Bump continuation prompt identity to v9. Do not change resolver selection,
  deduplication, request schemas, continuation count, evidence bytes, model-call
  limits, reportability, or static-only restrictions.

#### Exit criteria

One contract test must prove that a definition/use request retains a block ID
introduced by a prior response, while the existing unknown-block test continues
to prove that an invented ID is removed. Focused tests must pass twice, followed
by M14/M16/M17, full, type, lint, and unchanged M15 blind gates. Then replay a
fresh rank-one KTX session over the exact M17-17 frozen IR so the model can emit
the corrected block-targeted request before the six-entry limit. No new
decompilation or dynamic activity is permitted.

#### Current-ImageIO observation

The fresh v9 chain proved the new behavior at entry three: a block ID supplied
by the prior reader response survived canonicalization on a definition/use
request and selected a valid next slice. The six-entry run used one root
session, six total model calls, 710,378 input tokens, 12,477 output tokens, and
219,742 evidence bytes. No schema failure, budget deferral, new decompilation,
or dynamic activity occurred.

The terminal state was still `reviewer_inconclusive`. At entry five the model
explicitly identified `bb_9a1a0c81fcf253f9` in both its summary and request
rationale, stated that the prior request had left `block_id` null, and then
again emitted `block_id: null`. The sixth repeated variable-only slice returned
`proof_unavailable` without a model call. No vulnerability is claimed. The next
change must reject this internally inconsistent request shape and let the
existing bounded repair set the already supplied block ID; it must not infer or
insert the block automatically.

### M17-21 — Block-reference consistency repair

#### Trigger

M17-20 preserved a previously included block ID, but the proof-closing KTX
successor was present in a prior response's `omitted_block_ids`, not its included
block bodies. The model named that exact frozen ID in request rationale while
leaving `block_id` null. Canonicalization and validation therefore could not
accept the target even if a repair supplied it, and the broker repeated a
variable-only slice.

#### Implementation scope

- Treat both included and explicitly omitted block IDs from prior immutable
  responses as known continuation block identifiers. They authorize only a
  bounded request back into the same frozen IR; they do not count as proof.
- When a definition/use rationale references a known `bb_...` identifier but
  `block_id` is null, reject the response with one precise validation error so
  the existing M17-19 repair can correct the shape.
- Never infer, insert, or silently rewrite the block target. Invented IDs remain
  rejected or removed under the existing rules.
- Bump continuation prompt identity to v10. Preserve resolver behavior,
  schemas, calls, continuations, evidence budget, and reportability.

#### Exit criteria

Contract tests must prove that a prior omitted-block ID survives
canonicalization, that a rationale/block-field mismatch reaches the bounded
repair and is corrected, and that invented IDs remain excluded. Focused tests
must pass twice, followed by M14/M16/M17, full, type, lint, and unchanged M15
blind gates. Then run a fresh KTX v10 chain over the same frozen IR and require
the positive-transfer block to produce new address-backed facts before any
Hunter conclusion. Dynamic and new-decompiler activity remain prohibited.

#### Current-ImageIO observation

The fresh v10 chain emitted explicit frozen block IDs on every definition/use
request after the underlying reader was reached, proving both prior omitted-ID
admission and rationale/block repair behavior. The run used one root session,
six total model calls, 718,409 input tokens, 12,073 output tokens, and 219,905
evidence bytes. No schema error, budget deferral, new decompilation, or dynamic
activity occurred.

The terminal state remained `reviewer_inconclusive`. Entry five correctly
recovered the selected effective-length PHI and positive-length check in
`bb_b658b14a72a80a5e`, whose exact CFG successors are
`bb_8cf6af2391c86276` and `bb_acec6d125b307cf0`. Both successors remained in
the frozen omitted-block list. The final request asked for the post-check write
but targeted the already supplied predecessor block; deduplication therefore
returned `proof_unavailable` without another model call. No vulnerability is
claimed. The next change must make a block-targeted definition/use slice include
the target's immediate frozen CFG successors under the existing bounds.

### M17-22 — Block-targeted CFG successor frontier

#### Trigger

M17-21 made the final request structurally correct, but it targeted the block
containing the effective-length PHI and positive check. The actual transfer and
failure paths begin in that block's two exact frozen CFG successors. Because
definition/use selection prioritizes the target and variable uses without an
explicit successor frontier, both successors remained omitted and the final
deduplicated request produced no new facts.

#### Implementation scope

- For a definition/use request with `block_id`, add the target block and its
  immediate same-function CFG successors to both the selection focus and
  highest-priority request anchors.
- Use only successor IDs already present in the frozen normalized IR. Do not
  recurse beyond one edge, cross functions, infer semantic branch meaning, or
  bypass existing block/instruction/byte limits.
- Leave basic-block-neighborhood and all non-definition/use request behavior
  unchanged. Preserve deduplication, continuation count, evidence budget,
  prompts, schemas, reportability, and static-only restrictions.

#### Exit criteria

A deterministic contract fixture with non-adjacent successor blocks must prove
that a three-block response contains the exact target and both immediate CFG
successors rather than source-order filler blocks. Focused tests must pass twice,
followed by M14/M16/M17, full, type, lint, and unchanged M15 blind gates. Then
run a fresh KTX chain over the exact frozen IR and require the final successor
slice to expose new address-backed transfer or safe-failure evidence. No new
decompilation or dynamic activity is permitted.

#### Current observation

Implemented and validated on the frozen KTX rank-1 evidence. The focused suite
passed twice (37 tests per pass), the M14/M16/M17 set passed (253 tests), the
repository suite passed (799 passed, 8 skipped), Ruff and mypy passed, and the
unchanged M15 blind gate passed twice with TP=6, FP=0, FN=0 and digest
`sha256:84e4a0cdbbf6b44c689a259c579ef57f475e8064bcad549b3b68adec783795a4`.

The fresh subscription-backed static chain consumed seven model calls (the
frozen initial assessment plus six continuations), 880,168 input tokens, 17,108
output tokens, and 226,476 evidence bytes. The new frontier exposed the
64-bit selected-length PHI and then proved that the requested
`bb_acec6d125b307cf0` successor path contains no destination write and returns
zero. The terminal status remained `reviewer_inconclusive`, without claiming a
vulnerability, because the remaining possible write path
`bb_8cf6af2391c86276` is a sibling branch from an earlier predecessor rather
than a successor of the final requested block. It remained in the exact frozen
omission list. The next bounded change must include the target block's
same-function predecessor siblings without recursive CFG expansion.

### M17-23 — Block-targeted CFG branch-sibling frontier

#### Trigger

M17-22 followed the final target into its immediate successor and proved that
path returns zero without writing. The only unresolved possible transfer block,
`bb_8cf6af2391c86276`, is not downstream of that target: it is another successor
of the target's immediate predecessor. It therefore stayed omitted even though
the model named it exactly from frozen evidence.

#### Implementation scope

- For a definition/use request with `block_id`, retain the M17-22 target and
  immediate-successor frontier and add the other same-function successors of
  each immediate predecessor of the target.
- Select only IDs already present in the frozen normalized IR. Traverse one
  reverse edge solely to enumerate that predecessor's direct successors; do not
  include recursive ancestors, descendants, cross-function blocks, or inferred
  branch semantics.
- Keep all existing block, instruction, byte, continuation, token, and evidence
  budgets unchanged. Do not alter prompts, schemas, reportability, Reviewer
  thresholds, decompilation, VM, fuzzer, or dynamic behavior.

#### Exit criteria

A deterministic non-adjacent CFG fixture must prove that a three-block response
contains the exact target, its direct successor, and the other successor of its
immediate predecessor. The M17-22 successor contract must remain green. Run the
focused suite twice, M14/M16/M17, full, Ruff, mypy, and the unchanged M15 blind
gate twice. Finally, rerun the frozen KTX rank-1 chain and require new
address-backed evidence from `bb_8cf6af2391c86276`; classify only what that
evidence proves.

#### Current observation

Implemented and validated. The focused suite passed twice (38 tests per pass),
the M14/M16/M17 set passed (254 tests), the repository suite passed (800
passed, 8 skipped), Ruff and the project-standard 197-file mypy gate passed,
and the unchanged M15 gate passed twice with TP=6, FP=0, FN=0 and digest
`sha256:84e4a0cdbbf6b44c689a259c579ef57f475e8064bcad549b3b68adec783795a4`.

The fresh subscription-backed frozen KTX chain completed in seven model calls,
877,659 input tokens, 14,770 output tokens, and 257,621 evidence bytes. The
branch-sibling frontier exposed `bb_8cf6af2391c86276`, the transfer at
6668352364, and the complete direct callee `getCGDataProviderBytesAtOffset`
without omitted blocks. The terminal assessment was `not_vulnerable`: the
caller-side writable destination extent matches the forwarded 64-bit length on
the investigated paths, source availability may clamp that length, allocator
failure is checked, and the conversion path uses a zero-initialized temporary
buffer. This conclusion closes only the rank-1 size-mismatch candidate and does
not clear unrelated arithmetic or conversion-loop candidates. The next action
is to analyze the already-admitted rank-2 root before adding any broader code.

### M17-24 — Direct field-provenance anchor preservation

#### Trigger

The rank-2 `decodeSGI_RLEcompressed` Hunter produced one valid definition/use
request for the allocation length, payload read length, and four decoder-state
fields. The frozen broker selected the correct root and two cross-function field
providers, but returned `proof_unavailable` before any continuation model call.
Deterministic inspection showed that secondary-function provenance closure
consumed the 96-instruction allowance before the direct 0x134 and 0x138 field
ADD instructions. Those instructions were protected during byte fitting but had
already been omitted during slice construction.

#### Implementation scope

- Add each exact frozen object-field pointer ADD address to the existing
  field-provenance priority anchors, alongside its recovered guard addresses.
- Preserve the current candidate selection, definition/use closure, function,
  block, instruction, byte, continuation, and token bounds. Do not increase any
  budget or alter reportability, prompts, schemas, ranking, decompilation, VM,
  fuzzer, or dynamic behavior.
- Keep M17-22/M17-23 CFG frontiers and all previous blind gates unchanged.

#### Exit criteria

A deterministic multi-function fixture with a long lower-priority provenance
closure must fail before the change and resolve after it, retaining all four
direct field ADD addresses within the existing 32 KiB request. Run the focused
suite twice, M14/M16/M17, full, Ruff, project-standard mypy, and unchanged M15
gate twice. Then rerun only the frozen rank-2 SGI context chain and require a
real continuation response with address-backed allocation/read/destination
evidence. Classify only what the completed proof establishes.

#### Current observation

Implemented and validated. The focused suite passed twice (39 tests per pass),
the M14/M16/M17 set passed (255 tests), the repository suite passed (801
passed, 8 skipped), Ruff and the project-standard 197-file mypy gate passed,
and the unchanged M15 gate passed twice with TP=6, FP=0, FN=0 and the stable
observation digest.

The corrected rank-2 plan resolved 32,424 bytes of new evidence instead of
returning `proof_unavailable`. The fresh SGI chain used seven model calls,
869,052 input tokens, 16,143 output tokens, and 259,048 evidence bytes. It
traced the table-derived payload length through both range-reader wrappers to
`getCGDataProviderBytesAtOffset`, then to `_CGAccessSessionGetBytes` at
6668353124. The six-continuation ceiling was reached with one exact final
definition/use request still pending, so the terminal status correctly remained
`reviewer_inconclusive` and no vulnerability is claimed. The next bounded
change must resume only such a valid terminal request for one final
continuation, without rerunning the completed six-call chain or widening other
root budgets.

### M17-25 — Resumable final context continuation

#### Trigger

M17-24 reached the six-continuation ceiling after resolving every supplied
slice and persisted one exact definition/use request for
`_CGAccessSessionGetBytes`. The terminal cache currently returns that
inconclusive result unconditionally, so raising a policy limit would either
have no effect or require deleting the result and replaying six costly model
calls.

#### Implementation scope

- Permit one root to use at most seven context continuations. Keep the default
  at three and preserve the existing two-continuation policy for remaining
  roots after one root consumes an extended continuation.
- Resume a persisted terminal result only when it is
  `reviewer_inconclusive`, its stored entries exactly match the verified chain,
  its last resolved assessment still has disposition `needs_code_context` with
  exactly one request, and its entry count is below the active policy limit.
- Reuse all six persisted entries and issue only the newly allowed seventh
  model call. Completed results, rejected/unavailable evidence, invalid request
  counts, and unchanged limits remain cache hits with zero new model calls.
- Apply the same predicate in the real context CLI so a resumable terminal is
  routed back into its verified chain instead of being treated as an ordinary
  completed cache hit. Keep the full policy only for that existing root; later
  roots retain the reduced continuation policy.
- Do not change ranking, root admission, evidence or token budgets, prompts,
  reportability, Reviewer thresholds, decompilation, VM, fuzzer, or dynamic
  behavior.

#### Exit criteria

A deterministic persistence test must stop inconclusive at one continuation,
resume under a two-continuation policy, preserve the first chain entry, make
exactly one additional model call, and overwrite the result as completed. The
seven-entry schemas must accept seven and reject eight. Run the focused suite
twice, M14/M16/M17, full, Ruff, project-standard mypy, and the unchanged M15
gate twice. Finally, resume the existing frozen SGI rank-2 store with a
seven-continuation policy and classify only the new address-backed result; do
not replay the first six calls.

#### Current observation

Implemented and validated. The focused suite passed twice (40 tests per pass),
the M14/M16/M17 set passed (256 tests), the repository suite passed (802
passed, 8 skipped), Ruff and the project-standard 197-file mypy gate passed,
and the unchanged M15 gate passed twice with TP=6, FP=0, FN=0 and the stable
observation digest.

Against the persisted SGI rank-2 chain, the CLI reused all six immutable
entries and made exactly one new subscription-backed model call. The complete
chain now records eight model calls including the initial Hunter assessment,
1,067,199 input tokens, 18,945 output tokens, and 291,606 evidence bytes. Image
executions, decompiler invocations, fuzzer invocations, and VM boots remained
zero.

The seventh response resolved 32,558 bytes of address-backed evidence and
contained the complete `getCGDataProviderBytesAtOffset` function with no
omitted blocks. The Hunter still ended `reviewer_inconclusive`: it could not
relate the destination used at 6668353124 to `param_1`, because the normalized
IR represented the prologue call at 6668352924 as a 128-bit-returning indirect
call whose upper subpiece replaced the destination register.

Direct static inspection of the same frozen Mach-O explains the discrepancy.
The machine sequence sets a 0x2030 stack size, performs authenticated indirect
branch-and-link, allocates the large stack frame, and only then saves `x3`,
`x2`, `x1`, and `x0`; this is an argument-preserving stack-probe prologue, not
a producer of the destination pointer. The next bounded milestone must recover
that general prologue semantic during export/normalization and regenerate the
IR. Adding more Hunter sessions or evidence bytes would only repeat the false
dataflow.

### M17-26 — ARM64e stack-probe argument preservation

#### Trigger

M17-25 supplied the complete provider-reader function, but Ghidra modeled an
early authenticated indirect stack-probe call as a 128-bit value producer. Its
upper return subpiece replaced the incoming destination register in high
p-code, even though the underlying machine code saves `x1` after the probe and
uses that saved value as the `_CGAccessSessionGetBytes` destination. The false
clobber prevents the exact destination-capacity proof requested by the Hunter.

#### Implementation scope

- In the Ghidra exporter, tag a call as an argument-preserving stack probe only
  when it is a `CALLIND` within the first 0x40 function bytes and the listing
  contains the exact contiguous ARM64e sequence: frame-size setup in `w9`,
  `ADRP/ADD x17`, `LDR x16,[x17]`, `BLRAA x16,x17`, then `SUB sp,sp`.
- In the adapter, only for a tagged call, map 64-bit subpieces of its synthetic
  result back to the raw declared parameter order by ABI register slot. Retain
  the original SSA result, address, constants, and text, and add an explicit
  preserved-argument tag and explanatory suffix.
- Leave every untagged indirect call, malformed/non-64-bit subpiece, and
  out-of-range ABI slot unchanged. Do not recognize function names, target
  addresses, parser formats, or vulnerability labels.
- Keep the independent Reviewer compatible with the already permitted
  seven-response Hunter chain. If bounded response compaction removes a guard
  block or callsite, rebind edge references to the final retained slices before
  validating the packet; never leave a stale evidence reference.
- Do not alter ranking, admission, evidence/context/token budgets, prompts,
  continuation limits, reportability, Reviewer thresholds, VM, fuzzer, or
  dynamic behavior.

#### Exit criteria

Positive and negative adapter fixtures must prove that tagged `x0`/`x1`
subpieces recover `this`/destination while the identical untagged call remains
unchanged. Seven-entry Reviewer packets must validate while an eighth entry is
rejected, and compacted responses must not retain edge references to omitted
blocks. A source contract must enforce every machine instruction in the
exporter predicate. The exporter must compile and run in Ghidra 12.1.2 against
the same frozen Mach-O, clean its project, and recover `param_1` at 6668352924
without a function allowlist. Then run focused tests twice, M14/M16/M17, full,
Ruff, project-standard mypy, and the unchanged M15 gate twice. Finally,
regenerate the static pipeline under the new IR digest and rerun the admitted
SGI root through Hunter and Reviewer; classify only the new address-backed
proof.

#### Current observation

Implemented and validated. The focused adapter/context/Reviewer suite passed
twice (72 tests per pass), the M14/M16/M17 set passed (261 tests), and the
repository suite passed (807 passed, 8 skipped). Ruff and the project-standard
197-file mypy gate passed. The unchanged M15 gate passed twice with TP=6, FP=0,
FN=0 and stable observation digest
`sha256:84e4a0cdbbf6b44c689a259c579ef57f475e8064bcad549b3b68adec783795a4`.

A real exporter run over the 1,200-function frozen ImageIO corpus compiled
successfully and tagged three exact stack-probe prologues. Its temporary Ghidra
project was deleted. Normalizing that export produced IR digest
`sha256:d7514c017bab1c2933e8f66fca1df7c8d5989f0335e061928fc5d0f060000936`.
At 6668352924, the low and high synthetic subpieces now consume `this` and
`param_1` respectively and carry `abi:preserved_argument`; no ImageIO function
or address is present in the rule. The static pipeline retained snapshot
`sha256:47ad3755368140434c7821c0aa030c5631e5157dc50d7efc082440392c1c7adf`,
ImageIO UUID `EEB840D5-3559-386F-BBD3-D24AA749D2EC`, and rank 2 for
`decodeSGI_RLEcompressed`. It made no model or dynamic calls.

The two-root Hunter admission made three model calls, used 225,921 input and
4,777 output tokens, and requested code context for both roots. The SGI root
then completed its seven-response chain with eight model calls including its
initial assessment, 1,047,075 input tokens, 19,190 output tokens, and 263,448
evidence bytes. It emitted the conditional code hypothesis
`codehypothesis-sgi-rle-short-read-uninitialized-suffix`: the underlying reader
may clamp the requested row length to its available-byte count, the root
discards the returned count, and later parsing remains bounded by the original
row length.

The real run also exposed two integration defects before review: Reviewer
packets still capped Hunter context at two responses, and response compaction
could retain a call-edge guard ID after removing the referenced block. Both
were repaired without changing evidence or continuation budgets. The first
failed before a model call; a separate low-budget dry result made zero calls;
the final independent Reviewer completed with three calls, 568,364 input and
9,397 output tokens. Every image, fuzzer, generated-input, dynamic-experiment,
and VM counter remained zero.

The Reviewer proved the frozen target, reachable parser route, and
attacker-controlled SGI row offset/length, but ended `reviewer_inconclusive`.
Two exact static gaps remain: whether the root extent field at offset 200
equals or bounds the underlying reader length field at offset 80 on every row
read path, and the destination-write contract of the imported
`_CGAccessSessionGetBytes`. Therefore this is a useful conditional
uninitialized-read hypothesis, not a confirmed or Apple-submission-ready
vulnerability. The next bounded milestone must recover those two provenance
contracts rather than add sessions, lower Reviewer thresholds, or use dynamic
execution.

### M17-27 — Cross-object initialization and complete backend closure

#### Trigger

M17-26 could name the two missing proof obligations, but the 1,200-function
export omitted both `SGIReadPlugin` constructors and both `IIOReadPlugin`
constructors. The field-provenance selector also preferred an unrelated
lifecycle access over a function cited by the Reviewer. After constructor
coverage recovered the real extent write, the same root exposed two further
bounded broker defects: cross-function request anchors passed continuation
validation but failed at resolution, and the first definition/use refinement
of a direct-callee response remained at the ordinary 20-block frontier.

#### Implementation scope

- Promote constructors belonging to owners of mandatory parser evidence before
  the evidence cap. Use qualified symbol ownership and constructor identity;
  do not recognize ImageIO formats, function addresses, field offsets, or
  vulnerability classes.
- When resolving object-field provenance, prefer functions cited by the active
  request and one-hop base constructors reached from the root owner's
  constructors before unrelated lifecycle candidates.
- Require every requested block, address, and variable to belong to its
  `function_id` during continuation validation so the existing single repair
  turn corrects invalid cross-function anchors before broker resolution.
- Treat a block-addressed definition/use request as a refinement when its block
  was included, omitted, or named as a successor by a prior response, including
  a response reached through `direct_callee`. At the 96 KiB response ceiling,
  an equal-size request may advance only to such a newly referenced block.
- Retain seven continuations, the 96 KiB per-response cap, and the reduced
  192 KiB budget for later roots. Raise only the single extended-root evidence
  ceiling to 384 KiB after offline replay proved that 288 KiB and 320 KiB both
  truncated the final 25-block backend function.
- Preserve the frozen-IR, citation, reportability, no-execution, no-fuzzer, and
  no-VM contracts.

#### Exit criteria

Synthetic tests must prove parser-owner constructor promotion, cited-function
field preference, one-hop base-constructor provenance, target-local request
validation, direct-callee-to-definition/use refinement, and rejection above
the 384 KiB extended-root ceiling. The same frozen ImageIO export must contain
the SGI and base constructors, and offline replay must return all 25 backend
blocks with zero omissions within the bounded ceiling. Run focused tests,
M14/M16/M17, the full suite, Ruff, project-standard mypy, and the unchanged M15
blind gate twice before accepting the real Hunter and Reviewer results.

#### Current observation

Implemented and validated. The exporter selected 1,262 functions, including
both `SGIReadPlugin` and both `IIOReadPlugin` constructors, and produced IR
digest `sha256:ad32dd627bd743b589531d993153668d1313560298e53b05a5b86a942861e724`
for the unchanged snapshot and ImageIO UUID. The exact Reviewer request now
selects the SGI root, the cited reader `getBytesAtOffset`, and the base
constructor that writes the root extent. An offline final replay returned all
25 `getFileBytesAtOffset` blocks, zero omissions, 85,816 response bytes, and
380,046 total evidence bytes.

The focused suite passed 64 tests, the repository suite passed 813 tests with
8 environment-dependent skips, Ruff passed, and mypy passed 34 source files.
The unchanged M15 gate passed twice with TP=6, FP=0, FN=0 and stable observation
digest
`sha256:84e4a0cdbbf6b44c689a259c579ef57f475e8064bcad549b3b68adec783795a4`.

The real rank-2 SGI chain completed seven continuations and emitted
`codehypothesis-rle-discarded-short-read`. It used one root session, nine model
calls including repair calls, 1,296,938 input tokens, 23,761 output tokens, and
380,046 evidence bytes. The independent Reviewer made one call with 236,122
input and 3,347 output tokens. Every image, decompiler rerun after the frozen
export, generated input, dynamic experiment, fuzzer, and VM counter remained
zero.

The Reviewer proved the direct parser/backend path, the short-read
initialization invariant, applicable guards, sink, impact boundary, and
contradiction analysis, but correctly ended `reviewer_inconclusive`. The
remaining gap is not missing code: a validated immutable regular-file range
ordinarily makes `pread` complete, and the static evidence does not prove that
attacker-controlled image bytes alone can force a short read without external
truncation, mutation, or I/O failure. This candidate is therefore not Apple
submission ready. The next hunt should move to another admitted root rather
than lower Reviewer thresholds or claim this conditional path as a confirmed
vulnerability.

## Per-PR validation and merge procedure

For each M17 PR:

1. Confirm the diff touches only the PR's declared files and required exports or
   tests. Existing unrelated M13/F7 worktree changes are not included.
2. Run the PR-focused tests twice when deterministic artifact digests are part
   of the contract.
3. Run all M14 binary tests, the unchanged M15 12-case gate, and applicable M16
   tests.
4. Run the repository-wide test suite.
5. For PR1, PR2, PR3, PR4, and PR7, run the bounded current ImageIO static pilot
   and compare stage/coverage/admission evidence with the frozen baseline.
6. Inspect model-call, token, image-execution, VM, and fuzzer counters before
   merge.
7. Merge only when every required gate passes. Repair a failed PR on the same
   branch and rerun all affected gates before proceeding.
8. Remove temporary Ghidra projects, extracted binaries, exports, and test
   containers after preserving only the declared private evidence artifacts.

## Regression protections

- Do not edit M14/M15 oracle labels to make M17 pass.
- Do not lower prior ranking, coverage, or evidence-integrity assertions.
- All previously detected binary vulnerability classes remain represented in
  Hunter and Reviewer schemas.
- No F1-F7, ImageIO harness, fuzzer, VM bridge, crash triage, or dynamic oracle
  behavior changes in M17.
- The new code-first disposition does not replace generic VulnHunt
  `reportable`; promotion into M13/Apple reporting remains a separate later
  decision.
- A model/provider failure is recorded as deferred or inconclusive, never safe
  and never vulnerable.
- A new Apple release changes snapshot evidence, not code rules or allowlists.

## Failure interpretation

- **Target function absent from IR:** extraction/export/coverage defect; repair
  M17-1, not Hunter prompting.
- **Function present but not admitted:** narrow admission defect; repair M17-2
  without hard-coding the missed case.
- **Admitted but required caller/guard/sink missing:** capsule or broker defect;
  repair M17-3/M17-5.
- **Complete code evidence present but no hypothesis:** Hunter reasoning/contract
  defect; repair M17-4 and rerun all code-first blind cases.
- **Hunter hypothesis rejected because the proof is actually incomplete:** valid
  Reviewer behavior; improve evidence, not the acceptance threshold.
- **Patched control becomes reportable:** critical guard/path/decompiler
  precision failure; stop the milestone and repair before any new target scan.
- **Prior positive disappears:** regression; stop and restore the previous
  detection before proceeding.
- **Historical ImageIO target unavailable:** implementation may reach M17-6, but
  effectiveness remains unvalidated and M17 stays incomplete.

## Milestone completion criteria

M17 is complete only when all of the following are true:

1. All seven PRs are implemented, validated, and merged in order.
2. The real CLI runs Ghidra through Reviewer without importing or invoking the
   fuzz/dynamic path.
3. A zero-static-finding function can be admitted and produce a valid
   address-bound code hypothesis.
4. Interprocedural source, guard, sink, and return-use evidence survives strict
   context bounds or fails explicitly as incomplete.
5. The independent Reviewer, not the Hunter, is the final model-based judge.
6. Only the deterministic reportability gate can emit `reportable_static`.
7. All pre-M17 binary regression gates remain green.
8. The historical vulnerable ImageIO case is recovered blind from decompiled
   code, while patched/current controls do not become reportable.
9. Repeated blind runs meet the stability and cost ceilings.
10. Every run records zero image executions, fuzzing operations, generated
    inputs, VM boots, and dynamic experiments.

Until criterion 8 is met, the honest status is **implemented but not proven
effective on a real historical ImageIO vulnerability**.
