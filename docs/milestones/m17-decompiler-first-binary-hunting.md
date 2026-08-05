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
