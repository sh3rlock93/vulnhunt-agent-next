# M5 — C analysis graph, coverage, and Hunter portfolio

Status: Complete

## Outcome

The C pipeline no longer lets one LLM rank threshold decide what is analyzed.
Before ranking, a deterministic tree-sitter pass builds a source-to-sink graph,
creates bounded `AnalysisSlice` records, and selects the union of files required
to cover every detected entrypoint and critical sink. Rank remains a useful
priority signal, but a score below 5 cannot remove a graph-required file.

```text
Filter → C Analysis Graph → Rank → Coverage-aware Selector
       → Sandbox Prepare → Hunter Portfolio → Dedup → Review → Report
```

## Graph contract

`CAnalysisGraph` is a versioned, Pydantic-validated artifact containing:

- function and Flex/Bison grammar nodes;
- resolved local call edges and explicit Flex-to-Bison parser-flow edges;
- external-input source signals such as `read`, `recv`, `fgets`, `atoi`, and
  `strtol`;
- high-risk copy, allocation, command, path, format-string, and indexed-write
  sink signals;
- exported header APIs, parser nodes, and input-bearing roots as entrypoints;
- unresolved calls in a deterministic ledger rather than silently invented
  edges.

Node, edge, signal, and slice IDs derive from stable source identities. Sorted
input and output make the artifact identical when the same source file list is
provided in a different order.

Indexed writes receive an explicit guard hint. A simple index with both a
detected lower and upper comparison is downgraded from risk 5 to risk 2.
This heuristic changes scheduling only: it is not a proof of dominance,
correctness, or safety, and the Hunter must inspect the real control flow.

## Coverage policy

The `c-coverage-v1` planner creates:

1. a shortest source-preferred path for every critical sink;
2. a local slice for a disconnected critical sink;
3. a nearest-sink or local context slice for every otherwise uncovered
   entrypoint.

The plan records selected files, per-file reasons, covered IDs, and uncovered
IDs. `coverage_complete` means every *detected* entrypoint and critical sink has
a slice; it does not claim that the heuristic graph found every program path.

The Selector initially chooses the union of graph-required files and files with
LLM rank 5. An operator's later explicit selection is preserved. Each selected
C Hunter receives at most 12 compact slices involving its target file, including
symbols, locations, categories, risk, and sink detail.

## C Hunter portfolio

The single broad C prompt is replaced by six independent specialists:

- Bounds & Integers (default)
- Memory Lifetime (default)
- Parser State (default)
- Injection & Format
- Concurrency & Global State
- Error Contracts

The first three form the default portfolio. Each is a fresh session and treats
the supplied graph as a hypothesis to verify, not as evidence. Findings still
need sandbox reproduction and the M4 evidence/consensus gates.

## Deduplication

Cross-Hunter results first use a deterministic fingerprint of normalized
finding type, sink location, and entry location. Exact duplicates are grouped
without spending an LLM call. Only representatives of different deterministic
partitions are sent to the semantic Clusterer, and its groups are expanded back
to the original finding IDs. On a semantic clustering failure, deterministic
partitions are retained.

## Reference benchmark

The graph benchmark evaluates the same pinned libcue pair as M3, without invoking
a model and without putting the oracle into target source:

```bash
.venv/bin/python benchmarks/run_c_graph_benchmark.py \
  --repo /path/to/libcue-v2.2.1 \
  --expect vulnerable

.venv/bin/python benchmarks/run_c_graph_benchmark.py \
  --repo /path/to/libcue-v2.3.0 \
  --expect fixed
```

On the vulnerable commit, the expected slice is:

```text
cue_scanner.l: atoi
  → cue_parser.y: parser action
  → cd.c: track_set_index
  → track->index[i] indexed write
```

The vulnerable site has an upper guard but no lower guard and is risk 5. In
v2.3.0, the added `i < 0` guard changes that same scheduling signal to guarded,
risk 2, and removes it from critical sinks.

## Acceptance gates

- [x] Graph output is deterministic across source-list ordering.
- [x] Every detected entrypoint and critical sink is represented by a slice.
- [x] Graph-required files remain selected even when every LLM score is 1.
- [x] Flex/Bison parser flow reaches resolved C callees.
- [x] Hunters receive bounded slice context for their target file.
- [x] Six C specialists exist and three are enabled by default.
- [x] Exact cross-Hunter duplicates do not invoke the semantic Clusterer.
- [x] The vulnerable libcue revision produces the expected cross-file risk-5
  trace.
- [x] The fixed libcue revision downgrades the same indexed write to risk 2.
- [x] UI cards expose graph counts, coverage completeness, risk, and selection
  reasons.

## Verification

```bash
python -m ruff check src tests benchmarks
python -m mypy
python -m pytest --cov=vulnhunt_agent --cov-report=term-missing \
  --cov-report=xml --cov-fail-under=45
```

On 2026-07-20, local validation passed 71 standard tests at 65.89% branch
coverage, all three real Docker isolation contracts, and both real libcue
revisions. The vulnerable graph contained a scanner/parser/C slice to
`cd.c:347` with `lower_guard=no`; v2.3.0 reported `lower_guard=yes`, no critical
signal for that site, and complete detected coverage in both runs.
