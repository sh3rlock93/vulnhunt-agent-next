# M11.2 — Capacity-aware buffer-overflow ranking

Status: in progress; PR 1 of 7 implemented

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

## Non-goals

- Session, token, context, or parallelism increases
- New vulnerability families or new Hunter agents
- Prompt, verifier, UI, provider, sandbox, or intake changes
- Generic symbolic execution or whole-program points-to analysis
- Repository, file, function, constant, CVE, patch, or diff signatures
