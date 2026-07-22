# M11.4 authenticated planning and admission reliability

M11.4 closes the orchestration gap exposed by the authenticated libjpeg-turbo
issue 387 run. The analyzer already recovered the complete unchecked capacity
chain, but the production plan did not admit it and the model never received
its context.

The milestone does not add Hunters, vulnerability families, provider behavior,
target signatures, or larger budgets. It adds one vulnerability-agnostic
negative-result recheck for high-confidence unchecked capacity chains; the
recheck compares allocation and write formulas without encoding the benchmark
target or its known trigger.

## Sequential PRs

1. Use shared production planning and persist a semantic parity contract.
2. Schedule canonical capacity root-cause admission units.
3. Revisit seed-capped critical work without starvation.
4. Preserve critical-session input budget with per-work fairness.
5. Gate deterministic and authenticated libjpeg discovery on the same plan.

All five PRs are implemented. Each PR was validated independently before the
next PR started.

## Fixed release limits

- 12 Hunter sessions with one retry reservation
- 1,000,000 input tokens and 100,000 output tokens
- 24,000-byte contexts
- two parallel Hunters

## Release gate

The pinned vulnerable libjpeg-turbo tree must produce the same normalized
pre-execution plan in credential-free and authenticated modes. The affected
root cause must start a provider session within the first six admissions, its
cross-file context must stay bounded, and the authenticated Codex run must emit
a matching model candidate. Existing LibTIFF and libwebp gates must remain
green.

## Release evidence

- Source under test: libjpeg-turbo commit
  `c30b1e72dac76343ef9029833d1561de07d29bad`, tree
  `48074ffcebfb949fd22ded3281301259d4c9f265`
- Deterministic and authenticated normalized plan SHA-256:
  `9f054b92135300a49c73b8f196da73b4529115d372bde4041f27e476985117ff`
- Target pre-admission, paid-session, and actual provider-start rank: 2
- Target authenticated context: 23,466 bytes with both `tjbench.c` and
  `turbojpeg.c`
- Authenticated usage: 8 sessions, 783,622 input tokens, 190,464 cache-read
  tokens, and 8,888 output tokens
- Model candidate: unverified `heap_buffer_overflow` at
  `turbojpeg.c:1726`, matching the withheld oracle after discovery artifacts
  were frozen
- Oracle isolation: no oracle or fixed tree was provided to discovery and no
  denied oracle access attempt occurred
- Local validation: Ruff and scoped mypy passed; pytest reported 255 passed
  and 7 intentionally skipped tests
