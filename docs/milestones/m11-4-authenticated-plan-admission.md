# M11.4 authenticated planning and admission reliability

M11.4 closes the orchestration gap exposed by the authenticated libjpeg-turbo
issue 387 run. The analyzer already recovered the complete unchecked capacity
chain, but the production plan did not admit it and the model never received
its context.

The milestone does not add Hunters, vulnerability families, prompts, provider
behavior, target signatures, or larger budgets.

## Sequential PRs

1. Use shared production planning and persist a semantic parity contract.
2. Schedule canonical capacity root-cause admission units.
3. Revisit seed-capped critical work without starvation.
4. Preserve critical-session input budget with per-work fairness.
5. Gate deterministic and authenticated libjpeg discovery on the same plan.

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
