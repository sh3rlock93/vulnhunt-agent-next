# Milestone 2.5 — API-first OpenAI and Codex subscription provider

Status: Implementation complete; CI pending

## Decision

The default model gateway uses one deterministic selection rule:

1. Resolve the provider's explicitly named API-key environment variable.
2. If the value is non-empty, use the OpenAI Responses API.
3. If the value is absent, use the user's existing `codex login`.

The gateway does not fall back after an API request has started. Authentication,
quota, policy, and transient API errors remain visible to the operator instead
of silently changing billing paths or duplicating a request.

The default model is `gpt-5.6-sol` with medium reasoning effort.

## Subscription security boundary

- The application never reads, parses, copies, or exports Codex credential files.
- Authentication remains owned by the installed Codex CLI.
- Each inference call runs in a new empty temporary working directory.
- The request envelope is sent over stdin, so source text is not exposed in the
  child process argument list.
- Project/user configuration and execution rules are ignored for the child call.
- Shell, unified execution, code mode, apps, plugins, browser/computer use,
  image generation, and multi-agent features are disabled.
- The remaining Codex sandbox is read-only and network/tool use is forbidden by
  the adapter contract.
- Repository text and prior model messages are wrapped as untrusted request data.
- The final response must satisfy a strict JSON schema.
- Requested host tools are allow-listed and their arguments must decode to a
  JSON object before entering the existing agent loop.
- Direct API requests use stateless Responses calls and replay encrypted
  reasoning items across host-tool turns.
- Subscription concurrency defaults to two calls per client.
- Run events record the selected transport for ranker, hunter, and reviewer.

This boundary prevents the Codex fallback from becoming a second repository
execution plane. Target code execution remains in the hardened Docker sandbox.

## Acceptance criteria

- [x] `OPENAI_API_KEY` selects the Responses API.
- [x] An absent key selects the Codex subscription adapter.
- [x] Inline API keys remain supported only for legacy compatibility.
- [x] API cached input tokens map to the existing usage contract without double
  counting.
- [x] Codex tool calls map to the existing Converse-shaped host tool contract.
- [x] Unknown tools, invalid argument JSON, non-object arguments, and empty
  responses fail closed.
- [x] The example configuration defaults to `gpt-5.6-sol`.
- [x] Subscription usage is not mislabeled as a dollar cost in the UI.
- [x] A live `codex login` smoke test returns an allow-listed `read_file` call.
- [ ] GitHub Actions passes on supported Python versions.

## Verification

```bash
python -m ruff check src tests
python -m mypy
python -m pytest --cov=vulnhunt_agent --cov-report=term-missing \
  --cov-report=xml --cov-fail-under=45

# Explicit opt-in because CI must not receive a personal ChatGPT login.
VULNHUNT_RUN_CODEX_TESTS=1 \
  python -m pytest \
  tests/test_openai_provider.py::test_live_codex_subscription_tool_call -vv
```

Local live validation completed against Codex CLI 0.144.1 and
`gpt-5.6-sol`; the final stdin-based structured host-tool smoke test passed in
7.90 seconds.
