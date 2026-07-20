# Milestone 2 — Hardened sandbox and independent reproduction

Status: Validation pending

## Scope

- Create deterministic, content-addressed source tar snapshots with normalized
  ownership, timestamps, permissions, and a file manifest.
- Reject source symlinks, special files, source races, traversal archives,
  duplicate members, and configured size/member exhaustion.
- Separate Build, Hunter, and Reproducer execution roles.
- Remove host source bind mounts. Build receives a streamed source snapshot;
  Hunter receives a prepared image with the snapshot baked into `/code`;
  Reproducer receives a fresh streamed snapshot for every attempt.
- Run Hunter and Reproducer containers offline and non-root with a read-only
  root, all capabilities dropped, `no-new-privileges`, PID/CPU/memory limits,
  and bounded tmpfs workspaces.
- Replace Hunter shell command input with an argv-only execution contract.
  Shell execution remains internal to the trusted deterministic build plan.
- Validate and persist a reproduction job contract, resolved image digest,
  exact argv, outputs, captured files, duration, exit status, and oracle result.
- Support exit-code, stdout/stderr/combined regex, and file SHA-256 oracles.
  Regex matching runs in a bounded isolated subprocess.
- Execute each PoC in two clean containers by default. Promote only when every
  sequential attempt has the same image digest and command and passes its oracle.
- Bind a reproduction ID immutably to its complete job specification and make
  successful replay idempotent.
- Require matching two-attempt reproduction evidence and a real reviewer verdict
  before materializing a final report.
- Quarantine legacy LLM-only Reviewer reports under `manual_review`; they cannot
  enter the final-report path.

## Acceptance criteria

- [x] Identical source trees create identical source snapshot digests.
- [x] Source changes after snapshot creation do not mutate the stored snapshot.
- [x] Unsafe source entries and tar extraction primitives are rejected.
- [x] Build and Hunter containers have no host bind mounts.
- [x] Hunter and Reproducer containers are offline, non-root, capability-free,
  read-only, and protected by `no-new-privileges` and a PID limit.
- [x] Shell metacharacters passed as argv remain inert.
- [x] The same PoC succeeds against the same resolved image in two fresh
  Reproducer containers with the same machine oracle result.
- [x] Root filesystem writes, source mutation, external sockets, and Docker
  socket access fail in the real Docker contract test.
- [x] A mixed or incomplete reproduction group cannot pass strict report policy.
- [x] Reusing a reproduction ID with a changed image, oracle, command, or other
  job input is rejected.
- [x] Missing or tampered evidence artifacts prevent final report materialization.
- [x] Legacy Reviewer output is stored only as manual-review material.
- [ ] CI passes on Python 3.11, 3.12, and 3.13.
- [ ] The real Docker sandbox contract passes in GitHub Actions.

## Verification commands

```bash
python -m ruff check src tests
python -m mypy
python -m pytest --cov=vulnhunt_agent --cov-report=term-missing \
  --cov-report=xml --cov-fail-under=45
VULNHUNT_RUN_DOCKER_TESTS=1 \
  python -m pytest tests/test_docker_sandbox_integration.py -vv
```

Local forward-compatibility validation on Python 3.14.5 passed all 42 tests,
including both real Docker contracts, with 65.37% branch coverage. Ruff and mypy
reported no findings. The supported-version GitHub Actions matrix remains the
release authority for Python 3.11–3.13.

## Security boundary and deferred hardening

The Build container is isolated from the host source and Docker socket and runs
with all capabilities dropped and `no-new-privileges`, but dependency installation
still uses UID 0 inside the container and Docker bridge egress. Registry-only
egress enforcement, rootless Docker, DNS/HTTP build provenance, SBOM generation,
and a gVisor/Kata/Firecracker backend remain later defense-in-depth work.

Negative controls are supported by submitting a separate reproduction job, but
automatic negative-control derivation is not a Milestone 2 release gate. The
legacy UI pipeline now blocks unverified final reports; wiring candidate creation,
Reproducer scheduling, reviewer verification, and strict export into one end-to-end
application workflow is planned with the later orchestration/reporting milestones.
