# M3 — C native analysis

## Outcome

Run the existing rank → hunt → verify workflow against native C repositories.
The prepared image contains an immutable source snapshot and sanitizer-instrumented
build outputs. Hunters can compile and execute a small PoC without gaining a shell,
network access, a writable source tree, or host mounts.

## Supported project layouts

Auto prepare recognizes, in order:

1. `CMakeLists.txt`
2. `meson.build`
3. `configure` or `configure.ac`
4. `Makefile` or `GNUmakefile`

Builds use GCC with AddressSanitizer and UndefinedBehaviorSanitizer:

```text
-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined
```

CMake and Meson outputs live below `/opt/vulnhunt/build`. Autotools and Make
projects build in `/code`, which is writable only inside the disposable prepare
container and becomes read-only after the image is committed.

## Runtime boundary

- `/code`: immutable source snapshot baked into the prepared image
- `/opt/vulnhunt/build`: immutable prepared build artifacts
- `/workspace`: writable, `noexec` tmpfs for PoC source and evidence
- `/workspace/exec`: writable executable tmpfs for native PoC binaries only
- `/tmp`: writable `noexec` tmpfs
- no network, no host bind mounts, non-root UID, read-only root filesystem,
  all Linux capabilities dropped, and `no-new-privileges`
- Hunter commands are argv arrays executed directly; shell syntax is not accepted

The disposable prepare container has no host mounts and receives only the
`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETGID`, and `SETUID` capabilities required
by Debian package installation. These capabilities are absent from every Hunter
container.

## Reference benchmark

The pinned target is the small C library
[`lipnitsk/libcue`](https://github.com/lipnitsk/libcue):

- vulnerable release commit: `1b0f3917b8f908c81bb646ce42f29cf7c86443a1`
  (`v2.2.1`)
- upstream fix commit: `fdf72c8bded8d24cfa0608b8e97f2eed210a920e`
- fixed negative-control release: `cfb98a060fd79dbc3463d85f0f29c3c335dfa0ea`
  (`v2.3.0`)
- public issue: CVE-2023-43641 / GHSA-5982-x7hv-r9cj

The isolated fix commit predates an unrelated Flex grammar repair and does not
build with current Flex. The negative control therefore uses v2.3.0, which
contains both the security fix and the grammar repair.

The ground truth in `benchmarks/libcue-cve-2023-43641.toml` is used only after
the Hunter finishes. It is not put in the prompt and must not exist inside the
blind target checkout.

## Acceptance gates

Automated:

- C/header files are indexed by tree-sitter-c; Flex/Bison `.l`/`.y` inputs use
  a text metadata fallback so they remain visible to ranking and selection.
- C prompt/ranker selection is language-specific.
- each supported project layout produces a deterministic build plan.
- a real Docker contract compiles and runs an ASan-instrumented C PoC from
  `/workspace/exec`.
- Docker inspection confirms no host mounts, no network, read-only root,
  non-root user, dropped capabilities, and the split noexec/exec tmpfs policy.

Benchmark:

1. Clone the upstream repository into a fresh directory and check out the exact
   vulnerable SHA.
2. Prepare it with `c:gcc-13`; do not provide CVE, function, line, patch, or PoC
   details to the model.
3. Run the C Hunter and require a concrete input-to-sink trace plus sanitizer
   evidence. A static hypothesis alone is `unverified`.
4. Compare the final result to the private ground truth: the finding must identify
   the unchecked converted index reaching `track_set_index` in `cd.c`.
5. Repeat the native PoC oracle on the fixed SHA. The sanitizer crash must be absent.

The benchmark passes only when the vulnerable revision is confirmed and the fixed
revision is a clean negative control.

The independent oracle can be run against an already prepared image:

```bash
.venv/bin/python benchmarks/run_libcue_oracle.py \
  --repo /path/to/libcue \
  --image scanner/prepared:<tag> \
  --expect vulnerable
```

## Recorded validation

On 2026-07-20, a blind Codex-subscription run started only from `cd.c` and was
given no CVE, patch, vulnerable function, line, or known PoC data. In 7 Hunter
iterations it:

1. traced attacker input from `atoi()` in `cue_scanner.l:132`, through the parser,
   to the missing lower-bound check in `track_set_index`;
2. independently chose the overflow value `2147483648`;
3. wrote and compiled `index_oob.c` into `/workspace/exec`;
4. confirmed an ASan WRITE SEGV at `cd.c:347`.

The accumulated adapter usage was 168,401 input tokens, 2,072 output tokens, and
41,472 cache-read tokens. The independent oracle also produced the expected
contrast:

- v2.2.1: exit 134, sanitizer crash at `track_set_index`
- v2.3.0: exit 0, no sanitizer crash
