"""HunterTools — runtime side of the Bedrock tool calls.

Read tools (read_file/grep/list_dir) hit the local repo. Sandbox tools
(write_poc/exec) hit a container. read_poc reads from per-session disk
mirrors so reviewers in a fresh session can still cite exploit code.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from ...sandbox import ContainerExecutor


class HunterTools:
    """Dispatches tool calls. Deduplicates repeat reads/greps to keep the
    model from filling its context with the same bytes over and over."""

    MAX_BYTES = 60_000        # cap per read_file response
    MAX_MATCHES = 200
    MAX_GREP_BYTES = 50_000   # cap grep output (prevents context bombs)
    EXEC_OUTPUT_CAP = 20_000

    def __init__(
        self,
        repo: Path,
        sandbox: ContainerExecutor | None = None,
        poc_root: Path | list[Path] | None = None,
    ):
        self.repo = repo.resolve()
        self.sandbox = sandbox
        self.poc_roots: list[Path] = _normalize_roots(poc_root)
        self._seen_reads: set[tuple] = set()
        self._seen_greps: set[tuple] = set()
        for root in self.poc_roots:
            root.mkdir(parents=True, exist_ok=True)

    @property
    def poc_root(self) -> Path | None:
        """Primary PoC root for write_poc (the first one)."""
        return self.poc_roots[0] if self.poc_roots else None

    async def dispatch(self, name: str, inp: dict) -> str:
        try:
            if name == "read_file":
                key = ("read", inp["path"], inp.get("start", 1), inp.get("end"))
                if key in self._seen_reads:
                    return f"(already read {inp['path']} with the same range earlier in this session)"
                self._seen_reads.add(key)
                return self._read_file(inp["path"], inp.get("start", 1), inp.get("end"))
            if name == "grep":
                key = ("grep", inp["pattern"], inp.get("path"))
                if key in self._seen_greps:
                    return f"(already ran grep for {inp['pattern']!r} earlier in this session)"
                self._seen_greps.add(key)
                return self._grep(inp["pattern"], inp.get("path"), inp.get("max_results", 100))
            if name == "list_dir":
                return self._list_dir(inp["path"])
            if name == "read_poc":
                return self._read_poc(inp["path"])
            if name == "write_poc":
                return await self._write_poc(inp["path"], inp["content"])
            if name == "exec":
                return await self._exec(inp["cmd"], inp.get("timeout", 60))
            return f"ERROR: unknown tool {name}"
        except Exception as e:
            return f"ERROR: {e}"

    # --- repo reads ---

    def _safe_path(self, rel: str) -> Path:
        p = (self.repo / rel).resolve()
        if not str(p).startswith(str(self.repo)):
            raise ValueError(f"path escapes repo: {rel}")
        return p

    def _read_file(self, rel: str, start: int, end: int | None) -> str:
        p = self._safe_path(rel)
        if not p.is_file():
            return f"ERROR: not a file: {rel}"
        text = p.read_text(errors="replace")
        lines = text.splitlines()
        s = max(1, start) - 1
        e = len(lines) if end is None else min(end, len(lines))
        slice_ = lines[s:e]
        numbered = "\n".join(f"{i+s+1:6}: {line}" for i, line in enumerate(slice_))
        if len(numbered) > self.MAX_BYTES:
            numbered = numbered[: self.MAX_BYTES] + "\n... (truncated)"
        return numbered

    def _grep(self, pattern: str, sub: str | None, max_results: int) -> str:
        target = self._safe_path(sub) if sub else self.repo
        cap = min(max_results, self.MAX_MATCHES)
        proc = subprocess.run(
            ["rg", "-n", "--no-heading", "-e", pattern, str(target), "-m", str(cap)],
            capture_output=True, text=True, timeout=30,
        )
        out = proc.stdout.strip()
        if not out:
            return "(no matches)"
        if len(out) <= self.MAX_GREP_BYTES:
            return out
        cut = out[: self.MAX_GREP_BYTES].rsplit("\n", 1)[0]
        return cut + "\n... (truncated — narrow the pattern or use a 'path' arg)"

    def _list_dir(self, rel: str) -> str:
        p = self._safe_path(rel)
        if not p.is_dir():
            return f"ERROR: not a dir: {rel}"
        entries = sorted(p.iterdir())
        return "\n".join(
            f"{'D' if e.is_dir() else 'F'}  {e.relative_to(self.repo)}" for e in entries
        )

    # --- PoC mirror ---

    def _read_poc(self, rel: str) -> str:
        if not self.poc_roots:
            return "ERROR: no PoC directory available for this session"
        for root in self.poc_roots:
            p = (root / rel).resolve()
            if not str(p).startswith(str(root)):
                continue
            if p.is_file():
                text = p.read_text(errors="replace")
                if len(text) > self.MAX_BYTES:
                    text = text[: self.MAX_BYTES] + "\n... (truncated)"
                return text
        return f"ERROR: not a PoC file: {rel}"

    # --- sandbox ---

    async def _write_poc(self, path: str, content: str) -> str:
        if not self.sandbox:
            return "ERROR: sandbox not available"
        await self.sandbox.write_file(path, content)
        if self.poc_root:
            mirror = (self.poc_root / path).resolve()
            if str(mirror).startswith(str(self.poc_root)):
                mirror.parent.mkdir(parents=True, exist_ok=True)
                mirror.write_text(content)
        return f"OK: wrote {len(content)} bytes to /workspace/{path}"

    async def _exec(self, cmd: str, timeout: int) -> str:
        if not self.sandbox:
            return "ERROR: sandbox not available"
        r = await self.sandbox.exec(cmd, timeout=timeout)
        out = (r.stdout or "")[: self.EXEC_OUTPUT_CAP]
        err = (r.stderr or "")[: self.EXEC_OUTPUT_CAP]
        return (
            f"exit_code={r.exit_code} timed_out={r.timed_out}\n"
            f"--- stdout ---\n{out}\n--- stderr ---\n{err}"
        )


def _normalize_roots(arg) -> list[Path]:
    if arg is None:
        return []
    if isinstance(arg, (list, tuple)):
        return [Path(p).resolve() for p in arg]
    return [Path(arg).resolve()]
