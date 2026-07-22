"""Container-based sandbox. Uses the local `docker` CLI."""
from __future__ import annotations

import asyncio
import re
import secrets
import subprocess
import tempfile
import time
from pathlib import Path
from pathlib import PurePosixPath

from ..core.settings import ENV_TO_IMAGE
from ..infrastructure.artifacts import ArtifactStore
from ..intake.snapshot import SnapshotBuilder, validate_snapshot_archive
from . import cleanup
from .base import ExecResult, validate_argv


_WORKSPACE_SIZE = "256m"
_EXEC_WORKSPACE_SIZE = "64m"
_OUTPUT_LIMIT = 1024 * 1024


def base_image_for(env: str) -> str:
    return ENV_TO_IMAGE[env]


def language_of(env: str) -> str:
    return env.split(":", 1)[0]


class ContainerExecutor:
    """Long-lived sandbox container. Use `async with` or start()/stop()."""

    def __init__(
        self,
        repo: Path,
        image: str,
        network: str = "none",            # set to "bridge" during prepare step
        cpus: str = "2",
        memory: str = "2g",
        code_writable: bool = False,
        source_baked: bool = False,
        source_archive: Path | None = None,
    ):
        self.repo = repo.resolve()
        self.image = image
        self.network = network
        self.cpus = cpus
        self.memory = memory
        self.code_writable = code_writable
        self.source_baked = source_baked
        self.source_archive = source_archive.resolve() if source_archive else None
        self.name = f"{cleanup.NAME_PREFIX}{secrets.token_hex(4)}"
        self._started = False

    # ----- lifecycle -----

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *exc):
        await self.stop()

    async def start(self) -> None:
        if self._started:
            return
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}", self.image) is None:
            raise ValueError("invalid Docker image reference")
        if self.network not in {"none", "bridge"}:
            raise ValueError("sandbox network must be none or bridge")
        if not self.code_writable and not self.source_baked:
            raise RuntimeError(
                "Hunter sandboxes require a prepared image with a baked source snapshot"
            )
        if not self.code_writable and self.network != "none":
            raise ValueError("Hunter sandboxes require network=none")
        await self._ensure_image()
        security_args = [
            "--pids-limit", "128",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
        ]
        if self.code_writable:
            # The disposable prepare container has no host mounts. Debian's apt
            # needs these narrowly-scoped capabilities to switch to its download
            # user and unpack packages. Hunter containers never receive them.
            for capability in ("CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"):
                security_args.extend(("--cap-add", capability))
        filesystem_args = (
            []
            if self.code_writable
            else [
                "--read-only",
                "--user", "65532:65532",
                "--tmpfs",
                f"/workspace:rw,noexec,nosuid,nodev,size={_WORKSPACE_SIZE},mode=1777",
                "--tmpfs",
                f"/workspace/exec:rw,exec,nosuid,nodev,size={_EXEC_WORKSPACE_SIZE},mode=1777",
                "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
            ]
        )
        proc = await self._run_cli(
            "run", "-d",
            "--name", self.name,
            f"--network={self.network}",
            "--cpus", self.cpus,
            "--memory", self.memory,
            *security_args,
            *filesystem_args,
            "-w", "/workspace",
            self.image,
            "sleep", "infinity",
        )
        _check(proc, "start sandbox")
        self._started = True
        cleanup.register(self.name)
        if self.code_writable:
            try:
                await self._stream_source_snapshot()
            except Exception:
                await self.stop()
                raise

    async def stop(self) -> None:
        if not self._started:
            return
        await self._run_cli("rm", "-f", self.name)
        self._started = False
        cleanup.unregister(self.name)

    async def commit(self, image_tag: str) -> None:
        """Commit the current container state as a new image (used by prepare step)."""
        if not self._started:
            raise RuntimeError("container not running")
        proc = await self._run_cli("commit", self.name, image_tag)
        _check(proc, "commit")

    # ----- operations -----

    async def write_file(self, path: str, content: str) -> None:
        """Write a text file inside the container's /workspace (path is relative)."""
        await self.write_bytes(path, content.encode())

    async def write_bytes(self, path: str, content: bytes) -> None:
        """Write arbitrary bytes inside the container's /workspace."""
        relative = _safe_relative_path(path)
        full = f"/workspace/{relative.as_posix()}"
        parent = PurePosixPath(full).parent.as_posix()
        mkdir = await self._run_cli("exec", self.name, "mkdir", "-p", parent)
        _check(mkdir, "create PoC directory")
        written = await self._run_cli_input(
            content, "exec", "-i", self.name, "tee", full
        )
        _check(written, "write PoC file")

    async def exec(self, cmd: str, timeout: int = 60) -> ExecResult:
        """Run a trusted build command. Hunter and Reproducer calls use argv."""
        if not self.code_writable:
            raise RuntimeError("shell execution is restricted to the build sandbox")
        return await self._exec_process(("sh", "-lc", cmd), timeout=timeout, cwd="/workspace")

    async def exec_argv(
        self,
        argv: tuple[str, ...] | list[str],
        *,
        timeout: int = 60,
        cwd: str = "/workspace",
    ) -> ExecResult:
        """Run untrusted arguments directly without shell interpretation."""
        normalized = validate_argv(argv)
        normalized_cwd = _safe_container_cwd(cwd)
        return await self._exec_process(normalized, timeout=timeout, cwd=normalized_cwd)

    async def _exec_process(
        self, argv: tuple[str, ...], *, timeout: int, cwd: str
    ) -> ExecResult:
        started_at = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", "-w", cwd, self.name, *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_task = asyncio.create_task(_read_capped(proc.stdout))
        stderr_task = asyncio.create_task(_read_capped(proc.stderr))
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            await self._run_cli("kill", self.name)
            stdout = await stdout_task
            stderr = await stderr_task
            return ExecResult(
                exit_code=-1,
                stdout=stdout.decode(errors="replace"),
                stderr=(stderr.decode(errors="replace") + "\nexecution timed out").strip(),
                timed_out=True,
                duration_ms=int((time.monotonic() - started_at) * 1000),
            )
        stdout = await stdout_task
        stderr = await stderr_task
        return ExecResult(
            exit_code=proc.returncode if proc.returncode is not None else -1,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            duration_ms=int((time.monotonic() - started_at) * 1000),
        )

    # ----- internals -----

    async def _ensure_image(self) -> None:
        proc = await self._run_cli("image", "inspect", self.image)
        if proc.returncode == 0:
            return
        if self.image.startswith("scanner/prepared:"):
            raise RuntimeError(
                f"prepared image '{self.image}' not found. Run Sandbox Prepare first."
            )
        proc = await self._run_cli("pull", self.image)
        _check(proc, f"pull '{self.image}'")

    async def _run_cli(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return await self._run_cli_input(None, *args)

    async def _run_cli_input(
        self, data: bytes | None, *args: str
    ) -> subprocess.CompletedProcess[bytes]:
        proc = await asyncio.create_subprocess_exec(
            "docker", *args,
            stdin=asyncio.subprocess.PIPE if data is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate(data)
        return subprocess.CompletedProcess(
            args=("docker", *args),
            returncode=proc.returncode if proc.returncode is not None else -1,
            stdout=stdout,
            stderr=stderr,
        )

    async def _stream_cli_file(
        self, path: Path, *args: str
    ) -> subprocess.CompletedProcess[bytes]:
        def run() -> subprocess.CompletedProcess[bytes]:
            with path.open("rb") as stream:
                return subprocess.run(
                    ["docker", *args],
                    stdin=stream,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )

        return await asyncio.to_thread(run)

    async def _stream_source_snapshot(self) -> None:
        """Copy a normalized source tar into the build container without mounts."""
        if self.source_archive is not None:
            validate_snapshot_archive(self.source_archive)
            await self._extract_source_tar(self.source_archive)
            return
        with tempfile.TemporaryDirectory(prefix="vulnhunt-build-source-") as temporary:
            artifacts = ArtifactStore(Path(temporary) / "artifacts")
            snapshot = SnapshotBuilder(artifacts).create(self.repo)
            source_tar = artifacts.path_for(snapshot.snapshot_artifact)
            await self._extract_source_tar(source_tar)

    async def _extract_source_tar(self, source_tar: Path) -> None:
        mkdir = await self._run_cli("exec", self.name, "mkdir", "-p", "/code")
        _check(mkdir, "create source directory")
        extracted = await self._stream_cli_file(
            source_tar,
            "exec",
            "-i",
            self.name,
            "tar",
            "-xf",
            "-",
            "-C",
            "/code",
        )
        _check(extracted, "extract source snapshot")


def _check(proc, action: str) -> None:
    if proc.returncode != 0:
        raise RuntimeError(f"{action} failed: {proc.stderr.decode()}")


async def _read_capped(
    stream: asyncio.StreamReader | None, limit: int = _OUTPUT_LIMIT
) -> bytes:
    if stream is None:
        return b""
    retained = bytearray()
    while chunk := await stream.read(64 * 1024):
        if len(retained) < limit:
            retained.extend(chunk[: limit - len(retained)])
    return bytes(retained)


def _safe_relative_path(path: str) -> PurePosixPath:
    if "\\" in path:
        raise ValueError("path must use POSIX separators")
    relative = PurePosixPath(path)
    if (
        not path
        or relative.is_absolute()
        or ".." in relative.parts
        or relative == PurePosixPath(".")
    ):
        raise ValueError("path must stay below /workspace")
    return relative


def _safe_container_cwd(cwd: str) -> str:
    normalized = PurePosixPath(cwd)
    if not normalized.is_absolute() or ".." in normalized.parts:
        raise ValueError("cwd must be an absolute path below /workspace or /code")
    if not any(
        normalized == root or root in normalized.parents
        for root in (PurePosixPath("/workspace"), PurePosixPath("/code"))
    ):
        raise ValueError("cwd must stay below /workspace or /code")
    return normalized.as_posix()
