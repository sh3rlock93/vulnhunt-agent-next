"""Disposable Docker backend with no bind mounts and argv-only execution."""
from __future__ import annotations

import asyncio
import re
import secrets
import subprocess
import time
from pathlib import Path, PurePosixPath

from ..intake.snapshot import validate_snapshot_archive
from . import cleanup
from .base import ExecResult, SandboxExecution, SandboxJob, validate_argv
from .policy import SandboxPolicy, SandboxRole

_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ENV_ALLOWLIST = frozenset({"CLASSPATH", "LANG", "LC_ALL", "NODE_PATH", "PYTHONPATH"})
_OUTPUT_LIMIT = 1024 * 1024
_POC_LIMIT = 4 * 1024 * 1024


class HardenedDockerBackend:
    """Create a clean container for every execution attempt."""

    def __init__(self, policy: SandboxPolicy | None = None):
        self.policy = policy or SandboxPolicy.for_role(SandboxRole.REPRODUCE)
        if self.policy.role is not SandboxRole.REPRODUCE:
            raise ValueError("HardenedDockerBackend requires the reproduce role")

    async def execute(self, job: SandboxJob) -> SandboxExecution:
        validate_job(job)
        name = f"{cleanup.NAME_PREFIX}repro_{secrets.token_hex(5)}"
        image_digest = await self._image_digest(job.image)
        started = False
        try:
            proc = await self._run_cli(
                *self.policy.docker_run_args(name=name, image=job.image)
            )
            _check(proc, "start hardened reproduction sandbox")
            started = True
            cleanup.register(name)

            await self._setup_source(name, job)
            completed_setup: list[ExecResult] = []
            for command in job.setup_argvs:
                setup_result = await self._exec_argv(name, job, command)
                completed_setup.append(setup_result)
                if setup_result.exit_code != 0 or setup_result.timed_out:
                    break
            setup_results = tuple(completed_setup)
            if all(
                item.exit_code == 0 and not item.timed_out
                for item in setup_results
            ):
                result = await self._exec_argv(name, job, job.argv)
            else:
                failed = next(
                    item for item in setup_results
                    if item.exit_code != 0 or item.timed_out
                )
                result = ExecResult(
                    exit_code=failed.exit_code,
                    stdout=failed.stdout,
                    stderr=("setup command failed\n" + failed.stderr).strip(),
                    timed_out=failed.timed_out,
                    duration_ms=failed.duration_ms,
                )
            result.captured_files = await self._capture_files(name, job.capture_files)
            return SandboxExecution(
                image_digest=image_digest,
                result=result,
                setup_results=setup_results,
                environment_id=name,
            )
        finally:
            if started:
                await self._run_cli("rm", "-f", name)
                cleanup.unregister(name)

    async def _setup_source(self, name: str, job: SandboxJob) -> None:
        _check(
            await self._run_cli(
                "exec",
                name,
                "mkdir",
                "-p",
                "/workspace/source",
                "/workspace/poc",
                "/workspace/exec",
            ),
            "create workspace directories",
        )
        _check(
            await self._stream_cli(
                job.source_tar,
                "exec",
                "-i",
                name,
                "tar",
                "-xf",
                "-",
                "-C",
                "/workspace/source",
            ),
            "extract streamed source",
        )
        _check(
            await self._run_cli("exec", name, "chmod", "-R", "a-w", "/workspace/source"),
            "freeze source",
        )

        destination = PurePosixPath("/workspace/poc") / job.poc_path
        parent = str(destination.parent)
        _check(
            await self._run_cli("exec", name, "mkdir", "-p", parent),
            "create PoC directory",
        )
        _check(
            await self._stream_cli(
                job.poc_file,
                "exec",
                "-i",
                name,
                "tee",
                str(destination),
            ),
            "stream PoC",
        )

    async def _exec_argv(
        self,
        name: str,
        job: SandboxJob,
        argv: tuple[str, ...],
    ) -> ExecResult:
        args = build_exec_args(name=name, cwd=job.cwd, env=job.env, argv=argv)
        started_at = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            "docker",
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_task = asyncio.create_task(_read_capped(proc.stdout))
        stderr_task = asyncio.create_task(_read_capped(proc.stderr))
        try:
            await asyncio.wait_for(proc.wait(), timeout=job.timeout_seconds)
            stdout = await stdout_task
            stderr = await stderr_task
            return ExecResult(
                exit_code=proc.returncode if proc.returncode is not None else -1,
                stdout=_decode(stdout),
                stderr=_decode(stderr),
                duration_ms=int((time.monotonic() - started_at) * 1000),
            )
        except asyncio.TimeoutError:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            await self._run_cli("kill", name)
            stdout = await stdout_task
            stderr = await stderr_task
            return ExecResult(
                exit_code=-1,
                stdout=_decode(stdout),
                stderr=(_decode(stderr) + "\nexecution timed out").strip(),
                timed_out=True,
                duration_ms=int((time.monotonic() - started_at) * 1000),
            )

    async def _capture_files(
        self, name: str, paths: tuple[str, ...]
    ) -> dict[str, bytes]:
        captured: dict[str, bytes] = {}
        for path in paths:
            full = str(PurePosixPath("/workspace") / path)
            proc = await self._run_cli("exec", name, "cat", full)
            if proc.returncode == 0:
                captured[path] = proc.stdout[:_OUTPUT_LIMIT]
        return captured

    async def _image_digest(self, image: str) -> str:
        proc = await self._run_cli("image", "inspect", "--format={{.Id}}", image)
        _check(proc, f"inspect image {image}")
        digest = proc.stdout.decode().strip()
        if _IMAGE_DIGEST.fullmatch(digest) is None:
            raise RuntimeError(f"Docker returned an invalid image digest: {digest}")
        return digest

    async def _run_cli(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return subprocess.CompletedProcess(
            args=("docker", *args),
            returncode=proc.returncode if proc.returncode is not None else -1,
            stdout=stdout,
            stderr=stderr,
        )

    async def _stream_cli(
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


def build_exec_args(
    *, name: str, cwd: str, env: dict[str, str], argv: tuple[str, ...]
) -> list[str]:
    validate_argv(argv)
    _validate_relative_path(cwd, label="sandbox cwd")
    args = ["exec", "--workdir", str(PurePosixPath("/workspace/source") / cwd)]
    for key, value in sorted(env.items()):
        if key not in _ENV_ALLOWLIST:
            raise ValueError(f"environment variable is not allowlisted: {key}")
        if "\0" in value:
            raise ValueError(f"environment variable contains NUL: {key}")
        args.extend(["--env", f"{key}={value}"])
    args.append(name)
    args.extend(argv)
    return args


def validate_job(job: SandboxJob) -> None:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}", job.image) is None:
        raise ValueError("invalid Docker image reference")
    validate_argv(job.argv)
    for command in job.setup_argvs:
        validate_argv(command)
    _validate_relative_path(job.cwd, label="sandbox cwd")
    _validate_relative_path(job.poc_path, label="PoC path")
    if PurePosixPath(job.poc_path) == PurePosixPath("."):
        raise ValueError("PoC path must identify a file")
    for path in job.capture_files:
        _validate_relative_path(path, label="capture path")
    if not job.source_tar.is_file():
        raise FileNotFoundError(job.source_tar)
    if not job.poc_file.is_file():
        raise FileNotFoundError(job.poc_file)
    if job.poc_file.stat().st_size > _POC_LIMIT:
        raise ValueError("PoC artifact exceeds size limit")
    validate_snapshot_archive(job.source_tar)
    build_exec_args(name="validation", cwd=job.cwd, env=job.env, argv=job.argv)


def _validate_relative_path(value: str, *, label: str) -> None:
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must be relative and may not traverse parents")


def _decode(value: bytes) -> str:
    return value[:_OUTPUT_LIMIT].decode(errors="replace")


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


def _check(proc: subprocess.CompletedProcess[bytes], action: str) -> None:
    if proc.returncode != 0:
        error = proc.stderr[:8192].decode(errors="replace")
        raise RuntimeError(f"{action} failed: {error}")
