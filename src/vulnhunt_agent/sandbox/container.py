"""Container-based sandbox. Uses the local `docker` CLI."""
from __future__ import annotations

import asyncio
import secrets
import subprocess
from pathlib import Path

from ..core.settings import ENV_TO_IMAGE
from . import cleanup
from .base import ExecResult


_WORKSPACE_SIZE = "256m"


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
        code_writable: bool = False,      # set True during prepare so npm/mvn can write into /code
    ):
        self.repo = repo.resolve()
        self.image = image
        self.network = network
        self.cpus = cpus
        self.memory = memory
        self.code_writable = code_writable
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
        await self._ensure_image()
        code_mount = f"{self.repo}:/code" + ("" if self.code_writable else ":ro")
        proc = await self._run_cli(
            "run", "-d",
            "--name", self.name,
            f"--network={self.network}",
            "--cpus", self.cpus,
            "--memory", self.memory,
            "--tmpfs", f"/workspace:size={_WORKSPACE_SIZE}",
            "-v", code_mount,
            "-w", "/workspace",
            self.image,
            "sleep", "infinity",
        )
        _check(proc, "start sandbox")
        self._started = True
        cleanup.register(self.name)

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
        if path.startswith("/"):
            raise ValueError("path must be relative to /workspace")
        full = f"/workspace/{path}"
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", "-i", self.name,
            "sh", "-c", f"mkdir -p $(dirname {full}) && cat > {full}",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate(content.encode())
        if proc.returncode != 0:
            raise RuntimeError(f"write_file failed: {stderr.decode()}")

    async def exec(self, cmd: str, timeout: int = 60) -> ExecResult:
        """Run a shell command inside the container."""
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", self.name, "sh", "-lc", cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return ExecResult(exit_code=-1, stdout="", stderr="timeout", timed_out=True)
        return ExecResult(
            exit_code=proc.returncode if proc.returncode is not None else -1,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
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
        proc = await asyncio.create_subprocess_exec(
            "docker", *args,
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


def _check(proc, action: str) -> None:
    if proc.returncode != 0:
        raise RuntimeError(f"{action} failed: {proc.stderr.decode()}")
