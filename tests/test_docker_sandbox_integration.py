from __future__ import annotations

import hashlib
import json
import os
import subprocess
import uuid
from dataclasses import replace

import pytest

from vulnhunt_agent.domain.schemas import OracleSpec, OracleType
from vulnhunt_agent.infrastructure.artifacts import ArtifactStore
from vulnhunt_agent.intake.snapshot import SnapshotBuilder
from vulnhunt_agent.reproduction.oracles import evaluate_oracle
from vulnhunt_agent.sandbox.base import SandboxJob
from vulnhunt_agent.sandbox.container import ContainerExecutor
from vulnhunt_agent.sandbox.hardened import HardenedDockerBackend

IMAGE = "python:3.12-slim"


async def test_real_build_and_hunt_sandboxes_use_baked_source_without_mounts(
    tmp_path,
) -> None:
    _require_docker()
    source = tmp_path / "source"
    source.mkdir()
    (source / "target.py").write_text("VALUE = 7\n")
    prepared_image = f"scanner/prepared:m2-test-{uuid.uuid4().hex[:12]}"

    build = ContainerExecutor(
        repo=source,
        image=IMAGE,
        network="none",
        code_writable=True,
    )
    try:
        await build.start()
        inspect = json.loads(subprocess.run(
            ["docker", "inspect", build.name],
            check=True,
            capture_output=True,
            text=True,
        ).stdout)[0]
        assert inspect["HostConfig"]["Binds"] is None
        assert inspect["Mounts"] == []
        check = await build.exec(
            "python -c \"from pathlib import Path; "
            "assert Path('/code/target.py').read_text() == 'VALUE = 7\\\\n'\""
        )
        assert check.exit_code == 0, check.stderr
        await build.commit(prepared_image)
    finally:
        await build.stop()

    hunt = ContainerExecutor(
        repo=source,
        image=prepared_image,
        network="none",
        source_baked=True,
    )
    try:
        await hunt.start()
        inspect = json.loads(subprocess.run(
            ["docker", "inspect", hunt.name],
            check=True,
            capture_output=True,
            text=True,
        ).stdout)[0]
        host = inspect["HostConfig"]
        assert host["Binds"] is None
        assert inspect["Mounts"] == []
        assert host["NetworkMode"] == "none"
        assert host["ReadonlyRootfs"] is True
        assert host["CapDrop"] == ["ALL"]
        assert host["PidsLimit"] == 128
        assert inspect["Config"]["User"] == "65532:65532"
        assert "no-new-privileges" in host["SecurityOpt"]
        await hunt.write_file("proof.py", "print('POC_OK')\n")
        result = await hunt.exec_argv(("python", "/workspace/proof.py"))
        assert result.exit_code == 0
        assert result.stdout.strip() == "POC_OK"

        injection = await hunt.exec_argv(
            (
                "python",
                "-c",
                "import pathlib,sys; "
                "assert sys.argv[1] == 'x; touch /workspace/injected'; "
                "assert not pathlib.Path('/workspace/injected').exists(); "
                "assert pathlib.Path('/code/target.py').read_text() == 'VALUE = 7\\n'; "
                "assert __import__('os').geteuid() != 0",
                "x; touch /workspace/injected",
            )
        )
        assert injection.exit_code == 0, injection.stderr

        source_write = await hunt.exec_argv(
            (
                "python",
                "-c",
                "from pathlib import Path; "
                "Path('/code/target.py').write_text('mutated')",
            )
        )
        assert source_write.exit_code != 0
        assert (source / "target.py").read_text() == "VALUE = 7\n"
    finally:
        await hunt.stop()
        subprocess.run(
            ["docker", "image", "rm", "-f", prepared_image],
            check=False,
            capture_output=True,
        )


async def test_real_docker_sandbox_blocks_escape_primitives(tmp_path) -> None:
    _require_docker()

    source = tmp_path / "source"
    source.mkdir()
    (source / "target.py").write_text("VALUE = 1\n")
    artifacts = ArtifactStore(tmp_path / "artifacts")
    snapshot = SnapshotBuilder(artifacts).create(source)
    poc = artifacts.put_text(
        """
import pathlib
import socket
import os

root_blocked = False
try:
    pathlib.Path("/vulnhunt-host-write").write_text("escape")
except OSError:
    root_blocked = True

source_blocked = False
try:
    pathlib.Path("/workspace/source/target.py").write_text("mutated")
except OSError:
    source_blocked = True

network_blocked = False
try:
    socket.create_connection(("1.1.1.1", 53), timeout=0.2)
except OSError:
    network_blocked = True

assert root_blocked
assert source_blocked
assert network_blocked
assert not pathlib.Path("/var/run/docker.sock").exists()
assert pathlib.Path("/workspace/source/target.py").read_text() == "VALUE = 1\\n"
assert os.geteuid() != 0
status = pathlib.Path("/proc/self/status").read_text()
assert "NoNewPrivs:\\t1" in status
cap_eff = next(line for line in status.splitlines() if line.startswith("CapEff:"))
assert int(cap_eff.split()[1], 16) == 0
pids_max = pathlib.Path("/sys/fs/cgroup/pids.max")
if pids_max.exists() and pids_max.read_text().strip() != "max":
    assert int(pids_max.read_text()) <= 128
output = pathlib.Path("/workspace/output")
output.mkdir()
(output / "proof.txt").write_text("proof")
print("SANDBOX_CONTRACT_OK")
""".strip()
        + "\n",
        "text/x-python",
    )
    job = SandboxJob(
        image=IMAGE,
        source_tar=artifacts.path_for(snapshot.snapshot_artifact),
        poc_file=artifacts.path_for(poc.digest),
        poc_path="contract.py",
        argv=("python", "/workspace/poc/contract.py"),
        cwd=".",
        env={"PYTHONPATH": "/workspace/source"},
        timeout_seconds=20,
        capture_files=("output/proof.txt",),
    )
    backend = HardenedDockerBackend()
    executions = [await backend.execute(job), await backend.execute(job)]
    oracle = OracleSpec(
        type=OracleType.STDOUT_REGEX,
        pattern="SANDBOX_CONTRACT_OK",
    )
    file_oracle = OracleSpec(
        type=OracleType.FILE_SHA256,
        path="output/proof.txt",
        expected_sha256="sha256:" + hashlib.sha256(b"proof").hexdigest(),
    )
    assert {execution.image_digest for execution in executions} == {
        executions[0].image_digest
    }
    for execution in executions:
        assert execution.result.exit_code == 0, execution.result.stderr
        assert evaluate_oracle(oracle, execution.result).result == "passed"
        assert evaluate_oracle(file_oracle, execution.result).result == "passed"

    timed = await backend.execute(
        replace(
            job,
            argv=("python", "-c", "import time; time.sleep(5)"),
            timeout_seconds=1,
            capture_files=(),
        )
    )
    assert timed.result.timed_out
    assert timed.result.duration_ms < 3_000

    noisy = await backend.execute(
        replace(
            job,
            argv=("python", "-c", "print('x' * 2_000_000)"),
            capture_files=(),
        )
    )
    assert noisy.result.exit_code == 0
    assert len(noisy.result.stdout.encode()) == 1024 * 1024


def _require_docker() -> None:
    if os.environ.get("VULNHUNT_RUN_DOCKER_TESTS") != "1":
        pytest.skip("set VULNHUNT_RUN_DOCKER_TESTS=1 for the real Docker contract")
    subprocess.run(["docker", "info"], check=True, capture_output=True)
    subprocess.run(["docker", "image", "inspect", IMAGE], check=True, capture_output=True)
