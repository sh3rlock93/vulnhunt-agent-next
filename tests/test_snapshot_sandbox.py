from __future__ import annotations

import hashlib
import io
import os
import tarfile

import pytest
from pydantic import ValidationError

from tests.factories import HASH_A
from vulnhunt_agent.domain.schemas import OracleSpec, OracleType, ReproductionSpec
from vulnhunt_agent.infrastructure.artifacts import ArtifactStore
from vulnhunt_agent.intake.snapshot import (
    SnapshotBuilder,
    SnapshotError,
    validate_snapshot_archive,
)
from vulnhunt_agent.reproduction.oracles import evaluate_oracle
from vulnhunt_agent.sandbox.base import ExecResult
from vulnhunt_agent.sandbox.hardened import build_exec_args
from vulnhunt_agent.sandbox.policy import NetworkMode, SandboxPolicy, SandboxRole


def test_snapshot_is_deterministic_manifested_and_detached_from_source(tmp_path) -> None:
    source = tmp_path / "source"
    (source / "pkg").mkdir(parents=True)
    (source / ".git").mkdir()
    (source / "__pycache__").mkdir()
    (source / "pkg" / "app.py").write_text("print('safe snapshot')\n")
    (source / "run.sh").write_text("#!/bin/sh\nexit 0\n")
    (source / "run.sh").chmod(0o755)
    (source / ".git" / "config").write_text("secret")
    (source / "__pycache__" / "app.pyc").write_bytes(b"cache")

    artifacts = ArtifactStore(tmp_path / "artifacts")
    builder = SnapshotBuilder(artifacts)
    first = builder.create(
        source,
        source_url="https://example.test/repo.git",
        resolved_ref="abc123",
    )
    os.utime(source / "pkg" / "app.py", (2_000_000_000, 2_000_000_000))
    second = builder.create(
        source,
        source_url="https://example.test/repo.git",
        resolved_ref="abc123",
    )
    assert first == second
    assert first.file_count == 2

    manifest = artifacts.read_text(first.manifest_artifact)
    assert '"path":"pkg/app.py"' in manifest
    assert ".git" in manifest
    assert "__pycache__" in manifest

    source_tar = artifacts.path_for(first.snapshot_artifact)
    with tarfile.open(source_tar) as archive:
        names = archive.getnames()
        assert "pkg/app.py" in names
        assert "run.sh" in names
        assert not any(".git" in name or "__pycache__" in name for name in names)
        assert all(member.mtime == 0 for member in archive.getmembers())

    original = artifacts.read_bytes(first.snapshot_artifact)
    (source / "pkg" / "app.py").write_text("changed\n")
    assert artifacts.read_bytes(first.snapshot_artifact) == original


def test_snapshot_rejects_symlink_escape_and_size_exhaustion(tmp_path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("secret")
    (source / "escape").symlink_to(outside)
    with pytest.raises(SnapshotError, match="symlink"):
        SnapshotBuilder(ArtifactStore(tmp_path / "artifacts")).create(source)

    (source / "escape").unlink()
    (source / "large.bin").write_bytes(b"x" * 9)
    with pytest.raises(SnapshotError, match="size limit"):
        SnapshotBuilder(
            ArtifactStore(tmp_path / "small-artifacts"), max_file_bytes=8
        ).create(source)

    malicious = tmp_path / "malicious.tar"
    with tarfile.open(malicious, "w") as archive:
        member = tarfile.TarInfo("../../host-escape")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(SnapshotError, match="unsafe snapshot member"):
        validate_snapshot_archive(malicious)


def test_hardened_policies_forbid_mount_network_root_and_shell_bypass() -> None:
    reproduce = SandboxPolicy.for_role(SandboxRole.REPRODUCE)
    hunt = SandboxPolicy.for_role(SandboxRole.HUNT)
    build = SandboxPolicy.for_role(SandboxRole.BUILD)
    assert reproduce.network is NetworkMode.NONE
    assert hunt.network is NetworkMode.NONE
    assert build.network is NetworkMode.BRIDGE

    args = reproduce.docker_run_args(name="sandbox-1", image="python:3.12-slim")
    joined = " ".join(args)
    assert "--network=none" in args
    assert "--read-only" in args
    assert "--cap-drop=ALL" in args
    assert "--security-opt=no-new-privileges:true" in args
    assert "--pids-limit" in args
    assert "--user" in args
    assert "-v" not in args
    assert "--volume" not in args
    assert "--mount" not in args
    assert "/var/run/docker.sock" not in joined

    injected = "value; touch /tmp/escaped"
    exec_args = build_exec_args(
        name="sandbox-1",
        cwd=".",
        env={"PYTHONPATH": "/workspace/source"},
        argv=("python", "-c", injected),
    )
    assert exec_args[-1] == injected
    assert "sh" not in exec_args
    with pytest.raises(ValueError, match="not allowlisted"):
        build_exec_args(
            name="sandbox-1",
            cwd=".",
            env={"AWS_SECRET_ACCESS_KEY": "secret"},
            argv=("python", "-V"),
        )
    with pytest.raises(ValueError, match="traverse"):
        build_exec_args(
            name="sandbox-1",
            cwd="../host",
            env={},
            argv=("python", "-V"),
        )
    with pytest.raises(ValueError, match="network=none"):
        SandboxPolicy(
            role=SandboxRole.REPRODUCE,
            network=NetworkMode.BRIDGE,
        )


def test_reproduction_spec_and_oracles_are_machine_enforced() -> None:
    with pytest.raises(ValidationError, match="PoC path"):
        ReproductionSpec(
            reproduction_id="repro-1",
            run_id="run-1",
            candidate_id="cand-1",
            source_snapshot=HASH_A,
            image="python:3.12-slim",
            poc_artifact=HASH_A,
            poc_path="../poc.py",
            argv=("python", "/workspace/poc/poc.py"),
            oracle=OracleSpec(type=OracleType.EXIT_CODE, expected_exit_code=0),
        )
    with pytest.raises(ValidationError, match="Docker image"):
        ReproductionSpec(
            reproduction_id="repro-1",
            run_id="run-1",
            candidate_id="cand-1",
            source_snapshot=HASH_A,
            image="--privileged",
            poc_artifact=HASH_A,
            poc_path="poc.py",
            argv=("python", "/workspace/poc/poc.py"),
            oracle=OracleSpec(type=OracleType.EXIT_CODE, expected_exit_code=0),
        )

    assert evaluate_oracle(
        OracleSpec(type=OracleType.EXIT_CODE, expected_exit_code=0),
        ExecResult(exit_code=0, stdout="", stderr=""),
    ).result == "passed"
    assert evaluate_oracle(
        OracleSpec(type=OracleType.STDOUT_REGEX, pattern=r"LEAKED_[A-Z]+=1"),
        ExecResult(exit_code=0, stdout="LEAKED_SECRET=1", stderr=""),
    ).result == "passed"
    expected = "sha256:" + hashlib.sha256(b"proof").hexdigest()
    assert evaluate_oracle(
        OracleSpec(
            type=OracleType.FILE_SHA256,
            path="proof.txt",
            expected_sha256=expected,
        ),
        ExecResult(
            exit_code=0,
            stdout="",
            stderr="",
            captured_files={"proof.txt": b"proof"},
        ),
    ).result == "passed"
