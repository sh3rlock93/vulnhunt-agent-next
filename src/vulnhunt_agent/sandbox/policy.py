"""Role-specific hardened sandbox policy and Docker CLI argument generation."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SandboxRole(StrEnum):
    BUILD = "build"
    HUNT = "hunt"
    REPRODUCE = "reproduce"


class NetworkMode(StrEnum):
    NONE = "none"
    BRIDGE = "bridge"


@dataclass(frozen=True)
class SandboxPolicy:
    role: SandboxRole
    network: NetworkMode = NetworkMode.NONE
    cpus: str = "1"
    memory: str = "512m"
    pids_limit: int = 128
    workspace_size: str = "256m"
    tmp_size: str = "64m"
    user: str = "65532:65532"
    read_only_root: bool = True

    def __post_init__(self) -> None:
        if self.role in {SandboxRole.HUNT, SandboxRole.REPRODUCE}:
            if self.network is not NetworkMode.NONE:
                raise ValueError(f"{self.role.value} sandbox must use network=none")
            if not self.read_only_root:
                raise ValueError(f"{self.role.value} sandbox requires a read-only root")
            if self.user.split(":", 1)[0] == "0":
                raise ValueError(f"{self.role.value} sandbox may not run as root")
        if self.pids_limit < 16:
            raise ValueError("sandbox pids_limit is too small")

    @classmethod
    def for_role(cls, role: SandboxRole) -> "SandboxPolicy":
        if role is SandboxRole.BUILD:
            return cls(
                role=role,
                network=NetworkMode.BRIDGE,
                cpus="2",
                memory="2g",
                pids_limit=256,
                workspace_size="1g",
                tmp_size="256m",
            )
        return cls(role=role)

    def docker_run_args(self, *, name: str, image: str) -> list[str]:
        args = [
            "run",
            "-d",
            "--name",
            name,
            "--label",
            f"vulnhunt.role={self.role.value}",
            f"--network={self.network.value}",
            "--cpus",
            self.cpus,
            "--memory",
            self.memory,
            "--pids-limit",
            str(self.pids_limit),
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--user",
            self.user,
            "--ipc=none",
            "--ulimit",
            "nofile=1024:1024",
            "--tmpfs",
            f"/workspace:rw,nosuid,nodev,size={self.workspace_size},mode=1777",
            "--tmpfs",
            f"/tmp:rw,nosuid,nodev,noexec,size={self.tmp_size},mode=1777",
            "--env",
            "HOME=/tmp",
            "--workdir",
            "/workspace",
        ]
        if self.read_only_root:
            args.append("--read-only")
        args.extend([image, "sleep", "infinity"])
        return args
