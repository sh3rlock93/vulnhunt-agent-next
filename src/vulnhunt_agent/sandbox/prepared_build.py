"""Serializable, content-addressed plans for the existing native build path."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

PREPARED_BUILD_PLAN_POLICY = "prepared-build-plan-v1"
C_SANITIZER_FLAGS = "-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined"
RIPGREP_INSTALL_COMMAND = (
    "if ! command -v rg >/dev/null 2>&1; then "
    "apt-get update && apt-get install -y --no-install-recommends ripgrep "
    "&& rm -rf /var/lib/apt/lists/*; fi"
)
C_TOOLCHAIN_COMMAND = (
    "apt-get update && apt-get install -y --no-install-recommends "
    "cmake ninja-build meson flex bison autoconf automake libtool pkg-config "
    "&& rm -rf /var/lib/apt/lists/*"
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class CBuildSystem(StrEnum):
    CMAKE = "cmake"
    MESON = "meson"
    AUTOTOOLS = "autotools"
    MAKE = "make"
    UNSUPPORTED = "unsupported"


class PreparedBuildUnsupportedReason(StrEnum):
    NONE = "none"
    MISSING_BUILD_DESCRIPTOR = "missing_build_descriptor"


@dataclass(frozen=True)
class CBuildSelection:
    build_system: CBuildSystem
    descriptor: str
    install_commands: tuple[str, ...]
    expected_artifact_roots: tuple[str, ...]
    unsupported_reason: PreparedBuildUnsupportedReason = PreparedBuildUnsupportedReason.NONE

    @property
    def supported(self) -> bool:
        return self.unsupported_reason is PreparedBuildUnsupportedReason.NONE


@dataclass(frozen=True)
class PreparedBuildPlan:
    source_snapshot_sha256: str
    base_image: str
    build_system: CBuildSystem
    descriptor: str
    support_commands: tuple[str, ...]
    install_commands: tuple[str, ...]
    verify_commands: tuple[str, ...]
    compiler: str
    compiler_flags: tuple[str, ...]
    sanitizers: tuple[str, ...]
    expected_artifact_roots: tuple[str, ...]
    unsupported_reason: PreparedBuildUnsupportedReason
    policy_version: str = PREPARED_BUILD_PLAN_POLICY

    @property
    def supported(self) -> bool:
        return self.unsupported_reason is PreparedBuildUnsupportedReason.NONE

    def _core_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "policy_version": self.policy_version,
            "language": "c",
            "supported": self.supported,
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "base_image": self.base_image,
            "build_system": self.build_system.value,
            "descriptor": self.descriptor,
            "commands": {
                "support": list(self.support_commands),
                "install": list(self.install_commands),
                "verify": list(self.verify_commands),
            },
            "compiler": {
                "executable": self.compiler,
                "flags": list(self.compiler_flags),
                "sanitizers": list(self.sanitizers),
            },
            "expected_artifact_roots": list(self.expected_artifact_roots),
            "unsupported_reason": self.unsupported_reason.value,
        }

    @property
    def plan_sha256(self) -> str:
        return _canonical_sha256(self._core_dict())

    @property
    def image_identity_sha256(self) -> str:
        return _canonical_sha256({
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "base_image": self.base_image,
            "plan_sha256": self.plan_sha256,
        })

    @property
    def image_tag(self) -> str:
        digest = self.image_identity_sha256.removeprefix("sha256:")
        return f"scanner/prepared:c-{digest[:24]}"

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._core_dict(),
            "plan_sha256": self.plan_sha256,
            "image_identity_sha256": self.image_identity_sha256,
            "image_tag": self.image_tag,
        }

    def canonical_bytes(self) -> bytes:
        return (
            json.dumps(
                self.to_dict(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            + "\n"
        ).encode("utf-8")


def select_c_build(repo: Path) -> CBuildSelection:
    """Select the first existing native layout using the historical precedence."""
    flags = C_SANITIZER_FLAGS
    if (repo / "CMakeLists.txt").is_file():
        return CBuildSelection(
            build_system=CBuildSystem.CMAKE,
            descriptor="CMakeLists.txt",
            install_commands=(
                C_TOOLCHAIN_COMMAND,
                "cmake -S /code -B /opt/vulnhunt/build "
                "-DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF "
                f"-DCMAKE_C_FLAGS='{flags}'",
                "cmake --build /opt/vulnhunt/build --parallel 2",
            ),
            expected_artifact_roots=("/opt/vulnhunt/build",),
        )
    if (repo / "meson.build").is_file():
        return CBuildSelection(
            build_system=CBuildSystem.MESON,
            descriptor="meson.build",
            install_commands=(
                C_TOOLCHAIN_COMMAND,
                "meson setup /opt/vulnhunt/build /code "
                "--buildtype=debug --default-library=static "
                f"-Dc_args='{flags}'",
                "meson compile -C /opt/vulnhunt/build -j 2",
            ),
            expected_artifact_roots=("/opt/vulnhunt/build",),
        )
    if (repo / "configure").is_file() or (repo / "configure.ac").is_file():
        descriptor = "configure" if (repo / "configure").is_file() else "configure.ac"
        bootstrap = (
            "if [ ! -x /code/configure ]; then cd /code && autoreconf -fi; fi; "
            "mkdir -p /opt/vulnhunt/build && cd /opt/vulnhunt/build && "
            f"CFLAGS='{flags}' /code/configure --disable-shared --enable-static"
        )
        return CBuildSelection(
            build_system=CBuildSystem.AUTOTOOLS,
            descriptor=descriptor,
            install_commands=(
                C_TOOLCHAIN_COMMAND,
                bootstrap,
                "make -C /opt/vulnhunt/build -j2",
            ),
            expected_artifact_roots=("/opt/vulnhunt/build",),
        )
    if (repo / "Makefile").is_file() or (repo / "GNUmakefile").is_file():
        descriptor = "Makefile" if (repo / "Makefile").is_file() else "GNUmakefile"
        return CBuildSelection(
            build_system=CBuildSystem.MAKE,
            descriptor=descriptor,
            install_commands=(
                C_TOOLCHAIN_COMMAND,
                f"make -C /code -j2 CFLAGS='{flags}'",
            ),
            expected_artifact_roots=("/code",),
        )
    return CBuildSelection(
        build_system=CBuildSystem.UNSUPPORTED,
        descriptor="",
        install_commands=(),
        expected_artifact_roots=(),
        unsupported_reason=PreparedBuildUnsupportedReason.MISSING_BUILD_DESCRIPTOR,
    )


def create_c_prepared_build_plan(
    repo: Path,
    *,
    source_snapshot_sha256: str,
    base_image: str,
) -> PreparedBuildPlan:
    if _SHA256.fullmatch(source_snapshot_sha256) is None:
        raise ValueError("prepared build source snapshot must be a SHA-256 digest")
    if not base_image or "\0" in base_image:
        raise ValueError("prepared build base image is invalid")
    selection = select_c_build(repo)
    support = (RIPGREP_INSTALL_COMMAND,) if selection.supported else ()
    return PreparedBuildPlan(
        source_snapshot_sha256=source_snapshot_sha256,
        base_image=base_image,
        build_system=selection.build_system,
        descriptor=selection.descriptor,
        support_commands=support,
        install_commands=selection.install_commands,
        verify_commands=("cc --version",) if selection.supported else (),
        compiler="cc",
        compiler_flags=(
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fsanitize=address,undefined",
        ),
        sanitizers=("address", "undefined"),
        expected_artifact_roots=selection.expected_artifact_roots,
        unsupported_reason=selection.unsupported_reason,
    )


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
