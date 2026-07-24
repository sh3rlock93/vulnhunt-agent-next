"""Serializable, content-addressed plans for the existing native build path."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from copy import deepcopy
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

PREPARED_BUILD_PLAN_POLICY = "prepared-build-plan-v1"
PREPARED_BUILD_RECEIPT_POLICY = "prepared-build-v1"
C_SANITIZER_FLAGS = "-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined"
C_CMAKE_COMPATIBILITY_FLAG = "-Wno-error=format-overflow"
PACKAGE_LOCK_PATH = "/opt/vulnhunt/apt-packages.lock"
_C_PACKAGES = (
    "autoconf automake bison cmake file flex libtool meson ninja-build "
    "pkg-config ripgrep"
)
C_TOOLCHAIN_COMMAND = (
    "set -eu; apt-get update; mkdir -p /opt/vulnhunt; "
    f"packages='{_C_PACKAGES}'; "
    "apt-get --simulate install -y --no-install-recommends $packages "
    "| awk '/^Inst / { version=$3; gsub(/[()]/, \"\", version); "
    "print $2 \"=\" version }' | LC_ALL=C sort -u "
    f"> {PACKAGE_LOCK_PATH}; "
    f"test -s {PACKAGE_LOCK_PATH}; "
    f"xargs apt-get install -y --no-install-recommends < {PACKAGE_LOCK_PATH}; "
    f"while IFS= read -r locked; do pkg=${{locked%%=*}}; version=${{locked#*=}}; "
    "test \"$(dpkg-query -W -f='${Version}' \"$pkg\")\" = \"$version\"; "
    f"done < {PACKAGE_LOCK_PATH}; "
    "rm -rf /var/lib/apt/lists/*"
)
RIPGREP_INSTALL_COMMAND = (
    "if ! command -v rg >/dev/null 2>&1; then "
    "apt-get update && apt-get install -y --no-install-recommends ripgrep "
    "&& rm -rf /var/lib/apt/lists/*; fi"
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_EQUIVALENCE_EXCLUSIONS = [
    "images.final.digest",
    "commands[*].duration_ms",
    "commands[*].stdout_sha256",
    "commands[*].stderr_sha256",
    "tests[*].duration_ms",
    "tests[*].stdout_sha256",
    "tests[*].stderr_sha256",
]


class CBuildSystem(StrEnum):
    CMAKE = "cmake"
    MESON = "meson"
    AUTOTOOLS = "autotools"
    MAKE = "make"
    UNSUPPORTED = "unsupported"


class PreparedBuildUnsupportedReason(StrEnum):
    NONE = "none"
    MISSING_BUILD_DESCRIPTOR = "missing_build_descriptor"


class PreparedBuildFailureCode(StrEnum):
    PACKAGE_LOCK_MISSING = "package_lock_missing"
    PACKAGE_INSTALL_FAILED = "package_install_failed"
    NETWORK_ISOLATION_FAILED = "network_isolation_failed"
    BUILD_COMMAND_FAILED = "build_command_failed"
    TEST_COMMAND_FAILED = "test_command_failed"
    VERIFY_COMMAND_FAILED = "verify_command_failed"
    ARTIFACT_ROOT_MISSING = "artifact_root_missing"
    ARTIFACT_MISSING = "artifact_missing"
    SANITIZER_PROVENANCE_MISSING = "sanitizer_provenance_missing"
    IMAGE_DIGEST_UNAVAILABLE = "image_digest_unavailable"


class PreparedBuildVerificationError(RuntimeError):
    def __init__(self, code: PreparedBuildFailureCode, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class CBuildSelection:
    build_system: CBuildSystem
    descriptor: str
    install_commands: tuple[str, ...]
    test_commands: tuple[str, ...]
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
    test_commands: tuple[str, ...]
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
                "test": list(self.test_commands),
                "verify": list(self.verify_commands),
            },
            "compiler": {
                "executable": self.compiler,
                "flags": list(self.compiler_flags),
                "sanitizers": list(self.sanitizers),
            },
            "expected_artifact_roots": list(self.expected_artifact_roots),
            "network": {
                "preparation": "bridge",
                "networked_phases": ["package_install"],
                "offline_phases": ["build", "test", "verify", "artifact_verification"],
                "hunt": "none",
                "reproduction": "none",
            },
            "package_lock_path": PACKAGE_LOCK_PATH if self.supported else "",
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


@dataclass(frozen=True)
class PreparedCommandResult:
    phase: str
    command: str
    exit_code: int
    timed_out: bool
    duration_ms: int
    stdout_sha256: str
    stderr_sha256: str
    outcome: str = "passed"
    stdout: str = field(default="", repr=False, compare=False)
    stderr: str = field(default="", repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "command": self.command,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "outcome": self.outcome,
        }


@dataclass(frozen=True)
class PreparedArtifact:
    path: str
    size_bytes: int
    sha256: str
    sanitizer_markers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "sanitizer_markers": list(self.sanitizer_markers),
        }


@dataclass(frozen=True)
class PreparedBuildReceipt:
    source_snapshot_sha256: str
    plan_sha256: str
    build_system: CBuildSystem
    base_image: str
    base_image_digest: str
    final_image: str
    final_image_digest: str
    package_lock_entries: tuple[str, ...]
    package_lock_sha256: str
    compiler_version: str
    command_results: tuple[PreparedCommandResult, ...]
    test_results: tuple[PreparedCommandResult, ...]
    artifacts: tuple[PreparedArtifact, ...]
    policy_version: str = PREPARED_BUILD_RECEIPT_POLICY

    def _core_dict(self) -> dict[str, Any]:
        sanitizer_artifacts = [
            artifact.path for artifact in self.artifacts if artifact.sanitizer_markers
        ]
        return {
            "schema_version": 1,
            "policy_version": self.policy_version,
            "status": "verified",
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "plan_sha256": self.plan_sha256,
            "build_system": self.build_system.value,
            "images": {
                "base": {"reference": self.base_image, "digest": self.base_image_digest},
                "final": {"reference": self.final_image, "digest": self.final_image_digest},
            },
            "network": {
                "preparation": "bridge",
                "networked_phases": ["package_install"],
                "isolated_before": ["build", "test", "verify", "artifact_verification", "commit"],
                "hunt": "none",
                "reproduction": "none",
            },
            "package_lock": {
                "path": PACKAGE_LOCK_PATH,
                "sha256": self.package_lock_sha256,
                "entries": list(self.package_lock_entries),
            },
            "compiler": {
                "executable": "cc",
                "version": self.compiler_version,
                "version_sha256": _text_sha256(self.compiler_version),
            },
            "commands": [result.to_dict() for result in self.command_results],
            "tests": [result.to_dict() for result in self.test_results],
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "sanitizer_provenance": {
                "required": ["address", "undefined"],
                "observed": sorted({
                    marker
                    for artifact in self.artifacts
                    for marker in artifact.sanitizer_markers
                }),
                "artifacts": sanitizer_artifacts,
            },
            "equivalence_exclusions": [
                *_EQUIVALENCE_EXCLUSIONS,
            ],
        }

    def _equivalence_dict(self) -> dict[str, Any]:
        value = self._core_dict()
        value["images"]["final"]["digest"] = "<excluded>"
        for key in ("commands", "tests"):
            for result in value[key]:
                result["duration_ms"] = 0
                result["stdout_sha256"] = "<excluded>"
                result["stderr_sha256"] = "<excluded>"
        return value

    @property
    def equivalence_sha256(self) -> str:
        return _canonical_sha256(self._equivalence_dict())

    @property
    def receipt_sha256(self) -> str:
        return _canonical_sha256({
            **self._core_dict(),
            "equivalence_sha256": self.equivalence_sha256,
        })

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._core_dict(),
            "equivalence_sha256": self.equivalence_sha256,
            "receipt_sha256": self.receipt_sha256,
        }


def select_c_build(
    repo: Path,
    *,
    cmake_options: tuple[str, ...] = (),
    configure_options: tuple[str, ...] = (),
) -> CBuildSelection:
    """Select the first existing native layout using the historical precedence."""
    flags = C_SANITIZER_FLAGS
    if (repo / "CMakeLists.txt").is_file():
        if configure_options:
            raise ValueError("Autotools options require an Autotools build descriptor")
        option_args = _validated_cmake_option_args(repo, cmake_options)
        cmake_flags = f"{flags} {C_CMAKE_COMPATIBILITY_FLAG}"
        return CBuildSelection(
            build_system=CBuildSystem.CMAKE,
            descriptor="CMakeLists.txt",
            install_commands=(
                "cmake -S /code -B /opt/vulnhunt/build "
                "-DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF "
                f"-DCMAKE_C_FLAGS='{cmake_flags}'{option_args}",
                "cmake --build /opt/vulnhunt/build --parallel 2",
            ),
            test_commands=(
                "if [ -f /opt/vulnhunt/build/CTestTestfile.cmake ]; then "
                "ctest --test-dir /opt/vulnhunt/build --output-on-failure; "
                "else printf 'VULNHUNT_TESTS_NOT_DECLARED\\n'; fi",
            ),
            expected_artifact_roots=("/opt/vulnhunt/build",),
        )
    if (repo / "meson.build").is_file():
        _reject_foreign_build_options(cmake_options, configure_options)
        return CBuildSelection(
            build_system=CBuildSystem.MESON,
            descriptor="meson.build",
            install_commands=(
                "meson setup /opt/vulnhunt/build /code "
                "--buildtype=debug --default-library=static "
                f"-Dc_args='{flags}'",
                "meson compile -C /opt/vulnhunt/build -j 2",
            ),
            test_commands=("meson test -C /opt/vulnhunt/build --print-errorlogs",),
            expected_artifact_roots=("/opt/vulnhunt/build",),
        )
    if (repo / "configure").is_file() or (repo / "configure.ac").is_file():
        if cmake_options:
            raise ValueError("CMake options require a CMake build descriptor")
        option_args = _validated_configure_option_args(repo, configure_options)
        descriptor = "configure" if (repo / "configure").is_file() else "configure.ac"
        if _legacy_autotools_requires_source_copy(repo):
            bootstrap = (
                "mkdir -p /opt/vulnhunt/build && "
                "tar -C /code --exclude=.git --exclude=.hg --exclude=.svn -cf - . "
                "| tar -C /opt/vulnhunt/build -xf - && "
                "cd /opt/vulnhunt/build && "
                f"CFLAGS='{flags}' LDFLAGS='{flags}' "
                "./configure --disable-shared --enable-static"
                f"{option_args}"
            )
        else:
            bootstrap = (
                "if [ ! -x /code/configure ]; then cd /code && autoreconf -fi; fi; "
                "mkdir -p /opt/vulnhunt/build && cd /opt/vulnhunt/build && "
                f"CFLAGS='{flags}' LDFLAGS='{flags}' "
                "/code/configure --disable-shared --enable-static"
                f"{option_args}"
            )
        return CBuildSelection(
            build_system=CBuildSystem.AUTOTOOLS,
            descriptor=descriptor,
            install_commands=(
                bootstrap,
                "ASAN_OPTIONS=detect_leaks=0 make -C /opt/vulnhunt/build -j2",
            ),
            test_commands=(
                "if make -C /opt/vulnhunt/build -n check >/dev/null 2>&1; then "
                "make -C /opt/vulnhunt/build check; "
                "else printf 'VULNHUNT_TESTS_NOT_DECLARED\\n'; fi",
            ),
            expected_artifact_roots=("/opt/vulnhunt/build",),
        )
    if (repo / "Makefile").is_file() or (repo / "GNUmakefile").is_file():
        _reject_foreign_build_options(cmake_options, configure_options)
        descriptor = "Makefile" if (repo / "Makefile").is_file() else "GNUmakefile"
        return CBuildSelection(
            build_system=CBuildSystem.MAKE,
            descriptor=descriptor,
            install_commands=(
                f"make -C /code -j2 CFLAGS='{flags}'",
            ),
            test_commands=(
                "if make -C /code -n check >/dev/null 2>&1; then make -C /code check; "
                "elif make -C /code -n test >/dev/null 2>&1; then make -C /code test; "
                "else printf 'VULNHUNT_TESTS_NOT_DECLARED\\n'; fi",
            ),
            expected_artifact_roots=("/code",),
        )
    _reject_foreign_build_options(cmake_options, configure_options)
    return CBuildSelection(
        build_system=CBuildSystem.UNSUPPORTED,
        descriptor="",
        install_commands=(),
        test_commands=(),
        expected_artifact_roots=(),
        unsupported_reason=PreparedBuildUnsupportedReason.MISSING_BUILD_DESCRIPTOR,
    )


def create_c_prepared_build_plan(
    repo: Path,
    *,
    source_snapshot_sha256: str,
    base_image: str,
    cmake_options: tuple[str, ...] = (),
    configure_options: tuple[str, ...] = (),
) -> PreparedBuildPlan:
    if _SHA256.fullmatch(source_snapshot_sha256) is None:
        raise ValueError("prepared build source snapshot must be a SHA-256 digest")
    if not base_image or "\0" in base_image:
        raise ValueError("prepared build base image is invalid")
    selection = select_c_build(
        repo,
        cmake_options=cmake_options,
        configure_options=configure_options,
    )
    support = (C_TOOLCHAIN_COMMAND,) if selection.supported else ()
    return PreparedBuildPlan(
        source_snapshot_sha256=source_snapshot_sha256,
        base_image=base_image,
        build_system=selection.build_system,
        descriptor=selection.descriptor,
        support_commands=support,
        install_commands=selection.install_commands,
        test_commands=selection.test_commands,
        verify_commands=("cc --version",) if selection.supported else (),
        compiler="cc",
        compiler_flags=(
            "-O1",
            "-g",
            "-fno-omit-frame-pointer",
            "-fsanitize=address,undefined",
        ) + (
            (C_CMAKE_COMPATIBILITY_FLAG,)
            if selection.build_system is CBuildSystem.CMAKE
            else ()
        ),
        sanitizers=("address", "undefined"),
        expected_artifact_roots=selection.expected_artifact_roots,
        unsupported_reason=selection.unsupported_reason,
    )


def artifact_inventory_command(roots: tuple[str, ...]) -> str:
    """Return the approved offline command that inventories native outputs."""
    if not roots or any(not root.startswith("/") or "\0" in root for root in roots):
        raise ValueError("artifact roots must be non-empty absolute container paths")
    quoted_roots = " ".join(shlex.quote(root) for root in roots)
    return (
        "set -eu; count=0; "
        f"find {quoted_roots} -type f -readable -print | LC_ALL=C sort | "
        "while IFS= read -r artifact; do "
        "case \"$artifact\" in "
        "*/CMakeFiles/*/CompilerIdC/*|*/CMakeFiles/*/CMakeDetermineCompilerABI_C.bin|"
        "*/CMakeFiles/CMakeScratch/*|*/CMakeFiles/CMakeTmp/*|"
        "*/meson-private/sanitycheckc*) continue ;; esac; "
        "kind=$(file -b -- \"$artifact\"); "
        "case \"$kind\" in *ELF*|*current\\ ar\\ archive*) ;; *) continue ;; esac; "
        "count=$((count + 1)); test \"$count\" -le 4096; "
        "size=$(wc -c < \"$artifact\" | tr -d ' '); "
        "digest=$(sha256sum \"$artifact\" | awk '{print $1}'); "
        "symbols=$({ nm -A \"$artifact\" 2>/dev/null || true; "
        "nm -D -A \"$artifact\" 2>/dev/null || true; }); "
        "markers=''; "
        "if printf '%s' \"$symbols\" | grep -q '__asan_'; then markers='address'; fi; "
        "if printf '%s' \"$symbols\" | grep -q '__ubsan_'; then "
        "if [ -n \"$markers\" ]; then markers=\"$markers,undefined\"; "
        "else markers='undefined'; fi; fi; "
        "printf '%s\\t%s\\t%s\\t%s\\n' \"$artifact\" \"$size\" \"$digest\" \"$markers\"; "
        "done"
    )


def parse_artifact_inventory(output: str) -> tuple[PreparedArtifact, ...]:
    artifacts: list[PreparedArtifact] = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 4:
            raise PreparedBuildVerificationError(
                PreparedBuildFailureCode.ARTIFACT_MISSING,
                "native artifact inventory contains an unsafe or malformed path",
            )
        path, size_text, digest, marker_text = fields
        if (
            not path.startswith("/")
            or not size_text.isdigit()
            or int(size_text) < 0
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise PreparedBuildVerificationError(
                PreparedBuildFailureCode.ARTIFACT_MISSING,
                "native artifact inventory contains invalid metadata",
            )
        markers = tuple(marker for marker in marker_text.split(",") if marker)
        if any(marker not in {"address", "undefined"} for marker in markers):
            raise PreparedBuildVerificationError(
                PreparedBuildFailureCode.SANITIZER_PROVENANCE_MISSING,
                "native artifact inventory contains an unknown sanitizer marker",
            )
        artifacts.append(PreparedArtifact(
            path=path,
            size_bytes=int(size_text),
            sha256="sha256:" + digest,
            sanitizer_markers=markers,
        ))
    if not artifacts:
        raise PreparedBuildVerificationError(
            PreparedBuildFailureCode.ARTIFACT_MISSING,
            "prepared build produced no readable native artifacts",
        )
    if not any(artifact.sanitizer_markers for artifact in artifacts):
        raise PreparedBuildVerificationError(
            PreparedBuildFailureCode.SANITIZER_PROVENANCE_MISSING,
            "prepared build artifacts have no ASan/UBSan symbol provenance",
        )
    return tuple(artifacts)


def parse_package_lock(output: str) -> tuple[str, ...]:
    entries = tuple(line.strip() for line in output.splitlines() if line.strip())
    if (
        not entries
        or entries != tuple(sorted(set(entries)))
        or any(
            re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9]+)?=[^\s=]+", entry) is None
            for entry in entries
        )
    ):
        raise PreparedBuildVerificationError(
            PreparedBuildFailureCode.PACKAGE_LOCK_MISSING,
            "prepared build package lock is missing or invalid",
        )
    return entries


def verify_prepared_build_receipt(value: Any) -> None:
    """Fail closed when a persisted prepared-build-v1 receipt was altered."""
    if not isinstance(value, dict):
        raise ValueError("prepared build receipt must be an object")
    payload = deepcopy(value)
    claimed_receipt = payload.pop("receipt_sha256", "")
    if _SHA256.fullmatch(str(claimed_receipt)) is None:
        raise ValueError("prepared build receipt identity is missing")
    if _canonical_sha256(payload) != claimed_receipt:
        raise ValueError("prepared build receipt hash mismatch")

    claimed_equivalence = payload.pop("equivalence_sha256", "")
    if _SHA256.fullmatch(str(claimed_equivalence)) is None:
        raise ValueError("prepared build equivalence identity is missing")
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported prepared build receipt schema")
    if payload.get("policy_version") != PREPARED_BUILD_RECEIPT_POLICY:
        raise ValueError("unsupported prepared build receipt policy")
    if payload.get("status") != "verified":
        raise ValueError("prepared build receipt is not verified")
    if payload.get("equivalence_exclusions") != _EQUIVALENCE_EXCLUSIONS:
        raise ValueError("prepared build equivalence exclusions changed")

    images = payload.get("images")
    if not isinstance(images, dict):
        raise ValueError("prepared build image provenance is missing")
    for role in ("base", "final"):
        image = images.get(role)
        if (
            not isinstance(image, dict)
            or not str(image.get("reference") or "")
            or _SHA256.fullmatch(str(image.get("digest") or "")) is None
        ):
            raise ValueError(f"prepared build {role} image provenance is invalid")

    for key in ("commands", "tests"):
        results = payload.get(key)
        if not isinstance(results, list):
            raise ValueError(f"prepared build {key} are missing")
        for result in results:
            if (
                not isinstance(result, dict)
                or result.get("exit_code") != 0
                or result.get("timed_out") is not False
            ):
                raise ValueError(f"prepared build {key} contain a failed result")

    package_lock = payload.get("package_lock")
    if (
        not isinstance(package_lock, dict)
        or package_lock.get("path") != PACKAGE_LOCK_PATH
        or _SHA256.fullmatch(str(package_lock.get("sha256") or "")) is None
        or not isinstance(package_lock.get("entries"), list)
        or not package_lock["entries"]
    ):
        raise ValueError("prepared build package lock is invalid")

    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("prepared build artifacts are missing")
    sanitizer_paths = set()
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or not str(artifact.get("path") or "").startswith("/")
            or _SHA256.fullmatch(str(artifact.get("sha256") or "")) is None
            or not isinstance(artifact.get("sanitizer_markers"), list)
        ):
            raise ValueError("prepared build artifact provenance is invalid")
        if artifact["sanitizer_markers"]:
            sanitizer_paths.add(artifact["path"])
    sanitizer = payload.get("sanitizer_provenance")
    if (
        not isinstance(sanitizer, dict)
        or not sanitizer_paths
        or set(sanitizer.get("artifacts") or []) != sanitizer_paths
    ):
        raise ValueError("prepared build sanitizer provenance is invalid")

    equivalent = deepcopy(payload)
    equivalent["images"]["final"]["digest"] = "<excluded>"
    for key in ("commands", "tests"):
        for result in equivalent[key]:
            result["duration_ms"] = 0
            result["stdout_sha256"] = "<excluded>"
            result["stderr_sha256"] = "<excluded>"
    if _canonical_sha256(equivalent) != claimed_equivalence:
        raise ValueError("prepared build equivalence hash mismatch")


def _validated_cmake_option_args(repo: Path, options: tuple[str, ...]) -> str:
    if not options:
        return ""
    source = (repo / "CMakeLists.txt").read_text(encoding="utf-8", errors="replace")
    normalized: list[str] = []
    names: set[str] = set()
    for option in options:
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=(ON|OFF)", option)
        if match is None:
            raise ValueError("native CMake options must use DECLARED_BOOLEAN=ON|OFF")
        name, value = match.groups()
        if name in names:
            raise ValueError("native CMake option names must be unique")
        names.add(name)
        if re.search(rf"\boption\s*\(\s*{re.escape(name)}(?:\s|\))", source, re.I) is None:
            raise ValueError(f"native CMake option is not declared by the source: {name}")
        normalized.append(f"-D{name}={value}")
    return " " + " ".join(sorted(normalized))


def _validated_configure_option_args(repo: Path, options: tuple[str, ...]) -> str:
    if not options:
        return ""
    descriptor = repo / "configure.ac"
    if not descriptor.is_file():
        descriptor = repo / "configure"
    source = descriptor.read_text(encoding="utf-8", errors="replace")
    normalized: list[str] = []
    names: set[str] = set()
    for option in options:
        match = re.fullmatch(r"([a-z][a-z0-9-]*)=(ON|OFF)", option)
        if match is None:
            raise ValueError("native Autotools options must use declared-option=ON|OFF")
        name, value = match.groups()
        if name in names:
            raise ValueError("native Autotools option names must be unique")
        names.add(name)
        declared = (
            re.search(
                rf"\bAC_ARG_ENABLE\s*\(\s*\[?{re.escape(name)}\]?\s*(?:,|\))",
                source,
                re.I,
            )
            if descriptor.name == "configure.ac"
            else re.search(rf"--(?:enable|disable)-{re.escape(name)}\b", source)
        )
        if declared is None:
            raise ValueError(
                f"native Autotools option is not declared by the source: {name}"
            )
        prefix = "enable" if value == "ON" else "disable"
        normalized.append(f"--{prefix}-{name}")
    return " " + " ".join(sorted(normalized))


def _legacy_autotools_requires_source_copy(repo: Path) -> bool:
    """Detect a top-level generated Makefile that cannot resolve source files."""
    makefile = repo / "Makefile.in"
    if not makefile.is_file():
        return False
    source = makefile.read_text(encoding="utf-8", errors="replace")
    source_dir = re.search(
        r"(?m)^\s*(?:srcdir|top_srcdir)\s*(?::?=)\s*@(?:top_)?srcdir@\s*$",
        source,
    )
    vpath = re.search(r"(?m)^\s*VPATH\s*(?::?=)", source)
    return source_dir is None and vpath is None


def _reject_foreign_build_options(
    cmake_options: tuple[str, ...],
    configure_options: tuple[str, ...],
) -> None:
    if cmake_options:
        raise ValueError("CMake options require a CMake build descriptor")
    if configure_options:
        raise ValueError("Autotools options require an Autotools build descriptor")


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _text_sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()
