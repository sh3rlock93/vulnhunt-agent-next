"""Deterministic, content-addressed source snapshots.

Snapshots never include VCS metadata, dependency trees, interpreter caches, or
symlinks. The resulting tar contains normalized ownership and timestamps so
identical source trees produce identical content hashes.
"""
from __future__ import annotations

import hashlib
import io
import os
import stat
import tarfile
import tempfile
from pathlib import Path
from pathlib import PurePosixPath

from ..domain.schemas import (
    SourceFileEntry,
    SourceManifest,
    SourceSnapshot,
)
from ..infrastructure.artifacts import ArtifactStore

_EXCLUDED_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "target",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
)


class SnapshotError(RuntimeError):
    """The source tree cannot be represented as a safe immutable snapshot."""


class SnapshotBuilder:
    def __init__(
        self,
        artifacts: ArtifactStore,
        *,
        max_file_bytes: int = 64 * 1024 * 1024,
        max_total_bytes: int = 1024 * 1024 * 1024,
    ):
        self.artifacts = artifacts
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes

    def create(
        self,
        source: Path,
        *,
        source_url: str | None = None,
        resolved_ref: str | None = None,
    ) -> SourceSnapshot:
        source = source.resolve()
        if not source.is_dir():
            raise SnapshotError(f"source is not a directory: {source}")

        directories, files, excluded = self._inventory(source)
        entries: list[SourceFileEntry] = []
        total_bytes = 0

        with tempfile.TemporaryDirectory(prefix="vulnhunt-snapshot-") as temporary:
            tar_path = Path(temporary) / "source.tar"
            with tarfile.open(tar_path, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for relative, mode in directories:
                    info = _tar_info(relative, mode=mode, size=0)
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)

                for relative, path, mode in files:
                    try:
                        descriptor = os.open(
                            path,
                            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                        )
                    except OSError as exc:
                        raise SnapshotError(
                            f"cannot safely open source file: {relative}"
                        ) from exc
                    with os.fdopen(descriptor, "rb") as stream:
                        before = os.fstat(stream.fileno())
                        if not stat.S_ISREG(before.st_mode):
                            raise SnapshotError(
                                f"source entry changed type while snapshotting: {relative}"
                            )
                        if before.st_size > self.max_file_bytes:
                            raise SnapshotError(
                                f"source file exceeds size limit: {relative}"
                            )
                        content = stream.read()
                        after = os.fstat(stream.fileno())
                    if _stat_identity(before) != _stat_identity(after):
                        raise SnapshotError(f"source changed while snapshotting: {relative}")
                    total_bytes += len(content)
                    if total_bytes > self.max_total_bytes:
                        raise SnapshotError("source tree exceeds total snapshot size limit")

                    digest = "sha256:" + hashlib.sha256(content).hexdigest()
                    entries.append(
                        SourceFileEntry(
                            path=relative,
                            size=len(content),
                            mode=mode,
                            digest=digest,
                        )
                    )
                    info = _tar_info(relative, mode=mode, size=len(content))
                    archive.addfile(info, io.BytesIO(content))

            snapshot_ref = self.artifacts.put_file(
                tar_path, "application/vnd.vulnhunt.source-tar"
            )

        manifest = SourceManifest(
            source_url=source_url,
            resolved_ref=resolved_ref,
            files=tuple(entries),
            excluded_paths=tuple(sorted(excluded)),
        )
        manifest_ref = self.artifacts.put_json(manifest.model_dump(mode="json"))
        return SourceSnapshot(
            snapshot_artifact=snapshot_ref.digest,
            manifest_artifact=manifest_ref.digest,
            file_count=len(entries),
            total_bytes=total_bytes,
        )

    def _inventory(
        self, source: Path
    ) -> tuple[list[tuple[str, int]], list[tuple[str, Path, int]], set[str]]:
        directories: list[tuple[str, int]] = []
        files: list[tuple[str, Path, int]] = []
        excluded: set[str] = set()

        for root_text, dir_names, file_names in os.walk(
            source, topdown=True, followlinks=False
        ):
            root = Path(root_text)
            retained_dirs: list[str] = []
            for name in sorted(dir_names):
                path = root / name
                relative = path.relative_to(source).as_posix()
                if name in _EXCLUDED_NAMES:
                    excluded.add(relative)
                    continue
                if path.is_symlink():
                    raise SnapshotError(f"source symlink is not allowed: {relative}")
                mode = path.lstat().st_mode
                if not stat.S_ISDIR(mode):
                    raise SnapshotError(f"unsupported source entry: {relative}")
                retained_dirs.append(name)
                directories.append((relative, 0o755))
            dir_names[:] = retained_dirs

            for name in sorted(file_names):
                path = root / name
                relative = path.relative_to(source).as_posix()
                if name in _EXCLUDED_NAMES or name.endswith((".pyc", ".pyo")):
                    excluded.add(relative)
                    continue
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode):
                    raise SnapshotError(f"source symlink is not allowed: {relative}")
                if not stat.S_ISREG(mode):
                    raise SnapshotError(f"unsupported source entry: {relative}")
                normalized_mode = 0o755 if stat.S_IMODE(mode) & 0o111 else 0o644
                files.append((relative, path, normalized_mode))

        directories.sort(key=lambda item: item[0])
        files.sort(key=lambda item: item[0])
        return directories, files, excluded


def validate_snapshot_archive(
    path: Path,
    *,
    max_members: int = 200_000,
    max_total_bytes: int = 1024 * 1024 * 1024,
) -> None:
    """Reject traversal, links, devices, duplicates, and archive bombs."""
    names: set[str] = set()
    total_bytes = 0
    try:
        with tarfile.open(path) as archive:
            members = archive.getmembers()
            if len(members) > max_members:
                raise SnapshotError("snapshot contains too many archive members")
            for member in members:
                if "\\" in member.name:
                    raise SnapshotError(f"unsafe snapshot member path: {member.name}")
                normalized = PurePosixPath(member.name)
                if (
                    normalized.is_absolute()
                    or ".." in normalized.parts
                    or normalized == PurePosixPath(".")
                ):
                    raise SnapshotError(f"unsafe snapshot member path: {member.name}")
                canonical_name = normalized.as_posix()
                if canonical_name in names:
                    raise SnapshotError(f"duplicate snapshot member: {member.name}")
                names.add(canonical_name)
                if not (member.isfile() or member.isdir()):
                    raise SnapshotError(f"unsupported snapshot member: {member.name}")
                total_bytes += member.size
                if total_bytes > max_total_bytes:
                    raise SnapshotError("snapshot archive exceeds extraction size limit")
    except tarfile.TarError as exc:
        raise SnapshotError(f"invalid source snapshot archive: {exc}") from exc


def _tar_info(path: str, *, mode: int, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(path)
    info.size = size
    info.mode = mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.pax_headers = {}
    return info


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (value.st_ino, value.st_size, value.st_mtime_ns, value.st_mode)
