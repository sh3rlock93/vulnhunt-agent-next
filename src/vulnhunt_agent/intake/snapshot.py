"""Deterministic, content-addressed source snapshots.

Snapshots never include VCS metadata, dependency trees, or interpreter caches.
Repository-internal file symlinks are materialized as regular files with
auditable provenance; every other symlink remains forbidden. The resulting tar
contains normalized ownership and timestamps so identical source trees produce
identical content hashes.
"""
from __future__ import annotations

import hashlib
import io
import os
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath

from ..domain.schemas import (
    SourceFileEntry,
    SourceManifest,
    SourceSnapshot,
    SourceSymlinkEntry,
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


@dataclass(frozen=True)
class _SymlinkHop:
    path: Path
    target: str
    identity: tuple[int, int, int, int]


@dataclass(frozen=True)
class _InventoryFile:
    archive_path: str
    read_path: Path
    mode: int
    link_target: str | None = None
    resolved_path: str | None = None
    symlink_hops: tuple[_SymlinkHop, ...] = ()


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
        symlinks: list[SourceSymlinkEntry] = []
        total_bytes = 0

        with tempfile.TemporaryDirectory(prefix="vulnhunt-snapshot-") as temporary:
            tar_path = Path(temporary) / "source.tar"
            with tarfile.open(tar_path, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for relative, mode in directories:
                    info = _tar_info(relative, mode=mode, size=0)
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)

                for item in files:
                    self._validate_symlink_hops(item)
                    try:
                        descriptor = os.open(
                            item.read_path,
                            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                        )
                    except OSError as exc:
                        raise SnapshotError(
                            f"cannot safely open source file: {item.archive_path}"
                        ) from exc
                    with os.fdopen(descriptor, "rb") as stream:
                        before = os.fstat(stream.fileno())
                        if not stat.S_ISREG(before.st_mode):
                            raise SnapshotError(
                                "source entry changed type while snapshotting: "
                                f"{item.archive_path}"
                            )
                        if before.st_size > self.max_file_bytes:
                            raise SnapshotError(
                                f"source file exceeds size limit: {item.archive_path}"
                            )
                        content = stream.read()
                        after = os.fstat(stream.fileno())
                    if _stat_identity(before) != _stat_identity(after):
                        raise SnapshotError(
                            f"source changed while snapshotting: {item.archive_path}"
                        )
                    self._validate_symlink_hops(item)
                    total_bytes += len(content)
                    if total_bytes > self.max_total_bytes:
                        raise SnapshotError("source tree exceeds total snapshot size limit")

                    digest = "sha256:" + hashlib.sha256(content).hexdigest()
                    entries.append(
                        SourceFileEntry(
                            path=item.archive_path,
                            size=len(content),
                            mode=item.mode,
                            digest=digest,
                        )
                    )
                    pax_headers: dict[str, str] | None = None
                    if item.link_target is not None and item.resolved_path is not None:
                        symlinks.append(SourceSymlinkEntry(
                            path=item.archive_path,
                            target=item.link_target,
                            resolved_path=item.resolved_path,
                            digest=digest,
                        ))
                        pax_headers = {
                            "VULNHUNT.symlink_target": item.link_target,
                            "VULNHUNT.resolved_path": item.resolved_path,
                        }
                    info = _tar_info(
                        item.archive_path,
                        mode=item.mode,
                        size=len(content),
                        pax_headers=pax_headers,
                    )
                    archive.addfile(info, io.BytesIO(content))

            snapshot_ref = self.artifacts.put_file(
                tar_path, "application/vnd.vulnhunt.source-tar"
            )

        manifest = SourceManifest(
            schema_version=2,
            normalization_policy="source-snapshot-v3",
            source_url=source_url,
            resolved_ref=resolved_ref,
            files=tuple(entries),
            excluded_paths=tuple(sorted(excluded)),
            symlinks=tuple(symlinks),
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
    ) -> tuple[list[tuple[str, int]], list[_InventoryFile], set[str]]:
        directories: list[tuple[str, int]] = []
        files: list[_InventoryFile] = []
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
                    files.append(self._resolve_file_symlink(source, path, relative))
                    continue
                if not stat.S_ISREG(mode):
                    raise SnapshotError(f"unsupported source entry: {relative}")
                normalized_mode = 0o755 if stat.S_IMODE(mode) & 0o111 else 0o644
                files.append(_InventoryFile(relative, path, normalized_mode))

        directories.sort(key=lambda item: item[0])
        files.sort(key=lambda item: item.archive_path)
        return directories, files, excluded

    def _resolve_file_symlink(
        self,
        source: Path,
        path: Path,
        relative: str,
    ) -> _InventoryFile:
        current = path
        visited: set[str] = set()
        hops: list[_SymlinkHop] = []
        direct_target = ""

        while True:
            try:
                current_relative = current.relative_to(source).as_posix()
            except ValueError as exc:
                raise SnapshotError(
                    f"source symlink escapes repository: {relative}"
                ) from exc
            if current_relative in visited:
                raise SnapshotError(f"source symlink cycle is not allowed: {relative}")
            visited.add(current_relative)
            _validate_parent_directories(source, current, relative)

            try:
                current_stat = current.lstat()
            except FileNotFoundError as exc:
                raise SnapshotError(f"source symlink is dangling: {relative}") from exc
            if stat.S_ISLNK(current_stat.st_mode):
                target = os.readlink(current)
                if not direct_target:
                    direct_target = target
                if Path(target).is_absolute():
                    raise SnapshotError(
                        f"absolute source symlink is not allowed: {relative}"
                    )
                hops.append(_SymlinkHop(
                    path=current,
                    target=target,
                    identity=_stat_identity(current_stat),
                ))
                current = Path(os.path.normpath(current.parent / target))
                try:
                    target_relative = current.relative_to(source).as_posix()
                except ValueError as exc:
                    raise SnapshotError(
                        f"source symlink escapes repository: {relative}"
                    ) from exc
                if _is_excluded_relative(target_relative):
                    raise SnapshotError(
                        f"source symlink targets an excluded path: {relative}"
                    )
                continue
            if not stat.S_ISREG(current_stat.st_mode):
                raise SnapshotError(
                    f"source symlink target is not a regular file: {relative}"
                )
            normalized_mode = (
                0o755 if stat.S_IMODE(current_stat.st_mode) & 0o111 else 0o644
            )
            return _InventoryFile(
                archive_path=relative,
                read_path=current,
                mode=normalized_mode,
                link_target=direct_target,
                resolved_path=current.relative_to(source).as_posix(),
                symlink_hops=tuple(hops),
            )

    @staticmethod
    def _validate_symlink_hops(item: _InventoryFile) -> None:
        for hop in item.symlink_hops:
            try:
                current = hop.path.lstat()
                target = os.readlink(hop.path)
            except OSError as exc:
                raise SnapshotError(
                    f"source symlink changed while snapshotting: {item.archive_path}"
                ) from exc
            if _stat_identity(current) != hop.identity or target != hop.target:
                raise SnapshotError(
                    f"source symlink changed while snapshotting: {item.archive_path}"
                )


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


def _tar_info(
    path: str,
    *,
    mode: int,
    size: int,
    pax_headers: dict[str, str] | None = None,
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(path)
    info.size = size
    info.mode = mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.pax_headers = pax_headers or {}
    return info


def _validate_parent_directories(source: Path, path: Path, link: str) -> None:
    try:
        relative_parent = path.parent.relative_to(source)
    except ValueError as exc:
        raise SnapshotError(f"source symlink escapes repository: {link}") from exc
    current = source
    for part in relative_parent.parts:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError as exc:
            raise SnapshotError(f"source symlink is dangling: {link}") from exc
        if stat.S_ISLNK(mode):
            raise SnapshotError(
                f"source symlink traverses a directory symlink: {link}"
            )
        if not stat.S_ISDIR(mode):
            raise SnapshotError(f"source symlink is dangling: {link}")


def _is_excluded_relative(relative: str) -> bool:
    path = PurePosixPath(relative)
    return any(part in _EXCLUDED_NAMES for part in path.parts) or path.name.endswith(
        (".pyc", ".pyo")
    )


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (value.st_ino, value.st_size, value.st_mtime_ns, value.st_mode)
