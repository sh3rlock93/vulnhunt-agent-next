"""Immutable, read-only evidence snapshots for Apple dyld shared caches.

This module deliberately stops before extraction or decompilation.  It binds a
later analysis result to exact cache bytes without copying, loading, or
executing any image from the cache.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from ...domain.schemas import DomainModel, SHA256_PATTERN

_DYLD_HEADER_SIZE = 104
_DYLD_UUID_OFFSET = 88
_PRIMARY_NAME = re.compile(r"^dyld_shared_cache_(?P<cache_arch>arm64e?|x86_64h?)$")
_MAGIC = re.compile(r"^dyld_v[0-9]+\s+(?P<cache_arch>arm64e?|x86_64h?)$")
_PRODUCT_VERSION = r"^[0-9]+(?:\.[0-9]+){1,2}$"
_BUILD_VERSION = r"^[0-9A-Za-z]+$"
_UUID = r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$"
_SUBCACHE_KIND = r"(?:dylddata|dyldlinkedit|dyldreadonly)"
_MEMBER_SUFFIX = rf"(?:[0-9]{{1,3}}(?:\.{_SUBCACHE_KIND})?|symbols|atlas|map)"


class DyldArchitecture(StrEnum):
    ARM64 = "arm64"
    X86_64 = "x86_64"


class DyldSharedCacheFileRole(StrEnum):
    PRIMARY = "primary"
    SUBCACHE = "subcache"
    SYMBOLS = "symbols"
    AUXILIARY = "auxiliary"


class DyldSharedCacheFile(DomainModel):
    name: str = Field(
        pattern=(r"^dyld_shared_cache_(?:arm64e?|x86_64h?)(?:\." + _MEMBER_SUFFIX + r")?$"),
        max_length=80,
    )
    role: DyldSharedCacheFileRole
    size_bytes: int = Field(ge=1)
    sha256: str = Field(pattern=SHA256_PATTERN)


class BinarySnapshotCaptureLimits(DomainModel):
    max_files: int = Field(default=64, ge=1, le=256)
    max_total_size_bytes: int = Field(
        default=256 * 1024 * 1024 * 1024,
        ge=_DYLD_HEADER_SIZE,
        le=1024 * 1024 * 1024 * 1024,
    )


class BinarySnapshot(DomainModel):
    schema_version: Literal["imageio-binary-snapshot-v1"] = "imageio-binary-snapshot-v1"
    captured_at: datetime
    product_version: str = Field(pattern=_PRODUCT_VERSION)
    build_version: str = Field(pattern=_BUILD_VERSION)
    architecture: DyldArchitecture
    shared_cache_uuid: str = Field(pattern=_UUID)
    primary_magic: str = Field(min_length=1, max_length=32)
    primary_name: str = Field(pattern=_PRIMARY_NAME.pattern, max_length=80)
    files: tuple[DyldSharedCacheFile, ...] = Field(min_length=1, max_length=256)
    total_size_bytes: int = Field(ge=_DYLD_HEADER_SIZE)
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)
    read_only: Literal[True] = True
    accepts_image_input: Literal[False] = False

    @model_validator(mode="after")
    def validate_snapshot(self) -> "BinarySnapshot":
        if self.captured_at.tzinfo is None:
            raise ValueError("binary snapshot capture time must include a timezone")
        if len({item.name for item in self.files}) != len(self.files):
            raise ValueError("binary snapshot file names must be unique")
        if tuple(sorted(self.files, key=_file_sort_key)) != self.files:
            raise ValueError("binary snapshot files must use canonical cache order")

        primary_files = [
            item for item in self.files if item.role is DyldSharedCacheFileRole.PRIMARY
        ]
        if len(primary_files) != 1 or primary_files[0].name != self.primary_name:
            raise ValueError("binary snapshot must contain its declared primary cache")
        for item in self.files:
            _validate_file_role(item, primary_name=self.primary_name)
        if sum(item.size_bytes for item in self.files) != self.total_size_bytes:
            raise ValueError("binary snapshot total size does not match its files")

        _validate_architecture_binding(
            self.architecture,
            primary_name=self.primary_name,
            primary_magic=self.primary_magic,
        )
        expected_digest = _snapshot_digest(
            schema_version=self.schema_version,
            product_version=self.product_version,
            build_version=self.build_version,
            architecture=self.architecture,
            shared_cache_uuid=self.shared_cache_uuid,
            primary_magic=self.primary_magic,
            primary_name=self.primary_name,
            files=self.files,
            total_size_bytes=self.total_size_bytes,
        )
        if self.snapshot_sha256 != expected_digest:
            raise ValueError("binary snapshot digest does not match its evidence")
        return self


@dataclass(frozen=True)
class _HashedFile:
    size_bytes: int
    sha256: str
    header: bytes


def capture_dyld_shared_cache_snapshot(
    primary_path: Path,
    *,
    product_version: str,
    build_version: str,
    architecture: DyldArchitecture | str,
    captured_at: datetime | None = None,
    limits: BinarySnapshotCaptureLimits | None = None,
) -> BinarySnapshot:
    """Hash one dyld cache family without copying or executing its contents."""

    active_limits = limits or BinarySnapshotCaptureLimits()
    active_architecture = DyldArchitecture(architecture)
    primary = primary_path.expanduser()
    _validate_primary_path(primary, architecture=active_architecture)
    cache_paths = _discover_cache_family(primary)
    if len(cache_paths) > active_limits.max_files:
        raise ValueError("dyld cache family exceeds the configured file-count limit")

    observed_total = 0
    for path in cache_paths:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"dyld cache member must be a regular non-symlink file: {path.name}")
        observed_total += metadata.st_size
    if observed_total > active_limits.max_total_size_bytes:
        raise ValueError("dyld cache family exceeds the configured byte limit")

    captured_files: list[DyldSharedCacheFile] = []
    primary_header = b""
    actual_total = 0
    for path in cache_paths:
        captured = _hash_regular_file(path)
        actual_total += captured.size_bytes
        if actual_total > active_limits.max_total_size_bytes:
            raise ValueError("dyld cache family changed beyond the configured byte limit")
        role = _role_for_name(path.name, primary_name=primary.name)
        captured_files.append(
            DyldSharedCacheFile(
                name=path.name,
                role=role,
                size_bytes=captured.size_bytes,
                sha256=captured.sha256,
            )
        )
        if role is DyldSharedCacheFileRole.PRIMARY:
            primary_header = captured.header

    primary_magic, shared_cache_uuid = _parse_primary_header(primary_header)
    files = tuple(sorted(captured_files, key=_file_sort_key))
    _validate_architecture_binding(
        active_architecture,
        primary_name=primary.name,
        primary_magic=primary_magic,
    )
    digest = _snapshot_digest(
        schema_version="imageio-binary-snapshot-v1",
        product_version=product_version,
        build_version=build_version,
        architecture=active_architecture,
        shared_cache_uuid=shared_cache_uuid,
        primary_magic=primary_magic,
        primary_name=primary.name,
        files=files,
        total_size_bytes=actual_total,
    )
    return BinarySnapshot(
        captured_at=captured_at or datetime.now(UTC),
        product_version=product_version,
        build_version=build_version,
        architecture=active_architecture,
        shared_cache_uuid=shared_cache_uuid,
        primary_magic=primary_magic,
        primary_name=primary.name,
        files=files,
        total_size_bytes=actual_total,
        snapshot_sha256=digest,
    )


def write_binary_snapshot(snapshot: BinarySnapshot, output_directory: Path) -> Path:
    """Atomically persist a content-addressed JSON evidence manifest."""

    directory = output_directory.expanduser()
    if directory.exists() and directory.is_symlink():
        raise ValueError("binary snapshot output directory may not be a symlink")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = directory / f"binary-snapshot-{snapshot.snapshot_sha256[7:23]}.json"
    payload = json.dumps(snapshot.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    if target.exists():
        if target.is_symlink() or not target.is_file():
            raise ValueError("binary snapshot target must be a regular file")
        if target.read_text(encoding="utf-8") != payload:
            raise FileExistsError("content-addressed snapshot path contains different data")
        return target

    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=directory,
        prefix=".binary-snapshot-",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(file_descriptor, 0o600)
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return target


def _validate_primary_path(primary: Path, *, architecture: DyldArchitecture) -> None:
    name_match = _PRIMARY_NAME.fullmatch(primary.name)
    if name_match is None:
        raise ValueError("path must identify a primary dyld shared cache")
    if not primary.exists():
        raise FileNotFoundError(primary)
    metadata = primary.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("primary dyld cache must be a regular non-symlink file")
    if _normalized_architecture(name_match.group("cache_arch")) is not architecture:
        raise ValueError("primary dyld cache name does not match the requested architecture")


def _discover_cache_family(primary: Path) -> tuple[Path, ...]:
    suffix = re.compile(rf"^{re.escape(primary.name)}(?:\.{_MEMBER_SUFFIX})?$")
    members: list[Path] = []
    with os.scandir(primary.parent) as entries:
        for entry in entries:
            if suffix.fullmatch(entry.name) is None:
                continue
            path = Path(entry.path)
            if entry.is_symlink():
                raise ValueError(f"dyld cache member may not be a symlink: {entry.name}")
            members.append(path)
    if primary.name not in {item.name for item in members}:
        raise RuntimeError("primary dyld cache disappeared during discovery")
    return tuple(sorted(members, key=lambda path: _name_sort_key(path.name, primary.name)))


def _hash_regular_file(path: Path) -> _HashedFile:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"dyld cache member must be a regular file: {path.name}")
        digest = hashlib.sha256()
        header = bytearray()
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                if len(header) < _DYLD_HEADER_SIZE:
                    needed = _DYLD_HEADER_SIZE - len(header)
                    header.extend(chunk[:needed])
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            raise RuntimeError(f"dyld cache member changed while hashing: {path.name}")
        return _HashedFile(
            size_bytes=after.st_size,
            sha256="sha256:" + digest.hexdigest(),
            header=bytes(header),
        )
    finally:
        os.close(descriptor)


def _parse_primary_header(header: bytes) -> tuple[str, str]:
    if len(header) < _DYLD_HEADER_SIZE:
        raise ValueError("primary dyld cache header is truncated")
    try:
        magic = header[:16].split(b"\0", 1)[0].decode("ascii").rstrip()
    except UnicodeDecodeError as exc:
        raise ValueError("primary dyld cache magic is not ASCII") from exc
    if _MAGIC.fullmatch(magic) is None:
        raise ValueError("primary dyld cache magic is invalid")
    raw_uuid = header[_DYLD_UUID_OFFSET : _DYLD_UUID_OFFSET + 16]
    if raw_uuid == b"\0" * 16:
        raise ValueError("primary dyld cache UUID may not be zero")
    return magic, str(uuid.UUID(bytes=raw_uuid)).upper()


def _validate_architecture_binding(
    architecture: DyldArchitecture,
    *,
    primary_name: str,
    primary_magic: str,
) -> None:
    name_match = _PRIMARY_NAME.fullmatch(primary_name)
    magic_match = _MAGIC.fullmatch(primary_magic)
    if name_match is None or magic_match is None:
        raise ValueError("dyld cache identity is malformed")
    observed = {
        _normalized_architecture(name_match.group("cache_arch")),
        _normalized_architecture(magic_match.group("cache_arch")),
    }
    if observed != {architecture}:
        raise ValueError("dyld cache name, header, and requested architecture disagree")


def _normalized_architecture(value: str) -> DyldArchitecture:
    if value.startswith("arm64"):
        return DyldArchitecture.ARM64
    return DyldArchitecture.X86_64


def _role_for_name(name: str, *, primary_name: str) -> DyldSharedCacheFileRole:
    if name == primary_name:
        return DyldSharedCacheFileRole.PRIMARY
    if name == f"{primary_name}.symbols":
        return DyldSharedCacheFileRole.SYMBOLS
    if re.fullmatch(
        rf"{re.escape(primary_name)}\.[0-9]{{1,3}}(?:\.{_SUBCACHE_KIND})?",
        name,
    ):
        return DyldSharedCacheFileRole.SUBCACHE
    if name in {f"{primary_name}.atlas", f"{primary_name}.map"}:
        return DyldSharedCacheFileRole.AUXILIARY
    raise ValueError(f"unsupported dyld cache family member: {name}")


def _validate_file_role(item: DyldSharedCacheFile, *, primary_name: str) -> None:
    if _role_for_name(item.name, primary_name=primary_name) is not item.role:
        raise ValueError(f"dyld cache file role does not match its name: {item.name}")


def _name_sort_key(name: str, primary_name: str) -> tuple[int, int, str]:
    role = _role_for_name(name, primary_name=primary_name)
    if role is DyldSharedCacheFileRole.PRIMARY:
        return (0, 0, name)
    if role is DyldSharedCacheFileRole.SUBCACHE:
        suffix = name.removeprefix(primary_name + ".")
        return (1, int(suffix.split(".", 1)[0]), name)
    if role is DyldSharedCacheFileRole.SYMBOLS:
        return (2, 0, name)
    return (3, 0, name)


def _file_sort_key(item: DyldSharedCacheFile) -> tuple[int, int, str]:
    if item.role is DyldSharedCacheFileRole.PRIMARY:
        return (0, 0, item.name)
    if item.role is DyldSharedCacheFileRole.SUBCACHE:
        suffix = item.name.split(".", 1)[1]
        return (1, int(suffix.split(".", 1)[0]), item.name)
    if item.role is DyldSharedCacheFileRole.SYMBOLS:
        return (2, 0, item.name)
    return (3, 0, item.name)


def _snapshot_digest(
    *,
    schema_version: str,
    product_version: str,
    build_version: str,
    architecture: DyldArchitecture,
    shared_cache_uuid: str,
    primary_magic: str,
    primary_name: str,
    files: tuple[DyldSharedCacheFile, ...],
    total_size_bytes: int,
) -> str:
    identity = {
        "architecture": architecture.value,
        "build_version": build_version,
        "files": [item.model_dump(mode="json") for item in files],
        "primary_magic": primary_magic,
        "primary_name": primary_name,
        "product_version": product_version,
        "schema_version": schema_version,
        "shared_cache_uuid": shared_cache_uuid,
        "total_size_bytes": total_size_bytes,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()
