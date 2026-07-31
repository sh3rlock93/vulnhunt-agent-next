from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnhunt_agent.macos.binary_analysis import (
    BinarySnapshot,
    BinarySnapshotCaptureLimits,
    DyldArchitecture,
    DyldSharedCacheFileRole,
    capture_dyld_shared_cache_snapshot,
    write_binary_snapshot,
)

_CACHE_UUID = uuid.UUID("12345678-1234-5678-9abc-def012345678")


def _write_cache(
    path: Path,
    *,
    magic: bytes = b"dyld_v1  arm64e\0",
    cache_uuid: uuid.UUID = _CACHE_UUID,
    payload: bytes = b"primary-payload",
) -> None:
    header = bytearray(104)
    header[:16] = magic
    header[88:104] = cache_uuid.bytes
    path.write_bytes(bytes(header) + payload)


def _capture(primary: Path, *, captured_at: datetime | None = None) -> BinarySnapshot:
    return capture_dyld_shared_cache_snapshot(
        primary,
        product_version="26.0",
        build_version="25A123",
        architecture=DyldArchitecture.ARM64,
        captured_at=captured_at,
    )


def test_capture_binds_sorted_cache_family_to_content_and_uuid(tmp_path: Path) -> None:
    primary = tmp_path / "dyld_shared_cache_arm64e"
    _write_cache(primary)
    (tmp_path / f"{primary.name}.02").write_bytes(b"second")
    (tmp_path / f"{primary.name}.01").write_bytes(b"first")
    (tmp_path / f"{primary.name}.symbols").write_bytes(b"symbols")
    (tmp_path / "unrelated-image").write_bytes(b"ignored")

    snapshot = _capture(primary)

    assert snapshot.shared_cache_uuid == str(_CACHE_UUID).upper()
    assert [item.name for item in snapshot.files] == [
        primary.name,
        f"{primary.name}.01",
        f"{primary.name}.02",
        f"{primary.name}.symbols",
    ]
    assert [item.role for item in snapshot.files] == [
        DyldSharedCacheFileRole.PRIMARY,
        DyldSharedCacheFileRole.SUBCACHE,
        DyldSharedCacheFileRole.SUBCACHE,
        DyldSharedCacheFileRole.SYMBOLS,
    ]
    assert snapshot.files[1].sha256 == "sha256:" + hashlib.sha256(b"first").hexdigest()
    assert snapshot.total_size_bytes == sum(item.size_bytes for item in snapshot.files)
    assert snapshot.read_only is True
    assert snapshot.accepts_image_input is False


def test_snapshot_identity_is_stable_across_capture_times(tmp_path: Path) -> None:
    primary = tmp_path / "dyld_shared_cache_arm64e"
    _write_cache(primary)
    first_time = datetime(2026, 7, 30, 1, 2, tzinfo=UTC)

    first = _capture(primary, captured_at=first_time)
    second = _capture(primary, captured_at=first_time + timedelta(hours=1))

    assert first.captured_at != second.captured_at
    assert first.snapshot_sha256 == second.snapshot_sha256


def test_capture_includes_modern_split_cache_and_auxiliary_members(tmp_path: Path) -> None:
    primary = tmp_path / "dyld_shared_cache_arm64e"
    _write_cache(primary)
    modern_members = (
        f"{primary.name}.01",
        f"{primary.name}.02.dylddata",
        f"{primary.name}.03.dyldreadonly",
        f"{primary.name}.04.dyldlinkedit",
        f"{primary.name}.atlas",
        f"{primary.name}.map",
    )
    for index, name in enumerate(modern_members, start=1):
        (tmp_path / name).write_bytes(f"member-{index}".encode())

    snapshot = _capture(primary)

    assert [item.name for item in snapshot.files] == [primary.name, *modern_members]
    assert [item.role for item in snapshot.files] == [
        DyldSharedCacheFileRole.PRIMARY,
        DyldSharedCacheFileRole.SUBCACHE,
        DyldSharedCacheFileRole.SUBCACHE,
        DyldSharedCacheFileRole.SUBCACHE,
        DyldSharedCacheFileRole.SUBCACHE,
        DyldSharedCacheFileRole.AUXILIARY,
        DyldSharedCacheFileRole.AUXILIARY,
    ]


def test_snapshot_model_rejects_tampered_evidence(tmp_path: Path) -> None:
    primary = tmp_path / "dyld_shared_cache_arm64e"
    _write_cache(primary)
    snapshot = _capture(primary)
    payload = snapshot.model_dump(mode="json")
    payload["files"][0]["sha256"] = "sha256:" + "0" * 64

    with pytest.raises(ValidationError, match="digest does not match"):
        BinarySnapshot.model_validate(payload)


@pytest.mark.parametrize(
    ("magic", "message"),
    [
        (b"not_a_dyld_cache", "magic is invalid"),
        (b"dyld_v1  x86_64\0", "requested architecture disagree"),
    ],
)
def test_capture_rejects_invalid_or_mismatched_magic(
    tmp_path: Path,
    magic: bytes,
    message: str,
) -> None:
    primary = tmp_path / "dyld_shared_cache_arm64e"
    _write_cache(primary, magic=magic)

    with pytest.raises(ValueError, match=message):
        _capture(primary)


def test_capture_rejects_truncated_header_and_zero_uuid(tmp_path: Path) -> None:
    primary = tmp_path / "dyld_shared_cache_arm64e"
    primary.write_bytes(b"dyld_v1  arm64e\0")
    with pytest.raises(ValueError, match="header is truncated"):
        _capture(primary)

    _write_cache(primary, cache_uuid=uuid.UUID(int=0))
    with pytest.raises(ValueError, match="UUID may not be zero"):
        _capture(primary)


def test_capture_rejects_symlinked_primary_or_cache_member(tmp_path: Path) -> None:
    real_primary = tmp_path / "real-cache"
    _write_cache(real_primary)
    linked_primary = tmp_path / "dyld_shared_cache_arm64e"
    linked_primary.symlink_to(real_primary)

    with pytest.raises(ValueError, match="non-symlink"):
        _capture(linked_primary)

    linked_primary.unlink()
    _write_cache(linked_primary)
    real_subcache = tmp_path / "real-subcache"
    real_subcache.write_bytes(b"subcache")
    (tmp_path / f"{linked_primary.name}.01").symlink_to(real_subcache)
    with pytest.raises(ValueError, match="may not be a symlink"):
        _capture(linked_primary)


def test_capture_enforces_architecture_and_resource_limits(tmp_path: Path) -> None:
    x86_primary = tmp_path / "dyld_shared_cache_x86_64"
    _write_cache(x86_primary, magic=b"dyld_v1  x86_64\0")
    with pytest.raises(ValueError, match="requested architecture"):
        _capture(x86_primary)

    primary = tmp_path / "dyld_shared_cache_arm64e"
    _write_cache(primary)
    (tmp_path / f"{primary.name}.01").write_bytes(b"subcache")
    with pytest.raises(ValueError, match="file-count limit"):
        capture_dyld_shared_cache_snapshot(
            primary,
            product_version="26.0",
            build_version="25A123",
            architecture="arm64",
            limits=BinarySnapshotCaptureLimits(max_files=1),
        )
    with pytest.raises(ValueError, match="byte limit"):
        capture_dyld_shared_cache_snapshot(
            primary,
            product_version="26.0",
            build_version="25A123",
            architecture="arm64",
            limits=BinarySnapshotCaptureLimits(max_total_size_bytes=104),
        )


def test_write_binary_snapshot_is_atomic_private_and_idempotent(tmp_path: Path) -> None:
    primary = tmp_path / "dyld_shared_cache_arm64e"
    _write_cache(primary)
    snapshot = _capture(primary)
    output = tmp_path / "evidence"

    written = write_binary_snapshot(snapshot, output)
    repeated = write_binary_snapshot(snapshot, output)

    assert repeated == written
    assert BinarySnapshot.model_validate_json(written.read_text(encoding="utf-8")) == snapshot
    assert os.stat(written).st_mode & 0o777 == 0o600
    assert json.loads(written.read_text(encoding="utf-8"))["accepts_image_input"] is False


def test_write_binary_snapshot_rejects_symlinked_output_directory(tmp_path: Path) -> None:
    primary = tmp_path / "dyld_shared_cache_arm64e"
    _write_cache(primary)
    snapshot = _capture(primary)
    real_output = tmp_path / "real-output"
    real_output.mkdir()
    linked_output = tmp_path / "linked-output"
    linked_output.symlink_to(real_output, target_is_directory=True)

    with pytest.raises(ValueError, match="may not be a symlink"):
        write_binary_snapshot(snapshot, linked_output)
