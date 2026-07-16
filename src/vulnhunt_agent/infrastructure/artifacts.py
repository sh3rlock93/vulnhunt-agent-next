"""Content-addressed, immutable filesystem artifact store."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

from ..domain.schemas import ArtifactRef, SHA256_PATTERN


class ArtifactIntegrityError(RuntimeError):
    """Stored content does not match its content address."""


class ArtifactStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True)

    def put_bytes(self, content: bytes, media_type: str = "application/octet-stream") -> ArtifactRef:
        hex_digest = hashlib.sha256(content).hexdigest()
        digest = f"sha256:{hex_digest}"
        destination = self._path(digest)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            self._verify(destination, digest)
            return ArtifactRef(digest=digest, size=len(content), media_type=media_type)

        temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError:
                self._verify(destination, digest)
            else:
                destination.chmod(0o444)
        finally:
            temporary.unlink(missing_ok=True)
        return ArtifactRef(digest=digest, size=len(content), media_type=media_type)

    def put_text(self, content: str, media_type: str = "text/plain; charset=utf-8") -> ArtifactRef:
        return self.put_bytes(content.encode(), media_type)

    def put_json(self, value: object) -> ArtifactRef:
        content = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return self.put_text(content, "application/json")

    def put_file(self, path: Path, media_type: str = "application/octet-stream") -> ArtifactRef:
        return self.put_bytes(path.read_bytes(), media_type)

    def read_bytes(self, digest: str) -> bytes:
        path = self._path(digest)
        if not path.is_file():
            raise FileNotFoundError(digest)
        self._verify(path, digest)
        return path.read_bytes()

    def read_text(self, digest: str) -> str:
        return self.read_bytes(digest).decode()

    def path_for(self, digest: str) -> Path:
        path = self._path(digest)
        if not path.is_file():
            raise FileNotFoundError(digest)
        self._verify(path, digest)
        return path

    def _path(self, digest: str) -> Path:
        import re

        if re.fullmatch(SHA256_PATTERN, digest) is None:
            raise ValueError("invalid SHA-256 artifact digest")
        hex_digest = digest.removeprefix("sha256:")
        return self.objects / hex_digest[:2] / hex_digest[2:]

    @staticmethod
    def _verify(path: Path, digest: str) -> None:
        actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            raise ArtifactIntegrityError(f"artifact {digest} contains bytes for {actual}")
