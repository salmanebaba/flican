"""Stream bounded artifacts, including OCI archives, without loading them into RAM."""

import hashlib
import os
from pathlib import Path

MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_IMAGE_BYTES = 2 * 1024 * 1024 * 1024


def artifact_limit(relative: str) -> int:
    return MAX_IMAGE_BYTES if relative.endswith(".oci.tar") else MAX_REPORT_BYTES


def file_digest(path: Path, limit: int = MAX_REPORT_BYTES) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("Artifact must be a bounded regular file without symlinks.")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def copy_artifact(source: Path, target: Path, *, limit: int = MAX_REPORT_BYTES,
                  expected: str | None = None) -> tuple[str, int]:
    if source.is_symlink() or not source.is_file() or source.stat().st_size > limit:
        raise ValueError("Artifact must be a bounded regular file without symlinks.")
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    digest, size = hashlib.sha256(), 0
    with source.open("rb") as original, target.open("xb") as destination:
        os.fchmod(destination.fileno(), 0o600)
        before = os.fstat(original.fileno())
        while chunk := original.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ValueError("Artifact exceeds its size limit.")
            digest.update(chunk)
            destination.write(chunk)
        after = os.fstat(original.fileno())
    value = digest.hexdigest()
    if (before.st_size != size or before.st_mtime_ns != after.st_mtime_ns
            or before.st_size != after.st_size or (expected is not None and value != expected)):
        raise ValueError("Artifact changed or failed its integrity check during copying.")
    return value, size
