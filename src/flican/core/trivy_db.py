"""Prepare a shared or digest-pinned database before an isolated Trivy scan."""

import fcntl
import hashlib
import json
import os
import shutil
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from flican.adapters.trivy import run_trivy_db_update
from flican.core.cache import validate_trivy_db_digest
from flican.core.state import write_private_json


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("Trivy DB timestamps must be UTC.")
    return parsed


def _metadata(cache: Path) -> dict | None:
    database, metadata = cache / "db/trivy.db", cache / "db/metadata.json"
    try:
        if (cache.joinpath("db").is_symlink() or database.is_symlink() or metadata.is_symlink()
                or not database.is_file() or database.stat().st_size == 0
                or not metadata.is_file() or metadata.stat().st_size > 64 * 1024):
            return None
        value = json.loads(metadata.read_text())
        if not isinstance(value, dict) or type(value.get("Version")) is not int or value["Version"] != 2:
            return None
        for key in ("UpdatedAt", "NextUpdate", "DownloadedAt"):
            _time(value[key])
        return value
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _fresh(metadata: dict) -> bool:
    # Match the pinned Trivy client's NextUpdate / one-hour download grace period.
    now = datetime.now(timezone.utc)
    return now < _time(metadata["NextUpdate"]) or now < _time(metadata["DownloadedAt"]) + timedelta(hours=1)


def _hash(database: Path) -> str:
    with database.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _pinned(cache: Path, digest: str, payload_hash: str) -> bool:
    receipt = cache / ".flican-pin.json"
    try:
        if receipt.is_symlink() or not receipt.is_file() or receipt.stat().st_size > 4096:
            return False
        value = json.loads(receipt.read_text())
        return (isinstance(value, dict) and type(value.get("schema_version")) is int
                and value == {"schema_version": 1, "digest": digest, "database_sha256": payload_hash})
    except (OSError, ValueError):
        return False


def _promote(staging: Path, cache: Path) -> None:
    target = cache / "db"
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise ValueError("The Trivy DB destination must be a directory, not a file or symlink.")
    backup = cache / (".previous-db-" + uuid4().hex)
    if target.exists():
        target.rename(backup)
    try:
        staging.joinpath("db").rename(target)
    except BaseException:
        if backup.exists():
            backup.rename(target)
        raise
    if backup.exists():
        shutil.rmtree(backup)


@contextmanager
def trivy_database(docker: str, base: Path, *, db_digest: str | None = None,
                   offline: bool = False, updater=None, progress=None):
    """Keep preparation and readers serialized; failed downloads preserve the old DB."""
    validate_trivy_db_digest(db_digest)
    cache = base / "pinned" / db_digest.removeprefix("sha256:") if db_digest else base
    cache = cache.resolve()
    emit = progress or (lambda message: None)
    if offline and not cache.is_dir():
        raise ValueError(f"Trivy cache is not ready: {cache}. Run 'flican ci prepare <project>' "
                         "or 'flican db update' without --offline first, using the same cache/digest options.")
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(cache / ".flican-db.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            metadata = _metadata(cache)
            payload_hash = _hash(cache / "db/trivy.db") if metadata and db_digest else None
            trusted_pin = bool(db_digest and metadata and _pinned(cache, db_digest, payload_hash))
            needs_download = not trusted_pin if db_digest else (metadata is None or not _fresh(metadata))
            refreshed = False
            if offline:
                if metadata is None or (db_digest and not trusted_pin):
                    raise ValueError("Trivy database is missing, incompatible or has no matching pinned receipt. "
                                     "Run 'flican ci prepare <project>' or 'flican db update' online first, "
                                     "using the same cache/digest options.")
                emit("Using the cached Trivy database (--offline).")
            elif needs_download:
                emit("Downloading the selected Trivy database..." if db_digest else
                     "Preparing the missing or outdated Trivy database...")
                # The networked container sees only this empty staging cache, never the source.
                with TemporaryDirectory(prefix=".db-update-", dir=cache) as temporary:
                    staging = Path(temporary)
                    update = updater or run_trivy_db_update
                    result = update(docker, staging, db_digest=db_digest) if db_digest else update(docker, staging)
                    if result.returncode:
                        detail = " ".join((result.stderr or "").split())[-500:]
                        raise RuntimeError(f"Trivy DB update failed: Trivy exited with code {result.returncode}. {detail} "
                                           "No scan used the old DB; --offline is an explicit alternative.")
                    metadata = _metadata(staging)
                    if metadata is None:
                        raise ValueError("Trivy downloaded an incomplete or incompatible database.")
                    payload_hash = _hash(staging / "db/trivy.db")
                    _promote(staging, cache)
                    if db_digest:
                        write_private_json(cache / ".flican-pin.json", {
                            "schema_version": 1, "digest": db_digest, "database_sha256": payload_hash,
                        })
                    refreshed = True
            else:
                emit("Using the pinned Trivy database." if db_digest else "Trivy database is up to date.")
            payload_hash = payload_hash or _hash(cache / "db/trivy.db")
            info = {
                "schema_version": 1, "database_schema_version": metadata["Version"],
                "mode": "pinned" if db_digest else "auto", "offline": offline,
                "requested_digest": db_digest, "database_sha256": payload_hash,
                "updated_at": metadata["UpdatedAt"], "next_update": metadata["NextUpdate"],
                "downloaded_at": metadata["DownloadedAt"], "fresh": _fresh(metadata),
                "refreshed": refreshed,
            }
            yield cache, info
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
