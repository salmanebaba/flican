"""Private local state shared by scan provenance and reporting commands."""

import fcntl
import json
import os
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path


def state_directory() -> Path:
    override = os.environ.get("FLICAN_STATE_DIR")
    if override:
        return Path(override).expanduser().resolve()
    base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
    return (base / "flican").expanduser().resolve()


def private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("Flican state directories must not be symlinks.")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)


def write_private_json(path: Path, data: dict) -> None:
    write_private_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def write_private_text(path: Path, content: str) -> None:
    private_directory(path.parent)
    if path.is_symlink():
        raise ValueError("Flican state files must not be symlinks.")
    descriptor, name = tempfile.mkstemp(prefix=".flican-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_private_json(path: Path) -> dict:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
        raise ValueError("Flican credentials/state must be regular files with mode 0600.")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Flican state must contain a JSON object.")
    return value


@contextmanager
def state_lock(root: Path | None = None):
    directory = root if root is not None else state_directory()
    private_directory(directory)
    lock_path = directory / "reporting.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


class StateStore:
    """Small transactional journal; credentials are stored separately."""

    def __init__(self, root: Path | None = None):
        self.root = root if root is not None else state_directory()
        private_directory(self.root)
        self.path = self.root / "state.sqlite3"
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        self.path.chmod(0o600)
        with self.connection() as database:
            database.execute(
                "CREATE TABLE IF NOT EXISTS objects ("
                "kind TEXT NOT NULL, object_key TEXT NOT NULL, value TEXT NOT NULL, "
                "PRIMARY KEY (kind, object_key))"
            )

    @contextmanager
    def connection(self):
        database = None
        try:
            database = sqlite3.connect(self.path, timeout=30)
            with database:
                yield database
        except sqlite3.Error as error:
            raise RuntimeError("The Flican local state database is unavailable.") from error
        finally:
            if database is not None:
                database.close()

    def get(self, kind: str, key: str) -> dict | None:
        with self.connection() as database:
            row = database.execute(
                "SELECT value FROM objects WHERE kind = ? AND object_key = ?", (kind, key),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, kind: str, key: str, value: dict) -> None:
        with self.connection() as database:
            database.execute(
                "INSERT INTO objects(kind, object_key, value) VALUES (?, ?, ?) "
                "ON CONFLICT(kind, object_key) DO UPDATE SET value = excluded.value",
                (kind, key, json.dumps(value, sort_keys=True)),
            )
