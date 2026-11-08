import shutil
import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory


def snapshot_identity(root: Path) -> tuple[str, int]:
    inventory = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            with path.open("rb") as stream:
                inventory[path.relative_to(root).as_posix()] = {
                    "sha256": hashlib.file_digest(stream, "sha256").hexdigest(),
                    "executable": bool(path.stat().st_mode & 0o111),
                }
    content = json.dumps(inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(content).hexdigest(), len(inventory)


def create_snapshot(
    project_path: Path,
    files: list[Path],
    snapshot_path: Path,
    *, preserve_executable: bool = False,
) -> None:
    """Copy discovered files into a new snapshot directory."""
    snapshot_path.mkdir(mode=0o700, parents=True, exist_ok=False)

    for source in files:
        relative_path = source.relative_to(project_path)
        destination = snapshot_path / relative_path

        destination.parent.mkdir(
            mode=0o700,
            parents=True,
            exist_ok=True,
        )

        shutil.copyfile(source, destination)
        if preserve_executable:
            destination.chmod(0o700 if source.stat().st_mode & 0o111 else 0o600)

@contextmanager
def temporary_snapshot(
    project_path: Path,
    files: list[Path],
    *, preserve_executable: bool = False,
) -> Iterator[Path]:
    with TemporaryDirectory(prefix="flican-") as directory:
        snapshot_path = Path(directory) / "source"
        create_snapshot(project_path, files, snapshot_path, preserve_executable=preserve_executable)
        yield snapshot_path
