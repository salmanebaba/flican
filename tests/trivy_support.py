"""Small synthetic DB caches for tests that never run the real Trivy process."""

import json
import subprocess
from datetime import datetime, timedelta, timezone


def write_database(cache, *, stale=False, content=b"synthetic database", version=2):
    directory = cache / "db"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "trivy.db").write_bytes(content)
    now = datetime.now(timezone.utc)
    metadata = {
        "Version": version,
        "UpdatedAt": (now - timedelta(days=2)).isoformat(),
        "NextUpdate": (now + timedelta(days=-1 if stale else 1)).isoformat(),
        "DownloadedAt": (now - timedelta(hours=2 if stale else 0)).isoformat(),
    }
    (directory / "metadata.json").write_text(json.dumps(metadata))
    return metadata


def download_database(docker, cache, **options):
    write_database(cache)
    return subprocess.CompletedProcess([], 0, stdout="", stderr="")
