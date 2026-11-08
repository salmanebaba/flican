"""Shared scanner cache locations, resolved without creating or downloading data."""

import os
import re
from pathlib import Path


def trivy_cache_directory(override: Path | None = None) -> Path:
    """Use an explicit path, otherwise an absolute XDG cache base or ~/.cache."""
    if override is not None:
        return override.expanduser().resolve()
    fallback = Path.home() / ".cache"
    base = Path(os.environ.get("XDG_CACHE_HOME") or fallback)
    if not base.is_absolute():
        base = fallback
    return (base / "flican" / "trivy").resolve()


def validate_trivy_db_digest(value: str | None) -> str | None:
    if value is not None and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("--trivy-db-digest must be sha256: followed by 64 lowercase hex characters.")
    return value
