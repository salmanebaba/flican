from pathlib import Path

from flican.core.config import load_config
from flican.core.discovery import detect_languages, discover_files


def build_scan_plan(project_path: Path) -> dict:
    """Describe a scan using the current project configuration."""
    root = project_path.resolve(strict=True)

    if not root.is_dir():
        raise ValueError("Project path must be a directory.")

    config = load_config(root / "flican.yaml")

    excluded_names = set(config["project"]["exclude"])
    excluded_names.add(".flican")
    files = discover_files(root, excluded_names)

    return {
        "project_name": config["project"]["name"],
        "project_path": str(root),
        "file_count": len(files),
        "languages": detect_languages(files),
        "scanners": config["scanners"],
        "fail_on": config["policy"]["fail_on"].value,
        "tests": config.get("tests"),
        "build": config.get("build"),
        "requirements": {
            "docker": True,
            "trivy_cache": "trivy" in config["scanners"],
        },
    }
