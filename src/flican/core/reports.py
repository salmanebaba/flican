import os
from pathlib import Path


def save_report(report_path: Path, content: str) -> None:
    """Save a new report with access restricted to its owner."""
    report_path.parent.mkdir(
        mode=0o700,
        parents=True,
        exist_ok=True,
    )

    with report_path.open("x", encoding="utf-8") as report:
        os.fchmod(report.fileno(), 0o600)
        report.write(content)