from pathlib import Path
import json
import subprocess
from uuid import uuid4
from flican.core.models import Finding, Severity
from flican.core.docker import get_container_user, remove_container
from flican.core.paths import normalize_source_path

GITLEAKS_IMAGE = (
    "ghcr.io/gitleaks/gitleaks:v8.30.1"
    "@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
)


def build_scan_arguments(source_path: str) -> list[str]:
    """Build the arguments for a Gitleaks directory scan."""
    return [
        "dir",
        source_path,
        "--no-banner",
        "--no-color",
        "--log-level=warn",
        "--redact=100",
        "--exit-code=10",
        "--timeout=60",
        "--report-format=json",
        "--report-path=-",
    ]

def build_docker_command(
    docker_path: str,
    snapshot_path: Path,
    container_name: str,
    user_spec: str,
) -> list[str]:
    """Build the Docker command for a Gitleaks scan."""
    source_path = snapshot_path.resolve(strict=True)

    if not source_path.is_dir():
        raise ValueError("Snapshot path must be a directory.")

    if "," in str(source_path):
        raise ValueError("Snapshot paths containing commas are not supported yet.")

    return [
        docker_path,
        "run",
        "--rm",
        "--name", container_name,
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--user={user_spec}",
        "--mount",
        f"type=bind,source={source_path},target=/src,readonly",
        GITLEAKS_IMAGE,
        *build_scan_arguments("/src"),
    ]


def run_gitleaks(
    docker_path: str,
    snapshot_path: Path,
) -> subprocess.CompletedProcess[str]:
    """Run Gitleaks and clean up its container."""
    container_name = f"flican-gitleaks-{uuid4().hex}"
    user_spec = get_container_user(docker_path)

    command = build_docker_command(
        docker_path=docker_path,
        snapshot_path=snapshot_path,
        container_name=container_name,
        user_spec=user_spec,
    )

    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    finally:
        remove_container(docker_path, container_name)

def parse_gitleaks_report(
    result: subprocess.CompletedProcess[str],
) -> list[dict]:
    """Parse the report and check basic result consistency."""
    if result.returncode not in (0, 10):
        raise RuntimeError(
            f"Gitleaks failed with exit code {result.returncode}."
        )

    try:
        findings = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("Gitleaks returned invalid JSON.") from error

    if not isinstance(findings, list) or not all(
        isinstance(finding, dict) for finding in findings
    ):
        raise ValueError("Gitleaks report must be a list of objects.")

    for finding in findings:
        for field in ("RuleID", "File"):
            value = finding.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Gitleaks finding has invalid {field}.")

    expected_code = 10 if findings else 0
    if result.returncode != expected_code:
        raise ValueError("Gitleaks exit code does not match its report.")

    check_gitleaks_logs(result.stderr, len(findings))

    return findings

    return findings

def check_gitleaks_logs(stderr: str, finding_count: int) -> None:
    """Reject diagnostics except the matching findings summary."""
    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split(maxsplit=2)

        if (
            finding_count > 0
            and len(parts) == 3
            and parts[1] == "WRN"
            and parts[2] == f"leaks found: {finding_count}"
        ):
            continue

        raise RuntimeError("Scanner emitted diagnostics on stderr.")

def normalize_gitleaks_finding(raw: dict) -> Finding:
    """Convert a parsed Gitleaks record to Flican's common format."""
    file_path = normalize_source_path(raw["File"])

    line = raw.get("StartLine")
    if line is not None and (type(line) is not int or line < 0):
        raise ValueError("Gitleaks StartLine must be a non-negative integer.")

    description = raw.get("Description", "")
    if not isinstance(description, str):
        raise ValueError("Gitleaks Description must be a string.")

    column = raw.get("StartColumn")
    if column is not None and (type(column) is not int or column < 0):
        raise ValueError("Gitleaks StartColumn must be a non-negative integer.")

    return Finding(
        scanner="gitleaks",
        rule_id=raw["RuleID"],
        description=description.strip() or "Potential secret detected",
        severity=Severity.HIGH,
        file_path=file_path,
        line=None if line == 0 else line,
        column=column or None,
    )
