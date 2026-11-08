import subprocess
from importlib.resources import as_file, files
from pathlib import Path
from uuid import uuid4
import json


from flican.core.docker import get_container_user, remove_container
from flican.core.models import Finding, Severity
from flican.core.paths import normalize_source_path

SEMGREP_IMAGE = (
    "semgrep/semgrep:1.182.0"
    "@sha256:4a34048c04fef049f71665047f074cffb00cc3d89482f965a5cd151d589237af"
)
SEMGREP_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

def build_scan_arguments(source_path: str, rules_path: str) -> list[str]:
    return [
        "semgrep",
        "scan",
        f"--config={rules_path}",
        "--oss-only",
        "--metrics=off",
        "--disable-version-check",
        "--no-rewrite-rule-ids",
        "--strict",
        "--json",
        "--error",
        source_path,
    ]

def build_docker_command(
    docker_path: str,
    snapshot_path: Path,
    rules_path: Path,
    container_name: str,
    user_spec: str,
) -> list[str]:
    source_path = snapshot_path.resolve(strict=True)
    rules_dir = rules_path.resolve(strict=True)

    if not source_path.is_dir():
        raise ValueError("Snapshot path must be a directory.")

    if not rules_dir.is_dir():
        raise ValueError("Semgrep rules path must be a directory.")

    if any("," in str(path) for path in (source_path, rules_dir)):
        raise ValueError("Mount paths containing commas are not supported yet.")

    return [
        docker_path,
        "run",
        "--rm",
        "--name",
        container_name,
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--user={user_spec}",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=64m",
        "--env",
        "HOME=/tmp",
        "--mount",
        f"type=bind,source={source_path},target=/src,readonly",
        "--mount",
        f"type=bind,source={rules_dir},target=/rules/semgrep,readonly",
        SEMGREP_IMAGE,
        *build_scan_arguments("/src", "/rules/semgrep"),
    ]

def run_semgrep(
    docker_path: str,
    snapshot_path: Path,
) -> subprocess.CompletedProcess[str]:
    container_name = f"flican-semgrep-{uuid4().hex}"
    user_spec = get_container_user(docker_path)

    rules_resource = files("flican").joinpath(
        "rules",
        "semgrep",
    )

    with as_file(rules_resource) as rules_path:
        command = build_docker_command(
            docker_path=docker_path,
            snapshot_path=snapshot_path,
            rules_path=rules_path,
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

def parse_semgrep_report(
    result: subprocess.CompletedProcess[str],
) -> list[dict]:
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Semgrep failed with exit code {result.returncode}."
        )

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("Semgrep returned invalid JSON.") from error

    if not isinstance(report, dict):
        raise ValueError("Semgrep report must be an object.")

    errors = report.get("errors")
    if not isinstance(errors, list):
        raise ValueError("Semgrep report must contain an errors list.")

    if errors:
        raise RuntimeError("Semgrep reported scan errors.")

    findings = report.get("results")
    if not isinstance(findings, list) or not all(
        isinstance(finding, dict) for finding in findings
    ):
        raise ValueError("Semgrep results must be a list of objects.")

    for finding in findings:
        for field in ("check_id", "path"):
            value = finding.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Semgrep finding has invalid {field}."
                )

    expected_code = 1 if findings else 0
    if result.returncode != expected_code:
        raise ValueError("Semgrep exit code does not match its report.")

    return findings

def normalize_semgrep_finding(raw: dict) -> Finding:
    rule_id = raw.get("check_id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise ValueError("Semgrep finding has invalid check_id.")

    file_path = normalize_source_path(raw.get("path"))

    start = raw.get("start")
    if not isinstance(start, dict):
        raise ValueError("Semgrep finding has invalid start position.")

    line = start.get("line")
    if type(line) is not int or line < 1:
        raise ValueError("Semgrep finding line must be a positive integer.")

    column = start.get("col")
    if column is not None and (type(column) is not int or column < 1):
        raise ValueError("Semgrep finding column must be a positive integer.")

    extra = raw.get("extra")
    if not isinstance(extra, dict):
        raise ValueError("Semgrep finding has invalid extra data.")

    description = extra.get("message")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("Semgrep finding has invalid message.")

    raw_severity = extra.get("severity")
    if (
        not isinstance(raw_severity, str)
        or raw_severity not in SEMGREP_SEVERITY_MAP
    ):
        raise ValueError("Semgrep finding has invalid severity.")

    return Finding(
        scanner="semgrep",
        rule_id=rule_id,
        description=description.strip(),
        severity=SEMGREP_SEVERITY_MAP[raw_severity],
        file_path=file_path,
        line=line,
        column=column,
    )
