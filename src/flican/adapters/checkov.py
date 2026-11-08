"""Offline Terraform and Dockerfile checks using Flican's pinned profile."""

import json
import re
import subprocess
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path
from uuid import uuid4

from flican.core.docker import get_container_user, remove_container
from flican.core.models import Finding, Severity
from flican.core.paths import normalize_source_path

CHECKOV_VERSION = "3.3.30"
CHECKOV_IMAGE = (
    "bridgecrew/checkov:3.3.30"
    "@sha256:4b65e89f1fde292249fc0aa0d0db43302c036dfe39f7370b2d3517571082b894"
)
# Owner-selected policy for offline checks without native severity. This is a
# Flican blocking level, not a risk rating supplied by Checkov or a CVSS score.
CHECKOV_UNRATED_SEVERITY = Severity.HIGH
SUMMARY_COUNTS = ("passed", "failed", "skipped", "parsing_errors", "resource_count")
CHECKOV_FRAMEWORKS = ("terraform", "dockerfile")


@dataclass(frozen=True)
class CheckovReport:
    findings: list[dict]
    coverage: dict


def is_checkov_dockerfile(filename: str) -> bool:
    """Match the Dockerfile basenames recognized by the pinned Checkov runner."""
    return (
        re.fullmatch(r"(?:.+\.)?[Dd]ockerfile(?:\..+)?", filename) is not None
        and not filename.endswith((".dockerignore", ".Dockerignore"))
    )


def build_scan_arguments(source_path: str, profile_path: str) -> list[str]:
    # In this pinned version, get_default_config_paths() discovers project config
    # only for a separate --directory argument. Keep the equals form and a safe
    # working directory; a trusted config alone would still merge auto-loaded files.
    return [
        f"--directory={source_path}",
        f"--config-file={profile_path}",
    ]


def build_docker_command(
    docker_path: str,
    snapshot_path: Path,
    profile_path: Path,
    container_name: str,
    user_spec: str,
) -> list[str]:
    source = snapshot_path.resolve(strict=True)
    profile = profile_path.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("Snapshot path must be a directory.")
    if not profile.is_file():
        raise ValueError("Checkov profile path must be a file.")
    if any("," in str(path) for path in (source, profile)):
        raise ValueError("Mount paths containing commas are not supported yet.")

    return [
        docker_path, "run", "--rm", "--name", container_name,
        "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", f"--user={user_spec}",
        "--workdir=/tmp", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m",
        "--env", "HOME=/tmp",
        "--env", "PYTHONDONTWRITEBYTECODE=1",
        "--env", "ANSI_COLORS_DISABLED=1",
        "--env", "LOG_LEVEL=WARNING",
        "--mount", f"type=bind,source={source},target=/src,readonly",
        "--mount", f"type=bind,source={profile},target=/rules/checkov.yaml,readonly",
        CHECKOV_IMAGE,
        *build_scan_arguments("/src", "/rules/checkov.yaml"),
    ]


def run_checkov(
    docker_path: str,
    snapshot_path: Path,
) -> subprocess.CompletedProcess[str]:
    name = f"flican-checkov-{uuid4().hex}"
    user = get_container_user(docker_path)
    resource = files("flican").joinpath("rules", "checkov", "profile.yaml")
    with as_file(resource) as profile:
        command = build_docker_command(docker_path, snapshot_path, profile, name, user)
        try:
            return subprocess.run(
                command, capture_output=True, text=True, timeout=180, check=False,
            )
        finally:
            remove_container(docker_path, name)


def _validate_summary(summary: object) -> dict:
    if not isinstance(summary, dict):
        raise ValueError("Checkov report must contain a summary object.")
    for field in SUMMARY_COUNTS:
        value = summary.get(field)
        if type(value) is not int or value < 0:
            raise ValueError(f"Checkov summary has invalid {field}.")
    if summary.get("checkov_version") != CHECKOV_VERSION:
        raise ValueError("Checkov report version does not match the pinned version.")
    return summary


def _coverage(summary: dict, framework: str) -> dict:
    if summary["resource_count"] == 0:
        status = "no_resources"
    elif summary["skipped"]:
        status = "partial"
    elif summary["passed"] + summary["failed"] == 0:
        status = "no_checks"
    else:
        status = "completed"
    return {
        "framework": framework,
        "status": status,
        **{field: summary[field] for field in SUMMARY_COUNTS},
        "checkov_version": CHECKOV_VERSION,
    }


def _required_text(raw: dict, field: str) -> str:
    value = raw.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Checkov finding has invalid {field}.")
    return value.strip()


def _line(raw: dict) -> int | None:
    position = raw.get("file_line_range")
    if position is None:
        return None
    if (
        not isinstance(position, list)
        or len(position) != 2
        or any(type(value) is not int for value in position)
    ):
        raise ValueError("Checkov line range must contain two integers.")
    start, end = position
    if start == end == 0:
        return None
    if start < 1 or end < start:
        raise ValueError("Checkov line range must be positive and ordered.")
    return start


def _validate_record(raw: dict, expected_status: str) -> None:
    for field in ("check_id", "check_name", "resource"):
        _required_text(raw, field)
    # file_path is project-root-relative but starts with '/' in Checkov. Its
    # file_abs_path records the actual container path, which must stay in /src.
    _file_path(raw)
    _line(raw)
    result = raw.get("check_result")
    if not isinstance(result, dict) or result.get("result") != expected_status:
        raise ValueError("Checkov check result does not match its report bucket.")


def _file_path(raw: dict) -> str:
    path = raw.get("file_abs_path")
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("Checkov file_abs_path must be an absolute container path.")
    return normalize_source_path(path)


def _parse_framework_report(report: object) -> tuple[str, dict, list[dict], set[str]]:
    if not isinstance(report, dict):
        raise ValueError("Checkov framework report must be an object.")
    framework = report.get("check_type")
    if framework not in CHECKOV_FRAMEWORKS:
        raise ValueError("Checkov framework must be terraform or dockerfile.")
    summary = _validate_summary(report.get("summary"))
    results = report.get("results")
    if not isinstance(results, dict):
        raise ValueError("Checkov results must be an object.")
    errors = results.get("parsing_errors")
    if not isinstance(errors, list):
        raise ValueError("Checkov report must contain parsing_errors.")
    if errors or summary["parsing_errors"]:
        # Native Checkov may return 0 even after a framework failed to parse.
        label = "Terraform" if framework == "terraform" else "Dockerfile"
        raise RuntimeError(f"Checkov reported {label} parsing errors.")

    reported_files = set()
    for field, count, status in (
        ("passed_checks", "passed", "PASSED"),
        ("failed_checks", "failed", "FAILED"),
        ("skipped_checks", "skipped", "SKIPPED"),
    ):
        records = results.get(field)
        if not isinstance(records, list) or not all(isinstance(item, dict) for item in records):
            raise ValueError(f"Checkov {field} must be a list of objects.")
        if len(records) != summary[count]:
            raise ValueError(f"Checkov {field} does not match the summary.")
        for record in records:
            _validate_record(record, status)
            reported_files.add(_file_path(record))

    if summary["resource_count"] == 0 and any(
        summary[field] for field in ("passed", "failed", "skipped")
    ):
        raise ValueError("Checkov checks have no reported resources.")
    findings = [dict(record, check_type=framework) for record in results["failed_checks"]]
    return framework, summary, findings, reported_files


def parse_checkov_report(
    result: subprocess.CompletedProcess[str],
    *,
    expected_dockerfiles: set[str] | None = None,
) -> CheckovReport:
    if result.returncode not in (0, 1):
        raise RuntimeError(f"Checkov failed with exit code {result.returncode}.")
    # The profile sets the log threshold to WARNING. Healthy scans emit no stderr.
    if result.stderr.strip():
        diagnostic = next(line for line in result.stderr.splitlines() if line.strip())
        raise RuntimeError(f"Checkov emitted diagnostics on stderr: {diagnostic[:1000]!r}")
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("Checkov returned invalid JSON.") from error

    by_framework = {}
    if isinstance(document, dict) and "summary" not in document:
        # The native summary-only form loses framework identity. Keep its counts
        # globally, without inventing per-framework resource counts.
        summary = _validate_summary(document)
        if set(document) != {*SUMMARY_COUNTS, "checkov_version"} or any(
            summary[field] for field in ("passed", "failed", "skipped", "parsing_errors")
        ):
            raise ValueError("Checkov returned an incomplete report.")
    else:
        reports = document if isinstance(document, list) else [document]
        if not reports:
            raise ValueError("Checkov report list must not be empty.")
        for report in reports:
            framework, counts, findings, paths = _parse_framework_report(report)
            if framework in by_framework:
                raise ValueError("Checkov returned duplicate framework reports.")
            by_framework[framework] = (counts, findings, paths)
        summary = {
            field: sum(item[0][field] for item in by_framework.values())
            for field in SUMMARY_COUNTS
        }
        summary["checkov_version"] = CHECKOV_VERSION

    expected_code = 1 if summary["failed"] else 0
    if result.returncode != expected_code:
        raise ValueError("Checkov exit code does not match its report.")

    label = next(iter(by_framework)) if len(by_framework) == 1 else (
        "multiple" if by_framework else "unattributed"
    )
    coverage = _coverage(summary, label)
    coverage["frameworks"] = {
        framework: _coverage(by_framework[framework][0], framework)
        if framework in by_framework else {"status": "not_reported"}
        for framework in CHECKOV_FRAMEWORKS
    }
    if expected_dockerfiles is not None:
        reported = by_framework["dockerfile"][2] if "dockerfile" in by_framework else set()
        missing = expected_dockerfiles - reported
        if missing:
            names = ", ".join(sorted(missing))
            raise RuntimeError(f"Checkov did not report checks for Dockerfile(s): {names}")
        coverage["frameworks"]["dockerfile"].update(
            inventory_checked=True,
            files_expected=len(expected_dockerfiles),
            files_reported=len(reported),
        )
    findings = [
        record
        for framework in CHECKOV_FRAMEWORKS if framework in by_framework
        for record in by_framework[framework][1]
    ]
    return CheckovReport(findings, coverage)


def normalize_checkov_finding(raw: dict) -> Finding:
    _validate_record(raw, "FAILED")
    framework = raw.get("check_type")
    if framework is not None and framework not in CHECKOV_FRAMEWORKS:
        raise ValueError("Checkov finding has an unsupported framework.")
    raw_severity = raw.get("severity")
    if raw_severity is None:
        severity = CHECKOV_UNRATED_SEVERITY
        severity_source = "flican_policy"
    else:
        if not isinstance(raw_severity, str):
            raise ValueError("Checkov finding has invalid severity.")
        try:
            severity = Severity(raw_severity.lower())
        except ValueError as error:
            raise ValueError("Checkov finding has unknown severity.") from error
        severity_source = "checkov"
    return Finding(
        scanner="checkov",
        rule_id=_required_text(raw, "check_id"),
        description=_required_text(raw, "check_name"),
        severity=severity,
        file_path=_file_path(raw),
        line=_line(raw),
        resource_id=_required_text(raw, "resource"),
        severity_source=severity_source,
        framework=framework,
    )
