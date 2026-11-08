import subprocess
from pathlib import Path
from uuid import uuid4
import json

from flican.core.docker import get_container_user, remove_container
from flican.core.cache import validate_trivy_db_digest
from flican.core.models import Finding, Severity
from flican.core.paths import normalize_source_path


TRIVY_IMAGE = (
    "aquasec/trivy:0.76.1"
    "@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
)


def build_scan_arguments(source_path: str, cache_path: str) -> list[str]:
    return [
        "fs",
        "--scanners=vuln",
        f"--cache-dir={cache_path}",
        "--cache-backend=memory",
        "--skip-db-update",
        "--offline-scan",
        "--disable-telemetry",
        "--skip-version-check",
        "--format=json",
        "--exit-code=10",
        "--timeout=60s",
        source_path,
    ]

def build_db_update_arguments(cache_path: str, db_digest: str | None = None) -> list[str]:
    validate_trivy_db_digest(db_digest)
    arguments = [
        "image",
        "--download-db-only",
        f"--cache-dir={cache_path}",
        "--disable-telemetry",
        "--skip-version-check",
        "--no-progress",
        "--timeout=10m",
    ]
    if db_digest is not None:
        arguments += ["--db-repository", f"ghcr.io/aquasecurity/trivy-db@{db_digest}"]
    return arguments

def build_db_update_docker_command(
    docker_path: str,
    cache_path: Path,
    container_name: str,
    user_spec: str,
    db_digest: str | None = None,
) -> list[str]:
    cache_directory = cache_path.resolve(strict=True)

    if not cache_directory.is_dir():
        raise ValueError("Trivy cache path must be a directory.")

    if "," in str(cache_directory):
        raise ValueError("Mount paths containing commas are not supported yet.")

    return [
        docker_path,
        "run",
        "--rm",
        "--name",
        container_name,
        "--pull=never",
        "--network=bridge",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--user={user_spec}",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=64m",
        "--env",
        "HOME=/tmp",
        "--env",
        "TMPDIR=/cache",
        "--mount",
        f"type=bind,source={cache_directory},target=/cache",
        TRIVY_IMAGE,
        *build_db_update_arguments("/cache", db_digest),
    ]

def run_trivy_db_update(
    docker_path: str,
    cache_path: Path,
    db_digest: str | None = None,
) -> subprocess.CompletedProcess[str]:
    cache_path.mkdir(mode=0o700, parents=True, exist_ok=True)

    container_name = f"flican-trivy-db-{uuid4().hex}"
    user_spec = get_container_user(docker_path)

    command = build_db_update_docker_command(
        docker_path=docker_path,
        cache_path=cache_path,
        container_name=container_name,
        user_spec=user_spec,
        db_digest=db_digest,
    )

    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=660,
            check=False,
        )
    finally:
        remove_container(docker_path, container_name)

def build_docker_command(
    docker_path: str,
    snapshot_path: Path,
    cache_path: Path,
    container_name: str,
    user_spec: str,
) -> list[str]:
    source_path = snapshot_path.resolve(strict=True)
    cache_directory = cache_path.resolve()

    if not source_path.is_dir():
        raise ValueError("Snapshot path must be a directory.")

    if not cache_directory.is_dir():
        raise ValueError(
            f"Trivy cache is not ready: {cache_directory}. "
            "Run 'flican ci prepare <project>' or 'flican db update' first; "
            "use the same cache override if one was selected."
        )

    if any("," in str(path) for path in (source_path, cache_directory)):
        raise ValueError("Mount paths containing commas are not supported yet.")

    for filename in ("trivy.db", "metadata.json"):
        if not (cache_directory / "db" / filename).is_file():
            raise ValueError(
                f"Trivy database is missing {filename} in {cache_directory}. "
                "Run 'flican ci prepare <project>' or 'flican db update' first; "
                "use the same cache override if one was selected."
            )

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
        f"type=bind,source={cache_directory},target=/cache,readonly",
        TRIVY_IMAGE,
        *build_scan_arguments("/src", "/cache"),
    ]

def run_trivy(
    docker_path: str,
    snapshot_path: Path,
    cache_path: Path,
) -> subprocess.CompletedProcess[str]:
    container_name = f"flican-trivy-{uuid4().hex}"
    user_spec = get_container_user(docker_path)

    command = build_docker_command(
        docker_path=docker_path,
        snapshot_path=snapshot_path,
        cache_path=cache_path,
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

def check_trivy_logs(stderr: str) -> None:
    allowed_license_warning = (
        "[pip] Unable to find python `site-packages` directory. "
        "License detection is skipped.\t"
        'err="unable to find path to Python executable"'
    )

    for line in stderr.splitlines():
        parts = line.strip().split(maxsplit=2)

        if not parts:
            continue

        if len(parts) == 3:
            _, level, message = parts

            if level == "INFO":
                continue

            if level == "WARN" and message == allowed_license_warning:
                continue

        raise RuntimeError(
            f"Trivy emitted diagnostics on stderr: {line!r}"
        )

def parse_trivy_report(
    result: subprocess.CompletedProcess[str],
) -> list[dict]:
    if result.returncode not in (0, 10):
        raise RuntimeError(
            f"Trivy failed with exit code {result.returncode}."
        )

    check_trivy_logs(result.stderr)

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("Trivy returned invalid JSON.") from error

    if not isinstance(report, dict):
        raise ValueError("Trivy report must be an object.")

    schema_version = report.get("SchemaVersion")
    if type(schema_version) is not int or schema_version != 2:
        raise ValueError("Unsupported Trivy report schema. Expected 2.")

    groups = report.get("Results", [])
    if not isinstance(groups, list) or not all(
        isinstance(group, dict) for group in groups
    ):
        raise ValueError("Trivy Results must be a list of objects.")

    findings = []

    for group in groups:
        target = group.get("Target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Trivy result has invalid Target.")

        vulnerabilities = group.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list) or not all(
            isinstance(item, dict) for item in vulnerabilities
        ):
            raise ValueError(
                "Trivy Vulnerabilities must be a list of objects."
            )

        for vulnerability in vulnerabilities:
            findings.append({
                "Target": target,
                "Vulnerability": vulnerability,
            })

    expected_code = 10 if findings else 0
    if result.returncode != expected_code:
        raise ValueError("Trivy exit code does not match its report.")

    return findings

def normalize_trivy_finding(raw: dict) -> Finding:
    file_path = normalize_source_path(raw.get("Target"))

    vulnerability = raw.get("Vulnerability")
    if not isinstance(vulnerability, dict):
        raise ValueError("Trivy finding must contain a vulnerability object.")

    required_fields = (
        "VulnerabilityID",
        "PkgName",
        "InstalledVersion",
        "Severity",
    )

    for field in required_fields:
        value = vulnerability.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Trivy vulnerability has invalid {field}.")

    vulnerability_id = vulnerability["VulnerabilityID"].strip()
    package_name = vulnerability["PkgName"].strip()
    package_version = vulnerability["InstalledVersion"].strip()

    try:
        severity = Severity(vulnerability["Severity"].strip().lower())
    except ValueError as error:
        raise ValueError("Unsupported Trivy severity.") from error

    title = vulnerability.get("Title", "")
    fixed_version = vulnerability.get("FixedVersion", "")

    if not isinstance(title, str):
        raise ValueError("Trivy vulnerability has invalid Title.")

    if not isinstance(fixed_version, str):
        raise ValueError("Trivy vulnerability has invalid FixedVersion.")

    description = title.strip() or (
        f"{package_name} {package_version}: {vulnerability_id}"
    )

    return Finding(
        scanner="trivy",
        rule_id=vulnerability_id,
        description=description,
        severity=severity,
        file_path=file_path,
        line=None,
        package_name=package_name,
        package_version=package_version,
        fixed_version=fixed_version.strip() or None,
    )
