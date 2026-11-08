"""Pinned Trivy image analysis and CycloneDX conversion, without a Docker socket."""

import copy
import json
import re
from pathlib import Path, PurePosixPath
from uuid import uuid4

from flican.adapters.trivy import TRIVY_IMAGE, check_trivy_logs
from flican.core.docker import get_container_user, remove_container
from flican.core.models import Finding, Severity
from flican.core.process import run_bounded


def _command(docker, name, user, mounts):
    if any("," in str(source) for source, _ in mounts):
        raise ValueError("Image scan paths containing commas are not supported.")
    command = [docker, "run", "--rm", "--name", name, "--pull=never", "--network=none",
               "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
               "--cpus=2", "--memory=2g", "--memory-swap=2g", "--pids-limit=256",
               "--log-driver=none", "--user=" + user, "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=512m",
               "--env", "HOME=/tmp", "--workdir", "/tmp"]
    for source, target in mounts:
        command += ["--mount", f"type=bind,source={source.resolve(strict=True)},target={target},readonly"]
    return command + [TRIVY_IMAGE, "--config", ""]


def run_image_scan(docker: str, image: Path, cache: Path, output: Path, log: Path) -> int:
    name = "flican-image-" + uuid4().hex
    command = _command(docker, name, get_container_user(docker), [(image, "/input/layout"), (cache, "/cache")])
    command += ["image", "--input", "/input/layout", "--cache-dir=/cache", "--cache-backend=memory",
                "--scanners=vuln,secret", "--image-config-scanners=secret", "--skip-db-update",
                "--skip-java-db-update", "--offline-scan", "--disable-telemetry", "--skip-version-check",
                "--ignorefile", "", "--secret-config", "", "--list-all-pkgs", "--format=json", "--exit-code=10",
                "--max-image-size=4GB", "--timeout=180s"]
    try:
        return run_bounded(command, output, log, timeout=210)
    finally:
        remove_container(docker, name)


def run_sbom_conversion(docker: str, report: Path, output: Path, log: Path) -> int:
    name = "flican-sbom-" + uuid4().hex
    command = _command(docker, name, get_container_user(docker), [(report, "/input/report.json")])
    command += ["convert", "--format", "cyclonedx", "/input/report.json"]
    try:
        return run_bounded(command, output, log, timeout=120)
    finally:
        remove_container(docker, name)


def _severity(value):
    if value == "UNKNOWN":
        return Severity.HIGH, "flican:unknown-as-high"
    if not isinstance(value, str):
        raise ValueError("Image finding has no severity.")
    try:
        return Severity(value.lower()), "trivy"
    except ValueError as error:
        raise ValueError("Unsupported image finding severity.") from error


def _text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Image finding has invalid {label}.")
    return value.strip()


def _image_path(value):
    value = _text(value, "path")
    path = PurePosixPath(value.lstrip("/"))
    if ".." in path.parts or "\\" in value or any(ord(c) < 32 for c in value):
        raise ValueError("Invalid path in image findings.")
    return path.as_posix()


def parse_image_report(code: int, path: Path, stderr: str, image: dict) -> tuple[dict, list[Finding], dict]:
    if code not in (0, 10):
        raise RuntimeError(f"Trivy image analysis exited with code {code}.")
    # These pinned-version advisories describe valid coverage/severity choices, not scan failures.
    advisory = (
        r"\bWARN\s+(?:(?:\[os\]\s+)?OS is not detected\.?|"
        r"Using severities from other vendors for some vulnerabilities\. Read "
        r"https://trivy\.dev/docs/v0\.76/guide/scanner/vulnerability#severity-selection for details\.)$"
    )
    remaining = "\n".join(line for line in stderr.splitlines()
                          if not re.search(advisory, line))
    check_trivy_logs(remaining)
    report = json.loads(path.read_text())
    if (not isinstance(report, dict) or type(report.get("SchemaVersion")) is not int
            or report["SchemaVersion"] != 2 or report.get("ArtifactType") != "container_image"
            or not isinstance(report.get("Metadata"), dict)
            or report["Metadata"].get("ImageID") != image["config_digest"]):
        raise ValueError("The Trivy report does not identify the inspected OCI image.")
    groups = report.get("Results", [])
    if not isinstance(groups, list):
        raise ValueError("Trivy image Results must be an array.")
    sanitized, findings, package_count = copy.deepcopy(report), [], 0
    # ImageConfig can contain ENV values and build history; keep its digest, not its payload.
    sanitized["Metadata"].pop("ImageConfig", None)
    for index, group in enumerate(groups):
        if not isinstance(group, dict) or not isinstance(group.get("Target"), str):
            raise ValueError("Malformed Trivy image result group.")
        vulnerabilities, secrets, packages = (group.get(key, []) for key in ("Vulnerabilities", "Secrets", "Packages"))
        if any(not isinstance(items, list) or any(not isinstance(item, dict) for item in items)
               for items in (vulnerabilities, secrets, packages)):
            raise ValueError("Malformed Trivy image findings or package inventory.")
        package_count += len(packages)
        for item in vulnerabilities:
            severity, source = _severity(item.get("Severity"))
            identifier, package, version = (_text(item.get(key), key) for key in
                                             ("VulnerabilityID", "PkgName", "InstalledVersion"))
            fixed, title = item.get("FixedVersion", ""), item.get("Title", "")
            if not isinstance(fixed, str) or not isinstance(title, str):
                raise ValueError("Invalid vulnerability title/fix metadata.")
            findings.append(Finding("trivy-image", identifier, title.strip() or f"{package} {version}: {identifier}",
                                    severity, _image_path(item["PkgPath"]) if item.get("PkgPath") else None, None,
                                    package_name=package, package_version=version, fixed_version=fixed or None,
                                    resource_id=image["manifest_digest"], severity_source=source,
                                    framework=group.get("Type")))
        safe_secrets = []
        for item in secrets:
            severity, source = _severity(item.get("Severity"))
            line = item.get("StartLine")
            if line is not None and (type(line) is not int or line < 0):
                raise ValueError("Invalid secret finding line number.")
            identifier = _text(item.get("RuleID"), "secret RuleID")
            findings.append(Finding("trivy-image", identifier, _text(item.get("Title"), "secret Title"),
                                    severity, _image_path(group["Target"]), line or None,
                                    resource_id=image["manifest_digest"], severity_source=source, framework="secret"))
            safe_secrets.append({key: value for key, value in item.items()
                                 if key in {"RuleID", "Category", "Severity", "Title", "StartLine", "EndLine"}})
        if "Secrets" in group:
            sanitized["Results"][index]["Secrets"] = safe_secrets
    if code != (10 if findings else 0):
        raise ValueError("Trivy image exit code does not match its report.")
    return sanitized, findings, {"status": "completed", "packages": package_count,
                                 "os_detected": bool(report["Metadata"].get("OS"))}


def validate_sbom(path: Path, image: dict, report: dict | None = None) -> dict:
    value = json.loads(path.read_text())
    if (not isinstance(value, dict) or value.get("bomFormat") != "CycloneDX"
            or value.get("specVersion") not in ("1.4", "1.5", "1.6", "1.7")
            or type(value.get("version")) is not int or value["version"] < 1
            or not isinstance(value.get("metadata"), dict)
            or not isinstance(value["metadata"].get("component"), dict)
            or value["metadata"]["component"].get("type") != "container"
            or not isinstance(value["metadata"]["component"].get("name"), str)
            or not value["metadata"]["component"]["name"].strip()):
        raise ValueError("Trivy did not produce a valid supported CycloneDX inventory.")
    components = value.get("components", [])
    if not isinstance(components, list) or any(not isinstance(item, dict) or not isinstance(item.get("name"), str)
                                               or not isinstance(item.get("type"), str)
                                               for item in components):
        raise ValueError("Invalid CycloneDX component inventory.")
    properties = value["metadata"].setdefault("properties", [])
    if not isinstance(properties, list) or any(not isinstance(item, dict) or not isinstance(item.get("name"), str)
                                              or not isinstance(item.get("value"), str) for item in properties):
        raise ValueError("Invalid CycloneDX metadata properties.")
    if any(item["name"] in ("flican:image:manifest_digest", "flican:image:archive_sha256") for item in properties):
        raise ValueError("CycloneDX output already contains conflicting Flican image bindings.")
    if report is not None:
        packages = [package for group in report.get("Results", []) for package in group.get("Packages", [])]
        purls = {identifier["PURL"] for package in packages
                 if isinstance(identifier := package.get("Identifier", package.get("PkgIdentifier", {})), dict)
                 and isinstance(identifier.get("PURL"), str)}
        if (packages and not components) or not purls.issubset({component.get("purl") for component in components}):
            raise ValueError("The CycloneDX output dropped identified image packages.")
    properties += [{"name": "flican:image:manifest_digest", "value": image["manifest_digest"]},
                   {"name": "flican:image:archive_sha256", "value": image["archive_sha256"]}]
    return value
