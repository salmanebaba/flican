from pathlib import Path
from pathlib import PurePosixPath
import re
import yaml

from flican.core.models import Severity


def _project_relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or any(ord(c) < 32 for c in value):
        raise ValueError(f"{label} must be a project-relative path.")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ValueError(f"{label} must stay inside the project without traversal.")
    return value


def validate_build(value: object) -> dict:
    if not isinstance(value, dict) or set(value) - {"backend", "context", "dockerfile", "platform", "network", "timeout_seconds"}:
        raise ValueError("build accepts backend, context, dockerfile, platform, network and timeout_seconds.")
    if value.get("backend", "buildkit") != "buildkit":
        raise ValueError("Only the buildkit backend is currently supported.")
    context = _project_relative(value.get("context", "."), "build.context")
    dockerfile = _project_relative(value.get("dockerfile", "Dockerfile"), "build.dockerfile")
    platform = value.get("platform", "linux/amd64")
    if platform not in ("linux/amd64", "linux/arm64"):
        raise ValueError("build.platform must select one linux/amd64 or linux/arm64 image.")
    network = value.get("network", "none")
    if network not in ("none", "default"):
        raise ValueError("build.network must be none or default; host networking is not supported.")
    timeout = value.get("timeout_seconds", 600)
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ValueError("build.timeout_seconds must be an integer between 1 and 3600.")
    return {"backend": "buildkit", "context": context, "dockerfile": dockerfile,
            "platform": platform, "network": network, "timeout_seconds": timeout}


def validate_tests(value: object) -> dict:
    if not isinstance(value, dict) or set(value) - {"image", "command", "timeout_seconds", "network"}:
        raise ValueError("tests must contain only image, command, timeout_seconds and network.")
    image = value.get("image")
    if (not isinstance(image, str) or len(image) > 512
            or not re.fullmatch(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}", image)
            or "://" in image or ".." in image):
        raise ValueError("tests.image must be a container image pinned by @sha256: followed by 64 hex characters.")
    command = value.get("command")
    if (not isinstance(command, list) or not command or len(command) > 128
            or any(not isinstance(arg, str) or "\x00" in arg or len(arg) > 8192 for arg in command)
            or not command[0].strip()):
        raise ValueError("tests.command must be a non-empty argument list, for example [python, -m, unittest].")
    timeout = value.get("timeout_seconds", 300)
    if type(timeout) is not int or not 1 <= timeout <= 1800:
        raise ValueError("tests.timeout_seconds must be an integer between 1 and 1800.")
    network = value.get("network", "none")
    if network not in ("none", "bridge"):
        raise ValueError("tests.network must be none or bridge.")
    return {"image": image, "command": list(command), "timeout_seconds": timeout, "network": network}


def load_config(config_path: Path) -> dict:
    """Read and validate a YAML configuration file."""
    with config_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ValueError("Configuration must be a YAML mapping.")

    schema_version = data.get("schema_version")

    if type(schema_version) is not int:
        raise ValueError("schema_version must be an integer.")

    if schema_version != 1:
        raise ValueError("Unsupported schema_version. Expected 1.")

    project = data.get("project")

    if not isinstance(project, dict):
        raise ValueError("project must be a YAML mapping.")

    project_name = project.get("name")

    if not isinstance(project_name, str) or not project_name.strip():
        raise ValueError("project.name must be a non-empty string.")

    exclusions = project.get("exclude")

    if not isinstance(exclusions, list):
        raise ValueError("project.exclude must be a list.")

    for entry in exclusions:
        if not isinstance(entry, str) or not entry.strip():
            raise ValueError(
                "project.exclude entries must be non-empty strings."
            )

        if entry in {".", ".."} or any(
            character in entry for character in "/\\*?[]"
        ):
            raise ValueError(
                "project.exclude entries must be literal names."
            )

    policy = data.get("policy", {})
    if not isinstance(policy, dict):
        raise ValueError("policy must be a YAML mapping.")

    if set(policy) - {"fail_on"}:
        raise ValueError("policy only accepts the fail_on setting.")

    fail_on = policy.get("fail_on", "high")
    if not isinstance(fail_on, str):
        raise ValueError("policy.fail_on must be a string.")

    try:
        threshold = Severity(fail_on)
    except ValueError as error:
        raise ValueError(
            "policy.fail_on must be one of: "
            "info, low, medium, high, critical."
        ) from error

    data["policy"] = {"fail_on": threshold}

    if set(data) - {"schema_version", "project", "policy", "scanners", "tests", "build"}:
        raise ValueError("Unknown configuration setting.")
    if set(project) - {"name", "exclude"}:
        raise ValueError("Unknown project setting.")

    scanners = data.get("scanners", ["gitleaks", "semgrep"])

    if not isinstance(scanners, list) or not scanners:
        raise ValueError("scanners must be a non-empty list.")

    allowed_scanners = {"gitleaks", "semgrep", "trivy", "checkov"}

    for scanner in scanners:
        if not isinstance(scanner, str) or scanner not in allowed_scanners:
            raise ValueError(
                "scanners entries must be gitleaks, semgrep, trivy or checkov."
            )

    if len(scanners) != len(set(scanners)):
        raise ValueError("scanners must not contain duplicates.")

    data["scanners"] = scanners
    if "tests" in data:
        data["tests"] = validate_tests(data["tests"])
    if "build" in data:
        data["build"] = validate_build(data["build"])
    return data
