"""Shared Docker helpers for scanner adapters."""

import json
import os
import subprocess


def get_container_user(docker_path: str) -> str:
    """Choose a container user for a local Linux Docker Engine."""
    result = subprocess.run(
        [docker_path, "info", "--format", "{{json .SecurityOptions}}"],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )

    security_options = json.loads(result.stdout)

    if not isinstance(security_options, list) or not all(
        isinstance(option, str) for option in security_options
    ):
        raise ValueError("Invalid Docker security options.")

    if "name=userns" in security_options:
        raise ValueError("Docker userns-remap is not supported yet.")

    if "name=rootless" in security_options:
        return "0:0"

    return f"{os.getuid()}:{os.getgid()}"

def remove_container(docker_path: str, container_name: str) -> None:
    """Remove the scanner container if it still exists."""
    result = subprocess.run(
        [docker_path, "rm", "--force", container_name],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    if result.returncode == 0:
        return

    if f"No such container: {container_name}" in result.stderr:
        return

    raise RuntimeError(
        f"Cannot remove scanner container: {container_name}"
    )