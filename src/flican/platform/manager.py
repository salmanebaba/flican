"""Lifecycle for the pinned, private local DefectDojo stack."""

import json
import secrets
import shutil
import string
import subprocess
import time
from importlib.resources import as_file, files
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, build_opener

from flican.core.state import (
    private_directory, read_private_json, state_directory,
    state_lock, write_private_json, write_private_text,
)

DOJO_VERSION = "3.4.304"
COMPOSE_PROJECT = "flican-defectdojo"


def prepare_platform(port: int = 8088) -> dict:
    root = state_directory() / "defectdojo"
    private_directory(root)
    path = root / "platform.json"
    if path.exists():
        config = read_private_json(path)
        if config.get("version") != DOJO_VERSION or config.get("port") != port:
            raise ValueError("Existing platform version/port differs; keep its settings or plan a migration.")
        return config
    if not 1024 <= port <= 65535:
        raise ValueError("The local DefectDojo port must be between 1024 and 65535.")
    alphabet = string.ascii_letters + string.digits
    values = {
        "FLICAN_DOJO_PORT": str(port),
        "FLICAN_DOJO_DB_PASSWORD": secrets.token_hex(24),
        "FLICAN_DOJO_SECRET_KEY": secrets.token_hex(40),
        "FLICAN_DOJO_AES_KEY": "".join(secrets.choice(alphabet) for _ in range(32)),
        "FLICAN_DOJO_ADMIN_PASSWORD": secrets.token_urlsafe(24),
        "FLICAN_DOJO_WEBHOOK_SECRET": secrets.token_hex(32),
    }
    write_private_text(root / "compose.env", "".join(f"{key}={value}\n" for key, value in values.items()))
    config = {"version": DOJO_VERSION, "port": port, "url": f"http://127.0.0.1:{port}"}
    write_private_json(root / "login.json", {
        "url": config["url"], "username": "flican-admin",
        "password": values["FLICAN_DOJO_ADMIN_PASSWORD"],
    })
    write_private_json(path, config)
    return config


def run_compose(arguments: list[str], *, sensitive: bool = False, timeout: int = 900):
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("Docker CLI was not found in PATH.")
    root = state_directory() / "defectdojo"
    if not (root / "compose.env").is_file():
        raise ValueError("The local platform is not initialized; run flican platform up.")
    resource = files("flican.platform").joinpath("compose.yaml")
    with as_file(resource) as compose:
        command = [
            docker, "compose", "--project-name", COMPOSE_PROJECT,
            "--env-file", str(root / "compose.env"), "--file", str(compose),
            *arguments,
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    if not sensitive:
        write_private_text(root / "compose.log", result.stdout + result.stderr)
    if result.returncode:
        if sensitive:
            output = "\n".join(line for line in (result.stdout + result.stderr).splitlines()
                               if not line.startswith("FLICAN_BOOTSTRAP="))
            for line in (root / "compose.env").read_text().splitlines():
                key, value = line.split("=", 1)
                if any(word in key for word in ("PASSWORD", "SECRET", "KEY")):
                    output = output.replace(value, "[REDACTED]")
            write_private_text(root / "bootstrap-error.log", output)
        detail = f" See {root / ('bootstrap-error.log' if sensitive else 'compose.log')}."
        raise RuntimeError(f"Docker Compose failed with exit code {result.returncode}.{detail}")
    return result


def start_platform(port: int = 8088, progress=print) -> dict:
    with state_lock():
        config = prepare_platform(port)
        progress("Starting the local DefectDojo services...")
        run_compose(["config", "--quiet"], timeout=30)
        run_compose(["up", "--detach", "--pull", "missing"])
        progress("Waiting for the local web interface...")
        opener = build_opener(ProxyHandler({}))
        deadline = time.monotonic() + 300
        while True:
            try:
                with opener.open(config["url"] + "/login", timeout=5) as response:
                    if response.status == 200:
                        break
            except (OSError, HTTPError, URLError):
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("DefectDojo did not become ready; check platform status and compose.log.")
            time.sleep(2)
        progress("Preparing the managed API account...")
        code = files("flican.platform").joinpath("bootstrap.py").read_text(encoding="utf-8")
        result = run_compose(
            ["exec", "-T", "uwsgi", "python", "manage.py", "shell", "-c", code + "\nbootstrap()\n"],
            sensitive=True, timeout=120,
        )
        markers = [line.removeprefix("FLICAN_BOOTSTRAP=") for line in result.stdout.splitlines()
                   if line.startswith("FLICAN_BOOTSTRAP=")]
        if len(markers) != 1:
            raise RuntimeError("The local API-account bootstrap did not return a valid receipt.")
        connection = json.loads(markers[0])
        connection.update(url=config["url"], version=DOJO_VERSION)
        write_private_json(state_directory() / "defectdojo" / "connection.json", connection)
        return config


def stop_platform() -> None:
    with state_lock():
        run_compose(["stop"], timeout=120)


def platform_status() -> list[dict]:
    result = run_compose(["ps", "--all", "--format", "json"], timeout=30)
    output = result.stdout.strip()
    if not output:
        return []
    data = json.loads(output) if output.startswith("[") else [json.loads(line) for line in output.splitlines()]
    return [{key: row.get(key, "") for key in ("Service", "State", "Health")} for row in data]
