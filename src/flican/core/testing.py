"""Execute a declared test command in a bounded container with no writable host mount."""

import os
import selectors
import subprocess
from pathlib import Path
from time import monotonic
from uuid import uuid4

from flican.core.docker import get_container_user, remove_container

MAX_TEST_OUTPUT_BYTES = 8 * 1024 * 1024


def build_test_command(docker: str, snapshot: Path, settings: dict, name: str, user: str) -> list[str]:
    source = snapshot.resolve(strict=True)
    if not source.is_dir() or "," in str(source):
        raise ValueError("The test snapshot must be a directory without commas in its path.")
    return [
        docker, "run", "--rm", "--name", name, "--pull=never", "--read-only",
        "--network=" + settings["network"], "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--cpus=1", "--memory=512m", "--memory-swap=512m", "--pids-limit=128",
        "--log-driver=none", "--user=" + user,
        "--tmpfs", "/work:rw,exec,nosuid,nodev,size=256m,mode=1777",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        "--mount", f"type=bind,source={source},target=/src,readonly",
        "--env", "HOME=/tmp", "--workdir", "/work", "--entrypoint", "/bin/sh",
        settings["image"], "-c", 'cp -R /src/. /work/ || exit 124; exec "$@"',
        "flican-test", *settings["command"],
    ]


def run_application_tests(docker: str, snapshot: Path, settings: dict, log_path: Path) -> int:
    """Keep byte-bounded logs on failure/timeout and remove the container in all cases."""
    name = "flican-test-" + uuid4().hex
    command = build_test_command(docker, snapshot, settings, name, get_container_user(docker))
    process = None
    log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        with log_path.open("xb") as log:
            os.fchmod(log.fileno(), 0o600)
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT)
            deadline = monotonic() + settings["timeout_seconds"]
            size = 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, settings["timeout_seconds"])
                    for key, _ in selector.select(min(remaining, 0.2)):
                        chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        available = MAX_TEST_OUTPUT_BYTES - size
                        log.write(chunk[:available])
                        size += min(len(chunk), available)
                        if len(chunk) > available:
                            raise RuntimeError("Application test output exceeded the 8 MiB log limit.")
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, settings["timeout_seconds"])
            return process.wait(timeout=remaining)
    finally:
        try:
            remove_container(docker, name)
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait()
                if process.stdout is not None:
                    process.stdout.close()
