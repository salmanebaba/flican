"""Bound logs, output files and duration for trusted command-line tool processes."""

import os
import selectors
import signal
import subprocess
from contextlib import ExitStack
from pathlib import Path
from time import monotonic


def run_bounded(command: list[str], stdout: Path, stderr: Path, *, timeout: int,
                env: dict | None = None, output_limit: int = 64 * 1024 * 1024,
                log_limit: int = 8 * 1024 * 1024, watched: tuple[tuple[Path, int], ...] = ()) -> int:
    """Use a private process group so timeout/cancellation can stop the owned tool tree."""
    process, completed = None, False
    with ExitStack() as resources:
        handles = {}
        for path in dict.fromkeys((stdout, stderr)):
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            handle = resources.enter_context(path.open("xb"))
            os.fchmod(handle.fileno(), 0o600)
            handles[path] = handle
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT if stdout == stderr else subprocess.PIPE,
                                       env=env, start_new_session=True)
            deadline = monotonic() + timeout
            counts = {path: 0 for path in handles}
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, stdout)
                if stdout != stderr:
                    selector.register(process.stderr, selectors.EVENT_READ, stderr)
                while selector.get_map():
                    remaining = deadline - monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    for path, limit in watched:
                        if path.exists() and (path.is_symlink() or path.stat().st_size > limit):
                            raise ValueError("Generated artifact exceeds its size limit.")
                    for key, _ in selector.select(min(remaining, 0.2)):
                        chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        path = key.data
                        limit = log_limit if path == stderr else output_limit
                        available = limit - counts[path]
                        handles[path].write(chunk[:available])
                        counts[path] += min(available, len(chunk))
                        if len(chunk) > available:
                            raise ValueError("Tool output exceeds its size limit.")
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            result = process.wait(timeout=remaining)
            for path, limit in watched:
                if path.exists() and (path.is_symlink() or path.stat().st_size > limit):
                    raise ValueError("Generated artifact exceeds its size limit.")
            completed = True
            return result
        finally:
            if process is not None:
                if not completed:
                    try:
                        os.killpg(process.pid, signal.SIGINT)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait()
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
