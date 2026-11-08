"""A fresh, versioned hand-off file for one CLI invocation and its artifacts."""

import json
import hashlib
import os
import stat
import tempfile
from pathlib import Path
from uuid import uuid4

from flican.core.execution import execution_error
from flican.core.models import Run, RunStatus, RUN_MODES
from flican.core.provenance import utc_now


class ScanResultFile:
    def __init__(self, path: Path, project_path: Path, *, command: str = "scan"):
        if command not in RUN_MODES:
            raise ValueError("Unsupported execution command.")
        self.command = command
        raw = path.expanduser()
        # Resolve the parent, not the final component: never follow a target symlink.
        self.path = raw.parent.resolve() / raw.name
        self.project_path = project_path.resolve()
        if self.path.is_relative_to(self.project_path):
            relative = self.path.relative_to(self.project_path).parts
            if len(relative) < 2 or relative[0] != ".flican" or relative[1] == "runs":
                raise ValueError("Inside the project, --result-file must be under .flican/ and outside .flican/runs/.")
        if self.path.exists() or self.path.is_symlink():
            raise ValueError("Result file already exists; choose a fresh --result-file path for this invocation.")
        self.invocation_id = uuid4().hex
        self.started_at = utc_now()
        self._identity = None
        self._content_hash = None
        self._finished = False
        self._run_reference = None
        self._write(self._payload(None, None, finished=False))

    def _write(self, data: dict) -> None:
        content = json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + "\n"
        # Preserve the mode of existing user/CI directories.
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=".flican-result-", dir=self.path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(content)
            if self._identity is None:
                # Atomic publication with exclusive creation: never replace another file.
                try:
                    os.link(temporary, self.path, follow_symlinks=False)
                except FileExistsError as error:
                    raise ValueError("Result file already exists; choose a fresh --result-file path.") from error
            else:
                previous = self.path.lstat()
                if (not stat.S_ISREG(previous.st_mode) or (previous.st_dev, previous.st_ino) != self._identity
                        or previous.st_size != self._content_size
                        or hashlib.sha256(self.path.read_bytes()).hexdigest() != self._content_hash):
                    raise ValueError("The result file was replaced externally; refusing to overwrite it.")
                os.replace(temporary, self.path)
            current = self.path.lstat()
            self._identity = (current.st_dev, current.st_ino)
            self._content_size = len(content.encode("utf-8"))
            self._content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _available(root: Path, relative: str) -> bool:
        path = root / relative
        return not path.is_symlink() and path.resolve().is_relative_to(root.resolve()) and path.is_file()

    def _payload(self, run: Run | None, root: Path | None, *, finished: bool,
                 error: BaseException | None = None, attested: bool = False) -> dict:
        root = root.resolve() if root is not None else None
        if run is not None and (root is None or root.name != run.run_id):
            raise ValueError("The result must reference its exact run directory.")
        if finished and error is None and (run is None or run.status == RunStatus.RUNNING):
            raise ValueError("Cannot publish a final result for an unfinished run.")
        if finished and error is None and run.status == RunStatus.COMPLETED and not attested:
            raise ValueError("A completed run needs its attestation before publishing the final result.")
        paths = []
        if run is not None:
            expected = ["run.json", *run.artifacts]
            if attested and error is None:
                expected.append("manifest.json")
            paths = [path for path in dict.fromkeys(expected) if self._available(root, path)]
            if finished and error is None and run.status == RunStatus.COMPLETED and paths != list(dict.fromkeys(expected)):
                raise ValueError("A completed run artifact is missing or invalid; no final result was published.")

        status, decision, exit_code = "running", None, None
        message = None
        if finished:
            if error is not None:
                status = "cancelled" if isinstance(error, KeyboardInterrupt) else "failed"
                decision, exit_code, message = "incomplete", 2, execution_error(error)
            else:
                status, decision, exit_code = run.status.value, run.decision.value, run.exit_code
                details = run.error or "; ".join(f"{stage.tool}: {stage.error}" for stage in run.stages if stage.error)
                message = execution_error(RuntimeError(details)) if details else None
        return {
            "schema_version": 1, "command": self.command, "invocation_id": self.invocation_id,
            "project_path": str(self.project_path), "started_at": self.started_at,
            "finished_at": utc_now() if finished else None,
            "status": status, "decision": decision, "exit_code": exit_code, "error": message,
            "run_id": run.run_id if run is not None else None,
            "run_path": str(root.resolve()) if root is not None else None,
            "run_report_path": str(root / "run.json") if "run.json" in paths else None,
            "findings_report_path": str(root / "reports/findings.json") if "reports/findings.json" in paths else None,
            "manifest_path": str(root / "manifest.json") if "manifest.json" in paths else None,
            "artifact_paths": paths,
        }

    def bind(self, run: Run, root: Path) -> None:
        """Expose the run directory before any scanner starts."""
        self._check_reference(run, root)
        self._write(self._payload(run, root, finished=False))
        self._run_reference = (run.run_id, root.resolve())

    def _check_reference(self, run: Run | None, root: Path | None) -> None:
        if self._finished:
            raise ValueError("This scan result file is already finalized.")
        if run is not None and run.mode != self.command:
            raise ValueError("The result command does not match its run mode.")
        if self._run_reference is not None and (
            run is None or root is None or self._run_reference != (run.run_id, root.resolve())
        ):
            raise ValueError("This invocation is already bound to another run.")

    def finish(self, run: Run | None = None, root: Path | None = None, *,
               error: BaseException | None = None, attested: bool = False) -> None:
        self._check_reference(run, root)
        self._write(self._payload(run, root, finished=True, error=error, attested=attested))
        self._finished = True
