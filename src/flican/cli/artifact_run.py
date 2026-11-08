"""Shared journals, error handling and machine references for artifact commands."""

import subprocess
from pathlib import Path
from uuid import uuid4

import typer

from flican.core.artifacts import artifact_limit
from flican.core.execution import RunJournal, execution_error
from flican.core.models import Run, RunStatus, StageStatus
from flican.core.provenance import attest_execution, utc_now
from flican.core.scan_result import ScanResultFile
from flican.core.state import write_private_json


class ArtifactRun:
    def __init__(self, mode: str, project: Path, reference: Path | None):
        self.mode, self.project, self.reference = mode, project, reference
        self.journal, self.output = None, None
        self.report, self.artifacts, self.finalizers = {}, set(), []
        self.block = False

    def __enter__(self):
        self.started = utc_now()
        if self.reference is not None:
            self.output = ScanResultFile(self.reference, self.project, command=self.mode)
        return self

    @property
    def root(self):
        return self.journal.root

    def start(self, config, stages, source_sha256=None):
        run_id = uuid4().hex
        self.journal = RunJournal(self.project / ".flican/runs" / run_id, Run(
            run_id, config["project"]["name"], str(self.project), self.started,
            config["policy"]["fail_on"], tuple(stages), mode=self.mode, source_sha256=source_sha256,
        ))
        self.artifacts.add(f"reports/{self.mode}.json")
        self.report.update(schema_version=1, run_id=run_id, mode=self.mode, source_sha256=source_sha256)
        self._report()
        if self.output:
            self.output.bind(self.journal.run, self.root)

    def expect(self, *paths):
        self.artifacts.update(paths)

    def _report(self):
        run = self.journal.run
        self.report.update(status=run.status.value, decision=run.decision.value if run.decision else None,
                           exit_code=run.exit_code, error=run.error)
        write_private_json(self.root / f"reports/{self.mode}.json", self.report)
        for callback in self.finalizers:
            callback()

    def _available(self):
        return tuple(sorted(path for path in self.artifacts
                            if (self.root / path).is_file() and not (self.root / path).is_symlink()
                            and (self.root / path).stat().st_size <= artifact_limit(path)))

    def complete(self, stage, *, exit_code=0, findings_count=0, artifacts=(), coverage=None):
        self.expect(*artifacts)
        self.journal.complete(stage, exit_code=exit_code, findings_count=findings_count,
                              artifacts=tuple(artifacts), coverage=coverage)

    def _failure(self, error):
        cancelled = isinstance(error, KeyboardInterrupt)
        if cancelled:
            error = KeyboardInterrupt("Execution cancelled by user.")
        if self.journal is not None:
            try:
                if self.journal.run.status == RunStatus.RUNNING:
                    for stage in self.journal.run.stages:
                        if stage.status == StageStatus.RUNNING and not cancelled:
                            self.journal.fail(stage.stage_id, error)
                    self.journal.artifacts(self._available())
                self.journal.abort(error, cancelled=cancelled)
                self._report()
                typer.echo(f"Run directory: {self.root}", err=True)
            except (OSError, ValueError, RuntimeError) as failure:
                typer.echo(f"Cannot save the checkpoint: {execution_error(failure)}", err=True)
        typer.echo(f"Cannot complete {self.mode}: {execution_error(error)}", err=True)
        self._publish(error=error)

    def _publish(self, *, error=None, attested=False):
        if self.output:
            try:
                self.output.finish(self.journal.run if self.journal else None,
                                   self.root if self.journal else None, error=error, attested=attested)
            except (OSError, ValueError, RuntimeError) as failure:
                typer.echo(f"Cannot publish the result: {execution_error(failure)}", err=True)
                raise typer.Exit(code=2)

    def __exit__(self, kind, error, traceback):
        if error is not None:
            self._failure(error)
            raise typer.Exit(code=2)
        try:
            if self.journal is None:
                raise ValueError("No execution was started.")
            self.journal.artifacts(self._available())
            self.journal.finish(gate_failed=self.block)
            self._report()
            if self.journal.run.status != RunStatus.COMPLETED:
                raise ValueError("Required stages did not complete.")
            attest_execution(self.root, self.journal.run)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as failure:
            self._failure(failure)
            raise typer.Exit(code=2)
        self._publish(attested=True)
        typer.echo(f"{self.mode.capitalize()}: {self.journal.run.decision.value.upper()}")
        typer.echo(f"Run directory: {self.root}")
        if self.journal.run.exit_code:
            raise typer.Exit(code=self.journal.run.exit_code)
        return False
