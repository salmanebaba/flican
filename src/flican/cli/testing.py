"""Explicit application tests, with the same run and artifact hand-off contract."""

import hashlib
import shutil
import subprocess
from importlib.resources import files as package_files
from pathlib import Path
from uuid import uuid4

import typer
import yaml

from flican.core.config import load_config
from flican.core.discovery import discover_files
from flican.core.execution import RunJournal, execution_error
from flican.core.models import Run, RunStatus, StageResult, StageStatus
from flican.core.provenance import attest_test_run, canonical_digest, digest, utc_now
from flican.core.scan_result import ScanResultFile
from flican.core.snapshot import temporary_snapshot, snapshot_identity
from flican.core.state import write_private_json
from flican.core.testing import run_application_tests


def _publish(output, journal, *, error=None, attested=False):
    if output is None:
        return
    try:
        output.finish(journal.run if journal else None, journal.root if journal else None,
                      error=error, attested=attested)
    except (OSError, ValueError, RuntimeError) as failure:
        typer.echo(f"Cannot publish the test result file: {execution_error(failure)}", err=True)
        raise typer.Exit(code=2)


def test_project(
    project_path: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    result_file: Path | None = typer.Option(None, "--result-file", help="Write a fresh JSON run reference for CI."),
) -> None:
    """Run the declared application tests in an isolated container."""
    output, journal, native = None, None, None
    report = {}
    try:
        started = utc_now()
        if result_file is not None:
            output = ScanResultFile(result_file, project_path, command="test")
        config = load_config(project_path / "flican.yaml")
        if "tests" not in config:
            raise ValueError("No tests are configured. Add tests.image and tests.command to flican.yaml.")
        settings = config["tests"]
        docker = shutil.which("docker")
        if docker is None:
            raise RuntimeError("Docker CLI was not found in PATH.")
        excluded = set(config["project"]["exclude"]) | {".flican"}
        selected = discover_files(project_path, excluded)
        with temporary_snapshot(project_path, selected, preserve_executable=True) as snapshot:
            source_sha256, file_count = snapshot_identity(snapshot)
            profile = canonical_digest({
                "settings": settings,
                "runner": digest(package_files("flican").joinpath("core/testing.py").read_bytes()),
            })
            run_id = uuid4().hex
            root = project_path / ".flican/runs" / run_id
            journal = RunJournal(root, Run(
                run_id, config["project"]["name"], str(project_path), started,
                config["policy"]["fail_on"],
                (StageResult("tests", "tests", image=settings["image"], profile_hash=profile),), mode="test",
                source_sha256=source_sha256,
            ))
            report = {
                "schema_version": 1, "run_id": run_id, **settings,
                "source_sha256": source_sha256, "file_count": file_count,
                "status": "running", "exit_code": None, "error": None,
            }
            write_private_json(root / "reports/tests.json", report)
            journal.artifacts(("reports/tests.json",))
            if output is not None:
                output.bind(journal.run, root)
            journal.start("tests")
            typer.echo(f"Running application tests: {config['project']['name']} (network: {settings['network']})")
            native = run_application_tests(docker, snapshot, settings, root / "logs/tests.log")
            if native not in (0, 1):
                raise RuntimeError(f"Test runtime exited with code {native}; expected 0 (pass) or 1 (test failure). "
                                   "Inspect logs/tests.log for startup or command errors.")
            report.update(status="passed" if native == 0 else "failed", exit_code=native)
            write_private_json(root / "reports/tests.json", report)
            artifacts = ("reports/tests.json", "logs/tests.log")
            journal.complete("tests", exit_code=native, findings_count=0, artifacts=artifacts)
            journal.artifacts(artifacts)
            journal.finish(gate_failed=native == 1)
            attest_test_run(root, journal.run)
    except (KeyboardInterrupt, OSError, ValueError, RuntimeError, subprocess.SubprocessError, yaml.YAMLError) as error:
        cancelled = isinstance(error, KeyboardInterrupt)
        if cancelled:
            error = KeyboardInterrupt("Application tests cancelled by user.")
        if journal is not None:
            try:
                status = "cancelled" if cancelled else ("timed_out" if isinstance(error, subprocess.TimeoutExpired) else "error")
                report.update(status=status, exit_code=native, error=execution_error(error))
                write_private_json(journal.root / "reports/tests.json", report)
                if journal.run.status == RunStatus.RUNNING:
                    artifacts = tuple(path for path in ("reports/tests.json", "logs/tests.log")
                                      if (journal.root / path).is_file())
                    journal.artifacts(artifacts)
                    if not cancelled and journal.stage("tests").status == StageStatus.RUNNING:
                        journal.fail("tests", error, exit_code=native)
                journal.abort(error, cancelled=cancelled)
            except (OSError, ValueError, RuntimeError) as persistence_error:
                typer.echo(f"Cannot save the test checkpoint: {execution_error(persistence_error)}", err=True)
            typer.echo(f"Run directory: {journal.root}", err=True)
        typer.echo(f"Cannot run application tests: {execution_error(error)}", err=True)
        _publish(output, journal, error=error)
        raise typer.Exit(code=2)
    _publish(output, journal, attested=True)
    typer.echo(f"Tests: {'PASS' if native == 0 else 'FAIL'}")
    typer.echo(f"Run ID: {journal.run.run_id}")
    typer.echo(f"Run directory: {journal.root}")
    typer.echo(f"Test report: {journal.root / 'reports/tests.json'}")
    typer.echo(f"Test log: {journal.root / 'logs/tests.log'}")
    if native:
        raise typer.Exit(code=1)
