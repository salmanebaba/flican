"""Small provider-independent building blocks for CI templates."""

import shutil
import subprocess
from pathlib import Path

import typer
import yaml

from flican.core.ci import collect_scan, prepare_scanners
from flican.core.execution import execution_error

ci_app = typer.Typer(no_args_is_help=True, help="Prepare scanners and collect artifacts for CI.")


@ci_app.command("prepare")
def prepare(
    project_path: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    trivy_cache_dir: Path | None = typer.Option(
        None, "--trivy-cache-dir", file_okay=False, resolve_path=True,
        help="Override the shared Trivy cache (default: $XDG_CACHE_HOME/flican/trivy or ~/.cache/flican/trivy).",
    ),
    trivy_db_digest: str | None = typer.Option(
        None, "--trivy-db-digest", help="Prepare an official DB artifact pinned by sha256:...",
    ),
    tests_only: bool = typer.Option(False, "--tests-only", help="Prepare only the declared application test image."),
    workflow: bool = typer.Option(False, "--workflow", help="Also prepare the test image and Trivy image/DB for the full workflow."),
):
    """Explicitly pull missing pinned images and update the selected Trivy DB."""
    try:
        docker = shutil.which("docker")
        if docker is None:
            raise RuntimeError("Docker CLI was not found in PATH.")
        prepare_scanners(project_path, docker, trivy_cache_dir, progress=typer.echo,
                         db_digest=trivy_db_digest, tests_only=tests_only, workflow=workflow)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, yaml.YAMLError) as error:
        typer.echo(f"Cannot prepare CI scanners: {execution_error(error)}", err=True)
        raise typer.Exit(code=2)


@ci_app.command("collect")
def collect(
    result_file: Path = typer.Argument(...),
    scan_exit: int = typer.Option(..., "--exit-code", "--scan-exit", help="The real exit code from the Flican command."),
    output_dir: Path = typer.Option(..., "--output-dir", help="Fresh bundle directory under workspace/.flican/."),
    workspace: Path = typer.Option(Path("."), "--workspace", exists=True, file_okay=False, resolve_path=True),
):
    """Collect this invocation only, then propagate its gate or an integrity error."""
    try:
        summary = collect_scan(result_file, scan_exit, workspace, output_dir)
    except (OSError, ValueError, RuntimeError) as error:
        typer.echo(f"Cannot collect CI artifacts: {execution_error(error)}", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"CI bundle: {output_dir.absolute()}")
    typer.echo(f"CI decision: {summary['decision']} (scan exit {scan_exit}, collection exit {summary['exit_code']})")
    if summary["error"]:
        typer.echo(summary["error"], err=True)
    if summary["exit_code"]:
        raise typer.Exit(code=summary["exit_code"])
