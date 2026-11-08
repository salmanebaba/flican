"""Explicit DefectDojo context and synchronization commands."""

from pathlib import Path

import typer
import yaml

from flican.reporting.dojo_sync import initialize_context, sync_run

dojo_app = typer.Typer(no_args_is_help=True, help="Sync attested local scans to DefectDojo.")


@dojo_app.command("init")
def init(
    project_path: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    scope: str = typer.Option("local", help="Stable branch/environment scope."),
) -> None:
    """Create or reuse stable Product, Engagement and scanner Tests."""
    try:
        context = initialize_context(project_path, scope)
    except (OSError, ValueError, RuntimeError, yaml.YAMLError) as error:
        typer.echo(f"Cannot initialize DefectDojo: {error}", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"Product: {context['url']}/product/{context['product_id']}")
    typer.echo(f"Engagement: {context['url']}/engagement/{context['engagement_id']}")
    typer.echo(f"Scope: {scope}")


@dojo_app.command("sync")
def sync(
    run_path: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    scope: str = typer.Option("local", help="Scope registered by dojo init."),
    scanner: str | None = typer.Option(None, help="Sync one scanner from this run."),
    close_old: bool = typer.Option(False, help="Close absent findings only with attested complete coverage."),
) -> None:
    """Reimport a completed run; keep triage and existing scanner Test IDs."""
    try:
        receipts = sync_run(run_path, scope, scanner, close_old)
    except (OSError, ValueError, RuntimeError) as error:
        typer.echo(f"Cannot sync DefectDojo: {error}", err=True)
        raise typer.Exit(code=2)
    for receipt in receipts:
        typer.echo(f"{receipt['scanner']}: {receipt['status']} "
                   f"(Test {receipt['test_id']}, {receipt['finding_count']} findings)")
