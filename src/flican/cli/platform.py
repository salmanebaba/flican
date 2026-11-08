"""Local platform commands."""

import subprocess

import typer

from flican.core.state import state_directory
from flican.platform.manager import platform_status, start_platform, stop_platform

platform_app = typer.Typer(no_args_is_help=True, help="Run the local DefectDojo platform.")


@platform_app.command("up")
def up(port: int = typer.Option(8088, min=1024, max=65535)) -> None:
    """Start DefectDojo on loopback and prepare its API connection."""
    try:
        config = start_platform(port, progress=typer.echo)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        typer.echo(f"Cannot start the platform: {error}", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"DefectDojo: {config['url']}")
    typer.echo(f"Private UI login file: {state_directory() / 'defectdojo/login.json'}")


@platform_app.command("stop")
def stop() -> None:
    """Stop the local services and preserve their volumes."""
    try:
        stop_platform()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        typer.echo(f"Cannot stop the platform: {error}", err=True)
        raise typer.Exit(code=2)
    typer.echo("DefectDojo services stopped; data volumes retained.")


@platform_app.command("status")
def status() -> None:
    """Show the state of the managed services."""
    try:
        services = platform_status()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        typer.echo(f"Cannot read platform status: {error}", err=True)
        raise typer.Exit(code=2)
    for service in services:
        typer.echo(f"{service['Service']}: {service['State']} {service['Health']}".rstrip())
    if not services:
        typer.echo("No managed services are running.")
