from pathlib import Path

import typer
import yaml


project_app = typer.Typer(
    no_args_is_help=True,
    help="Manage project configuration.",
)


@project_app.command("init")
def init_project(
    project_path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        resolve_path=True,
    ),
) -> None:
    """Create a starter flican.yaml in an existing project."""
    config_path = project_path / "flican.yaml"
    config = {
        "schema_version": 1,
        "project": {
            "name": project_path.name.strip() or "project",
            "exclude": [
                ".git",
                ".venv",
                "node_modules",
                "__pycache__",
                ".flican",
                ".local",
            ],
        },
        "scanners": ["gitleaks", "semgrep"],
        "policy": {"fail_on": "high"},
    }

    content = yaml.safe_dump(
        config,
        sort_keys=False,
        allow_unicode=True,
    )

    try:
        with config_path.open("x", encoding="utf-8") as file:
            file.write(content)
    except FileExistsError:
        typer.echo(
            f"Configuration already exists: {config_path}",
            err=True,
        )
        raise typer.Exit(code=2)
    except OSError as error:
        typer.echo(f"Cannot create configuration: {error}", err=True)
        raise typer.Exit(code=2)

    typer.echo(f"Created configuration: {config_path}")