"""Explicit source-to-OCI builds; image security is evaluated by image scan."""

import shutil
from pathlib import Path

import typer
import yaml

from flican.cli.artifact_run import ArtifactRun
from flican.core.building import run_build
from flican.core.config import load_config
from flican.core.discovery import discover_files
from flican.core.models import StageResult
from flican.core.oci import inspect_oci
from flican.core.provenance import canonical_digest
from flican.core.snapshot import temporary_snapshot, snapshot_identity


def build_project(
    project_path: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    result_file: Path | None = typer.Option(None, "--result-file", help="Write a fresh build-result reference for CI."),
):
    """Build the configured Dockerfile into a local OCI archive."""
    try:
        with ArtifactRun("build", project_path, result_file) as operation:
            config = load_config(project_path / "flican.yaml")
            if "build" not in config:
                raise ValueError("Add a build configuration with context and dockerfile to flican.yaml.")
            docker = shutil.which("docker")
            if docker is None:
                raise RuntimeError("Docker CLI was not found.")
            settings = config["build"]
            selected = discover_files(project_path, set(config["project"]["exclude"]) | {".flican"})
            with temporary_snapshot(project_path, selected, preserve_executable=True) as snapshot:
                identity, count = snapshot_identity(snapshot)
                operation.start(config, [StageResult("build", "buildkit", profile_hash=canonical_digest(settings))], identity)
                operation.report.update(settings=settings, file_count=count)
                operation.expect("logs/build.log", "reports/buildkit.json")
                operation.journal.start("build")
                engine = run_build(docker, snapshot, settings, operation.root)
                image = inspect_oci(operation.root / "image/candidate.oci.tar")
                if image["platform"] != settings["platform"]:
                    raise ValueError("Exported image platform does not match the build configuration.")
                native_digest = engine["metadata"].get("containerimage.digest")
                if native_digest is not None and native_digest != image["manifest_digest"]:
                    raise ValueError("BuildKit metadata does not match the exported OCI image.")
                config_digest = engine["metadata"].get("containerimage.config.digest")
                if config_digest is not None and config_digest != image["config_digest"]:
                    raise ValueError("BuildKit metadata does not match the exported OCI config.")
                operation.report.update(builder=engine, image=image, image_path="image/candidate.oci.tar")
                operation.complete("build", artifacts=("logs/build.log", "reports/buildkit.json", "image/candidate.oci.tar"))
                typer.echo(f"OCI image: {operation.root / 'image/candidate.oci.tar'}")
                typer.echo(f"Manifest: {image['manifest_digest']}")
    except typer.Exit:
        raise
    except (OSError, ValueError, RuntimeError, yaml.YAMLError) as error:
        typer.echo(f"Cannot start build: {error}", err=True)
        raise typer.Exit(code=2)
