"""Evaluate a local OCI archive and create a bound CycloneDX SBOM."""

import shutil
from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory

import typer
import yaml

from flican.adapters.image_trivy import run_image_scan, parse_image_report, run_sbom_conversion, validate_sbom
from flican.cli.artifact_run import ArtifactRun
from flican.core.artifacts import MAX_IMAGE_BYTES, copy_artifact, file_digest
from flican.core.cache import trivy_cache_directory, validate_trivy_db_digest
from flican.core.config import load_config
from flican.core.models import Finding, GateDecision, Severity, StageResult
from flican.core.oci import inspect_oci, materialize_layout
from flican.core.policy import should_fail
from flican.core.state import write_private_json
from flican.core.trivy_db import trivy_database

image_app = typer.Typer(no_args_is_help=True, help="Scan local OCI image artifacts and generate a CycloneDX SBOM.")


@image_app.command("scan")
def scan_image(
    project_path: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    input_file: Path = typer.Option(..., "--input", exists=True, dir_okay=False, help="A single-platform OCI archive."),
    trivy_cache_dir: Path | None = typer.Option(None, "--trivy-cache-dir", file_okay=False),
    offline: bool = typer.Option(False, "--offline", help="Reuse the prepared Trivy DB without downloading."),
    trivy_db_digest: str | None = typer.Option(None, "--trivy-db-digest", help="Pin the official vulnerability DB."),
    result_file: Path | None = typer.Option(None, "--result-file", help="Write a fresh image-result reference for CI."),
):
    """Scan vulnerabilities, secrets and runtime user, then generate a CycloneDX SBOM."""
    try:
        with ArtifactRun("image", project_path, result_file) as operation:
            config = load_config(project_path / "flican.yaml")
            validate_trivy_db_digest(trivy_db_digest)
            docker = shutil.which("docker")
            if docker is None:
                raise RuntimeError("Docker CLI was not found.")
            findings = []
            operation.start(config, [StageResult("image-config", "image-config"), StageResult("image-scan", "trivy-image"),
                                     StageResult("sbom", "trivy-convert")])
            operation.expect("reports/findings.json", "logs/image.log", "logs/sbom.log")

            def save_findings():
                run = operation.journal.run
                passed = run.decision == GateDecision.ALLOW if run.decision in (GateDecision.ALLOW, GateDecision.BLOCK) else None
                write_private_json(operation.root / "reports/findings.json", {
                    "schema_version": 1, "scanners": ["image-config", "trivy-image"],
                    "gate": {"fail_on": run.policy_threshold.value, "passed": passed},
                    "execution": {"status": run.status.value, "decision": run.decision.value if run.decision else None},
                    "findings": [asdict(finding) for finding in findings],
                })

            operation.finalizers.append(save_findings)
            save_findings()
            with TemporaryDirectory(prefix="flican-image-input-") as temporary:
                private = Path(temporary) / "candidate.oci.tar"
                operation.journal.start("image-config")
                copy_artifact(input_file, private, limit=MAX_IMAGE_BYTES)
                image = inspect_oci(private)
                layout = materialize_layout(private, Path(temporary) / "layout", image)
                operation.report.update(image=image, input_path=str(input_file.absolute()))
                if image["user_status"] != "nonroot":
                    unknown = image["user_status"] == "unresolved"
                    findings.append(Finding("image-config", "flican.image.user-unresolved" if unknown else "flican.image.root-user",
                                            "Runtime USER could not be resolved from image layers." if unknown else "Image runtime user is UID 0.",
                                            Severity.HIGH, None, None, resource_id=image["manifest_digest"],
                                            severity_source="flican:image-policy", framework="image-config"))
                save_findings()
                operation.complete("image-config", findings_count=len(findings), coverage={"runtime_user": image["user_status"]})
                operation.journal.start("image-scan")
                raw = Path(temporary) / "trivy.json"
                with trivy_database(docker, trivy_cache_directory(trivy_cache_dir), db_digest=trivy_db_digest,
                                    offline=offline, progress=typer.echo) as (cache, database):
                    code = run_image_scan(docker, layout, cache, raw, operation.root / "logs/image.log")
                    sanitized, image_findings, coverage = parse_image_report(
                        code, raw, (operation.root / "logs/image.log").read_text(errors="replace"), image)
                findings.extend(image_findings)
                operation.report.update(database=database, coverage=coverage)
                write_private_json(operation.root / "reports/trivy-image.json", sanitized)
                save_findings()
                operation.complete("image-scan", exit_code=code, findings_count=len(image_findings),
                                   artifacts=("reports/trivy-image.json", "logs/image.log"), coverage={**coverage, "database": database})
                operation.journal.start("sbom")
                sbom_path = operation.root / "reports/sbom.cdx.json"
                code = run_sbom_conversion(docker, operation.root / "reports/trivy-image.json", sbom_path,
                                           operation.root / "logs/sbom.log")
                if code != 0:
                    raise RuntimeError(f"CycloneDX conversion failed with code {code}; inspect logs/sbom.log.")
                sbom = validate_sbom(sbom_path, image, sanitized)
                write_private_json(sbom_path, sbom)
                if file_digest(private, MAX_IMAGE_BYTES) != image["archive_sha256"]:
                    raise ValueError("The analyzed OCI artifact changed during image evaluation.")
                operation.report["components"] = len(sbom.get("components", []))
                operation.complete("sbom", artifacts=("reports/sbom.cdx.json", "logs/sbom.log"))
                operation.block = should_fail(findings, config["policy"]["fail_on"])
                typer.echo(f"Image findings: {len(findings)}; SBOM components: {operation.report['components']}")
                typer.echo(f"Manifest: {image['manifest_digest']}")
    except typer.Exit:
        raise
    except (OSError, ValueError, RuntimeError, yaml.YAMLError) as error:
        typer.echo(f"Cannot start image analysis: {error}", err=True)
        raise typer.Exit(code=2)
