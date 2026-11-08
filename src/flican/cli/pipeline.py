"""Local full workflow on one frozen source tree; CI orchestration stays external."""

import json
import os
import sys
from importlib.resources import files as package_files
from pathlib import Path

import typer
import yaml

from flican.cli.artifact_run import ArtifactRun
from flican.core.artifacts import MAX_IMAGE_BYTES, artifact_limit, copy_artifact
from flican.core.ci import collect_scan
from flican.core.config import load_config
from flican.core.discovery import discover_files
from flican.core.models import GateDecision, Run, StageResult
from flican.core.process import run_bounded
from flican.core.snapshot import temporary_snapshot, snapshot_identity
from flican.core.state import write_private_json

pipeline_app = typer.Typer(no_args_is_help=True, help="Run source checks, optional tests/build and image evaluation locally.")

_ENTRY = "import sys,runpy;sys.path.insert(0,sys.argv[1]);sys.argv=['flican',*sys.argv[2:]];runpy.run_module('flican.cli.main',run_name='__main__')"


@pipeline_app.command("run")
def run_pipeline(
    project_path: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    image_input: Path | None = typer.Option(None, "--image-input", exists=True, dir_okay=False,
                                          help="Evaluate an existing OCI archive instead of building."),
    trivy_cache_dir: Path | None = typer.Option(None, "--trivy-cache-dir", file_okay=False),
    offline: bool = typer.Option(False, "--offline", help="Reuse the prepared Trivy DB in source/image stages."),
    trivy_db_digest: str | None = typer.Option(None, "--trivy-db-digest", help="Pin the official Trivy DB."),
    result_file: Path | None = typer.Option(None, "--result-file", help="Write a fresh workflow result reference."),
):
    """Execute the workflow, then retain one verifiable artifact bundle."""
    try:
        with ArtifactRun("pipeline", project_path, result_file) as operation:
            config = load_config(project_path / "flican.yaml")
            if image_input is None and "build" not in config:
                raise ValueError("A pipeline requires build configuration or --image-input.")
            excluded = set(config["project"]["exclude"]) | {".flican"}
            if image_input is not None:
                image_input = image_input.absolute()
                if image_input.is_relative_to(project_path) and not any(
                    part in excluded for part in image_input.relative_to(project_path).parts
                ):
                    raise ValueError("Keep prebuilt OCI input outside the project or under an excluded directory such as .flican.")
            selected = discover_files(project_path, excluded)
            with temporary_snapshot(project_path, selected, preserve_executable=True) as frozen:
                identity, count = snapshot_identity(frozen)
                stages = [StageResult("source", "scan"), StageResult("tests", "test", required="tests" in config),
                          StageResult("build", "buildkit", required=image_input is None), StageResult("image", "image")]
                operation.start(config, stages, identity)
                operation.report.update(file_count=count, stages={}, image_origin="external" if image_input else "build",
                                        source_to_image="unverified-external" if image_input else "same-frozen-snapshot")
                findings = []

                def save_findings():
                    run = operation.journal.run
                    passed = run.decision == GateDecision.ALLOW if run.decision in (GateDecision.ALLOW, GateDecision.BLOCK) else None
                    write_private_json(operation.root / "reports/findings.json", {
                        "schema_version": 1, "scanners": [*config["scanners"], "image-config", "trivy-image"],
                        "gate": {"fail_on": run.policy_threshold.value, "passed": passed},
                        "execution": {"status": run.status.value, "decision": run.decision.value if run.decision else None},
                        "findings": findings,
                    })

                operation.expect("reports/findings.json")
                operation.finalizers.append(save_findings)
                save_findings()
                database_args = []
                if trivy_cache_dir is not None:
                    database_args += ["--trivy-cache-dir", str(trivy_cache_dir.resolve())]
                if offline:
                    database_args.append("--offline")
                if trivy_db_digest is not None:
                    database_args += ["--trivy-db-digest", trivy_db_digest]
                command = [sys.executable, "-I", "-c", _ENTRY, str(Path(str(package_files("flican"))).parent)]
                candidate, candidate_hash = None, None
                for stage in ("source", "tests", "build", "image"):
                    if operation.block:
                        operation.journal.skip(stage, "A prior policy/test gate blocked this dependent stage.")
                        continue
                    if stage == "tests" and "tests" not in config:
                        operation.journal.skip(stage, "Application tests were not configured.")
                        continue
                    if stage == "build" and image_input is not None:
                        target = operation.root / "image/candidate.oci.tar"
                        candidate_hash, _ = copy_artifact(image_input, target, limit=MAX_IMAGE_BYTES)
                        candidate = target
                        operation.expect("image/candidate.oci.tar")
                        operation.report["candidate_artifact"] = "image/candidate.oci.tar"
                        operation.journal.skip(stage, "Using the caller's existing OCI image; no second build.")
                        continue
                    operation.journal.start(stage)
                    typer.echo(f"Pipeline stage: {stage}")
                    reference = operation.root / "references" / (stage + ".json")
                    log = operation.root / "logs" / (stage + ".log")
                    operation.expect(log.relative_to(operation.root).as_posix())
                    if stage == "source":
                        # The DB pin is irrelevant when source Trivy is disabled; image evaluation still uses it.
                        args = ["scan", str(frozen), "--result-file", str(reference)]
                        if "trivy" in config["scanners"]:
                            args += database_args
                        timeout = 1800
                    elif stage == "tests":
                        args = ["test", str(frozen), "--result-file", str(reference)]
                        timeout = config["tests"]["timeout_seconds"] + 30
                    elif stage == "build":
                        args = ["build", str(frozen), "--result-file", str(reference)]
                        timeout = config["build"]["timeout_seconds"] + 90
                    else:
                        if candidate is None:
                            raise ValueError("No verified candidate image is available.")
                        args = ["image", "scan", str(frozen), "--input", str(candidate),
                                "--result-file", str(reference), *database_args]
                        timeout = 1200
                    code = run_bounded([*command, *args], log, log, timeout=timeout)
                    if code not in (0, 1, 2):
                        raise RuntimeError(f"The {stage} command ended unexpectedly with code {code}.")
                    bundle = frozen / ".flican" / ("pipeline-bundle-" + stage)
                    collected = collect_scan(reference, code, frozen, bundle)
                    if collected["status"] != "completed" or collected["exit_code"] != code:
                        raise ValueError(f"Could not verify the {stage} artifacts: {collected['error']}")
                    value = json.loads(reference.read_text())
                    child = Run.from_dict(json.loads(Path(value["run_report_path"]).read_text())) if value["run_report_path"] else None
                    if child is not None and stage != "image" and child.source_sha256 != identity:
                        raise ValueError("Source identity changed between workflow stages.")
                    prefix = "stages/" + stage
                    artifacts = []
                    for path in sorted(bundle.rglob("*")):
                        if not path.is_file():
                            continue
                        relative = prefix + "/" + path.relative_to(bundle).as_posix()
                        target = operation.root / relative
                        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        try:
                            os.link(path, target)
                        except OSError:
                            copy_artifact(path, target, limit=artifact_limit(relative))
                        operation.expect(relative)
                        artifacts.append(relative)
                    operation.report["stages"][stage] = {"exit_code": code, "bundle": prefix,
                                                          "run_id": value["run_id"], "decision": value["decision"]}
                    native_findings = bundle / "run/reports/findings.json"
                    if native_findings.is_file():
                        findings += json.loads(native_findings.read_text())["findings"]
                        save_findings()
                    if code == 2:
                        raise RuntimeError(f"The {stage} stage was incomplete; its diagnostics were retained.")
                    if child is None:
                        raise ValueError("A successful stage did not provide an execution journal.")
                    if stage == "build":
                        report = json.loads((bundle / "run/reports/build.json").read_text())
                        relative = prefix + "/run/image/candidate.oci.tar"
                        candidate = operation.root / relative
                        candidate_hash = report["image"]["archive_sha256"]
                        operation.report.update(candidate_artifact=relative, image=report["image"])
                    if stage == "image":
                        report = json.loads((bundle / "run/reports/image.json").read_text())
                        if report["image"]["archive_sha256"] != candidate_hash:
                            raise ValueError("Image evaluation did not use the workflow candidate.")
                        operation.report.update(image=report["image"], components=report["components"])
                    operation.complete(stage, exit_code=code, findings_count=sum(s.findings_count or 0 for s in child.stages),
                                       artifacts=artifacts)
                    operation.block = code == 1
    except typer.Exit:
        raise
    except (OSError, ValueError, RuntimeError, yaml.YAMLError) as error:
        typer.echo(f"Cannot start workflow: {error}", err=True)
        raise typer.Exit(code=2)
