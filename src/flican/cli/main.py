import shutil
import subprocess
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

import typer
import yaml

from flican.adapters.checkov import (
    is_checkov_dockerfile,
    normalize_checkov_finding,
    parse_checkov_report,
    run_checkov,
)
from flican.adapters.gitleaks import (
    normalize_gitleaks_finding,
    parse_gitleaks_report,
    run_gitleaks,
)
from flican.adapters.semgrep import (
    normalize_semgrep_finding,
    parse_semgrep_report,
    run_semgrep,
)
from flican.adapters.trivy import (
    normalize_trivy_finding,
    parse_trivy_report,
    run_trivy,
    run_trivy_db_update,
)
from flican.core.config import load_config
from flican.core.cache import trivy_cache_directory, validate_trivy_db_digest
from flican.core.trivy_db import trivy_database
from flican.core.discovery import discover_files, detect_languages
from flican.core.execution import RunJournal, execution_error
from flican.core.models import GateDecision, Run, RunStatus, StageResult, StageStatus
from flican.core.policy import should_fail
from flican.core.reports import save_report
from flican.core.scan_result import ScanResultFile
from flican.core.state import write_private_json
from flican.core.snapshot import temporary_snapshot, snapshot_identity
from flican.cli.project import project_app
from flican.cli.platform import platform_app
from flican.cli.dojo import dojo_app
from flican.cli.ci import ci_app
from flican.cli.testing import test_project
from flican.cli.building import build_project
from flican.cli.images import image_app
from flican.cli.pipeline import pipeline_app
from flican.core.planning import build_scan_plan
from flican.core.provenance import attest_run, scanner_profiles, utc_now


app = typer.Typer(no_args_is_help=True)
db_app = typer.Typer(
    no_args_is_help=True,
    help="Manage local scanner databases.",
)

app.add_typer(db_app, name="db")
app.add_typer(project_app, name="project")
app.add_typer(platform_app, name="platform")
app.add_typer(dojo_app, name="dojo")
app.add_typer(ci_app, name="ci")
app.command("test")(test_project)
app.command("build")(build_project)
app.add_typer(image_app, name="image")
app.add_typer(pipeline_app, name="pipeline")

@app.callback()
def main() -> None:
    """Local security scanning and pipeline orchestration."""


def _save_scan_progress(journal, scanners, findings, coverage):
    """An incomplete checkpoint has no passing policy verdict."""
    run = journal.run
    report = {
        "schema_version": 1,
        "scanners": scanners,
        "gate": {
            "fail_on": run.policy_threshold.value,
            "passed": (run.decision == GateDecision.ALLOW)
            if run.decision in (GateDecision.ALLOW, GateDecision.BLOCK) else None,
        },
        "execution": {"status": run.status.value,
                      "decision": run.decision.value if run.decision is not None else None,
                      "completed_scanners": [stage.tool for stage in run.stages
                                             if stage.status == StageStatus.COMPLETED]},
        "findings": [asdict(finding) for finding in findings],
    }
    if coverage:
        report["coverage"] = coverage
    if run.source_sha256 is not None:
        report["source_sha256"] = run.source_sha256
    write_private_json(journal.root / "reports/findings.json", report)
    if run.status == RunStatus.RUNNING:
        paths = tuple(path for stage in run.stages for path in stage.artifacts) + ("reports/findings.json",)
        journal.artifacts(paths)


def _finish_scan_result(output, journal, *, error=None, attested=False):
    if output is None:
        return
    try:
        output.finish(journal.run if journal is not None else None,
                      journal.root if journal is not None else None,
                      error=error, attested=attested)
    except (OSError, ValueError, RuntimeError) as failure:
        typer.echo(f"Cannot publish the scan result file: {execution_error(failure)}", err=True)
        if journal is not None:
            typer.echo(f"Run report: {journal.root / 'run.json'}", err=True)
        raise typer.Exit(code=2)


@app.command()
def scan(
    project_path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        resolve_path=True,
    ),
    trivy_cache_dir: Path | None = typer.Option(
        None,
        "--trivy-cache-dir",
        file_okay=False,
        resolve_path=True,
        help="Override the shared Trivy cache (default: $XDG_CACHE_HOME/flican/trivy or ~/.cache/flican/trivy).",
    ),
    offline: bool = typer.Option(False, "--offline", help="Use the cached Trivy DB without downloading or updating it."),
    trivy_db_digest: str | None = typer.Option(
        None, "--trivy-db-digest", help="Pin an official Trivy DB artifact by sha256:... (separate cache).",
    ),
    result_file: Path | None = typer.Option(
        None,
        "--result-file",
        help="Write a fresh JSON result reference for CI. Use .flican/ or a path outside the project.",
    ),
) -> None:
    """Scan secrets, code, dependencies, Terraform and Dockerfiles."""
    config_path = project_path / "flican.yaml"
    journal = None
    findings = []
    coverage = {}
    raw_reports = {}
    result_output = None
    attested = False

    try:
        started_at = utc_now()
        if result_file is not None:
            result_output = ScanResultFile(result_file, project_path)
        config = load_config(config_path)
        excluded_names = set(config["project"]["exclude"])
        excluded_names.add(".flican")
        files = discover_files(project_path, excluded_names)

        docker_path = shutil.which("docker")
        if docker_path is None:
            raise RuntimeError("Docker CLI was not found in PATH.")
        run_id = uuid4().hex
        run_path = project_path / ".flican" / "runs" / run_id
        reports_path = run_path / "reports"

        enabled_scanners = config["scanners"]

        if "trivy" in enabled_scanners:
            validate_trivy_db_digest(trivy_db_digest)
            trivy_cache_dir = trivy_cache_directory(trivy_cache_dir)
        elif trivy_db_digest is not None:
            raise ValueError("--trivy-db-digest requires trivy in the configured scanners.")

        with temporary_snapshot(project_path, files, preserve_executable=True) as snapshot_path:
            source_sha256, _ = snapshot_identity(snapshot_path)
            profiles = scanner_profiles(snapshot_path, enabled_scanners, excluded_names)
            runners = {"gitleaks": run_gitleaks, "semgrep": run_semgrep,
                       "trivy": run_trivy, "checkov": run_checkov}
            parsers = {"gitleaks": parse_gitleaks_report, "semgrep": parse_semgrep_report,
                       "trivy": parse_trivy_report, "checkov": parse_checkov_report}
            normalizers = {"gitleaks": normalize_gitleaks_finding, "semgrep": normalize_semgrep_finding,
                           "trivy": normalize_trivy_finding, "checkov": normalize_checkov_finding}
            ordered = [name for name in runners if name in enabled_scanners]
            run = Run(
                run_id=run_id, project_name=config["project"]["name"], project_path=str(project_path),
                started_at=started_at, policy_threshold=config["policy"]["fail_on"],
                stages=tuple(StageResult(name, name, profile_hash=profiles[name]["hash"],
                                         image=profiles[name]["details"]["image"]) for name in ordered),
                source_sha256=source_sha256,
            )
            journal = RunJournal(run_path, run)
            _save_scan_progress(journal, enabled_scanners, findings, coverage)
            if result_output is not None:
                result_output.bind(journal.run, run_path)
            expected_dockerfiles = {path.relative_to(project_path).as_posix()
                                    for path in files if is_checkov_dockerfile(path.name)}
            for name in ordered:
                journal.start(name)
                native = None
                stage_coverage = None
                try:
                    with ExitStack() as resources:
                        arguments = (docker_path, snapshot_path)
                        if name == "trivy":
                            database_cache, database_info = resources.enter_context(trivy_database(
                                docker_path, trivy_cache_dir, db_digest=trivy_db_digest,
                                offline=offline, updater=run_trivy_db_update, progress=typer.echo,
                            ))
                            arguments += (database_cache,)
                            stage_coverage = {"database": database_info}
                        native = runners[name](*arguments)
                        if name == "checkov":
                            parsed = parsers[name](native, expected_dockerfiles=expected_dockerfiles)
                            raw_findings, stage_coverage = parsed.findings, parsed.coverage
                        else:
                            raw_findings = parsers[name](native)
                        stage_findings = [normalizers[name](raw) for raw in raw_findings]
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                    journal.fail(name, error, exit_code=native.returncode if native is not None else None)
                else:
                    filename = name + ".json"
                    save_report(reports_path / filename, native.stdout)
                    journal.complete(name, exit_code=native.returncode, findings_count=len(stage_findings),
                                     artifacts=("reports/" + filename,), coverage=stage_coverage)
                    findings.extend(stage_findings)
                    raw_reports[filename] = native.stdout
                    if stage_coverage is not None:
                        coverage[name] = stage_coverage
                _save_scan_progress(journal, enabled_scanners, findings, coverage)

        fail_on = config["policy"]["fail_on"]
        gate_failed = should_fail(findings, fail_on)
        journal.finish(gate_failed=gate_failed)
        _save_scan_progress(journal, enabled_scanners, findings, coverage)
        if journal.run.status == RunStatus.COMPLETED:
            attest_run(run_path, project_path, config["project"]["name"], started_at,
                       profiles, coverage, [*raw_reports, "findings.json"])
            attested = True
    except (KeyboardInterrupt, OSError, ValueError, RuntimeError, subprocess.SubprocessError, yaml.YAMLError) as error:
        if isinstance(error, KeyboardInterrupt):
            error = KeyboardInterrupt("Scan cancelled by user.")
        if journal is not None:
            try:
                journal.abort(error, cancelled=isinstance(error, KeyboardInterrupt))
                _save_scan_progress(journal, enabled_scanners, findings, coverage)
            except (OSError, ValueError, RuntimeError) as persistence_error:
                typer.echo(f"Cannot save the final checkpoint: {execution_error(persistence_error)}", err=True)
            typer.echo(f"Run directory: {journal.root}", err=True)
        typer.echo(f"Cannot process project: {execution_error(error)}", err=True)
        _finish_scan_result(result_output, journal, error=error)
        raise typer.Exit(code=2)

    _finish_scan_result(result_output, journal, attested=attested)

    if journal.run.status != RunStatus.COMPLETED:
        typer.echo("Gate: INCOMPLETE", err=True)
        for stage in journal.run.stages:
            if stage.error:
                typer.echo(f"Cannot process project: {stage.tool}: {stage.error}", err=True)
        typer.echo(f"Run ID: {run_id}", err=True)
        typer.echo(f"Run directory: {run_path}", err=True)
        typer.echo(f"Run report: {run_path / 'run.json'}", err=True)
        raise typer.Exit(code=2)

    secret_findings = [finding for finding in findings if finding.scanner == "gitleaks"]
    sast_findings = [finding for finding in findings if finding.scanner == "semgrep"]
    sca_findings = [finding for finding in findings if finding.scanner == "trivy"]
    iac_findings = [finding for finding in findings if finding.scanner == "checkov"]
    languages = detect_languages(files)

    typer.echo(f"Project name: {config['project']['name']}")
    typer.echo(f"Project path: {project_path}")
    typer.echo(f"Files found: {len(files)}")
    typer.echo(f"Languages: {', '.join(languages) or 'not detected'}")
    typer.echo(f"Run ID: {run_id}")
    typer.echo(f"Run directory: {run_path}")
    typer.echo(f"Run status: {journal.run.status.value}")
    typer.echo(f"Run report: {run_path / 'run.json'}")
    typer.echo(f"Policy threshold: {fail_on}")
    typer.echo(f"Gate: {'FAIL' if gate_failed else 'PASS'}")

    typer.echo(f"Scanners: {', '.join(enabled_scanners)}")

    if "gitleaks" in enabled_scanners:
        typer.echo(f"Secret findings: {len(secret_findings)}")
    else:
        typer.echo("Secrets scan: disabled")

    if "semgrep" in enabled_scanners:
        typer.echo(f"SAST findings: {len(sast_findings)}")
    else:
        typer.echo("SAST scan: disabled")
    if "trivy" in enabled_scanners:
        typer.echo(f"SCA findings: {len(sca_findings)}")
    else:
        typer.echo("SCA scan: disabled")

    if "checkov" in enabled_scanners:
        typer.echo(f"IaC findings: {len(iac_findings)}")
        iac_coverage = coverage["checkov"]
        typer.echo(
            f"IaC coverage: {iac_coverage['status']} "
            f"({iac_coverage['resource_count']} resources, "
            f"{iac_coverage['passed']} passed, {iac_coverage['failed']} failed, "
            f"{iac_coverage['skipped']} skipped)"
        )
        for framework, details in iac_coverage["frameworks"].items():
            if details["status"] == "not_reported":
                typer.echo(f"Checkov {framework}: not_reported")
            else:
                typer.echo(
                    f"Checkov {framework}: {details['status']} "
                    f"({details['resource_count']} resources, "
                    f"{details['passed']} passed, {details['failed']} failed, "
                    f"{details['skipped']} skipped)"
                )
    else:
        typer.echo("IaC scan: disabled")

    typer.echo(f"Total findings: {len(findings)}")
    typer.echo(f"Reports directory: {reports_path}")

    if gate_failed:
        raise typer.Exit(code=1)

@app.command()
def plan(
    project_path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        resolve_path=True,
    ),
) -> None:
    """Preview a scan using the project configuration."""
    try:
        scan_plan = build_scan_plan(project_path)
    except (OSError, ValueError, RuntimeError, yaml.YAMLError) as error:
        typer.echo(f"Cannot plan scan: {error}", err=True)
        raise typer.Exit(code=2)

    typer.echo(f"Project name: {scan_plan['project_name']}")
    typer.echo(f"Project path: {scan_plan['project_path']}")
    typer.echo(f"Files found: {scan_plan['file_count']}")

    languages = ", ".join(scan_plan["languages"]) or "not detected"
    typer.echo(f"Languages: {languages}")
    typer.echo(f"Scanners: {', '.join(scan_plan['scanners'])}")
    typer.echo(f"Policy threshold: {scan_plan['fail_on']}")

    requirements = scan_plan["requirements"]
    docker_required = "yes" if requirements["docker"] else "no"
    typer.echo(f"Docker required: {docker_required}")

    if requirements["trivy_cache"]:
        typer.echo(f"Trivy cache: {trivy_cache_directory()} (default; --trivy-cache-dir overrides it)")
        typer.echo("Trivy DB: prepared/updated automatically; --offline uses only cached data.")

    tests = scan_plan["tests"]
    if tests:
        typer.echo(f"Application tests: configured (run explicitly with flican test; network: {tests['network']})")
        typer.echo(f"Test image: {tests['image']}")
        typer.echo(f"Test command: {tests['command']}")
        typer.echo(f"Test timeout: {tests['timeout_seconds']}s")
    else:
        typer.echo("Application tests: not configured")
    build = scan_plan["build"]
    if build:
        typer.echo(f"Build: configured (explicit build or pipeline run; platform: {build['platform']})")
        typer.echo(f"BuildKit: existing local Docker Engine; RUN network: {build['network']}")
        typer.echo(f"Dockerfile: {build['dockerfile']}; context: {build['context']}")
    else:
        typer.echo("Build: not configured (image scan accepts an existing OCI archive)")

    typer.echo("Plan generated.")

@app.command()
def doctor() -> None:
    """Check whether the Docker CLI is available."""
    docker_path = shutil.which("docker")

    if docker_path is None:
        typer.echo("Docker CLI was not found in PATH.", err=True)
        raise typer.Exit(code=2)

    typer.echo(f"Docker CLI: {docker_path}")

    try:
        result = subprocess.run(
            [docker_path, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        typer.echo(f"Cannot contact Docker Engine: {error}", err=True)
        raise typer.Exit(code=2)

    if result.returncode != 0:
        typer.echo("Docker Engine check failed.", err=True)
        typer.echo(result.stderr.strip(), err=True)
        raise typer.Exit(code=2)

    typer.echo(f"Docker Engine: {result.stdout.strip()}")


@db_app.command("update")
def update_database(
    cache_dir: Path | None = typer.Option(
        None,
        "--cache-dir",
        file_okay=False,
        resolve_path=True,
        help="Override the shared Trivy cache (default: $XDG_CACHE_HOME/flican/trivy or ~/.cache/flican/trivy).",
    ),
    trivy_db_digest: str | None = typer.Option(
        None, "--trivy-db-digest", help="Prepare an official DB artifact pinned by sha256:...",
    ),
) -> None:
    """Download or update Trivy's vulnerability database."""
    docker_path = shutil.which("docker")

    if docker_path is None:
        typer.echo("Docker CLI was not found in PATH.", err=True)
        raise typer.Exit(code=2)
    cache_dir = trivy_cache_directory(cache_dir)
    typer.echo(f"Updating Trivy database in {cache_dir}...")
    try:
        with trivy_database(docker_path, cache_dir, db_digest=trivy_db_digest,
                            updater=run_trivy_db_update, progress=typer.echo) as (selected_cache, _):
            typer.echo(f"Trivy database ready: {selected_cache / 'db'}")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        typer.echo(f"Cannot update database: {error}", err=True)
        raise typer.Exit(code=2)


def run() -> None:
    app()


if __name__ == "__main__":
    run()
