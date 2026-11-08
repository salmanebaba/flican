"""Prepare pinned scanners and collect a verified scan into a bounded CI bundle."""

import json
import os
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath

from flican.adapters.trivy import run_trivy_db_update
from flican.core.config import load_config
from flican.core.cache import trivy_cache_directory, validate_trivy_db_digest
from flican.core.trivy_db import trivy_database
from flican.core.execution import execution_error
from flican.core.models import Run, RunStatus, RUN_MODES
from flican.core.artifacts import MAX_IMAGE_BYTES, artifact_limit, copy_artifact
from flican.core.provenance import IMAGES, MAX_ARTIFACT_BYTES, digest, load_attested_run, load_attested_execution, utc_now
from flican.core.state import StateStore, write_private_json

REFERENCE_FIELDS = {
    "schema_version", "command", "invocation_id", "project_path", "started_at", "finished_at",
    "status", "decision", "exit_code", "error", "run_id", "run_path", "run_report_path",
    "findings_report_path", "manifest_path", "artifact_paths",
}
MAX_BUNDLE_BYTES = MAX_IMAGE_BYTES + 256 * 1024 * 1024


def prepare_scanners(project: Path, docker: str, cache: Path | None, progress=print,
                     *, db_digest: str | None = None, tests_only: bool = False, workflow: bool = False) -> None:
    config = load_config(project / "flican.yaml")
    if tests_only and workflow:
        raise ValueError("Choose either --tests-only or --workflow.")
    if tests_only:
        if "tests" not in config or db_digest is not None:
            raise ValueError("--tests-only requires a tests configuration and cannot select a Trivy DB.")
        images = {"application test": config["tests"]["image"]}
    else:
        images = {name: IMAGES[name] for name in config["scanners"]}
        if workflow:
            images["trivy"] = IMAGES["trivy"]
            if "tests" in config:
                images["application test"] = config["tests"]["image"]
    needs_database = not tests_only and (workflow or "trivy" in config["scanners"])
    if needs_database:
        validate_trivy_db_digest(db_digest)
        cache = trivy_cache_directory(cache)
    elif db_digest is not None:
        raise ValueError("--trivy-db-digest requires a source Trivy scanner or --workflow.")
    if cache is not None:
        cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, image in images.items():
        inspected = subprocess.run([docker, "image", "inspect", image], capture_output=True,
                                   text=True, timeout=30, check=False)
        if inspected.returncode:
            progress(f"Pulling pinned {name} image...")
            subprocess.run([docker, "pull", image], timeout=300, check=True)
        else:
            progress(f"Pinned {name} image is available.")
    if needs_database:
        progress(f"Preparing the Trivy vulnerability database in {cache}...")
        with trivy_database(docker, cache, db_digest=db_digest,
                            updater=run_trivy_db_update, progress=progress):
            progress("Trivy database ready.")


def _read(path: Path, limit=MAX_ARTIFACT_BYTES) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("CI inputs must be bounded regular files, without symlinks.")
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError("CI input exceeds the size limit.")
    return content


def _json(path: Path, limit=MAX_ARTIFACT_BYTES) -> dict:
    value = json.loads(_read(path, limit))
    if not isinstance(value, dict):
        raise ValueError("CI JSON inputs must be objects.")
    return value


def _utc(value) -> datetime:
    if not isinstance(value, str):
        raise ValueError("The CI reference needs final UTC timestamps.")
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("The CI reference needs final UTC timestamps.")
    return parsed


def _reference(value: dict, scan_exit: int, workspace: Path) -> tuple[Run | None, Path | None]:
    if set(value) != REFERENCE_FIELDS or type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ValueError("Unsupported or malformed CI reference schema.")
    if value["command"] not in RUN_MODES or not isinstance(value["invocation_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", value["invocation_id"]):
        raise ValueError("Invalid CI invocation identity.")
    expected = {0: ("completed", "allow"), 1: ("completed", "block")}
    valid = (value["status"], value["decision"]) == expected.get(scan_exit) if scan_exit in expected else (
        scan_exit == 2 and value["status"] in ("failed", "cancelled") and value["decision"] == "incomplete"
    )
    if not valid or type(value["exit_code"]) is not int or value["exit_code"] != scan_exit:
        raise ValueError("The final CI reference disagrees with the real scan process exit code.")
    if _utc(value["finished_at"]) < _utc(value["started_at"]):
        raise ValueError("The CI reference timestamps are not ordered.")
    project = Path(value["project_path"]) if isinstance(value["project_path"], str) else None
    if project is None or not project.is_absolute() or project.resolve() != project or not project.is_relative_to(workspace):
        raise ValueError("The CI project must be inside this workspace.")
    paths = value["artifact_paths"]
    if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths) or len(paths) > 256 or len(set(paths)) != len(paths):
        raise ValueError("Invalid CI artifact list.")
    if value["run_id"] is None:
        if scan_exit != 2 or paths or any(value[key] is not None for key in (
            "run_path", "run_report_path", "findings_report_path", "manifest_path"
        )):
            raise ValueError("A reference without a run cannot claim artifacts or success.")
        return None, None
    if not isinstance(value["run_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", value["run_id"]):
        raise ValueError("Invalid CI run identity.")
    root = project / ".flican/runs" / value["run_id"]
    if value["run_path"] != str(root) or root.resolve() != root:
        raise ValueError("The CI reference points outside its exact run directory.")
    run = Run.from_dict(_json(root / "run.json"))
    if (run.mode != value["command"] or run.run_id != value["run_id"] or run.project_path != str(project) or run.status.value != value["status"]
            or run.decision.value != value["decision"] or run.exit_code != scan_exit):
        raise ValueError("The execution journal disagrees with the CI reference.")
    allowed = {"run.json", *run.artifacts}
    if scan_exit in (0, 1):
        allowed.add("manifest.json")
        if set(paths) != allowed:
            raise ValueError("A complete CI bundle must contain every attested run artifact.")
    elif not set(paths).issubset(allowed) or "run.json" not in paths:
        raise ValueError("An incomplete CI bundle claims unknown artifacts.")
    for field, relative in (("run_report_path", "run.json"), ("findings_report_path", "reports/findings.json"),
                            ("manifest_path", "manifest.json")):
        expected_path = str(root / relative) if relative in paths else None
        if value[field] != expected_path:
            raise ValueError("A CI report path disagrees with its artifact list.")
    for relative in paths:
        path = PurePosixPath(relative)
        source = root / relative
        if (not relative or path.is_absolute() or ".." in path.parts or path.as_posix() != relative
                or "\\" in relative or source.resolve() != source or not source.is_relative_to(root)):
            raise ValueError("CI artifact paths must stay inside the run without symlinks.")
    return run, root


def collect_scan(reference: Path, scan_exit: int, workspace: Path, destination: Path) -> dict:
    workspace = workspace.resolve(strict=True)
    destination = destination.absolute()
    if not workspace.is_dir() or not destination.is_relative_to(workspace) or destination.resolve() != destination:
        raise ValueError("CI output must be inside the workspace without symlinks.")
    relative = destination.relative_to(workspace).parts
    if len(relative) < 2 or relative[0] != ".flican" or relative[1] == "runs":
        raise ValueError("CI output must be under workspace/.flican/ and outside its runs/.")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    summary = {"schema_version": 1, "created_at": utc_now(), "status": "failed", "decision": "incomplete",
               "scan_exit_code": scan_exit, "exit_code": 2, "invocation_id": None, "run_id": None,
               "attestation": "unavailable", "files": [], "error": None}
    try:
        if type(scan_exit) is not int or scan_exit not in (0, 1, 2):
            raise ValueError("The scan process did not return a supported Flican exit code.")
        value = _json(reference, 64 * 1024)
        if (value.get("error") is not None
                and (not isinstance(value["error"], str) or not value["error"].strip() or len(value["error"]) > 2000)):
            raise ValueError("Invalid CI error summary.")
        run, root = _reference(value, scan_exit, workspace)
        if root is not None and destination.is_relative_to(root):
            raise ValueError("A CI bundle cannot be written into its source run.")
        hashes = {}
        if run is not None and run.status == RunStatus.COMPLETED:
            if run.mode != "scan":
                manifest = load_attested_execution(root)
                if manifest.get("mode") != run.mode:
                    raise ValueError("The manifest does not match its run mode.")
            else:
                manifest, _ = load_attested_run(root)
            record = StateStore().get("run", run.run_id)
            hashes = {**manifest["artifacts"], "manifest.json": record["manifest_sha256"]}
            summary["attestation"] = "verified_locally"
        total = 0
        for relative in value["artifact_paths"]:
            source = root / relative
            total += source.stat().st_size
            if total > MAX_BUNDLE_BYTES:
                raise ValueError("CI bundle exceeds its total size limit.")
            target = destination / "run" / relative
            observed, size = copy_artifact(source, target, limit=artifact_limit(relative),
                                           expected=hashes[relative] if hashes else None)
            summary["files"].append({"path": target.relative_to(destination).as_posix(),
                                     "sha256": observed, "size_bytes": size})
        write_private_json(destination / (value["command"] + "-result.json"), value)
        summary.update(status="completed", decision=value["decision"], exit_code=scan_exit,
                       invocation_id=value["invocation_id"], run_id=value["run_id"])
    except (OSError, ValueError, RuntimeError, TypeError) as error:
        summary.update(status="failed", decision="incomplete", exit_code=2,
                       attestation="unavailable", error=execution_error(error))
    write_private_json(destination / "collection.json", summary)
    return summary
