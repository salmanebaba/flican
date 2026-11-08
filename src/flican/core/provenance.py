"""Locally attested scan envelopes used by external reporting adapters."""

import hashlib
import json
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

from flican.adapters.checkov import CHECKOV_IMAGE
from flican.adapters.gitleaks import GITLEAKS_IMAGE
from flican.adapters.semgrep import SEMGREP_IMAGE
from flican.adapters.trivy import TRIVY_IMAGE
from flican.core.models import Run, RunStatus, StageStatus
from flican.core.reports import save_report
from flican.core.state import StateStore
from flican.core.artifacts import artifact_limit, file_digest

IMAGES = {"gitleaks": GITLEAKS_IMAGE, "semgrep": SEMGREP_IMAGE,
          "trivy": TRIVY_IMAGE, "checkov": CHECKOV_IMAGE}
IGNORE_FILES = {
    "gitleaks": {".gitleaks.toml", "gitleaks.toml", ".gitleaksignore"},
    "semgrep": {".semgrepignore", ".gitignore"},
    "trivy": {".trivyignore", ".trivyignore.yaml", ".trivyignore.yml", "trivy.yaml", "trivy.yml"},
    "checkov": set(),
}
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def canonical_digest(value) -> str:
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def scanner_profiles(root: Path, scanners: list[str], exclusions: set[str],
                     *, paths: list[Path] | None = None) -> dict:
    resource = files("flican")
    selected = paths if paths is not None else [
        path for path in root.rglob("*") if path.is_file() and not path.is_symlink()
    ]
    profiles = {}
    for scanner in scanners:
        assets = {}
        if scanner == "semgrep":
            directory = resource.joinpath("rules", "semgrep")
            assets = {entry.name: digest(entry.read_bytes()) for entry in directory.iterdir()
                      if entry.name.endswith((".yaml", ".yml"))}
        elif scanner == "checkov":
            assets = {"profile.yaml": digest(resource.joinpath("rules", "checkov", "profile.yaml").read_bytes())}
        details = {
            "scanner": scanner, "image": IMAGES[scanner], "identity_version": 1,
            "adapter": digest(resource.joinpath("adapters", scanner + ".py").read_bytes()),
            "assets": assets, "exclusions": sorted(exclusions | {".flican"}),
            "ignore_files": {path.relative_to(root).as_posix(): digest(path.read_bytes())
                             for path in selected if path.name in IGNORE_FILES[scanner]},
        }
        profiles[scanner] = {"hash": canonical_digest(details), "details": details}
    return profiles


def attest_run(run_path: Path, project_path: Path, project_name: str, started_at: str,
               profiles: dict, coverage: dict, artifact_names: list[str]) -> dict:
    artifacts = {}
    for filename in artifact_names:
        path = run_path / "reports" / filename
        if path.is_symlink() or not path.is_file():
            raise ValueError("A scan artifact must be a regular file.")
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ValueError("Scan artifact exceeds the reporting size limit.")
        artifacts["reports/" + filename] = digest(path.read_bytes())
    # Older registered runs predate the execution journal. New journals must
    # prove all scanner stages completed before they become importable.
    execution = None
    execution_path = run_path / "run.json"
    if execution_path.exists() or execution_path.is_symlink():
        if execution_path.is_symlink() or not execution_path.is_file() or execution_path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ValueError("Invalid execution journal.")
        content = execution_path.read_bytes()
        execution = Run.from_dict(json.loads(content))
        if (execution.mode != "scan" or execution.status != RunStatus.COMPLETED or execution.run_id != run_path.name
                or execution.project_path != str(project_path.resolve()) or execution.project_name != project_name
                or execution.started_at != started_at or set(execution.artifacts) != set(artifacts)
                or {stage.tool for stage in execution.stages} != set(profiles)
                or any(stage.status != StageStatus.COMPLETED
                       or stage.profile_hash != profiles[stage.tool]["hash"] for stage in execution.stages)):
            raise ValueError("Only completed, matching scanner executions can be attested.")
        artifacts["run.json"] = digest(content)
    report = json.loads((run_path / "reports/findings.json").read_text(encoding="utf-8"))
    if "execution" in report and (
        not isinstance(report["execution"], dict) or report["execution"].get("status") != "completed"
    ):
        raise ValueError("An incomplete scan report cannot be attested.")
    completion = {}
    for scanner in profiles:
        details = coverage.get(scanner)
        completion[scanner] = {
            "status": "completed",
            # Other engines currently lack an explicit suppression/coverage contract.
            "can_close_old": bool(scanner == "checkov" and details
                                  and details.get("status") == "completed"
                                  and details.get("skipped") == 0),
        }
    manifest = {
        "schema_version": 1, "run_id": run_path.name,
        "project_path": str(project_path.resolve()), "project_name": project_name,
        "started_at": started_at, "completed_at": execution.finished_at if execution is not None else utc_now(),
        "profiles": profiles, "completion": completion, "artifacts": artifacts,
    }
    content = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    save_report(run_path / "manifest.json", content)
    store = StateStore()
    record = {"path": str(run_path.resolve()), "manifest_sha256": digest(content.encode()),
              "manifest": manifest}
    previous = store.get("run", manifest["run_id"])
    if previous is not None and previous != record:
        raise ValueError("This run ID already refers to different artifacts.")
    store.put("run", manifest["run_id"], record)
    return manifest


def load_attested_execution(run_path: Path, store: StateStore | None = None) -> dict:
    if run_path.is_symlink():
        raise ValueError("Run paths must not be symlinks.")
    root = run_path.resolve(strict=True)
    journal = store if store is not None else StateStore()
    record = journal.get("run", root.name)
    if record is None or record["path"] != str(root):
        raise ValueError("This run is not registered locally; create a fresh scan before syncing.")
    manifest_path = root / "manifest.json"
    if manifest_path.is_symlink() or manifest_path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise ValueError("Invalid scan manifest.")
    content = manifest_path.read_bytes()
    if digest(content) != record["manifest_sha256"]:
        raise ValueError("Scan manifest integrity check failed.")
    manifest = record["manifest"]
    for relative, expected in manifest["artifacts"].items():
        path = root / relative
        if path.is_symlink() or not path.resolve().is_relative_to(root) or not path.is_file() or path.stat().st_size > artifact_limit(relative):
            raise ValueError("Invalid or missing scan artifact.")
        if file_digest(path, artifact_limit(relative)) != expected:
            raise ValueError(f"Scan artifact integrity check failed: {relative}")
    return manifest


def attest_execution(run_path: Path, run: Run) -> dict:
    """Attest completed build/image/pipeline runs, including streamed OCI artifacts."""
    execution = Run.from_dict(json.loads((run_path / "run.json").read_text()))
    report_path = f"reports/{run.mode}.json"
    if (execution != run or run.mode not in ("build", "image", "pipeline")
            or run.status != RunStatus.COMPLETED or run.run_id != run_path.name
            or report_path not in run.artifacts):
        raise ValueError("Only completed matching artifact executions can be attested.")
    report = json.loads((run_path / report_path).read_text())
    if (not isinstance(report, dict) or report.get("run_id") != run.run_id
            or report.get("decision") != run.decision.value or report.get("exit_code") != run.exit_code):
        raise ValueError("Artifact report disagrees with its execution journal.")
    artifacts = {}
    for relative in ("run.json", *run.artifacts):
        path = run_path / relative
        if not path.resolve().is_relative_to(run_path.resolve()):
            raise ValueError("Artifact escaped its execution directory.")
        artifacts[relative] = file_digest(path, artifact_limit(relative))
    if run.mode == "build" and artifacts.get("image/candidate.oci.tar") != report.get("image", {}).get("archive_sha256"):
        raise ValueError("The build archive no longer matches its verified image identity.")
    if run.mode == "pipeline" and report.get("candidate_artifact") is not None:
        if artifacts.get(report["candidate_artifact"]) != report.get("image", {}).get("archive_sha256"):
            raise ValueError("The workflow candidate no longer matches the evaluated image.")
    manifest = {"schema_version": 1, "mode": run.mode, "run_id": run.run_id,
                "project_path": run.project_path, "project_name": run.project_name,
                "source_sha256": run.source_sha256, "started_at": run.started_at,
                "completed_at": run.finished_at, "artifacts": artifacts}
    content = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    save_report(run_path / "manifest.json", content)
    store = StateStore()
    record = {"path": str(run_path.resolve()), "manifest_sha256": digest(content.encode()), "manifest": manifest}
    previous = store.get("run", run.run_id)
    if previous is not None and previous != record:
        raise ValueError("This run ID already refers to different artifacts.")
    store.put("run", run.run_id, record)
    return manifest


def load_attested_run(run_path: Path, store: StateStore | None = None) -> tuple[dict, dict]:
    manifest = load_attested_execution(run_path, store)
    if manifest.get("mode", "scan") != "scan":
        raise ValueError("This mode is not a security scan for DefectDojo; only source scan runs are supported.")
    root = run_path.resolve(strict=True)
    report = json.loads((root / "reports/findings.json").read_text(encoding="utf-8"))
    if not isinstance(report, dict) or report.get("schema_version") != 1 or not isinstance(report.get("scanners"), list):
        raise ValueError("Invalid normalized report.")
    if set(report["scanners"]) != set(manifest["profiles"]):
        raise ValueError("The normalized report does not match its registered scanner profile.")
    if not isinstance(report.get("findings"), list):
        raise ValueError("The normalized report has no findings list.")
    return manifest, report


def attest_test_run(run_path: Path, run: Run) -> dict:
    execution = Run.from_dict(json.loads((run_path / "run.json").read_text()))
    expected = {"reports/tests.json", "logs/tests.log"}
    if (execution != run or run.mode != "test" or run.status != RunStatus.COMPLETED
            or run.run_id != run_path.name or len(run.stages) != 1
            or run.stages[0].tool != "tests" or run.stages[0].exit_code not in (0, 1)
            or run.exit_code != run.stages[0].exit_code or set(run.artifacts) != expected
            or set(run.stages[0].artifacts) != expected):
        raise ValueError("Only a completed, matching application test run can be attested.")
    report = json.loads((run_path / "reports/tests.json").read_text())
    if (not isinstance(report, dict) or type(report.get("schema_version")) is not int
            or report.get("schema_version") != 1 or report.get("run_id") != run.run_id
            or report.get("status") != ("passed" if run.exit_code == 0 else "failed")
            or report.get("exit_code") != run.exit_code or report.get("image") != run.stages[0].image):
        raise ValueError("The test report disagrees with its execution journal.")
    artifacts = {}
    for relative in ("run.json", *run.artifacts):
        path = run_path / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ValueError("Invalid application test artifact.")
        artifacts[relative] = digest(path.read_bytes())
    manifest = {
        "schema_version": 1, "mode": "test", "run_id": run.run_id,
        "project_path": run.project_path, "project_name": run.project_name,
        "started_at": run.started_at, "completed_at": run.finished_at,
        "profile_hash": run.stages[0].profile_hash, "artifacts": artifacts,
    }
    content = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    save_report(run_path / "manifest.json", content)
    store = StateStore()
    record = {"path": str(run_path.resolve()), "manifest_sha256": digest(content.encode()), "manifest": manifest}
    previous = store.get("run", run.run_id)
    if previous is not None and previous != record:
        raise ValueError("This run ID already refers to different artifacts.")
    store.put("run", run.run_id, record)
    return manifest
