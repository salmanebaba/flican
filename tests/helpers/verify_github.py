"""Check real demo conclusions and source/image artifact consistency."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath


RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str):
        raise ValueError("Artifact paths must be strings.")
    parts = PurePosixPath(relative)
    path = root / relative
    if (not relative or parts.is_absolute() or ".." in parts.parts or "\\" in relative
            or parts.as_posix() != relative or path.resolve() != path.absolute()
            or not path.resolve().is_relative_to(root.resolve()) or not path.is_file()
            or path.stat().st_size > 64 * 1024 * 1024):
        raise ValueError("Artifact is missing, oversized, or outside its bundle.")
    return path


def _json(root: Path, relative: str) -> dict:
    value = json.loads(_file(root, relative).read_text())
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object in the CI bundle.")
    return value


def _bundle(collection: Path) -> dict:
    root = collection.parent
    summary = _json(root, "collection.json")
    run = _json(root, "run/run.json")
    mode, code = run["mode"], summary["exit_code"]
    if mode not in ("scan", "image") or type(code) is not int or code not in (0, 1, 2):
        raise ValueError("Unsupported demo bundle mode or exit code.")
    reference = _json(root, f"{mode}-result.json")
    decision = {0: "allow", 1: "block", 2: "incomplete"}[code]
    if (summary["status"] != "completed" or summary.get("error") is not None
            or summary["scan_exit_code"] != code or reference["command"] != mode
            or any(value["run_id"] != run["run_id"] for value in (summary, reference))
            or summary["invocation_id"] != reference["invocation_id"]
            or any(value["decision"] != decision or value["exit_code"] != code
                   for value in (summary, reference, run))):
        raise ValueError("The collection, invocation reference, and run disagree.")
    if ((code in (0, 1) and run["status"] != "completed")
            or (code == 2 and run["status"] not in ("failed", "cancelled"))
            or reference["status"] != run["status"]):
        raise ValueError("Run status disagrees with its process exit.")
    files = summary["files"]
    if not isinstance(files, list) or len(files) > 256:
        raise ValueError("Invalid collected file list.")
    paths = [item["path"] for item in files]
    if (len(paths) != len(set(paths))
            or set(paths) != {"run/" + path for path in reference["artifact_paths"]}):
        raise ValueError("Collected file inventory disagrees with its reference.")
    for item in files:
        path = _file(root, item["path"])
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if path.stat().st_size != item["size_bytes"] or digest != item["sha256"]:
            raise ValueError("Downloaded artifact bytes do not match the CI hashes.")
    expected = set(paths) | {"collection.json", f"{mode}-result.json"}
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    if actual != expected:
        raise ValueError("The bundle contains missing or unlisted files.")
    if code in (0, 1):
        manifest = _json(root, "run/manifest.json")
        if manifest["run_id"] != run["run_id"]:
            raise ValueError("Manifest belongs to another run.")
        for relative, digest in manifest["artifacts"].items():
            path = _file(root, "run/" + relative)
            with path.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                    raise ValueError("Downloaded artifact disagrees with its manifest.")
    findings = _json(root, "run/reports/findings.json")
    if (findings["execution"]["decision"] != decision
            or findings["execution"]["status"] != run["status"]
            or findings["gate"]["fail_on"] != run["policy_threshold"]
            or findings["gate"]["passed"] is not (None if code == 2 else code == 0)):
        raise ValueError("Normalized report disagrees with its run and gate.")
    if code in (0, 1):
        blocked = any(RANK[f["severity"]] >= RANK[run["policy_threshold"]]
                      for f in findings["findings"])
        if blocked != (code == 1):
            raise ValueError("The gate disagrees with normalized finding severities.")
    return {"root": root, "run": run, "findings": findings["findings"],
            "decision": decision, "exit_code": code, "artifacts": len(actual)}


def verify_downloaded(destination: Path, scenario: str, conclusion: str) -> dict:
    source_code = {"allow": 0, "block": 1, "incomplete": 2}[scenario]
    bundles = {}
    for collection in destination.rglob("collection.json"):
        value = _bundle(collection)
        mode = value["run"]["mode"]
        if mode in bundles:
            raise ValueError("Multiple collections for the same demo stage.")
        bundles[mode] = value
    if set(bundles) != ({"scan", "image"} if scenario == "allow" else {"scan"}):
        raise ValueError("The demo is missing an expected bundle or ran a blocked dependent stage.")
    source = bundles["scan"]
    stages = source["run"]["stages"]
    if (source["exit_code"] != source_code
            or [stage["tool"] for stage in stages] != ["gitleaks", "semgrep", "trivy", "checkov"]
            or [stage["status"] for stage in stages] != ["completed"] * 3 + [
                "failed" if scenario == "incomplete" else "completed"]):
        raise ValueError("Source scanner outcomes disagree with the selected scenario.")
    final_code = source_code
    if "image" in bundles:
        image = bundles["image"]
        stages = image["run"]["stages"]
        if (image["exit_code"] not in (0, 1)
                or image["run"]["project_path"] != source["run"]["project_path"]
                or [stage["tool"] for stage in stages] != ["image-config", "trivy-image", "trivy-convert"]
                or any(stage["status"] != "completed" for stage in stages)):
            raise ValueError("Image analysis did not complete for this source project.")
        report = _json(image["root"], "run/reports/image.json")
        sbom = _json(image["root"], "run/reports/sbom.cdx.json")
        properties = {item["name"]: item["value"] for item in sbom["metadata"]["properties"]}
        identity = report["image"]
        if (report["run_id"] != image["run"]["run_id"]
                or properties.get("flican:image:manifest_digest") != identity["manifest_digest"]
                or properties.get("flican:image:archive_sha256") != identity["archive_sha256"]
                or len(sbom["components"]) != report["components"]):
            raise ValueError("SBOM and image identities disagree.")
        final_code = image["exit_code"]
    expected_conclusion = "success" if final_code == 0 else "failure"
    if conclusion != expected_conclusion:
        raise ValueError("The real Actions conclusion does not preserve the final gate.")
    return {"artifact_bytes_verified": True,
            "artifacts": sum(bundle["artifacts"] for bundle in bundles.values()),
            "bundles": {mode: {"run_id": bundle["run"]["run_id"], "decision": bundle["decision"],
                               "exit_code": bundle["exit_code"], "findings": len(bundle["findings"])}
                        for mode, bundle in bundles.items()}}


def verify(gh: str, repository: str, run_id: int, output: Path) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid repository name.")
    result = subprocess.run([gh, "api", f"repos/{repository}/actions/runs/{run_id}"],
                            capture_output=True, text=True, check=True)
    metadata = json.loads(result.stdout)
    scenario = metadata["display_title"].removeprefix("Flican ")
    if metadata["status"] != "completed" or scenario not in ("allow", "block", "incomplete"):
        raise ValueError("Expected a completed Flican demo run.")
    destination = output / str(run_id)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    subprocess.run([gh, "run", "download", str(run_id), "--repo", repository, "--dir", str(destination)],
                   capture_output=True, text=True, check=True)
    return {"scenario": scenario, "run_id": run_id, "source_commit": metadata["head_sha"],
            "conclusion": metadata["conclusion"], "url": metadata["html_url"],
            **verify_downloaded(destination, scenario, metadata["conclusion"])}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--gh", default=shutil.which("gh"))
    parser.add_argument("--output-dir", type=Path, default=Path(".local/github-actions"))
    parser.add_argument("run_id", type=int, nargs="+")
    args = parser.parse_args()
    if not args.gh:
        parser.error("Provide an authenticated GitHub CLI with --gh or PATH.")
    records = [verify(args.gh, args.repo, run_id, args.output_dir) for run_id in args.run_id]
    path = args.output_dir / "validation.json"
    path.write_text(json.dumps(records, indent=2) + "\n")
    path.chmod(0o600)
    for record in records:
        print(json.dumps(record))
