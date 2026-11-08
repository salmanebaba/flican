"""Regression checks for the two-bundle demo verification helper."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from helpers.verify_github import verify_downloaded


class TestGitHubArtifacts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def bundle(self, mode, code, *, wrong_sbom=False):
        root = self.root / mode
        root.mkdir()
        decision = {0: "allow", 1: "block", 2: "incomplete"}[code]
        status = "failed" if code == 2 else "completed"
        tools = ["gitleaks", "semgrep", "trivy", "checkov"] if mode == "scan" else [
            "image-config", "trivy-image", "trivy-convert"]
        stages = [{"tool": tool, "status": "failed" if code == 2 and tool == "checkov" else "completed"}
                  for tool in tools]
        run = {"run_id": mode + "-run", "mode": mode, "status": status, "decision": decision,
               "exit_code": code, "stages": stages, "policy_threshold": "high", "project_path": "/workspace/project"}
        findings = {"execution": {"status": status, "decision": decision},
                    "gate": {"fail_on": "high", "passed": None if code == 2 else code == 0},
                    "findings": [{"severity": "high"}] if code == 1 else []}
        content = {"run/run.json": run, "run/reports/findings.json": findings}
        if mode == "image":
            content.update({"run/reports/image.json": {"run_id": run["run_id"], "components": 0,
                "image": {"manifest_digest": "sha256:image", "archive_sha256": "archive"}},
                "run/reports/sbom.cdx.json": {"components": [], "metadata": {"properties": [
                    {"name": "flican:image:manifest_digest", "value": "sha256:wrong" if wrong_sbom else "sha256:image"},
                    {"name": "flican:image:archive_sha256", "value": "archive"}]}}})
        self.write(root, content)
        if code != 2:
            content["run/manifest.json"] = {"run_id": run["run_id"], "artifacts": {
                name.removeprefix("run/"): hashlib.sha256((root / name).read_bytes()).hexdigest()
                for name in content}}
            self.write(root, {"run/manifest.json": content["run/manifest.json"]})
        reference = {"command": mode, "run_id": run["run_id"], "invocation_id": mode + "-invocation",
                     "status": status, "decision": decision, "exit_code": code,
                     "artifact_paths": [name.removeprefix("run/") for name in content]}
        summary = {"status": "completed", "error": None, "run_id": run["run_id"],
                   "invocation_id": reference["invocation_id"], "decision": decision,
                   "exit_code": code, "scan_exit_code": code, "files": [
                       {"path": name, "sha256": hashlib.sha256((root / name).read_bytes()).hexdigest(),
                        "size_bytes": (root / name).stat().st_size} for name in content]}
        self.write(root, {f"{mode}-result.json": reference, "collection.json": summary})
        return root

    @staticmethod
    def write(root, files):
        for name, value in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))

    def test_source_allow_and_image_block_require_failed_workflow(self):
        self.bundle("scan", 0)
        self.bundle("image", 1)
        result = verify_downloaded(self.root, "allow", "failure")
        self.assertTrue(result["artifact_bytes_verified"])
        self.assertEqual(result["bundles"]["image"]["decision"], "block")
        self.assertEqual(set(result["bundles"]), {"scan", "image"})

    def test_source_and_image_allow_require_successful_workflow(self):
        self.bundle("scan", 0)
        self.bundle("image", 0)
        self.assertTrue(verify_downloaded(self.root, "allow", "success")["artifact_bytes_verified"])

    def test_source_block_has_no_image_bundle(self):
        self.bundle("scan", 1)
        self.assertEqual(set(verify_downloaded(self.root, "block", "failure")["bundles"]), {"scan"})

    def test_incomplete_source_is_expected_failure(self):
        self.bundle("scan", 2)
        self.assertEqual(verify_downloaded(self.root, "incomplete", "failure")["bundles"]["scan"]["exit_code"], 2)

    def test_missing_image_cannot_validate_complete_allow_scenario(self):
        self.bundle("scan", 0)
        with self.assertRaisesRegex(ValueError, "missing an expected bundle"):
            verify_downloaded(self.root, "allow", "success")

    def test_image_block_cannot_validate_green_workflow(self):
        self.bundle("scan", 0)
        self.bundle("image", 1)
        with self.assertRaisesRegex(ValueError, "does not preserve"):
            verify_downloaded(self.root, "allow", "success")

    def test_changed_file_is_rejected(self):
        source = self.bundle("scan", 0)
        self.bundle("image", 1)
        (source / "run/reports/findings.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "do not match the CI hashes"):
            verify_downloaded(self.root, "allow", "failure")

    def test_sbom_for_another_image_is_rejected_even_with_matching_file_hashes(self):
        self.bundle("scan", 0)
        self.bundle("image", 1, wrong_sbom=True)
        with self.assertRaisesRegex(ValueError, "SBOM and image identities"):
            verify_downloaded(self.root, "allow", "failure")

    def test_source_block_cannot_have_executed_image_stage(self):
        self.bundle("scan", 1)
        self.bundle("image", 1)
        with self.assertRaisesRegex(ValueError, "blocked dependent stage"):
            verify_downloaded(self.root, "block", "failure")

    def test_reference_from_another_run_is_rejected(self):
        source = self.bundle("scan", 0)
        self.bundle("image", 1)
        path = source / "scan-result.json"
        reference = json.loads(path.read_text())
        reference["run_id"] = "another-run"
        path.write_text(json.dumps(reference))
        with self.assertRaisesRegex(ValueError, "invocation reference, and run disagree"):
            verify_downloaded(self.root, "allow", "failure")
