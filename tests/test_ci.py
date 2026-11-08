import json
import contextlib
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from typer.testing import CliRunner

from state_support import isolated_state
from trivy_support import download_database
from flican.cli.main import app
from flican.core.ci import collect_scan, prepare_scanners
from flican.core.provenance import IMAGES, digest


class TestCICollection(unittest.TestCase):
    def setUp(self):
        isolated_state(self)
        self.workspace = Path(self.enterContext(TemporaryDirectory()))
        self.project = self.workspace / "project"
        self.project.mkdir()
        self.reference = self.project / ".flican/ci/result.json"
        self.destination = self.workspace / ".flican/bundle"
        self.config = self.project / "flican.yaml"
        self.config.write_text("schema_version: 1\nproject:\n  name: ci-test\n  exclude: []\n"
                               "scanners: [gitleaks, semgrep]\npolicy:\n  fail_on: high\n")

    def scan(self, case="allow"):
        leak = subprocess.CompletedProcess([], 0, stdout="[]", stderr="")
        sast = subprocess.CompletedProcess([], 0, stdout='{"results":[],"errors":[]}', stderr="")
        if case == "block":
            leak = subprocess.CompletedProcess([], 10, stdout='[{"RuleID":"test","File":"/src/app.py"}]',
                                               stderr="12:00PM WRN leaks found: 1\n")
        elif case == "incomplete":
            sast = subprocess.CompletedProcess([], 2, stdout="{}", stderr="synthetic failure")
        elif case == "preflight":
            self.config.unlink()
        with (patch("flican.cli.main.shutil.which", return_value="/fake/docker"),
              patch("flican.cli.main.run_gitleaks", return_value=leak),
              patch("flican.cli.main.run_semgrep", return_value=sast)):
            result = CliRunner().invoke(app, ["scan", str(self.project), "--result-file", str(self.reference)])
        self.assertEqual(result.exit_code, {"allow": 0, "block": 1, "incomplete": 2, "preflight": 2}[case], result.output)
        return json.loads(self.reference.read_text())

    def collect(self, code=0):
        return collect_scan(self.reference, code, self.workspace, self.destination)

    def test_allow_bundle_has_verified_bytes_and_no_private_state(self):
        value = self.scan()
        summary = self.collect()
        self.assertEqual((summary["status"], summary["decision"], summary["exit_code"]), ("completed", "allow", 0))
        self.assertEqual(summary["attestation"], "verified_locally")
        for item in summary["files"]:
            content = (self.destination / item["path"]).read_bytes()
            self.assertEqual(item["sha256"], digest(content))
            self.assertEqual(item["size_bytes"], len(content))
        self.assertEqual(summary["run_id"], value["run_id"])
        self.assertEqual(len(summary["files"]), 5)
        self.assertFalse(any("state.sqlite3" in item["path"] for item in summary["files"]))
        self.assertTrue((self.destination / "scan-result.json").is_file())

    def test_block_is_collected_but_cli_still_fails(self):
        self.scan("block")
        result = CliRunner().invoke(app, ["ci", "collect", str(self.reference), "--scan-exit", "1",
                                         "--workspace", str(self.workspace), "--output-dir", str(self.destination)])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertEqual(json.loads((self.destination / "collection.json").read_text())["decision"], "block")
        self.assertTrue((self.destination / "run/reports/gitleaks.json").is_file())

    def test_incomplete_scan_keeps_partial_reports_without_attestation(self):
        self.scan("incomplete")
        summary = self.collect(2)
        self.assertEqual((summary["status"], summary["decision"], summary["exit_code"]), ("completed", "incomplete", 2))
        self.assertEqual(summary["attestation"], "unavailable")
        self.assertTrue((self.destination / "run/reports/gitleaks.json").is_file())
        self.assertFalse((self.destination / "run/manifest.json").exists())

    def test_preflight_error_produces_a_diagnostic_bundle(self):
        self.scan("preflight")
        summary = self.collect(2)
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["exit_code"], 2)
        self.assertIsNone(summary["run_id"])
        self.assertEqual(summary["files"], [])

    def test_absent_reference_does_not_pass_and_is_not_fabricated(self):
        summary = self.collect(2)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["exit_code"], 2)
        self.assertFalse((self.destination / "scan-result.json").exists())
        self.assertTrue((self.destination / "collection.json").exists())

    def test_real_process_exit_cannot_be_overridden_by_a_pass_reference(self):
        self.scan()
        summary = self.collect(2)
        self.assertEqual(summary["exit_code"], 2)
        self.assertEqual(summary["decision"], "incomplete")
        self.assertIn("real scan process", summary["error"])
        self.assertFalse((self.destination / "run").exists())

    def test_signal_exit_and_boolean_exit_are_not_success(self):
        self.scan()
        for index, code in enumerate((130, False)):
            with self.subTest(code=code):
                self.destination = self.workspace / f".flican/invalid-exit-{index}"
                summary = self.collect(code)
                self.assertEqual(summary["exit_code"], 2)
                self.assertEqual(summary["status"], "failed")

    def test_malformed_and_unfinished_references_are_refused(self):
        baseline = self.scan()
        for index, changes in enumerate(({"schema_version": True}, {"status": "running"},
                                         {"finished_at": None}, {"unexpected": "must-not-be-exported"},
                                         {"artifact_paths": ["../../private-file"]})):
            with self.subTest(changes=changes):
                self.destination = self.workspace / f".flican/bad-{index}"
                self.reference.write_text(json.dumps({**baseline, **changes}))
                summary = self.collect()
                self.assertEqual(summary["exit_code"], 2)
                self.assertFalse((self.destination / "scan-result.json").exists())

    def test_cross_workspace_project_is_refused(self):
        value = self.scan()
        value["project_path"] = "/tmp/outside-workspace"
        self.reference.write_text(json.dumps(value))
        summary = self.collect()
        self.assertEqual(summary["exit_code"], 2)
        self.assertIn("inside this workspace", summary["error"])

    def test_modified_attested_report_is_not_copied(self):
        value = self.scan()
        (Path(value["run_path"]) / "reports/gitleaks.json").write_text('["changed"]')
        summary = self.collect()
        self.assertEqual(summary["exit_code"], 2)
        self.assertEqual(summary["files"], [])

    def test_symlink_artifact_cannot_export_another_file(self):
        value = self.scan()
        report = Path(value["run_path"]) / "reports/gitleaks.json"
        report.unlink()
        secret = self.workspace / "private.txt"
        secret.write_text("SYNTHETIC-PRIVATE-CONTENT")
        report.symlink_to(secret)
        summary = self.collect()
        self.assertEqual(summary["exit_code"], 2)
        self.assertFalse((self.destination / "run").exists())

    def test_existing_destination_is_never_mixed_with_another_run(self):
        self.scan()
        self.destination.mkdir(parents=True)
        sentinel = self.destination / "existing.txt"
        sentinel.write_text("preserve")
        with self.assertRaises(FileExistsError):
            self.collect()
        self.assertEqual(sentinel.read_text(), "preserve")
        self.assertFalse((self.destination / "collection.json").exists())

    def test_destination_cannot_be_a_source_directory(self):
        self.scan()
        self.destination = self.workspace / "new-source-folder"
        with self.assertRaisesRegex(ValueError, "workspace/.flican"):
            self.collect()
        self.assertFalse(self.destination.exists())


class TestCIPreparation(unittest.TestCase):
    def setUp(self):
        self.project = Path(self.enterContext(TemporaryDirectory()))
        self.config = self.project / "flican.yaml"
        self.config.write_text("schema_version: 1\nproject:\n  name: prep\n  exclude: []\n"
                               "scanners: [gitleaks, semgrep]\n")

    def test_only_missing_pinned_selected_images_are_pulled(self):
        results = [subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0)]
        with patch("flican.core.ci.subprocess.run", side_effect=results) as run:
            prepare_scanners(self.project, "/fake/docker", None, progress=lambda text: None)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[-1], ["/fake/docker", "pull", IMAGES["semgrep"]])
        self.assertFalse(any("trivy" in " ".join(command) for command in commands))
        self.assertIn("@sha256:", commands[-1][-1])

    def test_workflow_prepares_image_analysis_even_without_source_trivy(self):
        image = "python:test@sha256:" + "a" * 64
        with self.config.open("a") as output:
            output.write(f"tests:\n  image: {image}\n  command: [python, -m, unittest]\n")
        with (patch("flican.core.ci.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run,
              patch("flican.core.ci.trivy_database", return_value=contextlib.nullcontext()) as database):
            prepare_scanners(self.project, "/fake/docker", self.project / "cache", workflow=True, progress=lambda text: None)
        inspected = [call.args[0][-1] for call in run.call_args_list]
        self.assertEqual(set(inspected), {IMAGES["gitleaks"], IMAGES["semgrep"], IMAGES["trivy"], image})
        database.assert_called_once()

    def test_workflow_and_tests_only_are_rejected_before_docker(self):
        with patch("flican.core.ci.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "either"):
                prepare_scanners(self.project, "/fake/docker", None, workflow=True, tests_only=True)
        run.assert_not_called()

    def test_default_trivy_cache_is_prepared_without_option(self):
        self.config.write_text(self.config.read_text().replace("[gitleaks, semgrep]", "[trivy]"))
        with (patch.dict("os.environ", {"XDG_CACHE_HOME": str(self.project / "cache")}),
              patch("flican.core.ci.subprocess.run", return_value=subprocess.CompletedProcess([], 0)),
              patch("flican.core.ci.run_trivy_db_update", side_effect=download_database) as update):
            prepare_scanners(self.project, "/fake/docker", None, progress=lambda text: None)
        cache = self.project / "cache/flican/trivy"
        self.assertTrue(cache.is_dir())
        update.assert_called_once()
        self.assertEqual(update.call_args.args[1].parent, cache)
        self.assertTrue((cache / "db/trivy.db").is_file())
