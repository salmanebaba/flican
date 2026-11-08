"""CI references must identify this invocation and never turn failure into PASS."""

import json
import stat
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from typer.testing import CliRunner

from state_support import isolated_state
from flican.cli.main import app
from flican.core.provenance import load_attested_run
from flican.core.scan_result import ScanResultFile


class TestScanResultCLI(unittest.TestCase):
    def setUp(self):
        isolated_state(self)
        self.base = Path(self.enterContext(TemporaryDirectory(prefix="flican-result-test-")))
        self.project = self.base / "project"
        self.project.mkdir()
        self.output = self.project / ".flican/ci/result.json"
        (self.project / "app.py").write_text("value = 1\n")
        self.config = self.project / "flican.yaml"
        self.config.write_text(
            "schema_version: 1\nproject:\n  name: result-demo\n  exclude: []\n"
            "scanners: [gitleaks, semgrep]\npolicy:\n  fail_on: high\n",
        )
        self.docker = self.enterContext(patch("flican.cli.main.shutil.which", return_value="/fake/docker"))
        self.gitleaks = self.enterContext(patch("flican.cli.main.run_gitleaks", return_value=
            subprocess.CompletedProcess([], 0, stdout="[]", stderr="")))
        self.semgrep = self.enterContext(patch("flican.cli.main.run_semgrep", return_value=
            subprocess.CompletedProcess([], 0, stdout='{"results":[],"errors":[]}', stderr="")))

    def invoke(self, *arguments):
        return CliRunner().invoke(app, ["scan", str(self.project), "--result-file", str(self.output), *arguments])

    def read(self):
        return json.loads(self.output.read_text())

    def test_success_has_exact_artifact_paths_and_preserves_the_attestation(self):
        result = self.invoke()
        self.assertEqual(result.exit_code, 0, result.output)
        value = self.read()
        self.assertEqual((value["schema_version"], value["command"]), (1, "scan"))
        self.assertEqual((value["status"], value["decision"], value["exit_code"]), ("completed", "allow", 0))
        self.assertIsNone(value["error"])
        self.assertEqual(len(value["invocation_id"]), 32)
        self.assertEqual(Path(value["run_path"]).name, value["run_id"])
        root = Path(value["run_path"])
        self.assertEqual(value["artifact_paths"], ["run.json", "reports/gitleaks.json", "reports/semgrep.json",
                                                 "reports/findings.json", "manifest.json"])
        self.assertTrue(all((root / relative).is_file() for relative in value["artifact_paths"]))
        self.assertEqual(value["findings_report_path"], str(root / "reports/findings.json"))
        self.assertEqual(value["run_report_path"], str(root / "run.json"))
        self.assertEqual(value["manifest_path"], str(root / "manifest.json"))
        manifest, _ = load_attested_run(root)
        self.assertIn("run.json", manifest["artifacts"])
        self.assertNotIn(str(self.output), manifest["artifacts"])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_policy_block_keeps_cli_exit_code_one(self):
        self.gitleaks.return_value = subprocess.CompletedProcess([], 10,
            stdout='[{"RuleID":"synthetic","File":"/src/app.py"}]',
            stderr="12:00PM WRN leaks found: 1\n")
        result = self.invoke()
        self.assertEqual(result.exit_code, 1, result.output)
        value = self.read()
        self.assertEqual((value["status"], value["decision"], value["exit_code"]), ("completed", "block", 1))
        self.assertIsNotNone(value["manifest_path"])

    def test_scanner_failure_has_partial_artifacts_and_no_manifest(self):
        self.semgrep.return_value = subprocess.CompletedProcess([], 2, stdout="{}", stderr="native error")
        result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        value = self.read()
        self.assertEqual((value["status"], value["decision"], value["exit_code"]), ("failed", "incomplete", 2))
        self.assertIn("semgrep", value["error"])
        self.assertIn("reports/gitleaks.json", value["artifact_paths"])
        self.assertNotIn("reports/semgrep.json", value["artifact_paths"])
        self.assertIsNone(value["manifest_path"])

    def test_configuration_failure_before_run_creation_is_machine_readable(self):
        self.config.unlink()
        result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        value = self.read()
        self.assertEqual(value["exit_code"], 2)
        self.assertEqual(value["decision"], "incomplete")
        for key in ("run_id", "run_path", "run_report_path", "findings_report_path", "manifest_path"):
            self.assertIsNone(value[key])
        self.assertEqual(value["artifact_paths"], [])
        self.assertTrue(value["error"])
        self.assertFalse((self.project / ".flican/runs").exists())
        self.gitleaks.assert_not_called()

    def test_missing_docker_has_no_fictitious_run(self):
        self.docker.return_value = None
        result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIsNone(self.read()["run_id"])
        self.assertEqual(self.read()["status"], "failed")
        self.gitleaks.assert_not_called()

    def test_missing_offline_trivy_database_has_a_failed_run_and_partial_artifacts(self):
        self.config.write_text(self.config.read_text().replace("[gitleaks, semgrep]", "[gitleaks, trivy]"))
        with (patch.dict("os.environ", {"XDG_CACHE_HOME": str(self.base / "empty-cache")}),
              patch("flican.adapters.trivy.get_container_user", return_value="1000:1000")):
            result = self.invoke("--offline")
        self.assertEqual(result.exit_code, 2, result.output)
        value = self.read()
        self.assertIsNotNone(value["run_id"])
        self.assertEqual((value["status"], value["decision"]), ("failed", "incomplete"))
        self.assertIn("reports/gitleaks.json", value["artifact_paths"])
        self.assertIsNone(value["manifest_path"])
        self.assertIn("flican db update", value["error"])

    def test_timeout_does_not_export_subprocess_output_or_command(self):
        self.gitleaks.side_effect = subprocess.TimeoutExpired(["synthetic-private-command"], 90,
                                                            output="synthetic-private-output")
        result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertEqual(self.read()["exit_code"], 2)
        self.assertNotIn("synthetic-private", self.output.read_text())

    def test_cancellation_publishes_a_terminal_incomplete_reference(self):
        self.semgrep.side_effect = KeyboardInterrupt
        result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        value = self.read()
        self.assertEqual((value["status"], value["decision"], value["exit_code"]), ("cancelled", "incomplete", 2))
        self.assertIn("reports/gitleaks.json", value["artifact_paths"])
        self.assertIsNone(value["manifest_path"])

    def test_run_reference_is_available_before_scanners_start_and_is_not_scanned(self):
        def inspect(snapshot_docker, snapshot):
            value = self.read()
            self.assertEqual(value["status"], "running")
            self.assertIsNone(value["decision"])
            self.assertIsNone(value["exit_code"])
            self.assertIsNone(value["finished_at"])
            self.assertTrue(Path(value["run_report_path"]).is_file())
            self.assertFalse((snapshot / ".flican").exists())
            self.assertEqual(sorted(path.name for path in snapshot.iterdir()), ["app.py", "flican.yaml"])
            return subprocess.CompletedProcess([], 0, stdout="[]", stderr="")
        self.gitleaks.side_effect = inspect
        result = self.invoke()
        self.assertEqual(result.exit_code, 0, result.output)

    def test_existing_pass_reference_is_never_reused_or_overwritten(self):
        self.output.parent.mkdir(parents=True)
        stale = '{"status":"completed","decision":"allow","exit_code":0}\n'
        self.output.write_text(stale)
        result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("already exists", result.stderr)
        self.assertEqual(self.output.read_text(), stale)
        self.gitleaks.assert_not_called()

    def test_source_and_run_artifact_targets_are_refused_before_modification(self):
        before = self.config.read_bytes()
        for path in (self.config, self.project / "new-result.json", self.project / ".flican/runs/result.json"):
            with self.subTest(path=path):
                self.output = path
                result = self.invoke()
                self.assertEqual(result.exit_code, 2, result.output)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertFalse((self.project / "new-result.json").exists())
        self.assertFalse((self.project / ".flican").exists())
        self.gitleaks.assert_not_called()

    def test_target_symlink_does_not_modify_its_destination(self):
        self.output.parent.mkdir(parents=True)
        before = (self.project / "app.py").read_bytes()
        self.output.symlink_to(self.project / "app.py")
        result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertTrue(self.output.is_symlink())
        self.assertEqual((self.project / "app.py").read_bytes(), before)
        self.gitleaks.assert_not_called()

    def test_external_output_preserves_the_existing_parent_directory_mode(self):
        parent = self.base / "ci-artifacts"
        parent.mkdir(mode=0o755)
        parent.chmod(0o755)
        self.output = parent / "result.json"
        result = self.invoke()
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_export_failure_blocks_cli_without_destroying_valid_scan_evidence(self):
        original = ScanResultFile._write
        def fail_final(output, data):
            if data["status"] != "running":
                raise OSError("synthetic result export failure")
            return original(output, data)
        with patch.object(ScanResultFile, "_write", new=fail_final):
            result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("Cannot publish the scan result file", result.stderr)
        value = self.read()
        self.assertEqual(value["status"], "running")
        self.assertIsNone(value["exit_code"])
        _, report = load_attested_run(Path(value["run_path"]))
        self.assertTrue(report["gate"]["passed"])

    def test_unregistered_manifest_is_not_advertised_as_an_attestation(self):
        def fail_attestation(root, *args):
            (root / "manifest.json").write_text("{}\n")
            raise RuntimeError("synthetic state registration failure")
        with patch("flican.cli.main.attest_run", side_effect=fail_attestation):
            result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        value = self.read()
        self.assertIsNone(value["manifest_path"])
        self.assertNotIn("manifest.json", value["artifact_paths"])
        self.assertEqual(value["exit_code"], 2)

    def test_cli_usage_errors_do_not_create_a_result_file(self):
        result = self.invoke("--unknown-option")
        self.assertEqual(result.exit_code, 2)
        self.assertFalse(self.output.exists())
        self.gitleaks.assert_not_called()


class TestScanResultPublication(unittest.TestCase):
    def setUp(self):
        self.base = Path(self.enterContext(TemporaryDirectory()))
        self.project = self.base / "project"
        self.project.mkdir()
        self.path = self.base / "result.json"

    def test_failed_atomic_update_keeps_the_previous_checkpoint(self):
        output = ScanResultFile(self.path, self.project)
        before = self.path.read_bytes()
        with patch("flican.core.scan_result.os.replace", side_effect=OSError("synthetic disk failure")):
            with self.assertRaises(OSError):
                output.finish(error=RuntimeError("preflight failure"))
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(list(self.base.glob(".flican-result-*")), [])

    def test_externally_replaced_file_is_preserved(self):
        output = ScanResultFile(self.path, self.project)
        self.path.unlink()
        self.path.write_text("external data\n")
        with self.assertRaisesRegex(ValueError, "replaced externally"):
            output.finish(error=RuntimeError("preflight failure"))
        self.assertEqual(self.path.read_text(), "external data\n")

    def test_in_place_changes_are_not_overwritten(self):
        output = ScanResultFile(self.path, self.project)
        changed = self.path.read_text().replace('"scan"', '"edit"')
        self.path.write_text(changed)
        with self.assertRaisesRegex(ValueError, "replaced externally"):
            output.finish(error=RuntimeError("preflight failure"))
        self.assertEqual(self.path.read_text(), changed)

    def test_finalized_reference_cannot_be_reused(self):
        output = ScanResultFile(self.path, self.project)
        output.finish(error=RuntimeError("preflight failure"))
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "already finalized"):
            output.finish(error=RuntimeError("different invocation"))
        self.assertEqual(self.path.read_bytes(), before)

    def test_initial_publication_race_does_not_overwrite_another_file(self):
        def concurrent_creation(*args, **kwargs):
            self.path.write_text("another invocation\n")
            raise FileExistsError
        with patch("flican.core.scan_result.os.link", side_effect=concurrent_creation):
            with self.assertRaisesRegex(ValueError, "already exists"):
                ScanResultFile(self.path, self.project)
        self.assertEqual(self.path.read_text(), "another invocation\n")
        self.assertEqual(list(self.base.glob(".flican-result-*")), [])
