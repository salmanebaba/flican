"""Application tests preserve outcomes, isolation and CI evidence."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import yaml
from typer.testing import CliRunner

from state_support import isolated_state
from flican.cli.main import app
from flican.core.ci import collect_scan, prepare_scanners
from flican.core.config import load_config
from flican.core.provenance import load_attested_execution, load_attested_run
from flican.core.testing import build_test_command, run_application_tests

IMAGE = "python:test@sha256:" + "a" * 64


class TestApplicationConfig(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.path = self.root / "flican.yaml"
        self.base = {"schema_version": 1, "project": {"name": "app", "exclude": []}}

    def load(self, tests):
        self.path.write_text(yaml.safe_dump({**self.base, "tests": tests}))
        return load_config(self.path)

    def test_defaults_keep_network_disabled_and_require_a_pinned_image(self):
        settings = self.load({"image": IMAGE, "command": ["python", "-m", "unittest"]})["tests"]
        self.assertEqual(settings["network"], "none")
        self.assertEqual(settings["timeout_seconds"], 300)

    def test_invalid_configuration_is_rejected_before_execution(self):
        valid = {"image": IMAGE, "command": ["python", "-m", "unittest"]}
        changes = ({"image": "python:latest"}, {"image": "https://example.com/image@sha256:" + "a" * 64},
                   {"command": "npm test"}, {"command": []}, {"command": [True]},
                   {"command": [""]}, {"command": ["python", "\x00"]},
                   {"network": "host"}, {"network": True}, {"timeout_seconds": True},
                   {"timeout_seconds": 0}, {"timeout_seconds": 1801}, {"enabled": True})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.load({**valid, **change})


class TestApplicationCommand(unittest.TestCase):
    def setUp(self):
        isolated_state(self)
        self.workspace = Path(self.enterContext(TemporaryDirectory()))
        self.project = self.workspace / "project"
        self.project.mkdir()
        self.config = self.project / "flican.yaml"
        self.config.write_text(yaml.safe_dump({
            "schema_version": 1, "project": {"name": "application-demo", "exclude": []},
            "scanners": ["gitleaks"], "tests": {"image": IMAGE, "command": ["python", "-m", "unittest"]},
        }))
        (self.project / "app.py").write_text("value = 1\n")
        self.reference = self.project / ".flican/test-reference.json"
        self.bundle = self.workspace / ".flican/test-bundle"
        self.enterContext(patch("flican.cli.testing.shutil.which", return_value="/fake/docker"))

    def invoke(self, outcome=0):
        def execute(docker, snapshot, settings, log):
            self.snapshot = snapshot
            self.assertFalse((snapshot / ".flican").exists())
            self.assertEqual((snapshot / "app.py").read_text(), "value = 1\n")
            log.parent.mkdir(parents=True)
            log.write_bytes(b"application test output\n")
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        with patch("flican.cli.testing.run_application_tests", side_effect=execute):
            return CliRunner().invoke(app, ["test", str(self.project), "--result-file", str(self.reference)])

    def value(self):
        return json.loads(self.reference.read_text())

    def test_passing_run_is_attested_collected_and_keeps_source_unchanged(self):
        result = self.invoke()
        self.assertEqual(result.exit_code, 0, result.output)
        value = self.value()
        self.assertEqual((value["command"], value["decision"]), ("test", "allow"))
        self.assertIsNone(value["findings_report_path"])
        root = Path(value["run_path"])
        self.assertEqual(load_attested_execution(root)["mode"], "test")
        self.assertEqual(json.loads((root / "run.json").read_text())["mode"], "test")
        self.assertEqual(json.loads((root / "reports/tests.json").read_text())["status"], "passed")
        self.assertFalse(self.snapshot.exists())
        self.assertEqual((self.project / "app.py").read_text(), "value = 1\n")
        summary = collect_scan(self.reference, 0, self.workspace, self.bundle)
        self.assertEqual(summary["exit_code"], 0)
        self.assertEqual(summary["attestation"], "verified_locally")
        self.assertTrue((self.bundle / "test-result.json").is_file())
        self.assertEqual(len(summary["files"]), 4)

    def test_failed_tests_are_a_complete_block_and_collection_preserves_code_one(self):
        result = self.invoke(1)
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertEqual((self.value()["status"], self.value()["decision"]), ("completed", "block"))
        result = CliRunner().invoke(app, ["ci", "collect", str(self.reference), "--exit-code", "1",
                                         "--workspace", str(self.workspace), "--output-dir", str(self.bundle)])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertTrue((self.bundle / "run/logs/tests.log").is_file())

    def test_operational_failures_and_timeouts_keep_logs_without_attestation(self):
        cases = (127, 137, RuntimeError("runtime unavailable"),
                 subprocess.TimeoutExpired(["synthetic-private-command"], 3, output="synthetic-private-output"))
        for index, outcome in enumerate(cases):
            with self.subTest(outcome=outcome):
                self.reference = self.project / f".flican/error-{index}.json"
                self.bundle = self.workspace / f".flican/error-{index}-bundle"
                result = self.invoke(outcome)
                self.assertEqual(result.exit_code, 2, result.output)
                value = self.value()
                self.assertEqual(value["decision"], "incomplete")
                self.assertIsNone(value["manifest_path"])
                self.assertIn("logs/tests.log", value["artifact_paths"])
                run = json.loads(Path(value["run_report_path"]).read_text())
                self.assertEqual(run["stages"][0]["status"], "timed_out" if index == 3 else "failed")
                self.assertNotIn("synthetic-private", json.dumps(run))
                self.assertEqual(collect_scan(self.reference, 2, self.workspace, self.bundle)["exit_code"], 2)
                self.assertTrue((self.bundle / "run/logs/tests.log").is_file())

    def test_cancellation_keeps_diagnostics_and_never_publishes_a_pass(self):
        result = self.invoke(KeyboardInterrupt())
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertEqual(self.value()["status"], "cancelled")
        self.assertIn("logs/tests.log", self.value()["artifact_paths"])
        self.assertFalse(self.snapshot.exists())

    def test_tests_are_never_importable_as_security_findings(self):
        self.assertEqual(self.invoke().exit_code, 0)
        with self.assertRaisesRegex(ValueError, "not a security scan"):
            load_attested_run(Path(self.value()["run_path"]))

    def test_changed_log_or_mislabelled_command_cannot_pass_collection(self):
        self.assertEqual(self.invoke().exit_code, 0)
        original = self.value()
        self.reference.write_text(json.dumps({**original, "command": "scan"}))
        summary = collect_scan(self.reference, 0, self.workspace, self.bundle)
        self.assertEqual(summary["exit_code"], 2)
        self.reference.write_text(json.dumps(original))
        (Path(original["run_path"]) / "logs/tests.log").write_bytes(b"changed evidence")
        summary = collect_scan(self.reference, 0, self.workspace, self.workspace / ".flican/changed-log")
        self.assertEqual(summary["exit_code"], 2)
        self.assertEqual(summary["attestation"], "unavailable")

    def test_missing_configuration_has_a_machine_readable_error_without_a_run(self):
        settings = yaml.safe_load(self.config.read_text())
        settings.pop("tests")
        self.config.write_text(yaml.safe_dump(settings))
        with patch("flican.cli.testing.run_application_tests") as worker:
            result = CliRunner().invoke(app, ["test", str(self.project), "--result-file", str(self.reference)])
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIsNone(self.value()["run_id"])
        self.assertEqual(self.value()["command"], "test")
        worker.assert_not_called()

    def test_export_failure_preserves_the_attested_test_evidence(self):
        with patch("flican.cli.testing.ScanResultFile.finish", side_effect=RuntimeError("output unavailable")):
            result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        root = next(self.project.glob(".flican/runs/*"))
        self.assertEqual(load_attested_execution(root)["mode"], "test")
        self.assertEqual(self.value()["status"], "running")

    def test_prepare_tests_only_does_not_prepare_scanners_or_trivy(self):
        with (patch("flican.core.ci.subprocess.run", side_effect=[subprocess.CompletedProcess([], 1),
                                                               subprocess.CompletedProcess([], 0)]) as docker,
              patch("flican.core.ci.run_trivy_db_update") as database):
            prepare_scanners(self.project, "/fake/docker", None, progress=lambda text: None, tests_only=True)
        self.assertEqual(docker.call_args_list[0].args[0], ["/fake/docker", "image", "inspect", IMAGE])
        self.assertEqual(docker.call_args_list[1].args[0], ["/fake/docker", "pull", IMAGE])
        database.assert_not_called()

    def test_scan_does_not_execute_the_declared_tests(self):
        with (patch("flican.cli.main.run_gitleaks", return_value=subprocess.CompletedProcess([], 0, stdout="[]", stderr="")),
              patch("flican.cli.testing.run_application_tests") as worker):
            result = CliRunner().invoke(app, ["scan", str(self.project)])
        self.assertEqual(result.exit_code, 0, result.output)
        worker.assert_not_called()


class TestApplicationWorker(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.source = self.root / "source"
        self.source.mkdir()
        self.log = self.root / "logs/tests.log"
        self.settings = {"image": IMAGE, "command": ["python", "-m", "unittest"],
                         "timeout_seconds": 2, "network": "none"}

    def simulate(self, program, **changes):
        real_popen = subprocess.Popen

        def start(_command, **options):
            # Trusted producer only: exercise pipe bounds and cleanup without Docker.
            return real_popen([sys.executable, "-c", program], **options)

        with (patch("flican.core.testing.get_container_user", return_value="1000:1000"),
              patch("flican.core.testing.subprocess.Popen", side_effect=start),
              patch("flican.core.testing.remove_container") as remove):
            try:
                return run_application_tests("/fake/docker", self.source, {**self.settings, **changes}, self.log)
            finally:
                remove.assert_called_once()

    def test_worker_retains_stdout_stderr_and_native_failure(self):
        code = self.simulate('import sys; print("stdout"); print("stderr",file=sys.stderr); sys.exit(1)')
        self.assertEqual(code, 1)
        self.assertIn(b"stdout", self.log.read_bytes())
        self.assertIn(b"stderr", self.log.read_bytes())
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)

    def test_output_limit_stops_the_producer_and_bounds_the_artifact(self):
        with patch("flican.core.testing.MAX_TEST_OUTPUT_BYTES", 256):
            with self.assertRaisesRegex(RuntimeError, "log limit"):
                self.simulate('import os; os.write(1,b"x"*4096)')
        self.assertEqual(self.log.stat().st_size, 256)

    def test_timeout_preserves_partial_logs_and_cleans_the_worker(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.simulate('import time; print("started",flush=True); time.sleep(30)', timeout_seconds=1)
        self.assertIn(b"started", self.log.read_bytes())

    def test_container_has_readonly_source_bounded_resources_and_literal_arguments(self):
        literal = "$(touch /tmp/should-not-run-on-host)"
        command = build_test_command("docker", self.source, {**self.settings, "command": ["echo", literal]},
                                     "test-name", "1000:1000")
        self.assertEqual(command[-2:], ["echo", literal])
        self.assertIn("--network=none", command)
        self.assertIn("--read-only", command)
        self.assertIn("--memory=512m", command)
        self.assertIn("--pids-limit=128", command)
        self.assertIn("/work:rw,exec,nosuid,nodev,size=256m,mode=1777", command)
        self.assertEqual(command.count("--mount"), 1)
        mount = command[command.index("--mount") + 1]
        self.assertTrue(mount.endswith("target=/src,readonly"))
        self.assertNotIn("docker.sock", " ".join(command))
        self.assertNotIn("--privileged", command)
