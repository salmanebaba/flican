"""Opt-in application tests using the pinned Python and Node containers."""

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml
from typer.testing import CliRunner

from state_support import isolated_state
from flican.cli.main import app
from flican.core.ci import collect_scan

PYTHON = "python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337"
NODE = "node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392"


@unittest.skipUnless(os.environ.get("FLICAN_APPLICATION_DOCKER_TESTS") == "1",
                     "Set FLICAN_APPLICATION_DOCKER_TESTS=1 to run application containers.")
class TestApplicationDocker(unittest.TestCase):
    def setUp(self):
        isolated_state(self)
        self.workspace = Path(self.enterContext(TemporaryDirectory(prefix="flican-application-")))
        self.project = self.workspace / "project"
        self.project.mkdir()
        self.reference = self.workspace / ".flican/reference.json"
        self.bundle = self.workspace / ".flican/bundle"
        self.docker = shutil.which("docker")
        self.assertIsNotNone(self.docker)
        self.containers_before = self.containers()

    def containers(self):
        return set(subprocess.check_output([self.docker, "ps", "-aq", "--filter", "name=flican-test-"], text=True).split())

    def execute(self, command, *, expected=0, image=PYTHON, timeout=30, network="none"):
        (self.project / "flican.yaml").write_text(yaml.safe_dump({
            "schema_version": 1, "project": {"name": "real-application", "exclude": [".git"]},
            "scanners": ["gitleaks"], "tests": {
                "image": image, "command": command, "timeout_seconds": timeout, "network": network,
            },
        }))
        before = {path.relative_to(self.project).as_posix(): path.read_bytes()
                  for path in self.project.rglob("*") if path.is_file() and not path.is_symlink()}
        result = CliRunner().invoke(app, ["test", str(self.project), "--result-file", str(self.reference)])
        self.assertEqual(result.exit_code, expected, result.output)
        reference = json.loads(self.reference.read_text())
        run = json.loads(Path(reference["run_report_path"]).read_text())
        for path, content in before.items():
            self.assertEqual((self.project / path).read_bytes(), content)
        self.assertEqual(self.containers() - self.containers_before, set())
        summary = collect_scan(self.reference, expected, self.workspace, self.bundle)
        self.assertEqual(summary["exit_code"], expected)
        self.assertEqual(summary["attestation"], "verified_locally" if expected in (0, 1) else "unavailable")
        return reference, run

    def test_python_unittest_and_writable_copy_preserve_readonly_source(self):
        (self.project / "app.py").write_text("value = 1\n")
        (self.project / "test_app.py").write_text(
            "import os, unittest\nfrom pathlib import Path\nimport app\n"
            "class TestApp(unittest.TestCase):\n"
            " def test_value(self): self.assertEqual(app.value, 1)\n"
            " def test_writable_copy(self):\n"
            "  Path('app.py').write_text('changed in work copy')\n"
            "  self.assertEqual(Path('/src/app.py').read_text(), 'value = 1\\n')\n"
            "  with self.assertRaises(OSError): Path('/src/app.py').write_text('cannot change source')\n"
            " def test_environment(self):\n"
            "  self.assertNotIn('FLICAN_TEST_HOST_ONLY', os.environ)\n"
            "  self.assertFalse(Path('/var/run/docker.sock').exists())\n",
        )
        from unittest.mock import patch
        with patch.dict("os.environ", {"FLICAN_TEST_HOST_ONLY": "synthetic-operator-environment"}):
            reference, _ = self.execute(["python", "-m", "unittest", "discover", "-v"])
        log = (Path(reference["run_path"]) / "logs/tests.log").read_text()
        self.assertIn("Ran 3 tests", log)

    def test_python_failed_assertion_returns_one_with_attested_logs(self):
        (self.project / "test_app.py").write_text(
            "import unittest\nclass TestApp(unittest.TestCase):\n def test_failure(self): self.assertEqual(1, 2)\n",
        )
        reference, _ = self.execute(["python", "-m", "unittest", "discover", "-v"], expected=1)
        self.assertIn("FAILED", (Path(reference["run_path"]) / "logs/tests.log").read_text())

    def test_node_builtin_test_runner_passes(self):
        (self.project / "app.test.cjs").write_text(
            "const test=require('node:test');const assert=require('node:assert/strict');\n"
            "test('adds integers',()=>{assert.equal(2+3,5);});\n",
        )
        self.execute(["node", "--test", "app.test.cjs"], image=NODE)

    def test_node_failed_assertion_returns_one(self):
        (self.project / "app.test.cjs").write_text(
            "const test=require('node:test');const assert=require('node:assert/strict');\n"
            "test('intentional failure',()=>{assert.equal(2+3,99);});\n",
        )
        self.execute(["node", "--test", "app.test.cjs"], image=NODE, expected=1)

    def test_timeout_preserves_partial_logs_and_removes_the_container(self):
        reference, run = self.execute(["python", "-c", "import time; print('started',flush=True); time.sleep(30)"],
                                      timeout=3, expected=2)
        self.assertEqual(run["stages"][0]["status"], "timed_out")
        self.assertIn("started", (Path(reference["run_path"]) / "logs/tests.log").read_text())

    def test_missing_command_is_an_operational_error(self):
        _, run = self.execute(["flican-command-that-does-not-exist"], expected=2)
        self.assertEqual(run["stages"][0]["exit_code"], 127)

    def test_output_is_bounded_and_excess_is_an_operational_error(self):
        reference, _ = self.execute(["python", "-c", "import os; os.write(1,b'x'*(9*1024*1024))"], expected=2)
        self.assertEqual((Path(reference["run_path"]) / "logs/tests.log").stat().st_size, 8 * 1024 * 1024)

    def test_executable_script_is_preserved_in_the_test_snapshot(self):
        script = self.project / "test.sh"
        script.write_text("#!/bin/sh\nprintf 'executable script passed\\n'\n")
        script.chmod(0o755)
        reference, _ = self.execute(["./test.sh"])
        self.assertIn("executable script passed", (Path(reference["run_path"]) / "logs/tests.log").read_text())

    def test_bridge_network_is_an_explicit_profile_choice(self):
        reference, _ = self.execute(["python", "-c", "print('bridge profile executed')"], network="bridge")
        report = json.loads((Path(reference["run_path"]) / "reports/tests.json").read_text())
        self.assertEqual(report["network"], "bridge")
