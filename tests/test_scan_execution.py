"""Exercise checkpoints through the CLI, including partial and interrupted scans."""

import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from typer.testing import CliRunner

from state_support import isolated_state
from flican.cli.main import app
from flican.core.models import Run
from flican.core.provenance import attest_run, load_attested_run
from flican.core.state import StateStore

CHECKOV_REPORT = (Path(__file__).parent / "fixtures/checkov/finding-report.json").read_text()


def native(code=0, output="[]", stderr=""):
    return subprocess.CompletedProcess(["scanner"], code, stdout=output, stderr=stderr)


class TestScanExecution(unittest.TestCase):
    def setUp(self):
        isolated_state(self)
        self.project = Path(self.enterContext(TemporaryDirectory(prefix="flican-execution-")))
        (self.project / "app.py").write_text("value = 1\n")
        self.configure(["gitleaks", "semgrep"])
        self.enterContext(patch("flican.cli.main.shutil.which", return_value="/fake/docker"))
        self.gitleaks = self.enterContext(patch("flican.cli.main.run_gitleaks", return_value=native()))
        self.semgrep = self.enterContext(patch("flican.cli.main.run_semgrep", return_value=native(
            output='{"results":[],"errors":[]}',
        )))
        self.checkov = self.enterContext(patch("flican.cli.main.run_checkov", return_value=native(1, CHECKOV_REPORT)))

    def configure(self, scanners):
        (self.project / "flican.yaml").write_text(
            "schema_version: 1\nproject:\n  name: execution-demo\n  exclude: []\n"
            f"scanners: {json.dumps(scanners)}\npolicy:\n  fail_on: high\n",
        )

    def invoke(self):
        return CliRunner().invoke(app, ["scan", str(self.project)])

    def current(self):
        path = next(self.project.glob(".flican/runs/*/run.json"))
        return path.parent, Run.from_dict(json.loads(path.read_text()))

    def test_partial_reports_exist_before_next_scanner_and_independent_scans_continue(self):
        self.configure(["gitleaks", "semgrep", "checkov"])
        self.gitleaks.return_value = native(10, '[{"RuleID":"synthetic","File":"/src/app.py"}]',
                                             "12:00PM WRN leaks found: 1\n")

        def fail_after_checkpoint(*arguments):
            root, run = self.current()
            self.assertEqual([stage.status.value for stage in run.stages], ["completed", "running", "pending"])
            self.assertEqual(run.stages[0].findings_count, 1)
            self.assertTrue((root / "reports/gitleaks.json").is_file())
            checkpoint = json.loads((root / "reports/findings.json").read_text())
            self.assertEqual(len(checkpoint["findings"]), 1)
            self.assertIsNone(checkpoint["gate"]["passed"])
            return native(2, "{}", "synthetic scanner failure")

        self.semgrep.side_effect = fail_after_checkpoint
        result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        root, run = self.current()
        self.assertEqual([stage.status.value for stage in run.stages], ["completed", "failed", "completed"])
        self.assertEqual(run.exit_code, 2)
        self.assertEqual(run.stages[1].exit_code, 2)
        report = json.loads((root / "reports/findings.json").read_text())
        self.assertEqual(report["execution"]["completed_scanners"], ["gitleaks", "checkov"])
        self.assertEqual(len(report["findings"]), 2)
        self.assertIsNone(report["gate"]["passed"])
        self.assertEqual(report["execution"]["decision"], "incomplete")
        self.assertFalse((root / "reports/semgrep.json").exists())
        self.assertFalse((root / "manifest.json").exists())
        self.assertIsNone(StateStore().get("run", run.run_id))
        self.assertIn("Run report:", result.stderr)
        snapshots = [mock.call_args.args[1] for mock in (self.gitleaks, self.semgrep, self.checkov)]
        self.assertEqual(len(set(snapshots)), 1)
        self.assertFalse(snapshots[0].exists())
        with self.assertRaisesRegex(ValueError, "not registered"):
            load_attested_run(root)
        profiles = {stage.tool: {"hash": stage.profile_hash} for stage in run.stages}
        with self.assertRaisesRegex(ValueError, "Only completed"):
            attest_run(root, self.project, run.project_name, run.started_at, profiles, {},
                       ["gitleaks.json", "checkov.json", "findings.json"])

    def test_timeout_is_distinct_and_does_not_leak_subprocess_output(self):
        self.gitleaks.side_effect = subprocess.TimeoutExpired(
            ["scanner", "synthetic-private-command"], 90, output="synthetic-private-output",
        )
        result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        root, run = self.current()
        self.assertEqual([stage.status.value for stage in run.stages], ["timed_out", "completed"])
        self.assertIsNone(run.stages[0].exit_code)
        self.assertNotIn("synthetic-private", (root / "run.json").read_text() + result.output)
        self.assertFalse(self.gitleaks.call_args.args[1].exists())

    def test_cancellation_keeps_completed_reports_and_cancels_remaining_stages(self):
        self.configure(["gitleaks", "semgrep", "checkov"])
        self.semgrep.side_effect = KeyboardInterrupt
        result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        root, run = self.current()
        self.assertEqual(run.status.value, "cancelled")
        self.assertEqual([stage.status.value for stage in run.stages], ["completed", "cancelled", "cancelled"])
        self.assertTrue((root / "reports/gitleaks.json").exists())
        self.assertFalse((root / "manifest.json").exists())
        self.assertFalse(self.gitleaks.call_args.args[1].exists())
        self.checkov.assert_not_called()

    def test_storage_error_stops_remaining_scanners_and_records_incomplete_run(self):
        with patch("flican.cli.main.save_report", side_effect=OSError("synthetic storage failure")):
            result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        root, run = self.current()
        self.assertEqual([stage.status.value for stage in run.stages], ["failed", "skipped"])
        self.assertEqual(run.decision.value, "incomplete")
        self.assertIn("synthetic storage failure", run.error)
        self.assertIsNone(json.loads((root / "reports/findings.json").read_text())["gate"]["passed"])
        self.semgrep.assert_not_called()

    def test_success_is_attested_with_its_journal_and_later_tampering_is_rejected(self):
        result = self.invoke()
        self.assertEqual(result.exit_code, 0, result.output)
        root, run = self.current()
        manifest, report = load_attested_run(root)
        self.assertIn("run.json", manifest["artifacts"])
        self.assertEqual(manifest["completed_at"], run.finished_at)
        self.assertEqual(run.decision.value, "allow")
        self.assertTrue(report["gate"]["passed"])
        self.assertEqual(run.exit_code, 0)
        self.assertIn("Run report:", result.stdout)
        value = run.to_dict()
        value["project_name"] = "modified-after-attestation"
        (root / "run.json").write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "artifact integrity"):
            load_attested_run(root)

    def test_invalid_normalized_finding_rejects_the_whole_stage(self):
        self.gitleaks.return_value = native(10, json.dumps([
            {"RuleID": "first", "File": "/src/app.py"},
            {"RuleID": "invalid", "File": "/outside/private.txt"},
        ]), "12:00PM WRN leaks found: 2\n")
        result = self.invoke()
        self.assertEqual(result.exit_code, 2, result.output)
        root, run = self.current()
        self.assertEqual(run.stages[0].status.value, "failed")
        self.assertIsNone(run.stages[0].findings_count)
        self.assertFalse((root / "reports/gitleaks.json").exists())
        self.assertEqual(json.loads((root / "reports/findings.json").read_text())["findings"], [])
