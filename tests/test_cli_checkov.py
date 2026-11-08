import json
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from typer.testing import CliRunner

from flican.cli.main import app
from state_support import isolated_state

FIXTURES = Path(__file__).parent / "fixtures" / "checkov"
REPORT_TEXT = (FIXTURES / "finding-report.json").read_text(encoding="utf-8")


def prepare_project(project, scanners, threshold="high"):
    (project / "flican.yaml").write_text(
        "schema_version: 1\nproject:\n  name: checkov-test\n  exclude: []\n"
        f"scanners: {json.dumps(scanners)}\npolicy:\n  fail_on: {threshold}\n",
        encoding="utf-8",
    )
    shutil.copyfile(FIXTURES / "vulnerable" / "main.tf", project / "main.tf")


class TestCheckovCLI(unittest.TestCase):
    def setUp(self):
        isolated_state(self)

    def assert_failed_journal(self, project):
        path = next(project.glob(".flican/runs/*/run.json"))
        run = json.loads(path.read_text())
        self.assertEqual(run["status"], "failed")
        self.assertEqual(run["decision"], "incomplete")
        self.assertEqual(run["exit_code"], 2)
        self.assertEqual(run["stages"][0]["status"], "failed")
        self.assertFalse((path.parent / "manifest.json").exists())
        self.assertFalse((path.parent / "reports/checkov.json").exists())
        report = json.loads((path.parent / "reports/findings.json").read_text())
        self.assertIsNone(report["gate"]["passed"])

    def test_findings_follow_policy_and_keep_reports_resource_and_coverage(self):
        for threshold, code, passed in (("high", 1, False), ("critical", 0, True)):
            with self.subTest(threshold=threshold), TemporaryDirectory() as directory:
                project = Path(directory)
                prepare_project(project, ["checkov"], threshold)
                native = subprocess.CompletedProcess([], 1, stdout=REPORT_TEXT, stderr="")
                with (
                    patch("flican.cli.main.shutil.which", return_value="/fake/docker"),
                    patch("flican.cli.main.run_checkov", return_value=native) as checkov_mock,
                ):
                    result = CliRunner().invoke(app, ["scan", str(project)])
                self.assertEqual(result.exit_code, code, result.output)
                self.assertIn("IaC findings: 1", result.stdout)
                self.assertIn("IaC coverage: completed", result.stdout)
                checkov_mock.assert_called_once()
                self.assertFalse(checkov_mock.call_args.args[1].exists())
                reports = list(project.glob(".flican/runs/*/reports/checkov.json"))
                self.assertEqual(len(reports), 1)
                self.assertEqual(reports[0].read_text(encoding="utf-8"), REPORT_TEXT)
                report = json.loads((reports[0].parent / "findings.json").read_text(encoding="utf-8"))
                self.assertEqual(report["gate"], {"fail_on": threshold, "passed": passed})
                self.assertEqual(report["scanners"], ["checkov"])
                self.assertEqual(report["coverage"]["checkov"]["resource_count"], 1)
                finding = report["findings"][0]
                self.assertEqual(finding["severity"], "high")
                self.assertEqual(finding["severity_source"], "flican_policy")
                self.assertEqual(finding["resource_id"], "aws_s3_bucket_public_access_block.example")
                self.assertEqual(finding["framework"], "terraform")

    def test_unreported_dockerfile_returns_2_without_success_reports(self):
        with TemporaryDirectory() as directory:
            project = Path(directory)
            prepare_project(project, ["checkov"])
            (project / "Dockerfile").write_text("FROM\n", encoding="utf-8")
            native = subprocess.CompletedProcess([], 1, stdout=REPORT_TEXT, stderr="")
            with (
                patch("flican.cli.main.shutil.which", return_value="/fake/docker"),
                patch("flican.cli.main.run_checkov", return_value=native),
            ):
                result = CliRunner().invoke(app, ["scan", str(project)])
            self.assertEqual(result.exit_code, 2, result.output)
            self.assertIn("did not report checks for Dockerfile(s): Dockerfile", result.stderr)
            self.assert_failed_journal(project)

    def test_dockerfile_inventory_respects_exclusions_and_old_reports(self):
        with TemporaryDirectory() as directory:
            project = Path(directory)
            prepare_project(project, ["checkov"], "critical")
            config = project / "flican.yaml"
            config.write_text(config.read_text().replace("exclude: []", "exclude: [ignored]"))
            for name in ("ignored", ".flican"):
                folder = project / name
                folder.mkdir()
                (folder / "Dockerfile").write_text("FROM\n")
            native = subprocess.CompletedProcess([], 1, stdout=REPORT_TEXT, stderr="")
            with (
                patch("flican.cli.main.shutil.which", return_value="/fake/docker"),
                patch("flican.cli.main.run_checkov", return_value=native),
            ):
                result = CliRunner().invoke(app, ["scan", str(project)])
            self.assertEqual(result.exit_code, 0, result.output)
            path = next(project.glob(".flican/runs/*/reports/findings.json"))
            report = json.loads(path.read_text())
            details = report["coverage"]["checkov"]["frameworks"]["dockerfile"]
            self.assertEqual(details["files_expected"], 0)
            self.assertEqual(details["status"], "not_reported")

    def test_disabled_checkov_does_not_run_or_require_its_image(self):
        with TemporaryDirectory() as directory:
            project = Path(directory)
            prepare_project(project, ["gitleaks"])
            with (
                patch("flican.cli.main.shutil.which", return_value="/fake/docker"),
                patch("flican.cli.main.run_checkov") as checkov_mock,
                patch("flican.cli.main.run_gitleaks", return_value=subprocess.CompletedProcess([], 0, stdout="[]", stderr="")),
            ):
                result = CliRunner().invoke(app, ["scan", str(project)])
            self.assertEqual(result.exit_code, 0, result.output)
            checkov_mock.assert_not_called()
            self.assertIn("IaC scan: disabled", result.stdout)
            self.assertEqual(list(project.glob(".flican/runs/*/reports/checkov.json")), [])

    def test_native_success_with_parsing_errors_returns_2_without_success_report(self):
        report = json.loads(REPORT_TEXT)
        report["results"]["parsing_errors"] = ["/src/main.tf"]
        report["summary"]["parsing_errors"] = 1
        native = subprocess.CompletedProcess([], 0, stdout=json.dumps(report), stderr="")
        with TemporaryDirectory() as directory:
            project = Path(directory)
            prepare_project(project, ["checkov"])
            with (
                patch("flican.cli.main.shutil.which", return_value="/fake/docker"),
                patch("flican.cli.main.run_checkov", return_value=native),
            ):
                result = CliRunner().invoke(app, ["scan", str(project)])
            self.assertEqual(result.exit_code, 2, result.output)
            self.assertIn("Terraform parsing errors", result.stderr)
            self.assert_failed_journal(project)

    def test_operational_failures_are_not_policy_failures(self):
        for native in (
            subprocess.CompletedProcess([], 125, stdout="", stderr="image missing"),
            subprocess.CompletedProcess([], 0, stdout="not JSON", stderr=""),
        ):
            with self.subTest(code=native.returncode), TemporaryDirectory() as directory:
                project = Path(directory)
                prepare_project(project, ["checkov"])
                with (
                    patch("flican.cli.main.shutil.which", return_value="/fake/docker"),
                    patch("flican.cli.main.run_checkov", return_value=native),
                ):
                    result = CliRunner().invoke(app, ["scan", str(project)])
                self.assertEqual(result.exit_code, 2, result.output)
                self.assert_failed_journal(project)

    def test_no_resources_and_suppressions_are_visible_in_coverage(self):
        base = json.loads(REPORT_TEXT)
        empty = dict(base["summary"], failed=0, resource_count=0)
        skipped = json.loads(REPORT_TEXT)
        record = skipped["results"]["failed_checks"].pop()
        record["check_result"] = {"result": "SKIPPED", "suppress_comment": "fixture"}
        skipped["results"]["skipped_checks"].append(record)
        skipped["summary"].update(failed=0, skipped=1)
        for report, status in ((empty, "no_resources"), (skipped, "partial")):
            with self.subTest(status=status), TemporaryDirectory() as directory:
                project = Path(directory)
                prepare_project(project, ["checkov"])
                native = subprocess.CompletedProcess([], 0, stdout=json.dumps(report), stderr="")
                with (
                    patch("flican.cli.main.shutil.which", return_value="/fake/docker"),
                    patch("flican.cli.main.run_checkov", return_value=native),
                ):
                    result = CliRunner().invoke(app, ["scan", str(project)])
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertIn(f"IaC coverage: {status}", result.stdout)
                path = next(project.glob(".flican/runs/*/reports/findings.json"))
                normalized = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(normalized["coverage"]["checkov"]["status"], status)
                self.assertEqual(normalized["findings"], [])
