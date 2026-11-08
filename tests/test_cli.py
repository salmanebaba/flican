import unittest
import subprocess
import json


from unittest.mock import patch
from typer.testing import CliRunner
from flican.cli.main import app
from pathlib import Path
from tempfile import TemporaryDirectory
from state_support import isolated_state
from trivy_support import download_database, write_database

TRIVY_REPORT_TEXT = json.dumps({
    "SchemaVersion": 2,
    "Results": [
        {
            "Target": "/src/requirements.txt",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "TEST-001",
                    "PkgName": "demo-package",
                    "InstalledVersion": "1.0.0",
                    "Severity": "MEDIUM",
                    "Title": "Demo vulnerability",
                    "FixedVersion": "1.1.0",
                },
            ],
        },
    ],
})

class TestScanCommand(unittest.TestCase):

    def setUp(self):
        isolated_state(self)
        patcher = patch(
            "flican.cli.main.run_semgrep",
            return_value=subprocess.CompletedProcess(
                args=["docker", "run"],
                returncode=0,
                stdout=json.dumps({"results": [], "errors": []}),
                stderr="",
            ),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_discovery_error_returns_exit_code_2(self) -> None:
        runner = CliRunner()
        config = {
            "schema_version": 1,
            "project": {"name": "test-project", "exclude": []},
        }

        with (
            patch("flican.cli.main.load_config", return_value=config),
            patch(
                "flican.cli.main.discover_files",
                side_effect=PermissionError("Access denied for test"),
            ),
        ):
            result = runner.invoke(app, ["scan", "."])

        self.assertEqual(result.exit_code, 2)
        self.assertIn("Access denied for test", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_scan_uses_configured_exclusions(self) -> None:
        runner = CliRunner()

        with TemporaryDirectory() as directory:
            project = Path(directory)

            config_text = (
                "schema_version: 1\n"
                "project:\n"
                "  name: test-project\n"
                "  exclude: [ignored]\n"
            )

            (project / "flican.yaml").write_text(
                config_text, encoding="utf-8"
            )
            (project / "app.py").write_text("", encoding="utf-8")

            ignored = project / "ignored"
            ignored.mkdir()
            (ignored / "hidden.js").write_text("", encoding="utf-8")

            reports = project / ".flican" / "runs" / "previous" / "reports"
            reports.mkdir(parents=True)
            existing_report = reports / "findings.json"
            existing_report.write_text('{"findings": []}\n', encoding="utf-8")

            def scan_snapshot(docker_path, snapshot):
                self.assertFalse((snapshot / ".flican").exists())
                return subprocess.CompletedProcess(
                    args=["docker", "run"], returncode=0, stdout="[]", stderr=""
                )

            with (
                patch(
                    "flican.cli.main.shutil.which",
                    return_value="/fake/docker",
                ),
                patch(
                    "flican.cli.main.run_gitleaks",
                    side_effect=scan_snapshot,
                ),
            ):
                result = runner.invoke(app, ["scan", str(project)])

            self.assertEqual(existing_report.read_text(), '{"findings": []}\n')

        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Files found: 2", result.stdout)
        self.assertIn("Languages: Python", result.stdout)

    def test_findings_return_1_and_save_report(self) -> None:
        runner = CliRunner()
        report_text = '[{"RuleID":"test-rule","File":"/src/app.py"}]'

        with TemporaryDirectory() as directory:
            project = Path(directory)

            (project / "flican.yaml").write_text(
                "schema_version: 1\n"
                "project:\n"
                "  name: test-project\n"
                "  exclude: []\n",
                encoding="utf-8",
            )
            (project / "app.py").write_text("", encoding="utf-8")

            with (
                patch(
                    "flican.cli.main.shutil.which",
                    return_value="/fake/docker",
                ),
                patch(
                    "flican.cli.main.run_gitleaks",
                    return_value=subprocess.CompletedProcess(
                        args=["docker", "run"],
                        returncode=10,
                        stdout=report_text,
                        stderr="12:00PM WRN leaks found: 1\n",
                    ),
                ),
            ):
                result = runner.invoke(app, ["scan", str(project)])

            self.assertEqual(result.exit_code, 1, result.output)
            self.assertIn("Secret findings: 1", result.stdout)
            self.assertIn("Gate: FAIL", result.stdout)

            reports = list(
                project.glob(".flican/runs/*/reports/gitleaks.json")
            )
            self.assertEqual(len(reports), 1)
            self.assertEqual(
                reports[0].read_text(encoding="utf-8"),
                report_text,
            )

            normalized_path = reports[0].parent / "findings.json"
            normalized = json.loads(
                normalized_path.read_text(encoding="utf-8")
            )

            self.assertEqual(normalized["schema_version"], 1)
            self.assertEqual(len(normalized["findings"]), 1)
            self.assertEqual(
                normalized["findings"][0]["file_path"],
                "app.py",
            )
            self.assertEqual(
                normalized["gate"],
                {"fail_on": "high", "passed": False},
            )
            self.assertIsNone(normalized["findings"][0]["line"])

    def test_scanner_diagnostics_return_2_without_report(self) -> None:
        runner = CliRunner()
        report_text = "[]"

        with TemporaryDirectory() as directory:
            project = Path(directory)

            (project / "flican.yaml").write_text(
                "schema_version: 1\n"
                "project:\n"
                "  name: test-project\n"
                "  exclude: []\n",
                encoding="utf-8",
            )
            (project / "app.py").write_text("", encoding="utf-8")

            with (
                patch(
                    "flican.cli.main.shutil.which",
                    return_value="/fake/docker",
                ),
                patch(
                    "flican.cli.main.run_gitleaks",
                    return_value=subprocess.CompletedProcess(
                        args=["docker", "run"],
                        returncode=0,
                        stdout=report_text,
                        stderr="12:00PM WRN skipping file: permission denied\n",
                    ),
                ),
            ):
                result = runner.invoke(app, ["scan", str(project)])

            self.assertEqual(result.exit_code, 2, result.output)
            self.assertIn(
                "Scanner emitted diagnostics",
                result.stderr,
            )
            self.assertEqual(result.stdout, "")

            reports = list(
                project.glob(".flican/runs/*/reports/gitleaks.json")
            )
            self.assertEqual(reports, [])

    def test_findings_below_threshold_return_0(self) -> None:
        runner = CliRunner()
        report_text = '[{"RuleID":"test-rule","File":"/src/app.py"}]'

        with TemporaryDirectory() as directory:
            project = Path(directory)

            (project / "flican.yaml").write_text(
                "schema_version: 1\n"
                "project:\n"
                "  name: test-project\n"
                "  exclude: []\n"
                "policy:\n"
                "  fail_on: critical\n",
                encoding="utf-8",
            )
            (project / "app.py").write_text("", encoding="utf-8")

            with (
                patch(
                    "flican.cli.main.shutil.which",
                    return_value="/fake/docker",
                ),
                patch(
                    "flican.cli.main.run_gitleaks",
                    return_value=subprocess.CompletedProcess(
                        args=["docker", "run"],
                        returncode=10,
                        stdout=report_text,
                        stderr="12:00PM WRN leaks found: 1\n",
                    ),
                ),
            ):
                result = runner.invoke(app, ["scan", str(project)])

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("Gate: PASS", result.stdout)

            reports = list(
                project.glob(".flican/runs/*/reports/gitleaks.json")
            )
            self.assertEqual(len(reports), 1)
            self.assertEqual(
                reports[0].read_text(encoding="utf-8"),
                report_text,
            )

            normalized_path = reports[0].parent / "findings.json"
            normalized = json.loads(
                normalized_path.read_text(encoding="utf-8")
            )

            self.assertEqual(normalized["schema_version"], 1)
            self.assertEqual(len(normalized["findings"]), 1)
            self.assertEqual(
                normalized["findings"][0]["file_path"],
                "app.py",
            )
            self.assertEqual(
                normalized["gate"],
                {"fail_on": "critical", "passed": True},
            )
            self.assertIsNone(normalized["findings"][0]["line"])

    def test_sast_findings_return_1_and_save_report(self):
        runner = CliRunner()
        raw_finding = {
            "check_id": "flican.python.eval",
            "path": "/src/app.py",
            "start": {"line": 2},
            "extra": {
                "message": "Review eval() usage.",
                "severity": "HIGH",
            },
        }
        report_text = json.dumps({
            "results": [raw_finding],
            "errors": [],
        })

        gitleaks_result = subprocess.CompletedProcess(
            args=["docker", "run"],
            returncode=0,
            stdout="[]",
            stderr="",
        )
        semgrep_result = subprocess.CompletedProcess(
            args=["docker", "run"],
            returncode=1,
            stdout=report_text,
            stderr="",
        )

        with TemporaryDirectory() as directory:
            project = Path(directory)

            (project / "flican.yaml").write_text(
                "schema_version: 1\n"
                "project:\n"
                "  name: test-project\n"
                "  exclude: []\n",
                encoding="utf-8",
            )
            (project / "app.py").write_text(
                "user_input = input()\n"
                "result = eval(user_input)\n",
                encoding="utf-8",
            )

            with (
                patch(
                    "flican.cli.main.shutil.which",
                    return_value="/fake/docker",
                ),
                patch(
                    "flican.cli.main.run_gitleaks",
                    return_value=gitleaks_result,
                ),
                patch(
                    "flican.cli.main.run_semgrep",
                    return_value=semgrep_result,
                ),
            ):
                result = runner.invoke(app, ["scan", str(project)])

            self.assertEqual(result.exit_code, 1, result.output)
            self.assertIn("Secret findings: 0", result.stdout)
            self.assertIn("SAST findings: 1", result.stdout)
            self.assertIn("Total findings: 1", result.stdout)
            self.assertIn("Gate: FAIL", result.stdout)

            reports = list(
                project.glob(".flican/runs/*/reports/semgrep.json")
            )
            self.assertEqual(len(reports), 1)
            self.assertEqual(
                reports[0].read_text(encoding="utf-8"),
                report_text,
            )

            normalized_path = reports[0].parent / "findings.json"
            normalized = json.loads(
                normalized_path.read_text(encoding="utf-8")
            )

            self.assertEqual(len(normalized["findings"]), 1)
            self.assertEqual(
                normalized["findings"][0]["scanner"],
                "semgrep",
            )
            self.assertEqual(
                normalized["gate"],
                {"fail_on": "high", "passed": False},
            )

    def test_disabled_semgrep_is_not_run(self):
        runner = CliRunner()

        with TemporaryDirectory() as directory:
            project = Path(directory)

            (project / "flican.yaml").write_text(
                "schema_version: 1\n"
                "project:\n"
                "  name: test-project\n"
                "  exclude: []\n"
                "scanners: [gitleaks]\n",
                encoding="utf-8",
            )
            (project / "app.py").write_text(
                'print("hello")\n',
                encoding="utf-8",
            )

            with (
                patch(
                    "flican.cli.main.shutil.which",
                    return_value="/fake/docker",
                ),
                patch(
                    "flican.cli.main.run_gitleaks",
                    return_value=subprocess.CompletedProcess(
                        args=["docker", "run"],
                        returncode=0,
                        stdout="[]",
                        stderr="",
                    ),
                ) as gitleaks_mock,
                patch(
                    "flican.cli.main.run_semgrep",
                ) as semgrep_mock,
            ):
                result = runner.invoke(app, ["scan", str(project)])

            self.assertEqual(result.exit_code, 0, result.output)
            gitleaks_mock.assert_called_once()
            scanned_snapshot = gitleaks_mock.call_args.args[1]
            self.assertFalse(scanned_snapshot.exists())
            semgrep_mock.assert_not_called()

            self.assertIn("Secret findings: 0", result.stdout)
            self.assertIn("SAST scan: disabled", result.stdout)

            reports = list(
                project.glob(".flican/runs/*/reports/gitleaks.json")
            )
            self.assertEqual(len(reports), 1)
            self.assertFalse(
                (reports[0].parent / "semgrep.json").exists()
            )

            normalized_path = reports[0].parent / "findings.json"
            normalized = json.loads(
                normalized_path.read_text(encoding="utf-8")
            )

            self.assertEqual(
                normalized["scanners"],
                ["gitleaks"],
            )

    def test_disabled_gitleaks_is_not_run(self):
        runner = CliRunner()

        with TemporaryDirectory() as directory:
            project = Path(directory)

            (project / "flican.yaml").write_text(
                "schema_version: 1\n"
                "project:\n"
                "  name: test-project\n"
                "  exclude: []\n"
                "scanners: [semgrep]\n",
                encoding="utf-8",
            )
            (project / "app.py").write_text(
                'print("hello")\n',
                encoding="utf-8",
            )

            with (
                patch(
                    "flican.cli.main.shutil.which",
                    return_value="/fake/docker",
                ),
                patch(
                    "flican.cli.main.run_gitleaks",
                ) as gitleaks_mock,
                patch(
                    "flican.cli.main.run_semgrep",
                    return_value=subprocess.CompletedProcess(
                        args=["docker", "run"],
                        returncode=0,
                        stdout=json.dumps({
                            "results": [],
                            "errors": [],
                        }),
                        stderr="",
                    ),
                ) as semgrep_mock,
            ):
                result = runner.invoke(app, ["scan", str(project)])

            self.assertEqual(result.exit_code, 0, result.output)
            gitleaks_mock.assert_not_called()
            semgrep_mock.assert_called_once()

            self.assertIn("Secrets scan: disabled", result.stdout)
            self.assertIn("SAST findings: 0", result.stdout)

            reports = list(
                project.glob(".flican/runs/*/reports/semgrep.json")
            )
            self.assertEqual(len(reports), 1)
            self.assertFalse(
                (reports[0].parent / "gitleaks.json").exists()
            )

            normalized_path = reports[0].parent / "findings.json"
            normalized = json.loads(
                normalized_path.read_text(encoding="utf-8")
            )

            self.assertEqual(
                normalized["scanners"],
                ["semgrep"],
            )

    def test_trivy_uses_default_cache_directory(self):
        runner = CliRunner()

        with TemporaryDirectory() as directory:
            project = Path(directory)

            (project / "flican.yaml").write_text(
                "schema_version: 1\n"
                "project:\n"
                "  name: test-project\n"
                "  exclude: []\n"
                "scanners: [trivy]\n",
                encoding="utf-8",
            )

            with (
                patch(
                    "flican.cli.main.shutil.which",
                    return_value="/fake/docker",
                ),
                patch(
                    "flican.cli.main.run_trivy",
                    return_value=subprocess.CompletedProcess(
                        [], 0, stdout='{"SchemaVersion":2,"Results":[]}', stderr="",
                    ),
                ) as trivy_mock,
                patch.dict("os.environ", {"XDG_CACHE_HOME": str(project / "cache")}),
            ):
                write_database(project / "cache/flican/trivy")
                result = runner.invoke(
                    app,
                    ["scan", str(project)],
                )

            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(trivy_mock.call_args.args[2], project / "cache/flican/trivy")
            self.assertTrue((project / "cache/flican/trivy/db/trivy.db").is_file())

    def test_trivy_findings_follow_policy_and_save_reports(self):
        runner = CliRunner()
        trivy_result = subprocess.CompletedProcess(
            args=["docker", "run"],
            returncode=10,
            stdout=TRIVY_REPORT_TEXT,
            stderr="",
        )

        cases = [
            ("high", 0, True),
            ("medium", 1, False),
        ]

        for threshold, expected_code, passed in cases:
            with self.subTest(threshold=threshold), TemporaryDirectory() as directory:
                project = Path(directory) / "project"
                project.mkdir()
                cache = Path(directory) / "cache"
                cache.mkdir()
                write_database(cache)

                (project / "flican.yaml").write_text(
                    "schema_version: 1\n"
                    "project:\n"
                    "  name: test-project\n"
                    "  exclude: []\n"
                    "scanners: [trivy]\n"
                    f"policy:\n  fail_on: {threshold}\n",
                    encoding="utf-8",
                )

                with (
                    patch(
                        "flican.cli.main.shutil.which",
                        return_value="/fake/docker",
                    ),
                    patch(
                        "flican.cli.main.run_trivy",
                        return_value=trivy_result,
                    ) as trivy_mock,
                ):
                    result = runner.invoke(
                        app,
                        [
                            "scan", str(project),
                            "--trivy-cache-dir", str(cache),
                        ],
                    )

                self.assertEqual(
                    result.exit_code, expected_code, result.output
                )
                self.assertIn("SCA findings: 1", result.stdout)
                trivy_mock.assert_called_once()
                self.assertEqual(
                    trivy_mock.call_args.args[2], cache.resolve()
                )

                reports = list(
                    project.glob(".flican/runs/*/reports/trivy.json")
                )
                self.assertEqual(len(reports), 1)
                self.assertEqual(
                    reports[0].read_text(encoding="utf-8"),
                    TRIVY_REPORT_TEXT,
                )

                normalized = json.loads(
                    (reports[0].parent / "findings.json").read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(
                    normalized["gate"],
                    {"fail_on": threshold, "passed": passed},
                )
                self.assertEqual(
                    normalized["findings"][0]["package_name"],
                    "demo-package",
                )


class TestDatabaseUpdateCommand(unittest.TestCase):
    def test_update_prepares_database_in_a_staging_directory(self):
        runner = CliRunner()

        with TemporaryDirectory() as directory:
            cache = Path(directory) / "cache"

            with (
                patch(
                    "flican.cli.main.shutil.which",
                    return_value="/fake/docker",
                ),
                patch(
                    "flican.cli.main.run_trivy_db_update",
                    side_effect=download_database,
                ) as update_mock,
            ):
                result = runner.invoke(
                    app,
                    ["db", "update", "--cache-dir", str(cache)],
                )

            self.assertEqual(result.exit_code, 0, result.output)
            update_mock.assert_called_once()
            self.assertEqual(update_mock.call_args.args[0], "/fake/docker")
            self.assertEqual(update_mock.call_args.args[1].parent, cache.resolve())
            self.assertTrue((cache / "db/trivy.db").is_file())
            self.assertIn(
                f"Trivy database ready: {cache / 'db'}",
                result.stdout,
            )
            self.assertIn("Preparing the missing or outdated Trivy database", result.stdout)

    def test_failed_update_returns_2_and_displays_diagnostics(self):
        runner = CliRunner()
        update_result = subprocess.CompletedProcess(
            args=["docker", "run"],
            returncode=1,
            stdout="",
            stderr="Cannot download vulnerability database\n",
        )

        with TemporaryDirectory() as directory:
            cache = Path(directory) / "cache"

            with (
                patch(
                    "flican.cli.main.shutil.which",
                    return_value="/fake/docker",
                ),
                patch(
                    "flican.cli.main.run_trivy_db_update",
                    return_value=update_result,
                ),
            ):
                result = runner.invoke(
                    app,
                    ["db", "update", "--cache-dir", str(cache)],
                )

            self.assertEqual(result.exit_code, 2, result.output)
            self.assertIn(
                "Cannot download vulnerability database",
                result.stderr,
            )
            self.assertIn(
                "Trivy exited with code 1",
                result.stderr,
            )
            self.assertNotIn("Trivy database ready", result.stdout)

    def test_update_timeout_cleans_container_and_returns_2(self):
        runner = CliRunner()

        with TemporaryDirectory() as directory:
            cache = Path(directory) / "cache"

            with (
                patch(
                    "flican.cli.main.shutil.which",
                    return_value="/fake/docker",
                ),
                patch(
                    "flican.adapters.trivy.get_container_user",
                    return_value="1000:1000",
                ),
                patch(
                    "flican.adapters.trivy.subprocess.run",
                    side_effect=subprocess.TimeoutExpired(
                        cmd=["docker", "run"],
                        timeout=660,
                    ),
                ) as run_mock,
                patch(
                    "flican.adapters.trivy.remove_container",
                ) as remove_mock,
            ):
                result = runner.invoke(
                    app,
                    ["db", "update", "--cache-dir", str(cache)],
                )

            self.assertEqual(result.exit_code, 2, result.output)
            self.assertIn("timed out", result.stderr)
            self.assertNotIn("Trivy database ready", result.stdout)

            run_mock.assert_called_once()
            command = run_mock.call_args.args[0]
            container_name = command[command.index("--name") + 1]

            remove_mock.assert_called_once_with(
                "/fake/docker",
                container_name,
            )
