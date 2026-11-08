"""Real, offline engine checks; opt in with FLICAN_CHECKOV_DOCKER_TESTS=1."""

import json
import os
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from typer.testing import CliRunner

from flican.adapters.checkov import (
    is_checkov_dockerfile,
    normalize_checkov_finding,
    parse_checkov_report,
    run_checkov,
)
from flican.cli.main import app
from state_support import isolated_state

FIXTURES = Path(__file__).parent / "fixtures" / "checkov"


@unittest.skipUnless(
    os.environ.get("FLICAN_CHECKOV_DOCKER_TESTS") == "1",
    "Set FLICAN_CHECKOV_DOCKER_TESTS=1 to run the pinned Checkov image.",
)
class TestCheckovDocker(unittest.TestCase):
    def setUp(self):
        isolated_state(self)

    @classmethod
    def setUpClass(cls):
        cls.docker = shutil.which("docker")
        if cls.docker is None:
            raise RuntimeError("Docker is required for the requested integration tests.")

    def test_vulnerable_and_corrected_terraform(self):
        failed_result = run_checkov(self.docker, FIXTURES / "vulnerable")
        self.assertEqual(failed_result.returncode, 1, failed_result.stderr)
        failed = parse_checkov_report(failed_result)
        self.assertEqual(
            {raw["check_id"] for raw in failed.findings},
            {"CKV_AWS_53", "CKV_AWS_54", "CKV_AWS_55", "CKV_AWS_56"},
        )
        self.assertEqual(failed.coverage["resource_count"], 1)
        for raw in failed.findings:
            finding = normalize_checkov_finding(raw)
            self.assertEqual(finding.file_path, "main.tf")
            self.assertEqual(finding.severity_source, "flican_policy")

        corrected_result = run_checkov(self.docker, FIXTURES / "corrected")
        self.assertEqual(corrected_result.returncode, 0, corrected_result.stderr)
        corrected = parse_checkov_report(corrected_result)
        self.assertEqual(corrected.findings, [])
        self.assertEqual(corrected.coverage["passed"], 4)

    def test_native_zero_with_invalid_terraform_is_rejected(self):
        result = run_checkov(self.docker, FIXTURES / "invalid")
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaisesRegex(RuntimeError, "parsing errors"):
            parse_checkov_report(result)

    def test_empty_project_is_reported_without_coverage(self):
        with TemporaryDirectory() as directory:
            result = run_checkov(self.docker, Path(directory))
        parsed = parse_checkov_report(result)
        self.assertEqual(parsed.findings, [])
        self.assertEqual(parsed.coverage["status"], "no_resources")
        self.assertEqual(parsed.coverage["resource_count"], 0)

    def test_project_config_cannot_change_checks_or_load_python(self):
        for filename in (".checkov.yaml", ".checkov.yml"):
            with self.subTest(filename=filename), TemporaryDirectory() as directory:
                source = Path(directory)
                shutil.copyfile(FIXTURES / "vulnerable" / "main.tf", source / "main.tf")
                shutil.copyfile(
                    FIXTURES / "dockerfile" / "vulnerable" / "Dockerfile", source / "Dockerfile",
                )
                (source / filename).write_text(
                    "framework: [kubernetes]\nsoft-fail: true\n"
                    "external-checks-dir: [/src/custom-checks]\n",
                    encoding="utf-8",
                )
                checks = source / "custom-checks"
                checks.mkdir()
                (checks / "check.py").write_text(
                    'raise RuntimeError("FLICAN_UNTRUSTED_CHECK_EXECUTED")\n',
                    encoding="utf-8",
                )
                result = run_checkov(self.docker, source)
                self.assertNotIn("FLICAN_UNTRUSTED_CHECK_EXECUTED", result.stderr)
                self.assertNotIn("FLICAN_UNTRUSTED_CHECK_EXECUTED", result.stdout)
                self.assertEqual(result.returncode, 1, result.stderr)
                parsed = parse_checkov_report(result)
                self.assertEqual(parsed.coverage["failed"], 7)
                self.assertEqual(parsed.coverage["framework"], "multiple")
                self.assertEqual(parsed.coverage["frameworks"]["terraform"]["failed"], 4)
                self.assertEqual(parsed.coverage["frameworks"]["dockerfile"]["failed"], 3)

    def test_inline_suppression_is_visible_as_partial_coverage(self):
        with TemporaryDirectory() as directory:
            source = Path(directory)
            text = (FIXTURES / "vulnerable" / "main.tf").read_text(encoding="utf-8")
            text = text.replace(
                "  bucket",
                "  # checkov:skip=CKV_AWS_55: synthetic suppression test\n  bucket",
                1,
            )
            (source / "main.tf").write_text(text, encoding="utf-8")
            result = run_checkov(self.docker, source)
        parsed = parse_checkov_report(result)
        self.assertEqual(parsed.coverage["status"], "partial")
        self.assertEqual(parsed.coverage["skipped"], 1)
        self.assertEqual(len(parsed.findings), 3)

    def test_missing_native_profile_is_an_error(self):
        with patch(
            "flican.adapters.checkov.build_scan_arguments",
            return_value=["--directory=/src", "--config-file=/rules/missing.yaml"],
        ):
            result = run_checkov(self.docker, FIXTURES / "vulnerable")
        self.assertEqual(result.returncode, 2, result.stderr)
        with self.assertRaisesRegex(RuntimeError, "exit code 2"):
            parse_checkov_report(result)

    def test_resource_without_policies_has_explicit_coverage(self):
        with TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "main.tf").write_text(
                'resource "terraform_data" "example" {\n  input = "fixture"\n}\n',
                encoding="utf-8",
            )
            result = run_checkov(self.docker, source)
        parsed = parse_checkov_report(result)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(parsed.findings, [])
        self.assertIn(parsed.coverage["status"], ("no_resources", "no_checks"))

    def test_cli_applies_policy_to_real_engine_results(self):
        for threshold, expected_code in (("high", 1), ("critical", 0)):
            with self.subTest(threshold=threshold), TemporaryDirectory() as directory:
                source = Path(directory)
                shutil.copyfile(FIXTURES / "vulnerable" / "main.tf", source / "main.tf")
                (source / "flican.yaml").write_text(
                    "schema_version: 1\nproject:\n  name: checkov-real-cli\n  exclude: []\n"
                    f"scanners: [checkov]\npolicy:\n  fail_on: {threshold}\n",
                    encoding="utf-8",
                )
                result = CliRunner().invoke(app, ["scan", str(source)])
                self.assertEqual(result.exit_code, expected_code, result.output)
                self.assertIn("IaC findings: 4", result.stdout)
                report_path = next(source.glob(".flican/runs/*/reports/findings.json"))
                report = json.loads(report_path.read_text(encoding="utf-8"))
                self.assertEqual(len(report["findings"]), 4)
                self.assertEqual(report["gate"]["passed"], expected_code == 0)
                self.assertTrue(all(
                    item["severity_source"] == "flican_policy"
                    for item in report["findings"]
                ))

    def test_vulnerable_and_corrected_dockerfiles(self):
        for fixture, code, ids in (
            ("vulnerable", 1, {"CKV_DOCKER_1", "CKV_DOCKER_2", "CKV_DOCKER_3"}),
            ("corrected", 0, set()),
        ):
            with self.subTest(fixture=fixture):
                result = run_checkov(self.docker, FIXTURES / "dockerfile" / fixture)
                self.assertEqual(result.returncode, code, result.stderr)
                parsed = parse_checkov_report(result, expected_dockerfiles={"Dockerfile"})
                self.assertEqual({raw["check_id"] for raw in parsed.findings}, ids)
                details = parsed.coverage["frameworks"]["dockerfile"]
                self.assertEqual(details["files_reported"], 1)
                self.assertEqual(details["passed"], 2 if code else 5)
                for raw in parsed.findings:
                    finding = normalize_checkov_finding(raw)
                    self.assertEqual(finding.framework, "dockerfile")
                    self.assertEqual(finding.file_path, "Dockerfile")
                    self.assertEqual(finding.severity_source, "flican_policy")

    def test_mixed_cli_preserves_both_frameworks_and_applies_the_policy(self):
        for threshold, code in (("high", 1), ("critical", 0)):
            with self.subTest(threshold=threshold), TemporaryDirectory() as directory:
                source = Path(directory)
                shutil.copyfile(FIXTURES / "vulnerable" / "main.tf", source / "main.tf")
                shutil.copyfile(
                    FIXTURES / "dockerfile" / "vulnerable" / "Dockerfile", source / "Dockerfile",
                )
                (source / "flican.yaml").write_text(
                    "schema_version: 1\nproject:\n  name: mixed-real-cli\n  exclude: []\n"
                    f"scanners: [checkov]\npolicy:\n  fail_on: {threshold}\n",
                    encoding="utf-8",
                )
                result = CliRunner().invoke(app, ["scan", str(source)])
                self.assertEqual(result.exit_code, code, result.output)
                self.assertIn("IaC findings: 7", result.stdout)
                for framework in ("terraform", "dockerfile"):
                    self.assertIn(f"Checkov {framework}: completed", result.stdout)
                path = next(source.glob(".flican/runs/*/reports/findings.json"))
                report = json.loads(path.read_text())
                self.assertEqual(len(report["findings"]), 7)
                self.assertEqual(report["gate"]["passed"], code == 0)
                counts = report["coverage"]["checkov"]
                self.assertEqual(counts["resource_count"], 2)
                self.assertEqual(counts["frameworks"]["terraform"]["failed"], 4)
                self.assertEqual(counts["frameworks"]["dockerfile"]["failed"], 3)
                self.assertEqual({item["framework"] for item in report["findings"]},
                                 {"terraform", "dockerfile"})
                native = json.loads((path.parent / "checkov.json").read_text())
                self.assertIsInstance(native, list)
                self.assertEqual({item["check_type"] for item in native},
                                 {"terraform", "dockerfile"})

    def test_silently_skipped_dockerfiles_are_cli_errors(self):
        for other in ("none", "terraform", "dockerfile", "invalid_utf8"):
            with self.subTest(other=other), TemporaryDirectory() as directory:
                source = Path(directory)
                bad_name = "bad.Dockerfile" if other == "dockerfile" else "Dockerfile"
                (source / bad_name).write_bytes(b"\xff\xfe" if other == "invalid_utf8" else b"FROM\n")
                if other == "terraform":
                    shutil.copyfile(FIXTURES / "vulnerable" / "main.tf", source / "main.tf")
                elif other == "dockerfile":
                    shutil.copyfile(
                        FIXTURES / "dockerfile" / "corrected" / "Dockerfile", source / "Dockerfile",
                    )
                (source / "flican.yaml").write_text(
                    "schema_version: 1\nproject:\n  name: bad-dockerfile\n  exclude: []\n"
                    "scanners: [checkov]\npolicy:\n  fail_on: high\n",
                )
                result = CliRunner().invoke(app, ["scan", str(source)])
                self.assertEqual(result.exit_code, 2, result.output)
                self.assertIn(f"Dockerfile(s): {bad_name}", result.stderr)
                journal_path = next(source.glob(".flican/runs/*/run.json"))
                journal = json.loads(journal_path.read_text())
                self.assertEqual(journal["status"], "failed")
                self.assertEqual(journal["stages"][0]["status"], "failed")
                self.assertEqual(journal["exit_code"], 2)
                self.assertFalse((journal_path.parent / "manifest.json").exists())
                self.assertFalse((journal_path.parent / "reports/checkov.json").exists())

    def test_dockerfile_suppressions_still_prove_file_coverage(self):
        with TemporaryDirectory() as directory:
            source = Path(directory)
            header = "".join(
                f"# checkov:skip=CKV_DOCKER_{number}: synthetic suppression test\n"
                for number in (1, 2, 3, 7, 11)
            )
            text = (FIXTURES / "dockerfile" / "vulnerable" / "Dockerfile").read_text()
            (source / "Dockerfile").write_text(header + text)
            result = run_checkov(self.docker, source)
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = parse_checkov_report(result, expected_dockerfiles={"Dockerfile"})
        self.assertEqual(parsed.findings, [])
        self.assertEqual(parsed.coverage["status"], "partial")
        details = parsed.coverage["frameworks"]["dockerfile"]
        self.assertEqual(details["skipped"], 5)
        self.assertEqual(details["files_reported"], 1)

    def test_alternate_dockerfile_names_and_nested_paths(self):
        with TemporaryDirectory() as directory:
            source = Path(directory)
            folder = source / "containers"
            folder.mkdir()
            for filename in ("Dockerfile.dev", "worker.Dockerfile"):
                shutil.copyfile(
                    FIXTURES / "dockerfile" / "vulnerable" / "Dockerfile", folder / filename,
                )
            (folder / "Dockerfile.dockerignore").write_text("not a Dockerfile\n")
            expected = {
                path.relative_to(source).as_posix()
                for path in source.rglob("*") if path.is_file() and is_checkov_dockerfile(path.name)
            }
            result = run_checkov(self.docker, source)
        parsed = parse_checkov_report(result, expected_dockerfiles=expected)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(len(parsed.findings), 6)
        self.assertEqual(parsed.coverage["frameworks"]["dockerfile"]["files_reported"], 2)
        self.assertEqual({normalize_checkov_finding(raw).file_path for raw in parsed.findings}, expected)
