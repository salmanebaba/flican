import json
import subprocess
import unittest

from flican.adapters.trivy import (normalize_trivy_finding,parse_trivy_report,)
from flican.core.models import Finding, Severity

VULNERABILITY = {"VulnerabilityID": "CVE-2024-35195"}


def make_result(
    code: int,
    report: dict,
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["trivy", "fs"],
        returncode=code,
        stdout=json.dumps(report),
        stderr=stderr,
    )


class TestTrivyReport(unittest.TestCase):
    def test_accepts_empty_report_with_info_logs(self):
        result = make_result(
            0,
            {"SchemaVersion": 2},
            stderr="2026-10-30T12:00:00Z INFO Scan completed\n",
        )

        self.assertEqual(parse_trivy_report(result), [])

    def test_preserves_target_for_each_vulnerability(self):
        report = {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [VULNERABILITY],
                },
                {
                    "Target": "service/requirements.txt",
                    "Vulnerabilities": [VULNERABILITY],
                },
            ],
        }

        self.assertEqual(
            parse_trivy_report(make_result(10, report)),
            [
                {
                    "Target": "requirements.txt",
                    "Vulnerability": VULNERABILITY,
                },
                {
                    "Target": "service/requirements.txt",
                    "Vulnerability": VULNERABILITY,
                },
            ],
        )

    def test_rejects_exit_code_mismatch(self):
        positive_report = {
            "SchemaVersion": 2,
            "Results": [{
                "Target": "requirements.txt",
                "Vulnerabilities": [VULNERABILITY],
            }],
        }
        cases = [
            (0, positive_report),
            (10, {"SchemaVersion": 2}),
        ]

        for code, report in cases:
            with self.subTest(code=code):
                with self.assertRaisesRegex(ValueError, "does not match"):
                    parse_trivy_report(make_result(code, report))

    def test_rejects_diagnostics(self):
        for level in ("WARN", "ERROR"):
            with self.subTest(level=level):
                result = make_result(
                    0,
                    {"SchemaVersion": 2},
                    stderr=f"2026-10-30T12:00:00Z {level} Cannot scan file\n",
                )

                with self.assertRaisesRegex(RuntimeError, "diagnostics"):
                    parse_trivy_report(result)

    def test_rejects_scanner_failure(self):
        result = make_result(1, {"SchemaVersion": 2})

        with self.assertRaisesRegex(RuntimeError, "exit code 1"):
            parse_trivy_report(result)

    def test_accepts_unavailable_python_license_metadata(self):
        result = make_result(
            0,
            {"SchemaVersion": 2},
            stderr=(
                "2026-10-30T09:27:52Z\tWARN\t"
                "[pip] Unable to find python `site-packages` directory. "
                "License detection is skipped.\t"
                'err="unable to find path to Python executable"\n'
            ),
        )

        self.assertEqual(parse_trivy_report(result), [])



class TestTrivyNormalization(unittest.TestCase):
    def setUp(self):
        self.raw = {
            "Target": "/src/requirements.txt",
            "Vulnerability": {
                "VulnerabilityID": "TEST-001",
                "PkgName": "demo-package",
                "InstalledVersion": "1.0.0",
                "Severity": "HIGH",
                "Title": "  Vulnerable demo dependency  ",
                "FixedVersion": "1.1.0",
            },
        }

    def test_normalizes_package_details(self):
        finding = normalize_trivy_finding(self.raw)

        self.assertEqual(
            finding,
            Finding(
                scanner="trivy",
                rule_id="TEST-001",
                description="Vulnerable demo dependency",
                severity=Severity.HIGH,
                file_path="requirements.txt",
                line=None,
                package_name="demo-package",
                package_version="1.0.0",
                fixed_version="1.1.0",
            ),
        )

    def test_accepts_missing_optional_metadata(self):
        vulnerability = self.raw["Vulnerability"]
        del vulnerability["Title"]
        del vulnerability["FixedVersion"]

        finding = normalize_trivy_finding(self.raw)

        self.assertEqual(
            finding.description,
            "demo-package 1.0.0: TEST-001",
        )
        self.assertIsNone(finding.fixed_version)

    def test_rejects_unknown_severity(self):
        self.raw["Vulnerability"]["Severity"] = "UNKNOWN"

        with self.assertRaisesRegex(
            ValueError,
            "Unsupported Trivy severity",
        ):
            normalize_trivy_finding(self.raw)

    def test_rejects_invalid_required_fields(self):
        fields = (
            "VulnerabilityID",
            "PkgName",
            "InstalledVersion",
            "Severity",
        )

        for field in fields:
            for value in (None, "", "   ", 42):
                with self.subTest(field=field, value=value):
                    raw = {
                        **self.raw,
                        "Vulnerability": {
                            **self.raw["Vulnerability"],
                            field: value,
                        },
                    }

                    with self.assertRaisesRegex(
                        ValueError,
                        f"invalid {field}",
                    ):
                        normalize_trivy_finding(raw)

    def test_rejects_paths_outside_snapshot(self):
        paths = (
            "/etc/passwd",
            "../requirements.txt",
            "/src/../requirements.txt",
        )

        for path in paths:
            with self.subTest(path=path):
                raw = {**self.raw, "Target": path}

                with self.assertRaises(ValueError):
                    normalize_trivy_finding(raw)