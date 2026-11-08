import json
import subprocess
import unittest

from flican.adapters.semgrep import (normalize_semgrep_finding,parse_semgrep_report,)
from flican.core.models import Finding, Severity


FINDING = {
    "check_id": "flican.python.eval",
    "path": "/src/app.py",
}


def make_result(
    returncode: int,
    report: dict,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["semgrep", "scan"],
        returncode=returncode,
        stdout=json.dumps(report),
        stderr="",
    )


class TestSemgrepReport(unittest.TestCase):
    def test_accepts_valid_reports(self):
        cases = [
            (0, []),
            (1, [FINDING]),
        ]

        for code, findings in cases:
            with self.subTest(code=code):
                result = make_result(
                    code,
                    {"results": findings, "errors": []},
                )

                self.assertEqual(
                    parse_semgrep_report(result),
                    findings,
                )

    def test_rejects_scan_errors(self):
        result = make_result(
            0,
            {
                "results": [],
                "errors": [{"message": "Cannot parse file."}],
            },
        )

        with self.assertRaisesRegex(RuntimeError, "reported scan errors"):
            parse_semgrep_report(result)

    def test_rejects_exit_code_mismatch(self):
        cases = [
            (0, [FINDING]),
            (1, []),
        ]

        for code, findings in cases:
            with self.subTest(code=code):
                result = make_result(
                    code,
                    {"results": findings, "errors": []},
                )

                with self.assertRaisesRegex(ValueError, "does not match"):
                    parse_semgrep_report(result)

    def test_rejects_scanner_failure(self):
        result = make_result(
            2,
            {"results": [], "errors": []},
        )

        with self.assertRaisesRegex(RuntimeError, "exit code 2"):
            parse_semgrep_report(result)

def make_semgrep_finding() -> dict:
    return {
        "check_id": "flican.python.eval",
        "path": "/src/app.py",
        "start": {"line": 2},
        "extra": {
            "message": "  Review eval() usage.  ",
            "severity": "HIGH",
        },
    }


class TestSemgrepNormalization(unittest.TestCase):
    def test_preserves_columns_and_rejects_invalid_values(self):
        raw = make_semgrep_finding()
        raw["start"]["col"] = 12
        self.assertEqual(normalize_semgrep_finding(raw).column, 12)
        for value in (True, -1, 0, "12"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                raw["start"]["col"] = value
                normalize_semgrep_finding(raw)

    def test_normalizes_findings(self):
        cases = [
            ("HIGH", Severity.HIGH),
            ("ERROR", Severity.HIGH),
            ("WARNING", Severity.MEDIUM),
            ("INFO", Severity.LOW),
            ("CRITICAL", Severity.CRITICAL),
        ]

        for raw_severity, expected_severity in cases:
            with self.subTest(severity=raw_severity):
                raw = make_semgrep_finding()
                raw["extra"]["severity"] = raw_severity

                self.assertEqual(
                    normalize_semgrep_finding(raw),
                    Finding(
                        scanner="semgrep",
                        rule_id="flican.python.eval",
                        description="Review eval() usage.",
                        severity=expected_severity,
                        file_path="app.py",
                        line=2,
                    ),
                )

    def test_rejects_invalid_lines(self):
        for line in (0, -1, True, "2", None):
            with self.subTest(line=line):
                raw = make_semgrep_finding()
                raw["start"]["line"] = line

                with self.assertRaisesRegex(ValueError, "positive integer"):
                    normalize_semgrep_finding(raw)

    def test_rejects_unknown_severity(self):
        raw = make_semgrep_finding()
        raw["extra"]["severity"] = "URGENT"

        with self.assertRaisesRegex(ValueError, "invalid severity"):
            normalize_semgrep_finding(raw)
