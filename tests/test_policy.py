import unittest

from flican.core.models import Finding, Severity
from flican.core.policy import should_fail


def make_finding(severity: Severity) -> Finding:
    return Finding(
        scanner="test",
        rule_id="test-rule",
        description="Test finding",
        severity=severity,
        file_path="app.py",
        line=1,
    )


class TestPolicy(unittest.TestCase):
    def test_threshold_decisions(self) -> None:
        cases = [
            ("empty", [], Severity.HIGH, False),
            (
                "below",
                [Severity.INFO, Severity.LOW, Severity.MEDIUM],
                Severity.HIGH,
                False,
            ),
            ("boundary", [Severity.HIGH], Severity.HIGH, True),
            ("above", [Severity.CRITICAL], Severity.HIGH, True),
            ("mixed", [Severity.LOW, Severity.CRITICAL], Severity.HIGH, True),
            ("stricter", [Severity.HIGH], Severity.CRITICAL, False),
        ]

        for label, severities, fail_on, expected in cases:
            with self.subTest(case=label):
                findings = [
                    make_finding(severity)
                    for severity in severities
                ]

                self.assertEqual(
                    should_fail(findings, fail_on),
                    expected,
                )