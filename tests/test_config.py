import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from flican.core.config import load_config
from flican.core.models import Severity


BASE_CONFIG = (
    "schema_version: 1\n"
    "project:\n"
    "  name: test-project\n"
    "  exclude: []\n"
)


def load_test_config(extra_yaml: str) -> dict:
    with TemporaryDirectory() as directory:
        config_path = Path(directory) / "flican.yaml"
        config_path.write_text(
            BASE_CONFIG + extra_yaml,
            encoding="utf-8",
        )
        return load_config(config_path)


class TestPolicyConfig(unittest.TestCase):
    def test_loads_threshold(self) -> None:
        cases = [
            ("default", "", Severity.HIGH),
            (
                "configured",
                "policy:\n  fail_on: critical\n",
                Severity.CRITICAL,
            ),
        ]

        for label, extra_yaml, expected in cases:
            with self.subTest(case=label):
                config = load_test_config(extra_yaml)
                self.assertEqual(config["policy"]["fail_on"], expected)

    def test_rejects_invalid_policy(self) -> None:
        cases = [
            ("unknown level", "policy:\n  fail_on: urgent\n"),
            ("wrong value type", "policy:\n  fail_on: true\n"),
            ("wrong section type", "policy: []\n"),
            ("misspelled setting", "policy:\n  fail_onn: low\n"),
            ("misspelled section", "polciy:\n  fail_on: low\n"),
        ]

        for label, extra_yaml in cases:
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    load_test_config(extra_yaml)

class TestScannerConfig(unittest.TestCase):
    def test_loads_scanners(self):
        cases = [
            ("default", "", ["gitleaks", "semgrep"]),
            ("gitleaks", "scanners: [gitleaks]\n", ["gitleaks"]),
            ("semgrep", "scanners: [semgrep]\n", ["semgrep"]),
            ("trivy", "scanners: [trivy]\n", ["trivy"]),
            ("checkov", "scanners: [checkov]\n", ["checkov"]),
            (
                "all scanners",
                "scanners: [gitleaks, semgrep, trivy, checkov]\n",
                ["gitleaks", "semgrep", "trivy", "checkov"],
            ),
        ]

        for label, extra_yaml, expected in cases:
            with self.subTest(case=label):
                config = load_test_config(extra_yaml)

                self.assertEqual(
                    config["scanners"],
                    expected,
                )

    def test_rejects_invalid_scanners(self):
        cases = [
            ("empty", "scanners: []\n"),
            ("wrong section type", "scanners: semgrep\n"),
            ("unknown scanner", "scanners: [semgrepp]\n"),
            ("duplicates", "scanners: [gitleaks, gitleaks]\n"),
            ("wrong entry type", "scanners: [true]\n"),
            ("dictionary entry", "scanners: [{}]\n"),
            ("misspelled section", "scaners: [gitleaks]\n"),
        ]

        for label, extra_yaml in cases:
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    load_test_config(extra_yaml)
