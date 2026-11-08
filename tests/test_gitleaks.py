import unittest

from flican.adapters.gitleaks import normalize_gitleaks_finding


class TestGitleaksNormalization(unittest.TestCase):
    def test_preserves_columns_and_rejects_invalid_values(self):
        raw = {"RuleID": "test-rule", "File": "/src/app.py", "StartLine": 1, "StartColumn": 12}
        self.assertEqual(normalize_gitleaks_finding(raw).column, 12)
        for value in (True, -1, "12"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_gitleaks_finding(dict(raw, StartColumn=value))

    def test_normalizes_file_path(self) -> None:
        for path in (
            "/src/config/settings.py",
            "config/settings.py",
        ):
            with self.subTest(path=path):
                finding = normalize_gitleaks_finding(
                    {
                        "RuleID": "test-rule",
                        "File": path,
                        "StartLine": 7,
                    }
                )

                self.assertEqual(finding.file_path, "config/settings.py")
                self.assertEqual(finding.line, 7)

    def test_rejects_paths_outside_snapshot(self) -> None:
        for path in (
            "/etc/settings.py",
            "/src-other/settings.py",
            "../settings.py",
            "/src/../settings.py",
        ):
            with self.subTest(path=path):
                raw = {"RuleID": "test-rule", "File": path}

                with self.assertRaises(ValueError):
                    normalize_gitleaks_finding(raw)
