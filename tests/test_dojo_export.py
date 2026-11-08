import unittest

from dojo_support import finding

from flican.reporting.dojo_export import export_scanner


def export(findings, scanner="checkov"):
    return export_scanner(findings, scanner, "scope-identity", "profile-identity", "2026-10-31T10:00:00+00:00")


class TestGenericExport(unittest.TestCase):
    def test_preserves_scanner_metadata_and_maps_severity(self):
        result = export([finding(severity_source="flican_policy")])
        self.assertEqual(result["type"], "Flican Checkov (Generic Findings Import)")
        item = result["findings"][0]
        self.assertEqual(item["severity"], "High")
        self.assertEqual(item["file_path"], "main.tf")
        self.assertIn("Framework: terraform", item["description"])
        self.assertIn("Severity source: flican_policy", item["description"])
        self.assertEqual(len(item["unique_id_from_tool"]), 64)

    def test_terraform_identity_survives_line_description_and_severity_changes(self):
        original = export([finding()])["findings"][0]["unique_id_from_tool"]
        modified = export([finding(line=90, description="Updated explanation", severity="medium")])["findings"][0]["unique_id_from_tool"]
        self.assertEqual(original, modified)

    def test_same_line_source_occurrences_are_distinguished_by_column(self):
        rows = [finding("semgrep", file_path="app.py", rule_id="flican.python.eval", column=3),
                finding("semgrep", file_path="app.py", rule_id="flican.python.eval", column=20)]
        identities = [row["unique_id_from_tool"] for row in export(rows, "semgrep")["findings"]]
        self.assertEqual(len(set(identities)), 2)

    def test_ambiguous_repeated_identity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            export([finding(), finding()])

    def test_invalid_findings_and_outside_paths_are_rejected(self):
        for changes in ({"file_path": "/etc/passwd"}, {"file_path": "../app.py"},
                        {"file_path": 5}, {"line": True}, {"column": -1},
                        {"severity": "unknown"}, {"scanner": "unknown"}, {"description": ""}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    export([finding(**changes)])

    def test_empty_reports_keep_their_scanner_type_and_trivy_fix_information(self):
        self.assertEqual(export([], "semgrep")["findings"], [])
        row = finding("trivy", rule_id="CVE-2024-0001", package_name="example",
                      package_version="1.0", fixed_version="1.1", file_path="requirements.txt")
        item = export([row], "trivy")["findings"][0]
        self.assertEqual(item["vulnerability_ids"], ["CVE-2024-0001"])
        self.assertEqual(item["component_version"], "1.0")
        self.assertTrue(item["fix_available"])
        self.assertEqual(item["fix_version"], "1.1")
