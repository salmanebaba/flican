import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from flican.adapters.image_trivy import parse_image_report, validate_sbom
from flican.core.models import Severity


class TestImageTrivy(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.path = self.root / "report.json"
        self.image = {"config_digest": "sha256:" + "c" * 64, "manifest_digest": "sha256:" + "d" * 64,
                      "archive_sha256": "e" * 64}
        self.report = {"SchemaVersion": 2, "ArtifactType": "container_image",
                       "Metadata": {"ImageID": self.image["config_digest"]}, "Results": []}

    def parse(self, code=0):
        self.path.write_text(json.dumps(self.report))
        return parse_image_report(code, self.path, "", self.image)

    def test_empty_package_inventory_is_a_valid_bare_image_result(self):
        _, findings, coverage = self.parse()
        self.assertEqual(findings, [])
        self.assertEqual(coverage["packages"], 0)
        self.assertFalse(coverage["os_detected"])

    def test_vulnerabilities_keep_package_fix_and_image_identity(self):
        self.report["Results"] = [{"Target": "debian", "Type": "debian", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-TEST", "PkgName": "demo", "InstalledVersion": "1.0", "FixedVersion": "1.1",
            "Severity": "HIGH", "Title": "Synthetic vulnerability",
        }]}]
        _, findings, _ = self.parse(10)
        self.assertEqual(findings[0].package_name, "demo")
        self.assertEqual(findings[0].fixed_version, "1.1")
        self.assertEqual(findings[0].resource_id, self.image["manifest_digest"])

    def test_unknown_severity_uses_explicit_owner_approved_high_policy(self):
        self.report["Results"] = [{"Target": "app", "Vulnerabilities": [{
            "VulnerabilityID": "CVE-UNKNOWN", "PkgName": "demo", "InstalledVersion": "1", "Severity": "UNKNOWN",
        }]}]
        _, findings, _ = self.parse(10)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].severity_source, "flican:unknown-as-high")

    def test_secret_values_and_config_history_are_not_exported(self):
        canary = "SYNTHETIC-PRIVATE-MATCH"
        self.report["Metadata"]["ImageConfig"] = {"config": {"Env": ["SECRET=" + canary]}, "history": [canary]}
        self.report["Results"] = [{"Target": "app/settings.txt", "Secrets": [{
            "RuleID": "synthetic-secret", "Title": "Synthetic secret", "Severity": "CRITICAL", "StartLine": 3,
            "Code": {"Lines": [{"Content": canary}]}, "Match": canary, "FutureSecretField": canary,
        }]}]
        sanitized, findings, _ = self.parse(10)
        self.assertNotIn(canary, json.dumps(sanitized))
        self.assertNotIn(canary, str(findings))
        self.assertEqual(findings[0].line, 3)

    def test_report_for_another_image_or_inconsistent_exit_code_is_rejected(self):
        for change, code in (({"Metadata": {"ImageID": "sha256:" + "f" * 64}}, 0),
                             ({"ArtifactType": "filesystem"}, 0), ({"SchemaVersion": True}, 0), ({}, 10)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                original = self.report
                self.report = {**original, **change}
                try:
                    self.parse(code)
                finally:
                    self.report = original

    def test_malformed_findings_and_diagnostic_stderr_do_not_pass(self):
        self.report["Results"] = [{"Target": "app", "Secrets": [{"RuleID": "test", "Title": "test", "StartLine": -1}]}]
        with self.assertRaises(ValueError):
            self.parse(10)
        self.report["Results"] = []
        self.path.write_text(json.dumps(self.report))
        with self.assertRaises(RuntimeError):
            parse_image_report(0, self.path, "unexpected diagnostic", self.image)

    def test_vendor_severity_advisory_is_allowed_but_does_not_hide_errors(self):
        self.path.write_text(json.dumps(self.report))
        warning = ("2026-11-04T01:07:41Z\tWARN\tUsing severities from other vendors for some vulnerabilities. "
                   "Read https://trivy.dev/docs/v0.76/guide/scanner/vulnerability#severity-selection for details.")
        _, findings, _ = parse_image_report(0, self.path, warning, self.image)
        self.assertEqual(findings, [])
        for diagnostic in ("\n2026-11-04T01:07:41Z\tWARN\tPackage analysis skipped.", "\nERROR incomplete scan"):
            with self.subTest(diagnostic=diagnostic), self.assertRaises(RuntimeError):
                parse_image_report(0, self.path, warning + diagnostic, self.image)

    def test_cyclonedx_is_bound_to_the_scanned_archive_and_manifest(self):
        value = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                 "metadata": {"component": {"type": "container", "name": "candidate"}},
                 "components": [{"type": "library", "name": "demo", "purl": "pkg:pypi/demo@1"}]}
        self.path.write_text(json.dumps(value))
        report = {"Results": [{"Packages": [{"Identifier": {"PURL": "pkg:pypi/demo@1"}}]}]}
        validated = validate_sbom(self.path, self.image, report)
        self.assertIn({"name": "flican:image:manifest_digest", "value": self.image["manifest_digest"]},
                      validated["metadata"]["properties"])
        value["components"] = []
        self.path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "dropped"):
            validate_sbom(self.path, self.image, report)

    def test_invalid_sbom_or_forged_existing_binding_is_rejected(self):
        cases = ({}, {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": True, "metadata": {"component": {}}},
                 {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                  "metadata": {"component": {"type": "container", "name": "candidate"},
                               "properties": [{"name": "flican:image:manifest_digest", "value": "forged"}]}})
        for value in cases:
            self.path.write_text(json.dumps(value))
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_sbom(self.path, self.image)
