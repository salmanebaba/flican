import json
import subprocess
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from flican.adapters.checkov import (
    is_checkov_dockerfile,
    normalize_checkov_finding,
    parse_checkov_report,
    run_checkov,
)
from flican.core.models import Finding, Severity

FIXTURES = Path(__file__).parent / "fixtures" / "checkov"


def make_report():
    return json.loads((FIXTURES / "finding-report.json").read_text(encoding="utf-8"))


def make_result(code, report, stderr=""):
    return subprocess.CompletedProcess(
        ["docker", "run"], code, stdout=json.dumps(report), stderr=stderr,
    )


def passing_report():
    report = make_report()
    record = report["results"]["failed_checks"].pop()
    record["check_result"]["result"] = "PASSED"
    report["results"]["passed_checks"].append(record)
    report["summary"].update(failed=0, passed=1)
    return report


def dockerfile_report():
    report = make_report()
    report["check_type"] = "dockerfile"
    report["results"]["failed_checks"][0].update(
        check_id="CKV_DOCKER_1", check_name="Ensure port 22 is not exposed",
        file_path="/Dockerfile", file_abs_path="/src/Dockerfile",
        file_line_range=[2, 2], resource="/Dockerfile.EXPOSE",
    )
    return report


class TestCheckovReport(unittest.TestCase):
    def test_accepts_failed_and_passed_checks_with_coverage(self):
        for code, report, count in ((1, make_report(), 1), (0, passing_report(), 0)):
            with self.subTest(code=code):
                parsed = parse_checkov_report(make_result(code, report))
                self.assertEqual(len(parsed.findings), count)
                self.assertEqual(parsed.coverage["status"], "completed")
                self.assertEqual(parsed.coverage["resource_count"], 1)

    def test_accepts_summary_only_when_no_check_records_are_missing(self):
        summary = make_report()["summary"]
        summary.update(failed=0, resource_count=0)
        parsed = parse_checkov_report(make_result(0, summary))
        self.assertEqual(parsed.findings, [])
        self.assertEqual(parsed.coverage["status"], "no_resources")
        summary["resource_count"] = 1
        parsed = parse_checkov_report(make_result(0, summary))
        self.assertEqual(parsed.coverage["status"], "no_checks")
        summary["failed"] = 1
        with self.assertRaisesRegex(ValueError, "incomplete"):
            parse_checkov_report(make_result(0, summary))

    def test_rejects_native_success_with_parsing_errors(self):
        report = passing_report()
        report["results"]["parsing_errors"] = ["/src/broken.tf"]
        report["summary"]["parsing_errors"] = 1
        with self.assertRaisesRegex(RuntimeError, "parsing errors"):
            parse_checkov_report(make_result(0, report))

    def test_rejects_missing_error_information(self):
        report = make_report()
        del report["results"]["parsing_errors"]
        with self.assertRaises(ValueError):
            parse_checkov_report(make_result(1, report))

    def test_rejects_invalid_json_and_incomplete_or_wrong_report_shapes(self):
        for report in (None, [], {}, {"unexpected": []}):
            with self.subTest(report=report):
                with self.assertRaises(ValueError):
                    parse_checkov_report(make_result(0, report))
        result = subprocess.CompletedProcess([], 0, stdout="not JSON", stderr="")
        with self.assertRaisesRegex(ValueError, "invalid JSON"):
            parse_checkov_report(result)

    def test_rejects_exit_code_mismatch(self):
        for code, report in ((0, make_report()), (1, passing_report())):
            with self.subTest(code=code):
                with self.assertRaisesRegex(ValueError, "does not match"):
                    parse_checkov_report(make_result(code, report))

    def test_rejects_inconsistent_counts_and_wrong_buckets(self):
        report = make_report()
        report["summary"]["failed"] = 2
        with self.assertRaisesRegex(ValueError, "summary"):
            parse_checkov_report(make_result(1, report))
        report = make_report()
        report["results"]["failed_checks"][0]["check_result"]["result"] = "PASSED"
        with self.assertRaisesRegex(ValueError, "bucket"):
            parse_checkov_report(make_result(1, report))

    def test_rejects_invalid_counters_version_and_framework(self):
        for field, value in (("failed", True), ("passed", -1), ("resource_count", "1"),
                             ("checkov_version", "different")):
            with self.subTest(field=field, value=value):
                report = make_report()
                report["summary"][field] = value
                with self.assertRaises(ValueError):
                    parse_checkov_report(make_result(1, report))
        report = make_report()
        report["check_type"] = "kubernetes"
        with self.assertRaisesRegex(ValueError, "framework"):
            parse_checkov_report(make_result(1, report))

    def test_marks_suppressed_checks_as_partial_coverage(self):
        report = make_report()
        record = report["results"]["failed_checks"].pop()
        record["check_result"] = {"result": "SKIPPED", "suppress_comment": "fixture"}
        report["results"]["skipped_checks"].append(record)
        report["summary"].update(failed=0, skipped=1)
        parsed = parse_checkov_report(make_result(0, report))
        self.assertEqual(parsed.findings, [])
        self.assertEqual(parsed.coverage["status"], "partial")
        self.assertEqual(parsed.coverage["skipped"], 1)

    def test_distinguishes_resources_without_applicable_checks(self):
        report = make_report()
        report["results"]["failed_checks"] = []
        report["summary"]["failed"] = 0
        parsed = parse_checkov_report(make_result(0, report))
        self.assertEqual(parsed.coverage["status"], "no_checks")

    def test_rejects_checks_without_resources_and_operational_diagnostics(self):
        report = make_report()
        report["summary"]["resource_count"] = 0
        with self.assertRaisesRegex(ValueError, "no reported resources"):
            parse_checkov_report(make_result(1, report))
        with self.assertRaisesRegex(RuntimeError, "diagnostics"):
            parse_checkov_report(make_result(0, passing_report(), "WARNING incomplete scan\n"))
        for code in (2, 125, 137):
            with self.subTest(code=code):
                with self.assertRaisesRegex(RuntimeError, f"exit code {code}"):
                    parse_checkov_report(make_result(code, passing_report()))


class TestCheckovNormalization(unittest.TestCase):
    def setUp(self):
        self.raw = make_report()["results"]["failed_checks"][0]

    def test_preserves_resource_location_and_explicit_policy_origin(self):
        self.assertEqual(
            normalize_checkov_finding(self.raw),
            Finding(
                scanner="checkov", rule_id="CKV_AWS_55",
                description="Ensure S3 bucket has ignore public ACLs enabled",
                severity=Severity.HIGH, file_path="main.tf", line=2,
                resource_id="aws_s3_bucket_public_access_block.example",
                severity_source="flican_policy",
            ),
        )
        del self.raw["severity"]
        self.assertEqual(normalize_checkov_finding(self.raw).severity, Severity.HIGH)

    def test_preserves_native_severity_and_rejects_unknown_ratings(self):
        for severity in Severity:
            with self.subTest(severity=severity):
                self.raw["severity"] = severity.name
                finding = normalize_checkov_finding(self.raw)
                self.assertEqual(finding.severity, severity)
                self.assertEqual(finding.severity_source, "checkov")
        for severity in ("UNKNOWN", "NONE", "", True):
            with self.subTest(severity=severity):
                self.raw["severity"] = severity
                with self.assertRaises(ValueError):
                    normalize_checkov_finding(self.raw)

    def test_rejects_paths_outside_the_snapshot(self):
        for path in ("/etc/passwd", "/src-other/main.tf", "/src/../main.tf", "main.tf"):
            with self.subTest(path=path):
                self.raw["file_abs_path"] = path
                with self.assertRaises(ValueError):
                    normalize_checkov_finding(self.raw)

    def test_validates_positions_and_does_not_invent_missing_lines(self):
        for position in (None, [0, 0]):
            self.raw["file_line_range"] = position
            self.assertIsNone(normalize_checkov_finding(self.raw).line)
        for position in ([-1, 2], [3, 2], [True, 2], [1, "2"], [1], []):
            with self.subTest(position=position):
                self.raw["file_line_range"] = position
                with self.assertRaises(ValueError):
                    normalize_checkov_finding(self.raw)

    def test_rejects_missing_check_identity_and_resource(self):
        for field in ("check_id", "check_name", "resource"):
            for value in (None, "", 42):
                with self.subTest(field=field, value=value):
                    raw = deepcopy(self.raw)
                    raw[field] = value
                    with self.assertRaises(ValueError):
                        normalize_checkov_finding(raw)


class TestCheckovFrameworks(unittest.TestCase):
    def test_dockerfile_names_match_the_pinned_runner(self):
        for name in ("Dockerfile", "dockerfile", "Dockerfile.dev", "api.Dockerfile",
                     "api.dockerfile.prod"):
            with self.subTest(name=name):
                self.assertTrue(is_checkov_dockerfile(name))
        for name in ("Containerfile", "DOCKERFILE", "Dockerfile.dockerignore",
                     "api.Dockerfile.Dockerignore", "README.md", "Dockerfile."):
            with self.subTest(name=name):
                self.assertFalse(is_checkov_dockerfile(name))

    def test_accepts_single_dockerfile_and_preserves_framework_in_findings(self):
        parsed = parse_checkov_report(
            make_result(1, dockerfile_report()), expected_dockerfiles={"Dockerfile"},
        )
        self.assertEqual(parsed.coverage["framework"], "dockerfile")
        details = parsed.coverage["frameworks"]["dockerfile"]
        self.assertEqual(details["files_expected"], 1)
        self.assertEqual(details["files_reported"], 1)
        self.assertTrue(details["inventory_checked"])
        self.assertEqual(parsed.coverage["frameworks"]["terraform"]["status"], "not_reported")
        finding = normalize_checkov_finding(parsed.findings[0])
        self.assertEqual(finding.framework, "dockerfile")
        self.assertEqual(finding.file_path, "Dockerfile")
        self.assertEqual(finding.resource_id, "/Dockerfile.EXPOSE")
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_combines_frameworks_using_the_global_exit_code(self):
        for terraform in (make_report(), passing_report()):
            for reports in ([terraform, dockerfile_report()], [dockerfile_report(), terraform]):
                with self.subTest(terraform_failed=terraform["summary"]["failed"],
                                  first=reports[0]["check_type"]):
                    parsed = parse_checkov_report(
                        make_result(1, reports), expected_dockerfiles={"Dockerfile"},
                    )
                    self.assertEqual(parsed.coverage["framework"], "multiple")
                    self.assertEqual(parsed.coverage["resource_count"], 2)
                    self.assertEqual(parsed.coverage["failed"], terraform["summary"]["failed"] + 1)
                    self.assertEqual(len(parsed.findings), parsed.coverage["failed"])
                    self.assertEqual(parsed.coverage["frameworks"]["terraform"]["passed"],
                                     terraform["summary"]["passed"])
                    self.assertEqual(parsed.findings[-1]["check_type"], "dockerfile")

    def test_does_not_hide_a_framework_parsing_failure(self):
        for framework in ("terraform", "dockerfile"):
            broken = make_report() if framework == "terraform" else dockerfile_report()
            broken["results"]["parsing_errors"] = ["/src/broken"]
            broken["summary"]["parsing_errors"] = 1
            other = dockerfile_report() if framework == "terraform" else passing_report()
            with self.subTest(framework=framework):
                with self.assertRaisesRegex(RuntimeError, "parsing errors"):
                    parse_checkov_report(make_result(1, [other, broken]))

    def test_rejects_duplicate_unknown_and_incomplete_framework_entries(self):
        for reports in ([make_report(), make_report()], [None],
                        [{"check_type": "terraform"}], [make_report(), {}]):
            with self.subTest(reports=reports):
                with self.assertRaises(ValueError):
                    parse_checkov_report(make_result(1, reports))
        for code, reports in ((0, [make_report(), dockerfile_report()]),
                              (1, [passing_report()])):
            with self.subTest(code=code):
                with self.assertRaisesRegex(ValueError, "does not match"):
                    parse_checkov_report(make_result(code, reports))

    def test_missing_dockerfiles_are_errors_even_with_another_valid_report(self):
        empty = dict(make_report()["summary"], failed=0, resource_count=0)
        for report, code in ((empty, 0), (make_report(), 1), (dockerfile_report(), 1)):
            with self.subTest(report=report):
                with self.assertRaisesRegex(RuntimeError, "Dockerfile.dev"):
                    parse_checkov_report(
                        make_result(code, report),
                        expected_dockerfiles={"Dockerfile", "Dockerfile.dev"},
                    )

    def test_summary_only_counts_do_not_invent_per_framework_coverage(self):
        summary = dict(make_report()["summary"], failed=0, resource_count=1)
        parsed = parse_checkov_report(make_result(0, summary), expected_dockerfiles=set())
        self.assertEqual(parsed.coverage["status"], "no_checks")
        self.assertEqual(parsed.coverage["framework"], "unattributed")
        for details in parsed.coverage["frameworks"].values():
            self.assertEqual(details["status"], "not_reported")
            self.assertNotIn("resource_count", details)

    def test_normalizer_rejects_unknown_framework(self):
        raw = dockerfile_report()["results"]["failed_checks"][0]
        raw["check_type"] = "kubernetes"
        with self.assertRaisesRegex(ValueError, "unsupported framework"):
            normalize_checkov_finding(raw)


class TestCheckovExecution(unittest.TestCase):
    def test_cleans_the_same_container_after_success_or_timeout(self):
        completed = make_result(1, make_report())
        timeout = subprocess.TimeoutExpired(["docker", "run"], 180)
        for outcome in (completed, timeout):
            with self.subTest(outcome=type(outcome).__name__), TemporaryDirectory() as directory:
                with (
                    patch("flican.adapters.checkov.get_container_user", return_value="1000:1000"),
                    patch("flican.adapters.checkov.subprocess.run") as run_mock,
                    patch("flican.adapters.checkov.remove_container") as remove_mock,
                ):
                    if isinstance(outcome, Exception):
                        run_mock.side_effect = outcome
                        with self.assertRaises(subprocess.TimeoutExpired):
                            run_checkov("/fake/docker", Path(directory))
                    else:
                        run_mock.return_value = completed
                        self.assertIs(run_checkov("/fake/docker", Path(directory)), completed)
                command = run_mock.call_args.args[0]
                name = command[command.index("--name") + 1]
                remove_mock.assert_called_once_with("/fake/docker", name)
