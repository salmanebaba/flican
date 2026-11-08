"""Synthetic, locally attested run fixtures for reporting tests."""

import json
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

from flican.core.models import Finding, Severity
from flican.core.provenance import attest_run
from flican.core.reports import save_report

PROFILE = "a" * 64


def finding(scanner="checkov", **changes):
    value = asdict(Finding(
        scanner=scanner, rule_id="CKV_TEST_1", description="Synthetic check",
        severity=Severity.HIGH, file_path="main.tf", line=3,
        resource_id="example.resource" if scanner == "checkov" else None,
        framework="terraform" if scanner == "checkov" else None,
    ))
    value.update(changes)
    return value


def create_run(project: Path, *, findings=None, scanner="checkov", started="2026-10-31T10:00:00.000000+00:00",
               status="completed", skipped=0):
    project.mkdir(parents=True, exist_ok=True)
    run = project / ".flican/runs" / uuid4().hex
    report = {"schema_version": 1, "scanners": [scanner],
              "gate": {"passed": False, "fail_on": "high"},
              "findings": [finding(scanner)] if findings is None else findings}
    coverage = {"checkov": {"status": status, "skipped": skipped}} if scanner == "checkov" else {}
    if coverage:
        report["coverage"] = coverage
    save_report(run / "reports/findings.json", json.dumps(report) + "\n")
    save_report(run / f"reports/{scanner}.json", "{}\n")
    profiles = {scanner: {"hash": PROFILE, "details": {"scanner": scanner}}}
    manifest = attest_run(run, project, "unit-project", started, profiles, coverage,
                          ["findings.json", f"{scanner}.json"])
    return run, manifest
