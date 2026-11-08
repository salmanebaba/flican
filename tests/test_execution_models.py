import json
import unittest
from dataclasses import replace

from flican.core.models import GateDecision, Run, RunStatus, Severity, StageResult, StageStatus

START = "2026-11-01T10:00:00+00:00"
END = "2026-11-01T10:00:02+00:00"


def completed(**changes):
    values = dict(stage_id="gitleaks", tool="gitleaks", status=StageStatus.COMPLETED,
                  started_at=START, finished_at=END, duration_seconds=2.0,
                  exit_code=10, findings_count=2, artifacts=("reports/gitleaks.json",))
    values.update(changes)
    return StageResult(**values)


class TestExecutionModels(unittest.TestCase):
    def test_native_findings_exit_code_is_still_a_completed_execution(self):
        stage = completed()
        run = Run("test-run", "demo", "/tmp/demo", START, Severity.HIGH, (stage,),
                  status=RunStatus.COMPLETED, finished_at=END,
                  decision=GateDecision.BLOCK, exit_code=1)
        serialized = json.loads(json.dumps(run.to_dict(), allow_nan=False))
        self.assertEqual(serialized["status"], "completed")
        self.assertEqual(serialized["decision"], "block")
        self.assertEqual(serialized["stages"][0]["exit_code"], 10)
        self.assertEqual(serialized["stages"][0]["artifacts"], ["reports/gitleaks.json"])

    def test_running_stage_cannot_claim_a_final_result(self):
        for changes in ({"findings_count": 0}, {"exit_code": 0}, {"error": "failure"},
                        {"finished_at": END}, {"artifacts": ("reports/fake.json",)}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                StageResult("gitleaks", "gitleaks", StageStatus.RUNNING, started_at=START, **changes)

    def test_invalid_counts_durations_dates_and_paths_are_rejected(self):
        for changes in ({"findings_count": True}, {"findings_count": -1}, {"exit_code": False},
                        {"duration_seconds": float("nan")}, {"duration_seconds": -1},
                        {"started_at": "2026-11-01T10:00:00"}, {"finished_at": "2026-11-01T09:00:00Z"},
                        {"artifacts": ("../escape.json",)}, {"artifacts": ("/tmp/report.json",)},
                        {"artifacts": ("reports/./file.json",)}, {"artifacts": ("reports\\file.json",)}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                completed(**changes)

    def test_unusable_stage_cannot_claim_findings(self):
        with self.assertRaisesRegex(ValueError, "Unsuccessful stages"):
            completed(status=StageStatus.FAILED, error="invalid JSON")

    def test_skipping_requires_an_explicit_reason(self):
        with self.assertRaises(ValueError):
            StageResult("semgrep", "semgrep", StageStatus.SKIPPED, finished_at=END, duration_seconds=0)

    def test_run_cannot_pass_with_a_failed_required_stage(self):
        failed = completed(status=StageStatus.FAILED, findings_count=None, artifacts=(), error="scanner error")
        run = Run("test-run", "demo", "/tmp/demo", START, Severity.HIGH, (failed,))
        with self.assertRaisesRegex(ValueError, "usable stages"):
            replace(run, status=RunStatus.COMPLETED, finished_at=END, decision=GateDecision.ALLOW, exit_code=0)
        final = replace(run, status=RunStatus.FAILED, finished_at=END,
                        decision=GateDecision.INCOMPLETE, exit_code=2)
        self.assertEqual(final.to_dict()["decision"], "incomplete")

    def test_finished_run_cannot_leave_a_stage_pending(self):
        run = Run("test-run", "demo", "/tmp/demo", START, Severity.HIGH,
                  (StageResult("semgrep", "semgrep"),))
        with self.assertRaisesRegex(ValueError, "unfinished stages"):
            replace(run, status=RunStatus.FAILED, finished_at=END, decision=GateDecision.INCOMPLETE, exit_code=2)

    def test_duplicate_stage_ids_and_false_success_codes_are_rejected(self):
        stage = completed()
        with self.assertRaisesRegex(ValueError, "unique IDs"):
            Run("test-run", "demo", "/tmp/demo", START, Severity.HIGH, (stage, stage))
        with self.assertRaises(ValueError):
            Run("test-run", "demo", "/tmp/demo", START, Severity.HIGH, (stage,),
                status=RunStatus.COMPLETED, finished_at=END, decision=GateDecision.BLOCK, exit_code=0)

    def test_serialized_contract_rejects_unknown_fields_statuses_and_wrong_shapes(self):
        run = Run("test-run", "demo", "/tmp/demo", START, Severity.HIGH, (completed(),))
        self.assertEqual(Run.from_dict(run.to_dict()), run)
        for key, value in (("status", "passed"), ("schema_version", True), ("exit_code", 0),
                           ("unknown", "ignored?"), ("stages", {}), ("artifacts", "reports/file.json")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                Run.from_dict({**run.to_dict(), key: value})

    def test_stage_timestamps_must_stay_inside_the_run(self):
        with self.assertRaisesRegex(ValueError, "before its run"):
            Run("test-run", "demo", "/tmp/demo", END, Severity.HIGH, (completed(),))
        with self.assertRaisesRegex(ValueError, "after its run"):
            Run("test-run", "demo", "/tmp/demo", START, Severity.HIGH, (completed(),),
                status=RunStatus.COMPLETED, finished_at=START, decision=GateDecision.ALLOW, exit_code=0)
