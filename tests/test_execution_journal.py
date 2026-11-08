import json
import stat
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from flican.core.execution import RunJournal
from flican.core.models import GateDecision, Run, RunStatus, Severity, StageResult, StageStatus
from flican.core.provenance import utc_now


class TestRunJournal(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory())) / "test-run"
        run = Run("test-run", "demo", "/tmp/demo", utc_now(), Severity.HIGH,
                  (StageResult("gitleaks", "gitleaks"), StageResult("semgrep", "semgrep")))
        self.journal = RunJournal(self.root, run)

    def read(self):
        return Run.from_dict(json.loads((self.root / "run.json").read_text()))

    def test_each_checkpoint_is_readable_private_and_keeps_completed_results(self):
        self.assertEqual(self.read().stages[0].status, StageStatus.PENDING)
        self.journal.start("gitleaks")
        self.assertEqual(self.read().stages[0].status, StageStatus.RUNNING)
        self.journal.complete("gitleaks", exit_code=10, findings_count=2, artifacts=("reports/gitleaks.json",))
        self.journal.start("semgrep")
        self.journal.fail("semgrep", RuntimeError("invalid JSON"), exit_code=0)
        self.journal.finish(gate_failed=True)
        run = self.read()
        self.assertEqual(run.status, RunStatus.FAILED)
        self.assertEqual(run.decision, GateDecision.INCOMPLETE)
        self.assertEqual(run.exit_code, 2)
        self.assertEqual(run.stages[0].findings_count, 2)
        self.assertEqual(run.stages[1].exit_code, 0)
        self.assertEqual(stat.S_IMODE((self.root / "run.json").stat().st_mode), 0o600)

    def test_timeouts_keep_no_subprocess_output_or_command(self):
        self.journal.start("gitleaks")
        self.journal.fail("gitleaks", subprocess.TimeoutExpired(
            ["scanner", "synthetic-sensitive-command"], 90,
            output="synthetic-sensitive-output", stderr="synthetic-sensitive-error"))
        self.journal.abort(RuntimeError("stopped"))
        run = self.read()
        self.assertEqual(run.stages[0].status, StageStatus.TIMED_OUT)
        self.assertEqual(run.stages[1].status, StageStatus.SKIPPED)
        self.assertNotIn("synthetic-sensitive", (self.root / "run.json").read_text())

    def test_cancellation_records_running_and_not_yet_started_stages(self):
        self.journal.start("gitleaks")
        self.journal.abort(KeyboardInterrupt("Scan cancelled."), cancelled=True)
        run = self.read()
        self.assertEqual(run.status, RunStatus.CANCELLED)
        self.assertTrue(all(stage.status == StageStatus.CANCELLED for stage in run.stages))
        self.assertEqual(run.exit_code, 2)

    def test_invalid_transitions_cannot_erase_a_finished_stage(self):
        self.journal.start("gitleaks")
        self.journal.complete("gitleaks", exit_code=0, findings_count=0, artifacts=())
        with self.assertRaises(ValueError):
            self.journal.start("gitleaks")
        with self.assertRaises(ValueError):
            self.journal.fail("gitleaks", RuntimeError("replace previous evidence"))
        with self.assertRaises(ValueError):
            self.journal.finish(gate_failed=False)
        self.assertEqual(self.read().stages[0].status, StageStatus.COMPLETED)

    def test_required_stage_cannot_be_skipped_to_manufacture_success(self):
        with self.assertRaisesRegex(ValueError, "required"):
            self.journal.skip("gitleaks", "Skip required work")
        self.assertEqual(self.read().stages[0].status, StageStatus.PENDING)

    def test_pipeline_cannot_forget_a_child_gate_after_skipping_dependents(self):
        from dataclasses import replace
        journal = RunJournal(self.root.parent / "pipeline/test-run", replace(self.journal.run, mode="pipeline"))
        with self.assertRaises(ValueError):
            journal.skip("semgrep", "No prior block")
        journal.start("gitleaks")
        journal.complete("gitleaks", exit_code=1, findings_count=1, artifacts=())
        journal.skip("semgrep", "Source gate blocked")
        with self.assertRaisesRegex(ValueError, "child gate"):
            journal.finish(gate_failed=False)
        journal.finish(gate_failed=True)
        self.assertEqual(journal.run.exit_code, 1)

    def test_atomic_replace_failure_preserves_previous_checkpoint(self):
        before = (self.root / "run.json").read_bytes()
        with patch("flican.core.state.os.replace", side_effect=OSError("synthetic disk failure")):
            with self.assertRaises(OSError):
                self.journal.start("gitleaks")
        self.assertEqual((self.root / "run.json").read_bytes(), before)
        self.assertEqual(self.journal.run.stages[0].status, StageStatus.PENDING)
        self.assertEqual(list(self.root.glob(".flican-*")), [])

    def test_final_decision_cannot_be_overwritten_by_start_or_finish(self):
        for stage in self.journal.run.stages:
            self.journal.start(stage.stage_id)
            self.journal.complete(stage.stage_id, exit_code=0, findings_count=0, artifacts=())
        self.journal.finish(gate_failed=False)
        with self.assertRaises(ValueError):
            self.journal.finish(gate_failed=True)
        self.assertEqual(self.read().exit_code, 0)

    def test_a_new_journal_cannot_adopt_an_already_running_stage(self):
        from dataclasses import replace
        running = replace(self.journal.run.stages[0], status=StageStatus.RUNNING, started_at=utc_now())
        run = replace(self.journal.run, stages=(running,))
        root = self.root.parent / "another-parent/test-run"
        with self.assertRaisesRegex(ValueError, "pending stages"):
            RunJournal(root, run)
        self.assertFalse(root.exists())
