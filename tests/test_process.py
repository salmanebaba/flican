import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from flican.core.process import run_bounded


class TestBoundedProcess(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.output, self.error = self.root / "output", self.root / "error"

    def test_native_failure_preserves_both_bounded_streams(self):
        code = run_bounded([sys.executable, "-c", "import sys; print('result'); print('diagnostic',file=sys.stderr); sys.exit(7)"],
                           self.output, self.error, timeout=10)
        self.assertEqual(code, 7)
        self.assertEqual(self.output.read_text(), "result\n")
        self.assertEqual(self.error.read_text(), "diagnostic\n")

    def test_oversized_output_is_stopped_at_the_limit(self):
        with self.assertRaisesRegex(ValueError, "output exceeds"):
            run_bounded([sys.executable, "-c", "print('x'*10000)"], self.output, self.error,
                        timeout=10, output_limit=1024)
        self.assertEqual(self.output.stat().st_size, 1024)

    def test_timeout_stops_a_silent_process_and_keeps_its_partial_log(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            run_bounded([sys.executable, "-c", "import time; print('started',flush=True); time.sleep(30)"],
                        self.output, self.output, timeout=1)
        self.assertIn("started", self.output.read_text())
