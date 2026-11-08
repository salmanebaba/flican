import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from flican.core.snapshot import temporary_snapshot


class TestTemporarySnapshot(unittest.TestCase):
    def test_removes_snapshot_after_success(self):
        source_text = 'print("hello")\n'

        with TemporaryDirectory() as directory:
            project = Path(directory)
            source = project / "app.py"
            source.write_text(source_text, encoding="utf-8")

            with temporary_snapshot(project, [source]) as snapshot_path:
                self.assertTrue(snapshot_path.is_dir())
                self.assertEqual(
                    (snapshot_path / "app.py").read_text(encoding="utf-8"),
                    source_text,
                )

            self.assertFalse(snapshot_path.exists())
            self.assertEqual(
                source.read_text(encoding="utf-8"),
                source_text,
            )

    def test_removes_snapshot_after_error(self):
        source_text = 'print("hello")\n'

        with TemporaryDirectory() as directory:
            project = Path(directory)
            source = project / "app.py"
            source.write_text(source_text, encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "Scanner failed"):
                with temporary_snapshot(project, [source]) as snapshot_path:
                    self.assertTrue(snapshot_path.is_dir())
                    raise RuntimeError("Scanner failed")

            self.assertFalse(snapshot_path.exists())
            self.assertEqual(
                source.read_text(encoding="utf-8"),
                source_text,
            )