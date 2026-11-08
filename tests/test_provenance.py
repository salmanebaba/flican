import json
import stat
import unittest
from unittest.mock import patch
from pathlib import Path
from tempfile import TemporaryDirectory

from dojo_support import create_run
from state_support import isolated_state

from flican.core.provenance import digest, load_attested_run, scanner_profiles
from flican.core.state import StateStore, read_private_json, write_private_json


class TestRunProvenance(unittest.TestCase):
    def setUp(self):
        isolated_state(self)
        self.directory = Path(self.enterContext(TemporaryDirectory()))

    def test_registered_run_round_trips_and_state_is_private(self):
        run, manifest = create_run(self.directory / "project")
        loaded, report = load_attested_run(run)
        self.assertEqual(loaded, manifest)
        self.assertEqual(len(report["findings"]), 1)
        store = StateStore()
        self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(store.root.stat().st_mode), 0o700)

    def test_modified_report_and_rewritten_manifest_are_rejected(self):
        run, _ = create_run(self.directory / "project")
        report = run / "reports/findings.json"
        report.write_text("{}\n")
        with self.assertRaisesRegex(ValueError, "artifact integrity"):
            load_attested_run(run)
        manifest_path = run / "manifest.json"
        forged = json.loads(manifest_path.read_text())
        forged["artifacts"]["reports/findings.json"] = digest(report.read_bytes())
        manifest_path.write_text(json.dumps(forged))
        with self.assertRaisesRegex(ValueError, "manifest integrity"):
            load_attested_run(run)

    def test_unregistered_or_moved_run_cannot_be_imported(self):
        project = self.directory / "project"
        run, _ = create_run(project)
        moved = project / "unregistered"
        run.rename(moved)
        with self.assertRaisesRegex(ValueError, "not registered"):
            load_attested_run(moved)

    def test_artifact_symlinks_cannot_escape_the_registered_run(self):
        run, _ = create_run(self.directory / "project")
        reports = run / "reports"
        outside = self.directory / "outside"
        reports.rename(outside)
        reports.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Invalid or missing"):
            load_attested_run(run)

    def test_partial_and_unattested_coverage_cannot_close_findings(self):
        for scanner, status, skipped, eligible in (
            ("checkov", "completed", 0, True), ("checkov", "partial", 1, False),
            ("checkov", "no_resources", 0, False), ("semgrep", "completed", 0, False),
            ("trivy", "completed", 0, False), ("gitleaks", "completed", 0, False),
        ):
            with self.subTest(scanner=scanner, status=status):
                _, manifest = create_run(self.directory / "project", scanner=scanner,
                                          status=status, skipped=skipped)
                self.assertEqual(manifest["completion"][scanner]["can_close_old"], eligible)

    def test_profile_hashes_only_selected_native_ignore_files(self):
        root = self.directory / "project"
        root.mkdir()
        ignored = root / "excluded"
        ignored.mkdir()
        (ignored / ".semgrepignore").write_text("private configuration\n")
        source = root / "app.py"
        source.write_text("value = 1\n")
        profiles = scanner_profiles(root, ["semgrep"], {"excluded"}, paths=[source])
        self.assertEqual(profiles["semgrep"]["details"]["ignore_files"], {})


class TestPrivateState(unittest.TestCase):
    def test_state_override_is_isolated_from_default_namespace(self):
        with TemporaryDirectory() as directory:
            base = Path(directory)
            with patch.dict("os.environ", {"XDG_STATE_HOME": str(base)}, clear=True):
                default = StateStore()
                self.assertEqual(default.root, base / "flican")
                default.put("context", "project", {"name": "default"})
                with patch.dict("os.environ", {"FLICAN_STATE_DIR": str(base / "custom-state")}):
                    custom = StateStore()
                    self.assertEqual(custom.root, base / "custom-state")
                    self.assertIsNone(custom.get("context", "project"))
                    custom.put("context", "project", {"name": "custom"})
                self.assertEqual(default.get("context", "project"), {"name": "default"})
                self.assertEqual(custom.get("context", "project"), {"name": "custom"})

    def test_credentials_are_private_and_symlinks_are_rejected(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "private/connection.json"
            write_private_json(path, {"token": "synthetic-test-token"})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(read_private_json(path)["token"], "synthetic-test-token")
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "0600"):
                read_private_json(path)
            link = root / "private/link.json"
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "symlinks"):
                write_private_json(link, {"changed": True})
