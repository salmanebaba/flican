"""Automatic DB preparation shares defaults; offline scans never download."""

import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from typer.testing import CliRunner

from state_support import isolated_state
from trivy_support import download_database
from flican.cli.main import app
from flican.core.cache import trivy_cache_directory


class TestSharedTrivyCache(unittest.TestCase):
    def setUp(self):
        isolated_state(self)
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.project = self.root / "project"
        self.project.mkdir()
        self.base = self.root / "user-cache"
        self.cache = self.base / "flican/trivy"
        self.enterContext(patch.dict("os.environ", {"XDG_CACHE_HOME": str(self.base)}))
        self.enterContext(patch("flican.cli.main.shutil.which", return_value="/fake/docker"))
        self.configure(["trivy"])

    def configure(self, scanners):
        (self.project / "flican.yaml").write_text(
            "schema_version: 1\nproject: {name: cache-demo, exclude: []}\n"
            f"scanners: {json.dumps(scanners)}\n",
        )

    def test_prepare_update_and_scan_share_one_default_cache(self):
        self.exercise_commands(None)

    def test_explicit_paths_override_the_default_across_commands(self):
        self.exercise_commands(self.root / "custom-cache")
        self.assertFalse(self.base.exists())

    def exercise_commands(self, override):
        cache = override or self.cache
        success = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        report = subprocess.CompletedProcess([], 0, stdout='{"SchemaVersion":2,"Results":[]}', stderr="")
        option = ["--trivy-cache-dir", str(override)] if override else []
        db_option = ["--cache-dir", str(override)] if override else []
        with (patch("flican.core.ci.subprocess.run", return_value=success),
              patch("flican.core.ci.run_trivy_db_update", side_effect=download_database) as prepare_db,
              patch("flican.cli.main.run_trivy_db_update", return_value=success) as update_db,
              patch("flican.cli.main.run_trivy", return_value=report) as scan):
            commands = (["ci", "prepare", str(self.project), *option],
                        ["db", "update", *db_option],
                        ["scan", str(self.project), *option])
            for command in commands:
                result = CliRunner().invoke(app, command)
                self.assertEqual(result.exit_code, 0, result.output)
            prepare_db.assert_called_once()
            self.assertEqual(prepare_db.call_args.args[1].parent, cache)
            update_db.assert_not_called()  # The freshly prepared DB is reused.
            self.assertEqual(scan.call_args.args[2], cache)

    def test_unprepared_cache_is_an_incomplete_stage_without_implicit_download(self):
        self.configure(["gitleaks", "trivy"])
        for partial in (False, True):
            with self.subTest(partial=partial):
                if partial:
                    (self.cache / "db").mkdir(parents=True)
                    (self.cache / "db/trivy.db").write_text("synthetic")
                with (patch("flican.cli.main.run_gitleaks", return_value=subprocess.CompletedProcess(
                        [], 0, stdout="[]", stderr="")),
                      patch("flican.adapters.trivy.get_container_user", return_value="1000:1000"),
                      patch("flican.adapters.trivy.subprocess.run") as docker,
                      patch("flican.cli.main.run_trivy_db_update") as update):
                    result = CliRunner().invoke(app, ["scan", str(self.project), "--offline"])
                self.assertEqual(result.exit_code, 2, result.output)
                self.assertIn("flican ci prepare <project>", result.output)
                self.assertIn("flican db update", result.output)
                if not partial:
                    self.assertFalse(self.base.exists())
                docker.assert_not_called()
                update.assert_not_called()
        for journal in self.project.glob(".flican/runs/*/run.json"):
            value = json.loads(journal.read_text())
            self.assertEqual([stage["status"] for stage in value["stages"]], ["completed", "failed"])
            self.assertTrue((journal.parent / "reports/gitleaks.json").is_file())
            self.assertFalse((journal.parent / "manifest.json").exists())

    def test_plan_displays_default_without_creating_or_downloading_cache(self):
        with patch("flican.cli.main.subprocess.run") as docker:
            result = CliRunner().invoke(app, ["plan", str(self.project)])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn(str(self.cache), result.output)
        self.assertIn("--trivy-cache-dir overrides", result.output)
        docker.assert_not_called()
        self.assertFalse(self.base.exists())

    def test_preparation_without_trivy_does_not_create_default_cache(self):
        self.configure(["gitleaks"])
        with (patch("flican.core.ci.subprocess.run", return_value=subprocess.CompletedProcess([], 0)),
              patch("flican.core.ci.run_trivy_db_update") as update):
            result = CliRunner().invoke(app, ["ci", "prepare", str(self.project)])
        self.assertEqual(result.exit_code, 0, result.output)
        update.assert_not_called()
        self.assertFalse(self.base.exists())

    def test_empty_unset_or_relative_xdg_uses_home_cache(self):
        for value in (None, "", "relative-cache"):
            environment = {} if value is None else {"XDG_CACHE_HOME": value}
            with (self.subTest(value=value), patch.dict("os.environ", environment, clear=True),
                  patch("flican.core.cache.Path.home", return_value=self.root)):
                self.assertEqual(trivy_cache_directory(), self.root / ".cache/flican/trivy")
        self.assertFalse((self.root / ".cache").exists())


if __name__ == "__main__":
    unittest.main()
