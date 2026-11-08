"""Freshness, immutable DB selection, offline use and safe cache replacement."""

import hashlib
import json
import subprocess
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from typer.testing import CliRunner

from state_support import isolated_state
from trivy_support import download_database, write_database
from flican.adapters.trivy import build_db_update_docker_command, build_docker_command
from flican.cli.main import app
from flican.core.provenance import load_attested_run
from flican.core.trivy_db import trivy_database

DIGEST = "sha256:" + "a" * 64


class TestTrivyDatabase(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.cache = self.root / "cache"
        self.update = Mock(side_effect=download_database)

    def database(self, **options):
        return trivy_database("/fake/docker", self.cache, updater=self.update, **options)

    def test_empty_auto_cache_is_prepared_once_and_fresh_cache_is_reused(self):
        with self.database() as (cache, info):
            self.assertEqual(cache, self.cache)
            self.assertEqual(info["database_sha256"], hashlib.sha256(b"synthetic database").hexdigest())
            self.assertTrue(info["refreshed"])
            self.assertTrue(info["fresh"])
        with self.database() as (_, info):
            self.assertFalse(info["refreshed"])
        self.update.assert_called_once()
        self.assertFalse(list(self.cache.glob(".db-update-*")))

    def test_expired_cache_is_replaced_only_after_a_valid_download(self):
        write_database(self.cache, stale=True, content=b"old DB")

        def download(docker, staging):
            self.assertEqual((self.cache / "db/trivy.db").read_bytes(), b"old DB")
            write_database(staging, content=b"new DB")
            return subprocess.CompletedProcess([], 0)

        self.update.side_effect = download
        with self.database() as (_, info):
            self.assertTrue(info["refreshed"])
            self.assertEqual((self.cache / "db/trivy.db").read_bytes(), b"new DB")
        self.assertFalse(list(self.cache.glob(".previous-db-*")))

    def test_download_failure_keeps_old_database_and_has_no_silent_fallback(self):
        write_database(self.cache, stale=True, content=b"old DB")
        metadata = (self.cache / "db/metadata.json").read_bytes()
        self.update.side_effect = None
        self.update.return_value = subprocess.CompletedProcess([], 1, stderr="synthetic network failure")
        with self.assertRaisesRegex(RuntimeError, "synthetic network failure"):
            with self.database():
                self.fail("An unsuccessful update must not yield a database.")
        self.assertEqual((self.cache / "db/trivy.db").read_bytes(), b"old DB")
        self.assertEqual((self.cache / "db/metadata.json").read_bytes(), metadata)
        self.assertFalse(list(self.cache.glob(".db-update-*")))

    def test_success_exit_with_invalid_download_does_not_replace_old_database(self):
        write_database(self.cache, stale=True, content=b"old DB")
        self.update.side_effect = None
        self.update.return_value = subprocess.CompletedProcess([], 0)
        with self.assertRaisesRegex(ValueError, "incomplete or incompatible"):
            with self.database():
                self.fail("A missing downloaded DB is not success.")
        self.assertEqual((self.cache / "db/trivy.db").read_bytes(), b"old DB")

    def test_promotion_failure_restores_the_original_database(self):
        write_database(self.cache, stale=True, content=b"old DB")
        rename = Path.rename

        def fail_promotion(source, target):
            if source.name == "db" and source.parent.name.startswith(".db-update-"):
                raise PermissionError("synthetic promotion failure")
            return rename(source, target)

        with patch("flican.core.trivy_db.Path.rename", autospec=True, side_effect=fail_promotion):
            with self.assertRaisesRegex(PermissionError, "promotion failure"):
                with self.database():
                    self.fail("Promotion did not succeed.")
        self.assertEqual((self.cache / "db/trivy.db").read_bytes(), b"old DB")
        self.assertFalse(list(self.cache.glob(".previous-db-*")))

    def test_offline_missing_cache_never_creates_or_downloads_database(self):
        with self.assertRaisesRegex(ValueError, "flican db update"):
            with self.database(offline=True):
                self.fail("An offline cache must already exist.")
        self.update.assert_not_called()
        self.assertFalse(self.cache.exists())

    def test_offline_expired_cache_is_explicitly_reported_as_stale(self):
        write_database(self.cache, stale=True)
        with self.database(offline=True) as (_, info):
            self.assertTrue(info["offline"])
            self.assertFalse(info["fresh"])
        self.update.assert_not_called()

    def test_recent_download_grace_period_matches_trivy(self):
        metadata = write_database(self.cache)
        metadata["NextUpdate"] = metadata["UpdatedAt"]
        (self.cache / "db/metadata.json").write_text(json.dumps(metadata))
        with self.database() as (_, info):
            self.assertTrue(info["fresh"])
        self.update.assert_not_called()

    def test_invalid_or_incompatible_metadata_is_repaired_online(self):
        for version in (1, 3, True):
            with self.subTest(version=version):
                write_database(self.cache, version=version)
                with self.database() as (_, info):
                    self.assertEqual(info["database_schema_version"], 2)
                    self.assertTrue(info["refreshed"])
        self.assertEqual(self.update.call_count, 3)

    def test_pin_uses_a_separate_cache_and_remains_fixed_after_expiry(self):
        write_database(self.cache, content=b"latest DB")
        with self.database(db_digest=DIGEST) as (pinned, info):
            self.assertEqual(pinned, self.cache / "pinned" / ("a" * 64))
            self.assertEqual(info["requested_digest"], DIGEST)
            self.assertEqual(info["mode"], "pinned")
        write_database(pinned, stale=True)
        with self.database(db_digest=DIGEST) as (_, info):
            self.assertFalse(info["refreshed"])
            self.assertFalse(info["fresh"])
        self.update.assert_called_once()
        self.assertEqual(self.update.call_args.kwargs, {"db_digest": DIGEST})
        self.assertEqual((self.cache / "db/trivy.db").read_bytes(), b"latest DB")

    def test_different_digest_does_not_reuse_another_pins_database(self):
        paths = []
        for digest in (DIGEST, "sha256:" + "b" * 64):
            with self.database(db_digest=digest) as (cache, _):
                paths.append(cache)
        self.assertNotEqual(*paths)
        self.assertEqual(self.update.call_count, 2)

    def test_unregistered_or_modified_pin_is_not_accepted_offline(self):
        pinned = self.cache / "pinned" / ("a" * 64)
        write_database(pinned)
        with self.assertRaisesRegex(ValueError, "matching pinned receipt"):
            with self.database(db_digest=DIGEST, offline=True):
                self.fail("An arbitrary cached DB cannot claim an OCI digest.")
        with self.database(db_digest=DIGEST):
            pass
        with self.database(db_digest=DIGEST, offline=True):
            pass
        receipt = pinned / ".flican-pin.json"
        valid_receipt = receipt.read_text()
        receipt.write_text(valid_receipt.replace('"schema_version": 1', '"schema_version": true'))
        with self.assertRaisesRegex(ValueError, "matching pinned receipt"):
            with self.database(db_digest=DIGEST, offline=True):
                self.fail("A malformed receipt cannot establish a pinned DB identity.")
        receipt.write_text(valid_receipt)
        (pinned / "db/trivy.db").write_bytes(b"changed DB")
        with self.assertRaisesRegex(ValueError, "matching pinned receipt"):
            with self.database(db_digest=DIGEST, offline=True):
                self.fail("A modified pinned DB must be rejected.")
        self.assertEqual(self.update.call_count, 1)

    def test_invalid_pin_is_rejected_before_cache_or_subprocess_mutation(self):
        for digest in ("2", "latest", "sha256:short", "sha256:" + "A" * 64):
            with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, "--trivy-db-digest"):
                with self.database(db_digest=digest):
                    self.fail("A tag is not an immutable database version.")
        self.update.assert_not_called()
        self.assertFalse(self.cache.exists())

    def test_lock_is_held_through_the_reader_and_released_afterwards(self):
        write_database(self.cache)
        attempted, finished = threading.Event(), threading.Event()
        errors = []

        def another_reader():
            attempted.set()
            try:
                with self.database(offline=True):
                    finished.set()
            except Exception as error:
                errors.append(error)

        with self.database():
            worker = threading.Thread(target=another_reader, daemon=True)
            worker.start()
            self.assertTrue(attempted.wait(1))
            self.assertFalse(finished.wait(0.05))
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertTrue(finished.is_set())
        self.assertEqual(errors, [])

    def test_updater_has_only_cache_mount_and_source_worker_stays_offline(self):
        write_database(self.cache)
        snapshot = self.root / "source"
        snapshot.mkdir()
        updater = build_db_update_docker_command("docker", self.cache, "update-test", "1000:1000", DIGEST)
        scan = build_docker_command("docker", snapshot, self.cache, "scan-test", "1000:1000")
        self.assertIn("--network=bridge", updater)
        self.assertEqual(updater.count("--mount"), 1)
        self.assertNotIn(str(snapshot), " ".join(updater))
        self.assertIn("ghcr.io/aquasecurity/trivy-db@" + DIGEST, updater)
        self.assertIn("--network=none", scan)
        self.assertIn("--skip-db-update", scan)
        self.assertNotIn("--db-repository", scan)


class TestTrivyDatabaseCLI(unittest.TestCase):
    def setUp(self):
        isolated_state(self)
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "flican.yaml").write_text(
            "schema_version: 1\nproject: {name: auto-db, exclude: []}\nscanners: [gitleaks, trivy]\n",
        )
        self.enterContext(patch.dict("os.environ", {"XDG_CACHE_HOME": str(self.root / "cache")}))
        self.enterContext(patch("flican.cli.main.shutil.which", return_value="/fake/docker"))
        self.enterContext(patch("flican.cli.main.run_gitleaks", return_value=subprocess.CompletedProcess(
            [], 0, stdout="[]", stderr="")))
        self.scan = self.enterContext(patch("flican.cli.main.run_trivy", return_value=subprocess.CompletedProcess(
            [], 0, stdout='{"SchemaVersion":2,"Results":[]}', stderr="")))

    def test_scan_automatically_prepares_and_attests_the_database_used(self):
        with patch("flican.cli.main.run_trivy_db_update", side_effect=download_database) as update:
            result = CliRunner().invoke(app, ["scan", str(self.project)])
        self.assertEqual(result.exit_code, 0, result.output)
        update.assert_called_once()
        path = next(self.project.glob(".flican/runs/*"))
        _, report = load_attested_run(path)
        info = report["coverage"]["trivy"]["database"]
        self.assertEqual(info["mode"], "auto")
        self.assertTrue(info["refreshed"])
        run = json.loads((path / "run.json").read_text())
        self.assertEqual(run["stages"][1]["coverage"]["database"], info)

    def test_update_failure_preserves_other_scanner_artifacts_and_returns_two(self):
        with patch("flican.cli.main.run_trivy_db_update", return_value=subprocess.CompletedProcess(
                [], 1, stderr="synthetic network failure")):
            result = CliRunner().invoke(app, ["scan", str(self.project)])
        self.assertEqual(result.exit_code, 2, result.output)
        self.scan.assert_not_called()
        path = next(self.project.glob(".flican/runs/*"))
        self.assertTrue((path / "reports/gitleaks.json").is_file())
        self.assertFalse((path / "manifest.json").exists())
        self.assertIn("synthetic network failure", result.output)

    def test_cli_pin_is_shared_by_prepare_update_and_scan(self):
        cache = self.root / "cache/flican/trivy/pinned" / ("a" * 64)
        with (patch("flican.core.ci.subprocess.run", return_value=subprocess.CompletedProcess([], 0)),
              patch("flican.core.ci.run_trivy_db_update", side_effect=download_database) as prepare,
              patch("flican.cli.main.run_trivy_db_update") as update):
            for command in (["ci", "prepare", str(self.project)], ["db", "update"], ["scan", str(self.project)]):
                result = CliRunner().invoke(app, [*command, "--trivy-db-digest", DIGEST])
                self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(prepare.call_args.kwargs, {"db_digest": DIGEST})
        update.assert_not_called()
        self.assertEqual(self.scan.call_args.args[2], cache)
