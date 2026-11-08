"""Opt-in localhost API + native scanner checks; creates and removes test Products."""

import json
import os
import secrets
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from typer.testing import CliRunner

from state_support import isolated_state
from flican.cli.main import app
from flican.core.state import state_directory, write_private_json
from flican.platform.manager import run_compose
from flican.reporting.dojo_client import DojoClient
from flican.reporting.dojo_sync import connection_details, initialize_context, sync_run

FIXTURES = Path(__file__).parent / "fixtures/checkov"


@unittest.skipUnless(os.environ.get("FLICAN_DOJO_LIVE_TESTS") == "1",
                     "Set FLICAN_DOJO_LIVE_TESTS=1 with the local platform running.")
class TestLiveDefectDojo(unittest.TestCase):
    def setUp(self):
        self.original_state = state_directory()
        connection = connection_details()
        isolated_state(self)
        write_private_json(state_directory() / "defectdojo/connection.json", connection)
        self.client = DojoClient(connection["url"], connection["token"])
        self.project = Path(self.enterContext(TemporaryDirectory(prefix="flican-dojo-live-")))
        self.context = None
        self.addCleanup(self.cleanup_remote_product)

    def cleanup_remote_product(self):
        if self.context is None:
            return
        code = (
            "from dojo.models import Product\n"
            f"Product.objects.get(pk={self.context['product_id']}, "
            f"name={json.dumps(self.context['product_name'])}, "
            f"prod_type_id={self.context['prod_type']}).delete()\n"
        )
        with patch.dict(os.environ, {"FLICAN_STATE_DIR": str(self.original_state)}):
            run_compose(["exec", "-T", "uwsgi", "python", "manage.py", "shell", "-c", code],
                        sensitive=True, timeout=120)

    def configure(self, scanner):
        (self.project / "flican.yaml").write_text(
            "schema_version: 1\nproject:\n  name: flican-reporting-validation\n  exclude: []\n"
            f"scanners: [{scanner}]\npolicy:\n  fail_on: high\n",
        )

    def scan(self, code):
        before = set(self.project.glob(".flican/runs/*"))
        result = CliRunner().invoke(app, ["scan", str(self.project)])
        self.assertEqual(result.exit_code, code, result.output)
        created = set(self.project.glob(".flican/runs/*")) - before
        self.assertEqual(len(created), 1)
        return created.pop()

    def rows(self, receipts):
        self.assertEqual(len(receipts), 1)
        return self.client.list("findings", test=receipts[0]["test_id"])

    def test_checkov_close_reopen_triage_partial_and_stale_runs(self):
        self.configure("checkov")
        source = self.project / "main.tf"
        shutil.copyfile(FIXTURES / "vulnerable/main.tf", source)
        self.context = initialize_context(self.project)
        baseline = self.scan(1)
        first = sync_run(baseline)
        rows = self.rows(first)
        self.assertEqual(len(rows), 4)
        ids = {row["unique_id_from_tool"]: row["id"] for row in rows}
        self.assertTrue(all(row["active"] for row in rows))
        self.assertEqual(sync_run(baseline)[0]["status"], "already_synced")
        self.assertEqual(initialize_context(self.project)["engagement_id"], self.context["engagement_id"])

        shutil.copyfile(FIXTURES / "corrected/main.tf", source)
        fixed = self.scan(0)
        closed = self.rows(sync_run(fixed, close_old=True))
        self.assertEqual(len(closed), 4)
        self.assertTrue(all(not row["active"] and row["is_mitigated"] for row in closed))

        shutil.copyfile(FIXTURES / "vulnerable/main.tf", source)
        reappeared = self.scan(1)
        rows = self.rows(sync_run(reappeared))
        self.assertEqual({row["unique_id_from_tool"]: row["id"] for row in rows}, ids)
        self.assertTrue(all(row["active"] for row in rows))

        false_positive = next(row for row in rows if row["title"].startswith("CKV_AWS_56:"))
        self.client.request("PATCH", f"/api/v2/findings/{false_positive['id']}/",
                            {"false_p": True, "active": False})
        repeated = self.scan(1)
        rows = self.rows(sync_run(repeated))
        preserved = next(row for row in rows if row["id"] == false_positive["id"])
        self.assertTrue(preserved["false_p"])
        self.assertFalse(preserved["active"])

        text = source.read_text().replace(
            "  bucket", "  # checkov:skip=CKV_AWS_55: synthetic partial coverage\n  bucket", 1,
        )
        source.write_text(text)
        partial = self.scan(1)
        with self.assertRaisesRegex(ValueError, "complete coverage"):
            sync_run(partial, close_old=True)
        rows = self.rows(sync_run(partial))
        missing = next(row for row in rows if row["title"].startswith("CKV_AWS_55:"))
        self.assertTrue(missing["active"])
        with self.assertRaisesRegex(ValueError, "older run"):
            sync_run(baseline)
        self.assertEqual(len(rows), 4)

    def test_same_line_semgrep_occurrences_keep_distinct_stable_ids(self):
        self.configure("semgrep")
        (self.project / "app.py").write_text("eval(input()); eval(input())\n")
        self.context = initialize_context(self.project)
        first = self.scan(1)
        rows = self.rows(sync_run(first))
        self.assertEqual(len(rows), 2)
        ids = {row["unique_id_from_tool"]: row["id"] for row in rows}
        self.assertEqual(len(ids), 2)
        normalized = json.loads((first / "reports/findings.json").read_text())
        self.assertEqual(len({row["column"] for row in normalized["findings"]}), 2)
        second = self.scan(1)
        repeated = self.rows(sync_run(second))
        self.assertEqual({row["unique_id_from_tool"]: row["id"] for row in repeated}, ids)
        with self.assertRaisesRegex(ValueError, "complete coverage"):
            sync_run(second, close_old=True)

    def test_secret_occurrences_are_redacted_and_keep_distinct_columns(self):
        self.configure("gitleaks")
        unused_secrets = [secrets.token_urlsafe(32), secrets.token_urlsafe(32)]
        (self.project / "app.py").write_text(
            f'api_key = "{unused_secrets[0]}"; auth_token = "{unused_secrets[1]}"\n',
        )
        self.context = initialize_context(self.project)
        run = self.scan(1)
        raw = (run / "reports/gitleaks.json").read_text()
        self.assertTrue(all(value not in raw for value in unused_secrets), "Synthetic secrets were not redacted.")
        normalized = json.loads((run / "reports/findings.json").read_text())
        self.assertEqual(len(normalized["findings"]), 2)
        self.assertEqual(len({row["column"] for row in normalized["findings"]}), 2)
        rows = self.rows(sync_run(run))
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({row["unique_id_from_tool"] for row in rows}), 2)
        transmitted = "\n".join(path.read_text() for path in (run / "reporting").glob("generic-*.json"))
        self.assertTrue(all(value not in transmitted for value in unused_secrets), "Synthetic secrets reached the export.")
