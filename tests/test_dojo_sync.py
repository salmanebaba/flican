import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from dojo_support import PROFILE, create_run
from state_support import isolated_state

from flican.core.state import StateStore
from flican.reporting.dojo_client import DojoAPIError
from flican.reporting.dojo_sync import _ensure, context_identity, sync_run

URL = "http://127.0.0.1:8088"


class FakeDojo:
    def __init__(self):
        self.rows = {}
        self.calls = 0
        self.unavailable = False
        self.lose_response = False
        self.test = {"id": 3, "engagement": 2, "title": "Managed Test",
                     "test_type_name": "Flican Checkov (Generic Findings Import)",
                     "deduplication_algorithm": "unique_id_from_tool",
                     "hash_code_fields": ["unique_id_from_tool"], "description": ""}

    def request(self, method, path, data=None):
        if self.unavailable:
            raise DojoAPIError("Simulated unavailable instance.")
        if path == "/api/v2/products/1/":
            return {"id": 1, "name": "Managed Product", "prod_type": 7}
        if path == "/api/v2/engagements/2/":
            return {"id": 2, "name": "Managed Engagement", "product": 1}
        if path == "/api/v2/tests/3/":
            return dict(self.test)
        raise AssertionError((method, path))

    def reimport(self, test_id, report, *, close_old, completed_at):
        self.calls += 1
        incoming = {row["unique_id_from_tool"] for row in report["findings"]}
        if close_old:
            for identity, row in self.rows.items():
                if identity not in incoming:
                    row["active"] = False
        for row in report["findings"]:
            identity = row["unique_id_from_tool"]
            self.rows.setdefault(identity, {"id": len(self.rows) + 1, "test": test_id,
                                           "active": True, "unique_id_from_tool": identity})
        self.test["description"] = report["description"]
        if self.lose_response:
            self.lose_response = False
            raise DojoAPIError("Simulated response loss after server commit.")
        return {"test_id": test_id}

    def list(self, resource, **filters):
        if resource == "findings" and filters == {"test": 3}:
            return list(self.rows.values())
        raise AssertionError((resource, filters))


class TestDojoSynchronization(unittest.TestCase):
    def setUp(self):
        isolated_state(self)
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.project = self.root / "project"
        self.project.mkdir()
        _, self.key = context_identity(self.project, "local", URL)
        self.store = StateStore()
        self.store.put("context", self.key, {
            "key": self.key, "scope": "local", "project_path": str(self.project), "url": URL,
            "product_id": 1, "product_name": "Managed Product", "prod_type": 7,
            "engagement_id": 2, "engagement_name": "Managed Engagement",
        })
        self.store.put("stream", self.key + ":checkov", {
            "profile_hash": PROFILE, "title": "Managed Test", "test_id": 3,
        })
        self.server = FakeDojo()
        self.enterContext(patch("flican.reporting.dojo_sync.connection_details", return_value={
            "url": URL, "token": "synthetic-unit-token",
        }))
        self.client = self.enterContext(patch("flican.reporting.dojo_sync.DojoClient", return_value=self.server))

    def test_failed_gate_imports_and_repeat_sync_is_idempotent(self):
        run, _ = create_run(self.project)
        receipts = sync_run(run)
        self.assertEqual(receipts[0]["status"], "synced")
        self.assertEqual(receipts[0]["test_id"], 3)
        self.assertIn("Local policy gate: FAIL", self.server.test["description"])
        repeated = sync_run(run)
        self.assertEqual(repeated[0]["status"], "already_synced")
        self.assertEqual(self.server.calls, 1)
        self.assertEqual(len(self.server.rows), 1)
        self.assertEqual(len(list((run / "reporting").glob("defectdojo-*.json"))), 1)
        self.assertEqual(len(list((run / "reporting").glob("generic-*.json"))), 1)

    def test_network_failure_retains_pending_receipt_and_retries_same_test(self):
        run, _ = create_run(self.project)
        self.server.unavailable = True
        with self.assertRaises(DojoAPIError):
            sync_run(run)
        self.assertTrue((run / "reports/findings.json").is_file())
        receipts = list((run / "reporting").glob("defectdojo-*.json"))
        self.assertEqual(len(receipts), 1)
        self.assertIn('"status": "pending"', receipts[0].read_text())
        self.server.unavailable = False
        self.assertEqual(sync_run(run)[0]["status"], "synced")
        self.assertEqual(len(self.server.rows), 1)

    def test_response_loss_after_commit_can_be_replayed_without_duplicates(self):
        run, _ = create_run(self.project)
        self.server.lose_response = True
        with self.assertRaises(DojoAPIError):
            sync_run(run)
        self.assertEqual(len(self.server.rows), 1)
        self.assertEqual(sync_run(run)[0]["status"], "synced")
        self.assertEqual(len(self.server.rows), 1)
        self.assertEqual(self.server.calls, 2)

    def test_stale_run_is_refused_before_upload(self):
        older, _ = create_run(self.project)
        newer, _ = create_run(self.project, started="2026-10-31T11:00:00.000000+00:00")
        sync_run(newer)
        with self.assertRaisesRegex(ValueError, "older run"):
            sync_run(older)
        self.assertEqual(self.server.calls, 1)

    def test_partial_coverage_and_changed_profiles_do_not_close_findings(self):
        partial, _ = create_run(self.project, status="partial", skipped=1)
        with self.assertRaisesRegex(ValueError, "complete coverage"):
            sync_run(partial, close_old=True)
        self.assertEqual(self.server.calls, 0)
        stream = self.store.get("stream", self.key + ":checkov")
        stream["profile_hash"] = "different-profile"
        self.store.put("stream", self.key + ":checkov", stream)
        with self.assertRaisesRegex(ValueError, "compatible"):
            sync_run(partial)
        self.assertEqual(self.server.calls, 0)

    def test_modified_reports_are_rejected_before_network_access(self):
        run, _ = create_run(self.project)
        (run / "reports/findings.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "integrity"):
            sync_run(run)
        self.client.assert_not_called()

    def test_replaced_test_and_unsafe_deduplication_are_refused(self):
        for index, change in enumerate(({"engagement": 99}, {"deduplication_algorithm": "hash_code"})):
            with self.subTest(change=change):
                run, _ = create_run(self.project, started=f"2026-10-31T10:00:0{index}.000000+00:00")
                original = dict(self.server.test)
                self.server.test.update(change)
                message = "registered Test" if "engagement" in change else "deduplication"
                with self.assertRaisesRegex(ValueError, message):
                    sync_run(run)
                self.server.test = original
        self.assertEqual(self.server.calls, 0)

    def test_ambiguous_remote_contexts_are_not_adopted(self):
        client = Mock()
        client.list.return_value = [{"id": 1, "name": "same"}, {"id": 2, "name": "same"}]
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            _ensure(client, "products", None, {}, {"name": "same"}, {"name": "same"})
        client.request.assert_not_called()
