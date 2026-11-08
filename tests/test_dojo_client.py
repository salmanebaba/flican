import unittest
from unittest.mock import patch

from flican.reporting.dojo_client import DojoAPIError, DojoClient, NoRedirect


class TestDojoClient(unittest.TestCase):
    def test_credentials_require_https_or_loopback_and_no_embedded_userinfo(self):
        for url in ("http://remote.example", "https://user:pass@example.com", "https://example.com?token=x"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                DojoClient(url, "synthetic-token")
        for url in ("http://127.0.0.1:8088", "http://localhost:8088", "https://example.com"):
            with self.subTest(url=url):
                self.assertEqual(DojoClient(url, "synthetic-token").url, url)

    def test_redirects_and_pagination_do_not_forward_credentials(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.example"))
        client = DojoClient("http://127.0.0.1:8088", "synthetic-token")
        with patch.object(client, "request", return_value={"results": [], "next": "https://other.example/api/v2/findings/"}) as request:
            with self.assertRaisesRegex(DojoAPIError, "origin"):
                client.list("findings", test=1)
            request.assert_called_once()

    def test_reimport_explicitly_disables_closing_and_does_not_force_triage(self):
        client = DojoClient("http://127.0.0.1:8088", "synthetic-token")
        with patch.object(client, "request", return_value={"test": 4}) as request:
            client.reimport(4, {"findings": []}, close_old=False, completed_at="2026-10-31T10:00:00+00:00")
        payload = request.call_args.kwargs["content"]
        self.assertIn(b'name="close_old_findings"\r\n\r\nfalse', payload)
        self.assertIn(b'name="minimum_severity"\r\n\r\nInfo', payload)
        self.assertIn(b'name="deduplication_execution_mode"\r\n\r\nsync', payload)
        self.assertNotIn(b'name="active"', payload)
        self.assertNotIn(b'name="verified"', payload)
