import json
import subprocess
import unittest
from importlib.resources import files
from unittest.mock import patch

import yaml

from state_support import isolated_state
from flican.core.state import read_private_json, state_directory
from flican.platform.manager import prepare_platform, run_compose


class TestLocalPlatform(unittest.TestCase):
    def setUp(self):
        isolated_state(self)

    def test_prepare_preserves_secrets_and_refuses_an_implicit_port_change(self):
        first = prepare_platform()
        root = state_directory() / "defectdojo"
        environment = (root / "compose.env").read_bytes()
        login = read_private_json(root / "login.json")
        self.assertEqual(prepare_platform(), first)
        self.assertEqual((root / "compose.env").read_bytes(), environment)
        self.assertEqual(read_private_json(root / "login.json"), login)
        self.assertGreater(len(login["password"]), 20)
        with self.assertRaisesRegex(ValueError, "migration"):
            prepare_platform(8099)
        self.assertEqual((root / "compose.env").read_bytes(), environment)

    def test_compose_publishes_only_the_loopback_web_port(self):
        compose = yaml.safe_load(files("flican.platform").joinpath("compose.yaml").read_text())
        for name, service in compose["services"].items():
            ports = service.get("ports", [])
            if name == "nginx":
                self.assertTrue(ports)
                self.assertTrue(all(port.startswith("127.0.0.1:") for port in ports))
            else:
                self.assertEqual(ports, [])
            self.assertIn("@sha256:", service["image"])
            self.assertNotIn("docker.sock", json.dumps(service.get("volumes", [])))
        self.assertTrue(compose["networks"]["dojo"]["internal"])

    def test_bootstrap_success_does_not_write_the_token_to_a_log(self):
        prepare_platform()
        result = subprocess.CompletedProcess([], 0, stdout='FLICAN_BOOTSTRAP={"token":"synthetic-token"}\n', stderr="")
        with patch("flican.platform.manager.shutil.which", return_value="docker"), patch(
            "flican.platform.manager.subprocess.run", return_value=result,
        ):
            run_compose(["exec", "bootstrap"], sensitive=True)
        root = state_directory() / "defectdojo"
        self.assertFalse((root / "compose.log").exists())
        self.assertFalse((root / "bootstrap-error.log").exists())

    def test_bootstrap_error_log_redacts_credentials_and_token_receipts(self):
        prepare_platform()
        root = state_directory() / "defectdojo"
        password = read_private_json(root / "login.json")["password"]
        result = subprocess.CompletedProcess([], 1,
            stdout='FLICAN_BOOTSTRAP={"token":"synthetic-token"}\n', stderr="Failed: " + password)
        with patch("flican.platform.manager.shutil.which", return_value="docker"), patch(
            "flican.platform.manager.subprocess.run", return_value=result,
        ), self.assertRaises(RuntimeError):
            run_compose(["exec", "bootstrap"], sensitive=True)
        log = (root / "bootstrap-error.log").read_text()
        self.assertNotIn(password, log)
        self.assertNotIn("synthetic-token", log)
        self.assertIn("[REDACTED]", log)
