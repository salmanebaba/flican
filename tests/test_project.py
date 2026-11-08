import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from typer.testing import CliRunner

from flican.cli.main import app
from flican.core.config import load_config
from flican.core.models import Severity


class TestProjectInit(unittest.TestCase):
    def test_creates_valid_configuration(self):
        with TemporaryDirectory() as directory:
            project = Path(directory) / "demo-api"
            project.mkdir()

            result = CliRunner().invoke(
                app, ["project", "init", str(project)]
            )
            self.assertEqual(result.exit_code, 0, result.output)

            config = load_config(project / "flican.yaml")
            self.assertEqual(config["project"]["name"], "demo-api")
            self.assertEqual(config["scanners"], ["gitleaks", "semgrep", "trivy"])
            self.assertEqual(config["policy"]["fail_on"], Severity.HIGH)

    def test_preserves_existing_configuration(self):
        with TemporaryDirectory() as directory:
            project = Path(directory)
            config_path = project / "flican.yaml"
            original = (
                "schema_version: 1\n"
                "project: {name: custom-project, exclude: []}\n"
                "scanners: [checkov]\n"
                "policy: {fail_on: critical}\n"
            ).encode("utf-8")
            config_path.write_bytes(original)

            result = CliRunner().invoke(
                app, ["project", "init", str(project)]
            )

            self.assertEqual(result.exit_code, 2, result.output)
            self.assertIn("already exists", result.stderr)
            self.assertEqual(config_path.read_bytes(), original)