import os
import shutil
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import json

from typer.testing import CliRunner
from flican.cli.main import app
from flican.adapters.semgrep import (
    normalize_semgrep_finding,
    parse_semgrep_report,
    run_semgrep,
)
from flican.core.models import Severity
from state_support import isolated_state


@unittest.skipUnless(
    os.environ.get("FLICAN_SEMGREP_DOCKER_TESTS") == "1",
    "Set FLICAN_SEMGREP_DOCKER_TESTS=1 to run Semgrep.",
)
class TestSemgrepDocker(unittest.TestCase):
    def setUp(self):
        isolated_state(self)

    @classmethod
    def setUpClass(cls):
        cls.docker = shutil.which("docker")
        if cls.docker is None:
            raise RuntimeError("Docker is required for these tests.")

    def test_subprocess_shell_true_and_false(self):
        functions = ["run", "Popen", "call", "check_call", "check_output"]

        for shell, expected_code in ((True, 1), (False, 0)):
            with self.subTest(shell=shell), TemporaryDirectory() as directory:
                source = Path(directory)
                lines = ["import subprocess", "command = input()"]
                lines.extend(
                    f"subprocess.{name}(command, shell={shell})"
                    for name in functions
                )
                (source / "app.py").write_text(
                    "\n".join(lines) + "\n",
                    encoding="utf-8",
                )

                result = run_semgrep(self.docker, source)
                self.assertEqual(
                    result.returncode, expected_code, result.stderr
                )

                findings = [
                    normalize_semgrep_finding(raw)
                    for raw in parse_semgrep_report(result)
                ]
                expected = []
                if shell:
                    expected = [
                        (
                            "flican.python.subprocess-shell",
                            "app.py",
                            line,
                            Severity.HIGH,
                        )
                        for line in range(3, 8)
                    ]

                self.assertCountEqual(
                    [
                        (f.rule_id, f.file_path, f.line, f.severity)
                        for f in findings
                    ],
                    expected,
                )

    def test_eval_in_javascript_and_typescript(self):
        for extension, parameter in (
            ("js", "value"),
            ("ts", "value: string"),
        ):
            for call, expected_code in (("eval", 1), ("JSON.parse", 0)):
                with (
                    self.subTest(extension=extension, call=call),
                    TemporaryDirectory() as directory,
                ):
                    source = Path(directory)
                    filename = f"app.{extension}"
                    code = (
                        f"function parse({parameter}) {{\n"
                        f"  return {call}(value);\n"
                        "}\n"
                    )
                    (source / filename).write_text(
                        code, encoding="utf-8"
                    )

                    result = run_semgrep(self.docker, source)
                    self.assertEqual(
                        result.returncode, expected_code, result.stderr
                    )

                    findings = [
                        normalize_semgrep_finding(raw)
                        for raw in parse_semgrep_report(result)
                    ]
                    expected = []
                    if call == "eval":
                        expected = [
                            (
                                "flican.javascript.eval",
                                filename,
                                2,
                                Severity.HIGH,
                            )
                        ]

                    self.assertCountEqual(
                        [
                            (f.rule_id, f.file_path, f.line, f.severity)
                            for f in findings
                        ],
                        expected,
                    )

    def test_cli_applies_policy_to_semgrep_findings(self):
        for threshold, expected_code in (("high", 1), ("critical", 0)):
            with (
                self.subTest(threshold=threshold),
                TemporaryDirectory() as directory,
            ):
                source = Path(directory)
                (source / "app.js").write_text(
                    "function parse(value) {\n"
                    "  return eval(value);\n"
                    "}\n",
                    encoding="utf-8",
                )
                (source / "flican.yaml").write_text(
                    "schema_version: 1\n"
                    "project:\n"
                    "  name: semgrep-cli-test\n"
                    "  exclude: []\n"
                    "scanners: [semgrep]\n"
                    f"policy:\n  fail_on: {threshold}\n",
                    encoding="utf-8",
                )

                result = CliRunner().invoke(app, ["scan", str(source)])
                self.assertEqual(
                    result.exit_code, expected_code, result.output
                )
                self.assertIn("SAST findings: 1", result.stdout)

                reports = list(
                    source.glob(".flican/runs/*/reports/findings.json")
                )
                self.assertEqual(len(reports), 1)
                report = json.loads(reports[0].read_text(encoding="utf-8"))

                self.assertEqual(
                    report["gate"],
                    {
                        "fail_on": threshold,
                        "passed": expected_code == 0,
                    },
                )
                self.assertEqual(
                    [
                        (f["scanner"], f["rule_id"], f["severity"])
                        for f in report["findings"]
                    ],
                    [("semgrep", "flican.javascript.eval", "high")],
                )
                self.assertTrue(
                    (reports[0].parent / "semgrep.json").is_file()
                )
