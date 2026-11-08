"""Artifact commands and workflow dependencies cannot turn partial evidence into PASS."""

import contextlib
import json
import subprocess
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import yaml
from typer.testing import CliRunner

from oci_support import make_oci
from state_support import isolated_state
from flican.cli.main import app
from flican.core.ci import collect_scan
from flican.core.config import load_config
from flican.core.oci import inspect_oci
from flican.core.provenance import load_attested_execution, load_attested_run

IMAGE = "python:test@sha256:" + "a" * 64


class TestArtifactWorkflow(unittest.TestCase):
    def setUp(self):
        isolated_state(self)
        self.workspace = Path(self.enterContext(TemporaryDirectory()))
        self.project = self.workspace / "project"
        self.project.mkdir()
        self.config = self.project / "flican.yaml"
        self.settings = {"schema_version": 1, "project": {"name": "workflow-test", "exclude": []},
                         "scanners": ["gitleaks"], "tests": {"image": IMAGE, "command": ["python", "-m", "unittest"]},
                         "build": {"context": ".", "dockerfile": "Dockerfile"}}
        self.save_config()
        (self.project / "app.py").write_text("value = 1\n")
        (self.project / "Dockerfile").write_text("FROM scratch\nCOPY app.py /app.py\nUSER 65532\n")
        self.reference = self.project / ".flican/result.json"
        self.user, self.test_code, self.build_error, self.source_block = "65532", 0, False, False
        self.calls = []
        self.enterContext(patch("flican.cli.building.shutil.which", return_value="/fake/docker"))
        self.enterContext(patch("flican.cli.building.run_build", side_effect=self.build))
        self.enterContext(patch("flican.cli.images.run_image_scan", side_effect=self.scan_image))
        self.enterContext(patch("flican.cli.images.run_sbom_conversion", side_effect=self.sbom))
        self.enterContext(patch("flican.cli.images.trivy_database", side_effect=lambda *a, **k: contextlib.nullcontext(
            (self.workspace, {"mode": "offline", "fresh": False}))))
        self.enterContext(patch("flican.cli.testing.run_application_tests", side_effect=self.execute_tests))
        self.enterContext(patch("flican.cli.main.run_gitleaks", side_effect=self.gitleaks))
        self.enterContext(patch("flican.cli.pipeline.run_bounded", side_effect=self.child))

    def save_config(self):
        self.config.write_text(yaml.safe_dump(self.settings))

    def build(self, docker, snapshot, settings, root):
        (root / "logs").mkdir(exist_ok=True)
        (root / "logs/build.log").write_text("synthetic BuildKit log\n")
        if self.build_error:
            raise RuntimeError("synthetic build error")
        make_oci(root / "image/candidate.oci.tar", user=self.user)
        image = inspect_oci(root / "image/candidate.oci.tar")
        metadata = {"containerimage.digest": image["manifest_digest"], "containerimage.config.digest": image["config_digest"]}
        (root / "reports/buildkit.json").write_text(json.dumps(metadata))
        return {"driver": "docker", "rootless": False, "metadata": metadata}

    def scan_image(self, docker, layout, cache, output, log):
        index = json.loads((layout / "index.json").read_text())
        descriptor = index["manifests"][0]
        manifest = json.loads((layout / "blobs/sha256" / descriptor["digest"][7:]).read_text())
        output.write_text(json.dumps({"SchemaVersion": 2, "ArtifactType": "container_image", "Results": [],
                                      "Metadata": {"ImageID": manifest["config"]["digest"]}}))
        log.parent.mkdir(exist_ok=True)
        log.write_text("")
        return 0

    def sbom(self, docker, report, output, log):
        output.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                                      "metadata": {"component": {"type": "container", "name": "candidate"}}}))
        log.write_text("")
        return 0

    def execute_tests(self, docker, snapshot, settings, log):
        log.parent.mkdir(exist_ok=True)
        log.write_text("synthetic application test log\n")
        return self.test_code

    def gitleaks(self, *args):
        if self.source_block:
            return subprocess.CompletedProcess([], 10, stdout='[{"RuleID":"synthetic","File":"/src/app.py"}]',
                                               stderr="12:00PM WRN leaks found: 1\n")
        return subprocess.CompletedProcess([], 0, stdout="[]", stderr="")

    def child(self, command, stdout, stderr, **options):
        arguments = command[5:]
        self.calls.append(arguments[0])
        result = CliRunner().invoke(app, arguments)
        stdout.parent.mkdir(exist_ok=True)
        stdout.write_text(result.output)
        return result.exit_code

    def invoke(self, command, *options):
        return CliRunner().invoke(app, [*command, str(self.project), *options, "--result-file", str(self.reference)])

    def value(self):
        return json.loads(self.reference.read_text())

    def test_build_artifact_is_verified_and_collectable(self):
        result = self.invoke(["build"])
        self.assertEqual(result.exit_code, 0, result.output)
        value = self.value()
        manifest = load_attested_execution(Path(value["run_path"]))
        self.assertEqual(manifest["mode"], "build")
        self.assertIn("image/candidate.oci.tar", manifest["artifacts"])
        summary = collect_scan(self.reference, 0, self.workspace, self.workspace / ".flican/bundle")
        self.assertEqual(summary["exit_code"], 0)
        with self.assertRaisesRegex(ValueError, "not a security scan"):
            load_attested_run(Path(value["run_path"]))

    def test_build_failure_keeps_logs_and_has_no_image_attestation(self):
        self.build_error = True
        result = self.invoke(["build"])
        self.assertEqual(result.exit_code, 2, result.output)
        value = self.value()
        self.assertIsNone(value["manifest_path"])
        self.assertIn("logs/build.log", value["artifact_paths"])

    def test_build_collection_accepts_an_oci_archive_larger_than_64_mib(self):
        padding = self.workspace / "padding.bin"
        with padding.open("wb") as stream:
            stream.truncate(65 * 1024 * 1024)

        def large_build(*args):
            details = self.build(*args)
            with tarfile.open(args[-1] / "image/candidate.oci.tar", "a") as archive:
                info = tarfile.TarInfo("unused-layout-padding")
                info.size = padding.stat().st_size
                with padding.open("rb") as content:
                    archive.addfile(info, content)
            return details

        with patch("flican.cli.building.run_build", side_effect=large_build):
            result = self.invoke(["build"])
        self.assertEqual(result.exit_code, 0, result.output)
        summary = collect_scan(self.reference, 0, self.workspace, self.workspace / ".flican/large-bundle")
        self.assertEqual(summary["exit_code"], 0, summary)
        image = next(item for item in summary["files"] if item["path"].endswith(".oci.tar"))
        self.assertGreater(image["size_bytes"], 64 * 1024 * 1024)
        self.assertEqual(summary["attestation"], "verified_locally")

    def test_runtime_root_and_unknown_user_block_image_policy(self):
        for index, user in enumerate(("", "app")):
            with self.subTest(user=user):
                image = self.workspace / f"input-{index}.oci.tar"
                make_oci(image, user=user)
                self.reference = self.project / f".flican/image-{index}.json"
                result = self.invoke(["image", "scan"], "--input", str(image), "--offline")
                self.assertEqual(result.exit_code, 1, result.output)
                root = Path(self.value()["run_path"])
                findings = json.loads((root / "reports/findings.json").read_text())
                self.assertEqual(len(findings["findings"]), 1)
                self.assertFalse(findings["gate"]["passed"])
                self.assertTrue((root / "reports/sbom.cdx.json").is_file())

    def test_image_tool_failure_keeps_config_findings_but_never_passes(self):
        image = self.workspace / "input.oci.tar"
        make_oci(image, user="0")
        with patch("flican.cli.images.run_image_scan", side_effect=RuntimeError("scanner error")):
            result = self.invoke(["image", "scan"], "--input", str(image), "--offline")
        self.assertEqual(result.exit_code, 2, result.output)
        root = Path(self.value()["run_path"])
        findings = json.loads((root / "reports/findings.json").read_text())
        self.assertEqual(len(findings["findings"]), 1)
        self.assertIsNone(findings["gate"]["passed"])
        self.assertIsNone(self.value()["manifest_path"])

    def test_full_workflow_uses_one_source_identity_and_one_candidate(self):
        result = self.invoke(["pipeline", "run"], "--offline")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.calls, ["scan", "test", "build", "image"])
        root = Path(self.value()["run_path"])
        report = json.loads((root / "reports/pipeline.json").read_text())
        source_hash = json.loads((root / "run.json").read_text())["source_sha256"]
        for stage in ("source", "tests", "build"):
            child = json.loads((root / f"stages/{stage}/run/run.json").read_text())
            self.assertEqual(child["source_sha256"], source_hash)
        manifest = load_attested_execution(root)
        self.assertEqual(manifest["artifacts"][report["candidate_artifact"]], report["image"]["archive_sha256"])
        collected = collect_scan(self.reference, 0, self.workspace, self.workspace / ".flican/full-bundle")
        self.assertEqual(collected["attestation"], "verified_locally")
        self.assertTrue((self.workspace / ".flican/full-bundle/pipeline-result.json").is_file())

    def test_source_block_skips_dependent_stages_without_building(self):
        self.source_block = True
        result = self.invoke(["pipeline", "run"], "--offline")
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertEqual(self.calls, ["scan"])
        run = json.loads(Path(self.value()["run_report_path"]).read_text())
        self.assertEqual([stage["status"] for stage in run["stages"]], ["completed", "skipped", "skipped", "skipped"])
        self.assertEqual(run["decision"], "block")

    def test_application_failure_blocks_build_and_image(self):
        self.test_code = 1
        result = self.invoke(["pipeline", "run"], "--offline")
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertEqual(self.calls, ["scan", "test"])
        self.assertEqual(self.value()["decision"], "block")

    def test_build_error_keeps_completed_stage_evidence(self):
        self.build_error = True
        result = self.invoke(["pipeline", "run"], "--offline")
        self.assertEqual(result.exit_code, 2, result.output)
        root = Path(self.value()["run_path"])
        self.assertTrue((root / "stages/source/run/reports/gitleaks.json").is_file())
        self.assertTrue((root / "stages/tests/run/logs/tests.log").is_file())
        self.assertTrue((root / "stages/build/run/logs/build.log").is_file())
        self.assertIsNone(self.value()["manifest_path"])

    def test_image_policy_block_is_preserved_in_the_complete_workflow(self):
        self.user = "0"
        result = self.invoke(["pipeline", "run"], "--offline")
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertEqual(self.calls, ["scan", "test", "build", "image"])
        self.assertEqual(self.value()["status"], "completed")

    def test_external_image_does_not_trigger_a_second_build(self):
        image = self.workspace / "external.oci.tar"
        make_oci(image)
        self.settings.pop("build")
        self.settings.pop("tests")
        self.save_config()
        result = self.invoke(["pipeline", "run"], "--image-input", str(image), "--offline")
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.calls, ["scan", "image"])
        root = Path(self.value()["run_path"])
        report = json.loads((root / "reports/pipeline.json").read_text())
        self.assertEqual(report["source_to_image"], "unverified-external")

    def test_invalid_build_settings_are_rejected(self):
        for changes in ({"context": "../outside"}, {"dockerfile": "/etc/passwd"}, {"network": "host"},
                        {"timeout_seconds": True}, {"backend": "unknown"}, {"platform": "linux/amd64,linux/arm64"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.settings["build"] = {"context": ".", "dockerfile": "Dockerfile", **changes}
                self.save_config()
                load_config(self.config)

    def test_changed_candidate_cannot_receive_a_passing_workflow_attestation(self):
        original = self.child
        def mutate_after_evaluation(command, stdout, stderr, **options):
            code = original(command, stdout, stderr, **options)
            arguments = command[5:]
            if arguments[0] == "image":
                Path(arguments[arguments.index("--input") + 1]).write_bytes(b"changed candidate")
            return code
        with patch("flican.cli.pipeline.run_bounded", side_effect=mutate_after_evaluation):
            result = self.invoke(["pipeline", "run"], "--offline")
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIsNone(self.value()["manifest_path"])
        self.assertIn("candidate", result.output)

    def test_source_identity_change_stops_the_workflow_before_build(self):
        original = self.child
        def mutate_source(command, stdout, stderr, **options):
            arguments = command[5:]
            if arguments[0] == "test":
                (Path(arguments[1]) / "app.py").write_text("value = 999\n")
            return original(command, stdout, stderr, **options)
        with patch("flican.cli.pipeline.run_bounded", side_effect=mutate_source):
            result = self.invoke(["pipeline", "run"], "--offline")
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertEqual(self.calls, ["scan", "test"])
        self.assertIn("Source identity", result.output)
