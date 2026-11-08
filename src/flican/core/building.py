"""Build one OCI artifact with the existing local Docker Engine BuildKit driver."""

import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from flican.core.artifacts import MAX_IMAGE_BYTES
from flican.core.process import run_bounded


def _read_tool(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=True)
    if len(result.stdout) > 128 * 1024:
        raise ValueError("Unexpectedly large Docker capability response.")
    return result.stdout.strip()


def builder_details(docker: str) -> dict:
    endpoint = os.environ.get("DOCKER_HOST") or json.loads(_read_tool(
        [docker, "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
    ))
    if not isinstance(endpoint, str) or not endpoint.startswith("unix:///"):
        raise ValueError("This build backend requires a local Docker Engine Unix socket.")
    info = json.loads(_read_tool([docker, "info", "--format",
        '{"security":{{json .SecurityOptions}},"driver":{{json .DriverStatus}},"plugins":{{json .ClientInfo.Plugins}}}']))
    plugins = [item for item in info["plugins"] if item.get("Name") == "buildx"]
    if len(plugins) != 1 or not Path(plugins[0]["Path"]).is_file():
        raise ValueError("A working Docker Buildx plugin is required.")
    if not any("containerd.snapshotter" in str(item) for item in info["driver"]):
        raise ValueError("OCI export requires the Docker containerd image store for this backend. "
                         "No alternate or privileged builder was started.")
    description = _read_tool([docker, "buildx", "inspect", "default"])
    if not any(line.strip().startswith("Driver:") and line.split(":", 1)[1].strip() == "docker"
               for line in description.splitlines()):
        raise ValueError("The default builder must use the existing Docker Engine driver.")
    return {"backend": "buildkit", "driver": "docker", "endpoint": endpoint,
            "rootless": "name=rootless" in info["security"], "builder": description,
            "buildx_version": plugins[0].get("Version"), "plugin_directory": str(Path(plugins[0]["Path"]).parent)}


def run_build(docker: str, snapshot: Path, settings: dict, root: Path) -> dict:
    context = (snapshot / settings["context"]).resolve(strict=True)
    dockerfile = (snapshot / settings["dockerfile"]).resolve(strict=True)
    if (not context.is_dir() or not dockerfile.is_file() or not context.is_relative_to(snapshot)
            or not dockerfile.is_relative_to(snapshot)):
        raise ValueError("The build context and Dockerfile must exist inside the selected snapshot.")
    output, metadata = root / "image/candidate.oci.tar", root / "reports/buildkit.json"
    if any("," in str(path) for path in (context, dockerfile, output)):
        raise ValueError("Build paths containing commas are not supported.")
    if output.exists() or output.is_symlink():
        raise ValueError("Build output must be a fresh artifact.")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = builder_details(docker)
    with TemporaryDirectory(prefix="flican-build-client-") as temporary:
        config = Path(temporary)
        (config / "config.json").write_text(json.dumps({"auths": {}, "cliPluginsExtraDirs": [details["plugin_directory"]]}))
        env = {"PATH": os.environ.get("PATH", os.defpath), "LANG": "C.UTF-8",
               "DOCKER_CONFIG": str(config), "BUILDX_CONFIG": str(config / "buildx"),
               "DOCKER_HOST": details["endpoint"], "BUILDX_NO_DEFAULT_ATTESTATIONS": "1"}
        command = [docker, "buildx", "build", "--builder", "default", "--progress=plain",
                   "--provenance=false", "--sbom=false", "--network=" + settings["network"],
                   "--platform", settings["platform"], "--file", str(dockerfile),
                   "--metadata-file", str(metadata), "--output",
                   f"type=oci,oci-mediatypes=true,compression=gzip,force-compression=true,dest={output}", str(context)]
        try:
            code = run_bounded(command, root / "logs/build.log", root / "logs/build.log",
                               timeout=settings["timeout_seconds"], env=env,
                               watched=((output, MAX_IMAGE_BYTES), (metadata, 4 * 1024 * 1024)))
            if code != 0:
                raise RuntimeError(f"BuildKit exited with code {code}; inspect logs/build.log.")
            if not output.is_file() or output.is_symlink() or not metadata.is_file() or metadata.is_symlink():
                raise ValueError("BuildKit did not produce the expected OCI archive and metadata.")
            output.chmod(0o600)
            metadata.chmod(0o600)
            native = json.loads(metadata.read_text())
            if not isinstance(native, dict):
                raise ValueError("Invalid BuildKit metadata.")
            return {**details, "metadata": native}
        except BaseException:
            output.unlink(missing_ok=True)
            raise
