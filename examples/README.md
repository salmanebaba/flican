# CI integration examples

The examples use a synthetic calculator project to demonstrate tests, source
scanning, OCI build, image scanning/SBOM, and report collection. See the
[CI guide](../docs/CI_TEMPLATES.md) for commands and artifact handling. Examples
and fixtures are not installed in the CLI wheel.

## Jenkins

[jenkins/Jenkinsfile](jenkins/Jenkinsfile) expects this Flican repository checked
out at the workspace root. Configure a Pipeline job with **Pipeline script from
SCM** and script path `examples/jenkins/Jenkinsfile`.

The agent needs:

- a Linux label matching `flican-linux`;
- Python 3.12+, Git, and a verified Flican command in `PATH`;
- access to Docker Engine, Buildx, and the containerd image store for OCI export.

The pipeline creates a fresh `project-BUILD_NUMBER` using
[demo_project.py](../tests/helpers/demo_project.py), runs Python unit tests,
prepares scanners, scans source, builds an OCI archive, and evaluates the image.
The `allow` fixture describes source checks only: vulnerabilities in the pinned
base image can still block the image gate.

Source and image bundles are archived from
`.flican/ci/build-BUILD_NUMBER/*-bundle/**` in `post/always`. The OCI archive stays
in the workspace and is not included in that archive pattern. Private state
uses Flican's default location unless the agent sets `FLICAN_STATE_DIR`; scan
and collection must use the same location.

For an application repository, replace synthetic preparation with its checkout,
use its project path, tests, and Dockerfile, and install Flican on the agent.
Use a suitable build agent for application code; a local controller running
trusted demo fixtures is not a general untrusted-project execution service.

## GitHub Actions

The root [composite action](../action.yml) installs isolated Flican, prepares
source scanners, runs the source gate, and collects its bundle. Its `tool`
output exposes the command path for later steps in the **same job**.

[scan-demo.yml](../.github/workflows/scan-demo.yml) also configures Docker for
OCI export, runs the calculator tests, builds the image, and calls image
scan/collection using that command. It uploads both source and image bundles,
even after a gate block. The OCI file is temporary runner data and is not uploaded.

Manual scenarios `allow`, `block`, and `incomplete` describe the source fixture.
A source block or error skips build/image. A source pass can still produce a
failed workflow when the image gate blocks. The
[verification helper](../tests/helpers/verify_github.py) checks that actual
conclusion against the collected decisions and verifies downloaded file hashes.

For existing pipelines, keep checkout/tests/build under CI ownership and adapt
these security steps to the application's paths. See the
[image guide](../docs/IMAGE_WORKFLOW.md) for OCI format and builder requirements.
