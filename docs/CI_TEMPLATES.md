# GitHub Actions and Jenkins templates

The composite action provides source scanning and verified report collection.
The Jenkinsfile and GitHub Actions demo also demonstrate
[application tests](APPLICATION_TESTS.md), OCI build, and
[image/SBOM commands](IMAGE_WORKFLOW.md) on a synthetic calculator project.
Dojo is optional and no reporting token is required. Adapt the examples' project
preparation, tests, and Dockerfile to use them with an existing application.

## Common commands

`flican ci prepare PROJECT [--trivy-cache-dir CACHE]` prepares selected pinned
scanner images, reusing existing copies. With Trivy selected, it also prepares
or updates the database when needed. Preparation may use the network. `scan`
prepares missing/stale data automatically; `--offline` requires prepared data.
Download containers are separate from offline source workers. Scans do not
implicitly pull scanner images.

Default shared cache: `$XDG_CACHE_HOME/flican/trivy` with an absolute XDG base,
otherwise `~/.cache/flican/trivy`. `db update` uses the same default, overridable
by `--cache-dir`. Templates explicitly choose `RUNNER_TEMP`/workspace caches
for CI isolation. `--trivy-db-digest` pins an official database; pass the same
digest to preparation and scanning. See [TRIVY_DATABASE.md](TRIVY_DATABASE.md).

`flican ci collect RESULT --exit-code CODE --workspace WORKSPACE --output-dir DIR`
checks the process result/reference and copies only that run's available artifacts.
`--scan-exit` is also accepted as an alias. `DIR` must be fresh, under
`WORKSPACE/.flican/`, outside its `runs/`. Collection returns:

- `0` for a valid collection of `allow`;
- `1` for a valid collection of `block`;
- `2` for incomplete scans or reference/integrity/collection failures.

Collection failure cannot turn a block into success. Paths must stay inside
the workspace and exact run without traversal/symlinks. Complete runs are checked
against local attestation; scan and collection must share `FLICAN_STATE_DIR`.
A reference without a run, such as a config failure, yields a diagnostic bundle
without invented results.

From the repository, with a fresh destination:

```bash
flican ci prepare tests/fixtures/projects/calculator
flican_scan_exit=0
flican scan tests/fixtures/projects/calculator \
  --result-file .flican/ci/manual-001/result.json || flican_scan_exit=$?
flican ci collect .flican/ci/manual-001/result.json \
  --exit-code "$flican_scan_exit" --workspace "$PWD" \
  --output-dir .flican/ci/manual-001/bundle
```

The `||` captures the actual exit for propagation by collection; it does not
force the gate green with `|| true`.

## Archived bundle

```text
bundle/
  collection.json           # Decision, actual exit, collection result, hashes
  scan-result.json          # Validated invocation reference
  run/
    run.json
    reports/
      findings.json
      ... usable native reports ...
    manifest.json           # For a complete attested execution
```

`collection.json.status` describes **collection**, not absence of vulnerabilities.
A `completed` collection can retain `decision: block` and `exit_code: 1`.
Each `files` entry records relative path, SHA-256, and copied byte count.
Errors leave code `2` diagnostics, possibly some copied files, without claiming
complete collection.

Since the image extension, limits are 64 MiB per report/log, 2 GiB per `.oci.tar`,
2 GiB + 256 MiB total, and 256 paths. Private SQLite/Dojo/registry credentials
are excluded. `verified_locally` proves runner-local verification, not inter-job
trust or a portable Dojo connection. Persistent CI reporting is separate work.

## GitHub Actions

[action.yml](../action.yml) is a Linux composite action requiring Python 3.12+
and Docker. It installs its code in a temporary venv, prepares scanners, runs
`scan`, then `ci collect`. It publishes no application image and receives no
cloud or Dojo credentials.

| Input | Default | Purpose |
| --- | --- | --- |
| `project` | `.` | Existing project containing `flican.yaml` |
| `artifact-directory` | `.flican/ci-artifacts` | Fresh workspace destination |
| `trivy-cache-directory` | Cache under `RUNNER_TEMP` | Optional Trivy cache override |

The action outputs `artifact-directory` and `tool`. `tool` is the isolated
Flican executable path for later steps in the same job; it is not a portable
installation or an output for another runner. The demo passes it through an
environment variable to the image stage, which sets the same private state
location and prepares Trivy with `ci prepare --workflow`.

Action shell steps explicitly use the workspace root, so `project` stays
workspace-relative even when the caller sets another default working directory.
A consumer retains its checkout/tests/build, invokes the action at a verified
commit, and uploads artifacts with `if: always()`. Upload belongs to the caller
and does not change the gate failure. Private action repositories require access
for the consumer; local `uses: ./` does not require cross-repository sharing.

[scan-demo.yml](../.github/workflows/scan-demo.yml) uses `uses: ./` to test this
repository. Manual `workflow_dispatch` selects the source scenario: `allow`,
`block`, or `incomplete`. The workflow configures Docker's containerd image
store, prepares the fixture, runs its tests, invokes the source action, exports
an OCI image, and evaluates the image/SBOM. Action dependencies are pinned to
commits. Token permissions are `contents: read`; checkout credentials are not
persisted.

Source output is collected under `.flican/ci-artifacts/`, image output under
`.flican/image-artifacts/`. Upload runs with `if: always()` and
`include-hidden-files: true`. Only those bundles are uploaded; the OCI file at
`$RUNNER_TEMP/flican-image/candidate.oci.tar` is temporary and is not retained
by this workflow. A source block/error skips dependent build/image steps.
The `allow` source fixture can still yield **workflow failure** if the image
contains blocking findings. Native report counts can change as the DB updates.

## Jenkins

The [Jenkinsfile](../examples/jenkins/Jenkinsfile) is a complete calculator demo
requiring the Flican repository at the workspace root. A **Pipeline script from
SCM** job checks out the selected branch and reads that path. The Linux agent
must match `flican-linux`, have Python 3.12+, a verified Flican command in `PATH`,
and Docker Engine/Buildx with the containerd image store.

It generates `project-BUILD_NUMBER`, runs tests, prepares scanners with
`--workflow`, scans source, exports OCI, and scans the image. Each build uses
`.flican/ci/build-BUILD_NUMBER/` for references, OCI, and separate source/image
bundles. `post/always` archives only `*-bundle/**`, including after exits `1`/`2`.
Failure before collection remains a job failure. Flican's private state stays
outside the archived bundles; scan/collect inherit the same location.

For a real application, replace synthetic preparation with its checkout and
adapt project paths, tests, and Dockerfile. See [examples/README.md](../examples/README.md).

## Validation projects

[demo_project.py](../tests/helpers/demo_project.py) creates a fresh calculator copy:

- `allow`: corrected IaC/Dockerfile and no declared dependencies;
- `block`: original vulnerable fixture with HIGH policy;
- `incomplete`: invalid Dockerfile, preserving other scanner results.

Source fixture: [calculator](../tests/fixtures/projects/calculator/README.md).
Workflow destination `.flican/demo-project` is generated, not the versioned fixture.
The passing fixture is not a coverage benchmark: all four scanners execute, but
an empty dependency file does not exercise CVE detection. `block` retains the
vulnerable dependency.

## Verify an integration

Use fresh disposable copies of the [calculator fixture](../tests/fixtures/projects/calculator/README.md)
and check actual CI conclusions as well as the collected process codes:

| Source scenario | Source scan/collection exit | Dependent work |
| --- | --- | --- |
| `allow` | `0` | Build, then image scan/SBOM |
| `block` | `1` | Build/image skipped; source reports retained |
| `incomplete` | `2` | Build/image skipped; source diagnostics retained |

For a completed image scan, image/collection exit `0` allows the workflow and
`1` blocks it. Operational or integrity errors remain failures. A demo succeeds
as a validation when the real workflow conclusion matches the gates, even if
that conclusion is failure. A blocked scan must never be forced green.

Check artifact hashes/sizes, invocation/run consistency, and all configured
scanner states. No report from a previous build may substitute for the current
run. The [GitHub helper](../tests/helpers/verify_github.py) reads actual run
metadata and checks downloaded source/image bundles using an authenticated `gh`:

```bash
python tests/helpers/verify_github.py \
  --repo YOUR_ACCOUNT/flican \
  --output-dir .local/github-actions-review \
  RUN_ID
```

Use a fresh output directory and the real run ID. For `allow`, the helper
requires both bundles and completed image analysis, and derives success/failure
from the image gate. For `block`/`incomplete`, it requires only the expected
source result. It verifies local byte consistency, not portable signatures.

Remote Dojo reporting and inter-job attestation remain separate extensions;
gate/artifact integration works without them.

References: [Jenkins archiving](https://www.jenkins.io/doc/pipeline/tour/tests-and-artifacts/),
[pinned actions](https://docs.github.com/en/actions/reference/security/secure-use),
[upload-artifact](https://github.com/actions/upload-artifact).
