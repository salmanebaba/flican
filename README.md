# Flican

Security CLI for scanning a project's source and container images, applying a
policy, and keeping verifiable reports. Run it locally or as a step in a
Jenkins or GitHub Actions pipeline.

**Status: development prototype.** Install from this repository or a verified
wheel. No public PyPI or Marketplace release has been published yet.

## Install

Requirements: Linux, Python 3.12+, and access to Docker Engine. From a repository checkout:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
flican doctor
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup.
Scanner images are pinned by digest. Preparation may download these images and
the Trivy database; scan workers run without network access.

## Scan a project

From the project directory, create a configuration if one does not exist:

```bash
flican project init .
```

The starter configuration enables Gitleaks and Semgrep with `fail_on: high`.
An existing `flican.yaml` is preserved and the command returns `2`.
Adjust the scanners and exclusions to the project's files:

```yaml
schema_version: 1
project:
  name: my-project
  exclude: [.git, .venv, node_modules, __pycache__, .flican, .local, build, dist]
scanners: [gitleaks, semgrep]
policy:
  fail_on: high
```

```bash
flican plan .
flican ci prepare .
flican scan .
```

`plan` previews the configuration and file count. `ci prepare` pulls missing
images and prepares the database when Trivy is selected. `scan` analyzes a
temporary copy of the selected files, saves results, and applies the policy.
The `.flican` output directory is always excluded.

| Scanner | Current coverage |
| --- | --- |
| Gitleaks | Secrets in project files |
| Semgrep | Three local rules: Python `eval()`/`subprocess(shell=True)` and JS/TS `eval()` |
| Trivy | Source SCA validated on exact-version `requirements.txt`; separate image scanning |
| Checkov | Terraform `.tf` and Dockerfiles; see the [Checkov contract](docs/CHECKOV.md) |

Add `trivy` and/or `checkov` to `scanners` to enable these checks within their
supported scope. Languages detected by `plan` do not imply full SAST coverage;
coverage depends on the bundled rules.

## Scan an image and generate its SBOM

The CI or developer builds the image and exports an OCI archive. Flican then
analyzes that artifact:

```bash
flican ci prepare . --workflow
flican image scan . --input /path/to/candidate.oci.tar
```

`--workflow` also prepares Trivy and its database for image scanning, even when
source Trivy scanning is disabled. The scan verifies digests, checks CVEs,
secrets, and the effective USER, generates a CycloneDX SBOM, and applies the policy.
The profile accepts one Linux amd64/arm64 image per OCI archive.
Direct registry references and Docker `save` tarballs are unsupported inputs.
The caller remains responsible for retaining the input archive.

The [image guide](docs/IMAGE_WORKFLOW.md) covers OCI export, checks, SBOM,
limits, and the optional build commands.

## Integrate with CI

The primary workflow leaves checkout, application tests, build, push, and
deployment to the CI. Flican provides source and image scans, gates, and evidence:

```text
Checkout → application tests → flican scan → image build → flican image scan
                                    ↓                            ↓
                              collect + archive            collect + archive
```

After checkout, with Flican installed and the project at the workspace root,
this shell block creates a fresh source reference and bundle:

```bash
set -eu
mkdir -p .flican/ci
ci_dir="$(mktemp -d "$PWD/.flican/ci/source.XXXXXX")"
flican ci prepare .
scan_exit=0
flican scan . --result-file "$ci_dir/source.json" || scan_exit=$?
flican ci collect "$ci_dir/source.json" \
  --exit-code "$scan_exit" --workspace "$PWD" --output-dir "$ci_dir/bundle"
```

Archive this invocation's `bundle` with an `always` condition and preserve the
exit code. `ci collect` verifies artifacts and propagates a block or error;
it does not turn a failed gate into success. Scan and collection use the same
private local state (`FLICAN_STATE_DIR` when set). State and credentials stay
outside the bundle.

The [CI examples](docs/CI_TEMPLATES.md) and [JSON reference contract](docs/SCAN_RESULT.md)
provide details. The composite action provides source scanning; the repository's
GitHub Actions demo and Jenkinsfile demonstrate tests, source scanning, OCI build,
and image/SBOM scanning on a synthetic project. Adapt their checkout, tests, and
Dockerfile to your application; see the [image guide](docs/IMAGE_WORKFLOW.md).

## Reports and scan exit codes

| Code | Meaning |
| --- | --- |
| `0` | Required checks completed and the gate passed; findings below the threshold may remain |
| `1` | Checks completed and the policy blocked the result |
| `2` | Configuration, tool, timeout, report, or integrity error; incomplete result |

Runs are stored under `<project>/.flican/runs/<run-id>/`:

- `run.json`: stage states and results;
- `reports/findings.json`: normalized source findings and gate decision;
- usable native reports, with image secrets sanitized;
- `reports/sbom.cdx.json`: CycloneDX inventory for complete image scans;
- `manifest.json`: hashes registered with a local attestation for a complete run.

Usable results survive errors. A `verified_locally` collection proves verification
on this machine against its private state; it is not a portable signature or a
cross-runner trust mechanism.

The gate uses severity, not application reachability. Findings can require human
triage; a vendor may classify a package match differently from a generic CVE
rating. Native image `UNKNOWN` severity becomes HIGH with an explicit policy
source. Exceptions, VEX processing, and manual continuation after a blocked gate
are not implemented in Flican.

## Trivy database and options

The shared cache is `$XDG_CACHE_HOME/flican/trivy` when the XDG base is absolute,
otherwise `~/.cache/flican/trivy`. The database is prepared and refreshed
automatically according to its metadata during scanning. Available options:

- `--trivy-cache-dir PATH`: override the cache for `scan`, `image scan`, or `ci prepare`;
- `--offline` on `scan`/`image scan`/`pipeline run`: reuse a compatible cached database, including an older one;
- `--trivy-db-digest sha256:...`: select an immutable official database artifact;
- `flican db update`: prepare/update the database alone; `--cache-dir` selects its path.

See [TRIVY_DATABASE.md](docs/TRIVY_DATABASE.md) for modes and recorded evidence.

## Optional commands

| Command | Purpose |
| --- | --- |
| `flican test PROJECT` | Run the declared application test command in a container |
| `flican build PROJECT` | Build an OCI archive with the available BuildKit backend |
| `flican pipeline run PROJECT` | Chain source checks, optional tests, build, and image checks; `--image-input` accepts an existing image |
| `flican platform up`, `status`, `stop` | Manage the local DefectDojo stack |
| `flican dojo init PROJECT`, `flican dojo sync RUN_PATH` | Initialize contexts and synchronize attested local source scans |

These commands are explicit. An existing pipeline can keep its tests and builder
and call only `scan` and `image scan`. DefectDojo remains optional; portable
reporting to a remote service from CI has not been delivered.

## Documentation and development

- [Guide index](docs/README.md): detailed contracts, configuration, and limits.
- [CI examples](examples/README.md): Jenkins template and GitHub action usage.
- [Contributing](CONTRIBUTING.md): development environment, tests, and branches.
- [Architecture and roadmap](docs/ARCHITECTURE.md): components, data flow, and planned extensions.

`main` carries the stable version; `dev` integrates current changes. Tool tests
remain versioned with the code. Tests, labs, caches, and demos are not installed
in the wheel. Live cloud auditing, DAST, AI, controlled registry publication,
and SARIF/HTML exports remain future extensions.

## License

Flican is distributed under the [MIT license](LICENSE). Scanner engines and the
optional DefectDojo stack retain their own licenses.
