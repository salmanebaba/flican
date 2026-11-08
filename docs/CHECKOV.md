# Checkov contract: local Terraform and Dockerfiles

Static IaC and Dockerfile checks using a bundled, controlled Checkov profile.

## Version and scope

```text
bridgecrew/checkov:3.3.30@sha256:4b65e89f1fde292249fc0aa0d0db43302c036dfe39f7370b2d3517571082b894
```

The bundled profile covers `terraform` and `dockerfile`, individually and in a
mixed project. Checks come from this image. Fixtures are scanned statically:
no AWS provisioning, image build, or execution of project `RUN`, `CMD`, or
`HEALTHCHECK` instructions.

Validated inputs are Terraform `.tf`, `Dockerfile`, `Dockerfile.dev`, and
`worker.Dockerfile`, including subdirectories. Selection follows the pinned
engine's naming rules; `Dockerfile.dockerignore` is excluded. Kubernetes,
Terraform plans/state, image contents, and live cloud auditing are outside this
workflow. Checkov does not replace complete Docker syntax validation or inspection
of the base image's effective user.

Checkov is optional and needs neither a Trivy database nor an API key for this
profile. Gitleaks and Semgrep remain the defaults when `scanners` is omitted.

## Configuration

In a Terraform/Dockerfile project's `flican.yaml`:

```yaml
schema_version: 1
project:
  name: configuration-project
  exclude: [.git, .terraform, .venv, .flican]
scanners: [checkov]
policy:
  fail_on: high
```

With Docker and the scanner image already available:

```bash
flican scan /path/to/project
```

Adding `trivy` does not require a cache argument. Its database is automatically
prepared/refreshed unless `--offline` is used. `flican ci prepare /path/to/project`
prepares prerequisites; `flican db update` only updates the shared database.
`--trivy-cache-dir` remains an optional override. Checkov checks are bundled in
its pinned image.

## Execution profile

The [bundled profile](../src/flican/rules/checkov/profile.yaml) enforces Terraform,
Dockerfile, full JSON output, no Prisma Cloud downloads, no result upload,
no external module downloads, and no soft fail.

The container mounts the shared snapshot read-only at `/src`, with no network,
no capabilities, and `no-new-privileges`. Its filesystem is read-only, with a
128 MiB temporary `/tmp`. The host timeout is 180 seconds; `finally` requests
container removal.

Working directory and `HOME` are `/tmp`. The argument deliberately uses
`--directory=/src`, including `=`. In the pinned version, automatic config
search treats the separate `--directory /src` form specially. An explicit config
alone can still merge automatically discovered configuration. See the
[versioned source](https://raw.githubusercontent.com/bridgecrewio/checkov/3.3.30/checkov/common/util/config_utils.py).

Real tests verify that project `.checkov.yaml`/`.checkov.yml` files cannot change
frameworks, enable soft fail, or load Python via `external-checks-dir`.
A missing bundled profile is an error. Repeat these checks after engine upgrades.
Inline `checkov:skip` suppressions are recognized, retained in the native report,
and reflected by `partial` coverage.

## Native report and failures

The normal profile returns `0` when checks have no failures and `1` when checks
fail. The parser also validates JSON and counters; native codes do not directly
become Flican's policy verdict.

Normal JSON contains `check_type`, `results`, and `summary`. One reported framework
produces an object; multiple frameworks produce a list. Validate each report,
reject unexpected/duplicate frameworks, and check the native code against the
sum of failures. A passing framework remains usable when the other produces
the overall native code `1`.

When no check produces a result, Checkov may emit only six summary fields without
framework identity. Accept this form only when no check result or parsing error
is announced without its underlying data. Counters remain global; do not invent
a Terraform/Dockerfile attribution.

**Verified case:** invalid `.tf` can return native `0` with `parsing_errors: 1`.
Flican rejects it with code `2`. Inconsistent counts, incorrect version/framework,
paths outside `/src`, diagnostics at configured WARNING level, and invalid JSON
are also rejected.

### Silently skipped Dockerfiles

**Verified cases:** `FROM` without an argument and non-UTF-8 Dockerfiles can be
ignored with native `0` and no `parsing_errors`. Another valid Dockerfile or
Terraform result can mask the omission.

The CLI therefore passes the discovered, non-excluded Dockerfile inventory to
the parser. Each expected file must appear in at least one passed, failed, or
suppressed Dockerfile check. Otherwise Flican returns `2` before saving successful
reports. Paths are relative to the same snapshot. User-excluded files and output
directories are not required. Files skipped by engine filters also cause an
error; review scope and declare an intentional exclusion in `flican.yaml`.
This proves checks exist for each file, not exhaustive inspection of every
instruction or build stage.

## Severity and normalization

Offline mode can omit native severity, as described in the [Checkov CLI reference](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html).
The prototype policy is:

- absent or `null` native severity: **HIGH**, `severity_source: flican_policy`;
- recognized native severity: preserve it, `severity_source: checkov`;
- unknown native severity: operational error, with no implicit downgrade.

The fallback HIGH is a **Flican blocking level**, not a CVSS score or rating
provided by Checkov.

Each finding keeps check ID/name, `framework`, `resource_id`, snapshot-relative
path, and starting line when available. The parser uses `file_abs_path` for scope
validation: native `file_path` starts with `/` even when project-relative.
`framework`, `resource_id`, and `severity_source` are optional `Finding` fields,
`null` when an adapter does not supply them. JSON retains `schema_version: 1`
with these compatible additions.

## Coverage and gate

`findings.json` includes `coverage.checkov` with version and aggregate `passed`,
`failed`, `skipped`, `parsing_errors`, and `resource_count`. Per-framework entries
under `.frameworks.terraform` and `.frameworks.dockerfile` retain known native
statuses and counts.

The global `framework` is the single reported name, `multiple` for two reports,
or `unattributed` for a summary without identity. Dockerfile coverage also exposes
`inventory_checked`, `files_expected`, and `files_reported` when the CLI supplies
an inventory.

| Status | Meaning |
| --- | --- |
| `completed` | Resources/checks evaluated, with no reported suppression |
| `partial` | At least one check suppressed; inspect the native report |
| `no_resources` | No resources reported in the relevant summary |
| `no_checks` | Resources reported but no check results |
| `not_reported` | No native report for this framework; counts unknown |

`completed` describes reported check evaluation and can include failed checks.
A framework absent from the project can be `not_reported`. A missing expected
Dockerfile yields `2` instead of a successful coverage record.

Mixed fixture coverage excerpt:

```json
{
  "framework": "multiple",
  "status": "completed",
  "failed": 7,
  "resource_count": 2,
  "frameworks": {
    "terraform": {"status": "completed", "failed": 4},
    "dockerfile": {
      "status": "completed",
      "failed": 3,
      "inventory_checked": true,
      "files_expected": 1,
      "files_reported": 1
    }
  }
}
```

The gate evaluates unsuppressed findings against `policy.fail_on`. A passed gate
does not claim complete infrastructure coverage. Missing coverage and suppressions
remain visible in CLI and JSON output.

`checkov.json` is the native report; `findings.json` contains normalized findings,
coverage, and the common verdict. A parser failure marks the Checkov stage
`failed` in `run.json` without registering a valid native report. Other scanners'
usable results survive, the run becomes incomplete, and the final code is `2`.

## Reproducible validation

Terraform `vulnerable`/`corrected` fixtures under `tests/fixtures/checkov/`
contain `aws_s3_bucket_public_access_block`. Observed checks are `CKV_AWS_53`,
`54`, `55`, and `56`: four false values give four findings; corrected values
give four passing checks.

Dockerfile fixtures under `tests/fixtures/checkov/dockerfile/` cover:

- `vulnerable`: `CKV_DOCKER_1` (port 22), `2` (missing HEALTHCHECK), and `3`
  (missing USER), with three findings and two passed checks;
- `corrected`: no findings and five passed checks; its synthetic health command
  is not a production probe;
- `invalid`: silently ignored by the engine and rejected by Flican.

Suppressions of all five applicable checks (`1`, `2`, `3`, `7`, `11`) stay visible
and contribute to evidence that a file was inspected.

Without Docker:

```bash
python -m unittest discover -s tests -p 'test_checkov.py' -v
python -m unittest discover -s tests -p 'test_cli_checkov.py' -v
python -m unittest discover -s tests -p 'test_config.py' -v
```

Real engine, with its image present and Docker accessible:

```bash
FLICAN_CHECKOV_DOCKER_TESTS=1 python -m unittest discover -s tests -p 'test_checkov_docker.py' -v
```

The Docker tests cover fixtures, mixed projects, errors with native `0`,
project config, missing profile, suppressions, absent checks, alternate names,
non-UTF-8 files, and real gates at `high` and `critical` thresholds.
