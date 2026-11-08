# Flican's own continuous integration

[ci.yml](../.github/workflows/ci.yml) checks Flican itself on pushes to `dev` or
`main`, pull requests targeting either branch, and manual dispatch. It uses one
Ubuntu 24.04 job with Python 3.12 and a ten-minute timeout.

This differs from [scan-demo.yml](../.github/workflows/scan-demo.yml), which
manually exercises Flican's scanners against synthetic application projects.
Consumer Jenkins/GitHub integrations remain in [CI_TEMPLATES.md](CI_TEMPLATES.md).

## Execution flow

```text
Checkout → Python 3.12 → build wheel → verify contents → install that wheel
    → verify installed CLI → unit tests → SHA256SUMS → upload tested wheel
```

| Step | What it verifies or produces |
| --- | --- |
| Checkout | Current revision, without persisted Git credentials |
| Set up Python | Explicit interpreter; pip download cache keyed by `pyproject.toml` |
| Build | `dist/flican-*.whl`, with runtime dependencies excluded from the build output |
| Verify contents | Runtime source/assets, metadata, README, console command, package boundary |
| Install | Built wheel and its declared dependencies, using a regular installation |
| Verify command | `flican` imports from installed `site-packages`; `--help` works |
| Unit tests | Standard discovery against that installed package |
| Checksum | `dist/SHA256SUMS` identifies the exact wheel bytes |
| Upload | Wheel/checksum artifact retained for seven days after successful checks |

The [wheel verifier](../tests/helpers/verify_wheel.py) compares Python/YAML
runtime files byte-for-byte with `src/flican/`. It rejects missing/extra files,
duplicate ZIP paths, an old or unrelated package namespace, changed source,
stale embedded README, and mismatched distribution/entry-point metadata.
Adding another runtime resource format requires updating this verifier's suffix
list along with package data.

Unit tests run with Python isolated mode. Docker/Dojo test flags are explicitly
disabled; scanner images, vulnerability databases, and a local Dojo server are
not prerequisites. A unit failure stops subsequent upload. This artifact is a
tested development wheel, not publication to PyPI, GHCR, or a GitHub Release.

The workflow has `contents: read`, pinned action commits, and cancellation of
superseded runs for the same branch/PR. It needs no cloud/registry/Dojo secrets.

## Run relevant checks locally

From the repository with its development environment active:

```bash
python -m unittest discover -s tests -q
mkdir -p .local
wheel_check="$(mktemp -d "$PWD/.local/wheel-check.XXXXXX")"
python -m pip wheel . --no-deps --wheel-dir "$wheel_check"
python tests/helpers/verify_wheel.py "$wheel_check"/*.whl
```

Use a fresh build checkout when validating packaging. Stale generated files in
`build/` must not leak into a new wheel. The verifier catches unexpected files.
CI checks out fresh source and installs its built wheel before running tests;
the local development command above uses the editable environment.

For workflow edits, install [actionlint](https://github.com/rhysd/actionlint) and
check GitHub Actions expressions and context availability before pushing:

```bash
actionlint .github/workflows/*.yml
```

The `runner` context is available only at supported workflow keys. For example,
`FLICAN_STATE_DIR` uses `runner.temp` in the unit-test step's environment. Check
[context availability](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability)
when changing expression placement.

## Read CI results

Open **Actions → Flican CI** in the repository and select the relevant run.
Inspect individual steps on failure. After success, download the
`flican-wheel-RUN_ID-ATTEMPT` artifact. From its extracted directory, verify:

```bash
sha256sum --check SHA256SUMS
```

Unit-test success checks the installed Python package. Real scanner/Docker/Dojo
coverage is exercised separately through the tests and scenarios in the
[contribution guide](../CONTRIBUTING.md) and [CI templates](CI_TEMPLATES.md).

References: [workflow triggers](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows),
[setup-python caching](https://github.com/actions/setup-python#caching-packages-dependencies),
[artifact upload](https://github.com/actions/upload-artifact),
[concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).
