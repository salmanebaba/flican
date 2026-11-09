# Developing Flican

Tool code lives under `src/flican/`. Tests and small fixtures are versioned with
the code; they are not installed in the user wheel.

## Environment

From the repository, with Python 3.12+:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

An editable installation makes `flican` use the modified source. Docker is needed
for scanners and container integration checks. Standard unit tests use mocks and
temporary directories.

## Verification

```bash
python -m unittest discover -s tests -q
git diff --check
```

The [tool CI workflow](docs/TOOL_CI.md) builds and verifies a wheel, installs it,
and runs unit tests on pushes/PRs for `dev` and `main`. A separate security job
uses Flican to scan the repository and the resolved dependencies of its isolated
installation. The tested wheel/checksum and security reports are retained as
GitHub Actions artifacts. The separate `scan-demo.yml` workflow exercises
scanners on synthetic application projects.

For workflow changes, run `actionlint .github/workflows/*.yml` to check GitHub
expressions and supported contexts. See [tool CI validation](docs/TOOL_CI.md).

Docker and live DefectDojo tests are optional and explicitly enabled. Their
requirements and commands are in the [Checkov](docs/CHECKOV.md),
[application test](docs/APPLICATION_TESTS.md), and [DefectDojo](docs/DEFECTDOJO.md)
guides. Manual OCI workflow checks are documented in the [image guide](docs/IMAGE_WORKFLOW.md).

To build a wheel after changes:

```bash
python -m pip wheel . --no-deps --wheel-dir dist
python tests/helpers/verify_wheel.py dist/*.whl
```

Then verify installation outside the checkout and the presence of required
assets. Generated runtime data, caches, and credentials stay outside the package.
Bundled runtime assets, including rules and the optional platform compose file,
are required package data.

## Branches and changes

- `main` carries a stable version with its tests and documentation.
- `dev` integrates current changes and their corresponding tests.
- Promotion to `main` requires diff review and relevant validation. A pull request
  can retain that review record.

Tool tests are not restricted to `dev`: a stable version must be verifiable from
its own sources. GitHub branch protections are separate account/repository settings.

Prepare focused commits and inspect the staged diff before committing. Separate
behavior changes, file moves, and local-data cleanup so each step can be reviewed.

## Layout and local data

- `src/flican/`: commands, adapters, core, reporting, and required runtime assets.
- `tests/`: tool tests, synthetic fixtures, and CI validation helpers under `tests/helpers/`.
- `tests/fixtures/projects/calculator/`: small synthetic project for the validation
  harness; see its [description](tests/fixtures/projects/calculator/README.md).
- `docs/`: usage guides and contracts; see the [index](docs/README.md).
- `examples/`: [CI templates](examples/README.md) to adapt to user projects.
- `.local/`, `.flican/`, `.venv/`, `build/`, `dist/`: generated
  data ignored by Git. Switching branches does not delete it.

Keep personal work journals, machine-specific validation records, large caches,
and local service bootstraps outside the product repository. Version reusable
examples, small regression fixtures, and the contracts needed to develop Flican.
Public guides should describe current behavior and reproducible checks.

For additional scanner coverage, follow [ADDING_A_SCANNER.md](docs/ADDING_A_SCANNER.md):
native contract, normalization, errors, policy, testing, and documented limits.
