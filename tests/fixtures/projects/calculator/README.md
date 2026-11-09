# Regression fixture: calculator

Small synthetic project for checking Flican CLI/CI workflows. Its files support
scanner, application-test, OCI export, and SBOM checks. It is not installed in
the user wheel.

| File | Purpose |
| --- | --- |
| `app.py`, `tests/test_app.py` | Standard-library calculator and three unittest tests |
| `requirements.txt` | Dependency-free base; the generator adds the SCA test dependency |
| `infra/main.tf` | Deliberately weak Terraform configuration for Checkov |
| `Dockerfile` | Static fixture: port 22, USER, and HEALTHCHECK checks |
| `Dockerfile.build` | Pinned Python build, copies `app.py`, uses USER 65532:65532 |
| `flican.yaml` | Scanners, policy, and optional test/build commands |

The versioned `requirements.txt` contains no third-party dependencies. The
generator writes an intentionally old dependency only into disposable `block`
and `incomplete` projects. These declarations are not installed in the calculator
image, so source SCA and image SBOM inventories can differ.

## Prepare a disposable copy

From the Flican repository root, with the environment activated:

```bash
mkdir -p .local
fixture_dir="$(mktemp -d "$PWD/.local/calculator.XXXXXX")"
python3 tests/helpers/demo_project.py \
  --scenario allow --output "$fixture_dir/project"
flican plan "$fixture_dir/project"
```

The [generator](../../../helpers/demo_project.py) accepts three scenarios:

- `allow`: substitutes corrected Terraform/Dockerfile fixtures and keeps the
  dependency declaration empty;
- `block`: retains vulnerable Terraform/Dockerfile fixtures and generates the
  old SCA dependency in this copy;
- `incomplete`: generates the old SCA dependency and introduces an invalid
  Dockerfile to check exit code `2`.

`allow` describes the source gate; the image gate depends on real image packages
and the database used. Finding counts vary with that database. Each generator
invocation requires a fresh output directory.

## Check the application

```bash
(cd "$fixture_dir/project" && python3 -m unittest discover -s tests -v)
```

Tests cover addition, negative values, and rejection of invalid expressions.
See the [CI guides](../../../../docs/CI_TEMPLATES.md) for scan/gate and archiving
scenarios, and the [image guide](../../../../docs/IMAGE_WORKFLOW.md) for build/image/SBOM.

Generated runs belong to the disposable copy under `.flican/`. Each new scan
creates its own journal and local attestation without modifying the source fixture.
