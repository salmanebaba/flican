# Flican guides

Start with the [product README](../README.md) to install the CLI, configure a
project, and run scans. The [architecture](ARCHITECTURE.md) explains components,
data flow, trust boundaries, and planned extensions.

## Usage and contracts

| Guide | Topic |
| --- | --- |
| [CI_INTEGRATION.md](CI_INTEGRATION.md) | CI and Flican responsibilities, integration, and limits |
| [CI_TEMPLATES.md](CI_TEMPLATES.md) | GitHub/Jenkins source templates, artifacts, and validation scenarios |
| [IMAGE_WORKFLOW.md](IMAGE_WORKFLOW.md) | OCI, image scan, SBOM, and optional orchestration |
| [SCAN_RESULT.md](SCAN_RESULT.md) | JSON run references and artifact collection |
| [RUN_EXECUTION.md](RUN_EXECUTION.md) | Run/StageResult journals, states, and partial results |
| [TRIVY_DATABASE.md](TRIVY_DATABASE.md) | Cache, updates, offline mode, and database pinning |
| [CHECKOV.md](CHECKOV.md) | Terraform/Dockerfile coverage and Flican severity policy |
| [DEFECTDOJO.md](DEFECTDOJO.md) | Optional local reporting and its limits |
| [APPLICATION_TESTS.md](APPLICATION_TESTS.md) | Optional application test runner and configuration |

Guides describe supported behavior, reproducible checks, and current limitations.
Versioned templates are under [examples/](../examples/README.md).

## Development

- [Contributing](../CONTRIBUTING.md): environment, tests, branches, and packaging.
- [Tool CI](TOOL_CI.md): unit tests against the installed wheel and build artifacts.
- [Adding a scanner](ADDING_A_SCANNER.md): contract and implementation procedure.
- [Calculator fixture](../tests/fixtures/projects/calculator/README.md): synthetic
  project and disposable copies for CLI/CI validation.
- [Architecture roadmap](ARCHITECTURE.md#roadmap): extensions beyond delivered capabilities.
