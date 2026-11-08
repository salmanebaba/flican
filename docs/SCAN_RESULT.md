# JSON run reference for CI

`--result-file` gives a CLI or CI caller the exact run and artifacts without
parsing terminal text or selecting the newest directory by timestamp. See the
[CI templates](CI_TEMPLATES.md) for collection and archiving.

## Usage

`flican test PROJECT --result-file PATH` uses the same
16-field schema with `command: test`. `run_report_path` points to its journal,
`findings_report_path` remains `null`, and `artifact_paths` includes
`reports/tests.json`. `ci collect` also validates run mode and stores the
reference as `test-result.json`. Existing source scan commands/codes are retained.
See [APPLICATION_TESTS.md](APPLICATION_TESTS.md).

All run modes use the same 16 fields: `command` is `scan`,
`test`, `build`, `image`, or `pipeline`. Image/pipeline populate
`findings_report_path`; test/build leave it `null`. The collected reference is
`<command>-result.json`. Collection accepts up to 256 paths, 64 MiB per report/log,
2 GiB per `.oci.tar` archive, and 2 GiB + 256 MiB total. Archives are copied/hashed
as streams. Run and manifest must match the announced mode. See
[IMAGE_WORKFLOW.md](IMAGE_WORKFLOW.md) for builder commands and limits.

From the repository root, after `flican ci prepare tests/fixtures/projects/calculator`:

```bash
flican scan tests/fixtures/projects/calculator \
  --result-file tests/fixtures/projects/calculator/.flican/ci/manual-001.json
```

The fixture normally returns `1` because HIGH findings block the policy.
Writing a reference does not turn the result into success. Use a different name,
such as `manual-002.json`, for the next invocation.

The destination must be **fresh**. Any existing file, including a previous
Flican reference, is rejected unchanged before scanners start. In CI, use a path
unique to build/attempt or a new temporary directory. Code `2` after rejection
does not make the old file current.

Inside the scanned project, the destination must be under `.flican/` and outside
`.flican/runs/`. A destination outside the project, such as the runner's temporary
directory, is also allowed. This prevents scanning the output file or confusing
it with source, configuration, or another run's artifact.

## Versioned contract

| Field | Meaning |
| --- | --- |
| `schema_version` | `1` for this contract |
| `command` | `scan`, `test`, `build`, `image`, or `pipeline` |
| `invocation_id` | Identifier for this CLI call, even without a run |
| `project_path` | Absolute project path |
| `started_at`, `finished_at` | UTC invocation dates; finish is `null` until finalized |
| `status` | `running`, `completed`, `failed`, or `cancelled` |
| `decision` | Initially `null`, then `allow`, `block`, or `incomplete` |
| `exit_code` | Initially `null`, then `0`, `1`, or `2` |
| `error` | Bounded error summary or `null` |
| `run_id`, `run_path` | Run ID and absolute path; `null` before creation |
| `run_report_path` | Absolute `run.json` path, or `null` if absent |
| `findings_report_path` | Absolute available common report path, or `null` |
| `manifest_path` | Absolute successfully attested manifest path, otherwise `null` |
| `artifact_paths` | Available file paths relative to `run_path` |

Blocked-result excerpt:

```json
{
  "schema_version": 1,
  "command": "scan",
  "status": "completed",
  "decision": "block",
  "exit_code": 1,
  "run_path": "/workspace/my-api/.flican/runs/RUN_ID",
  "artifact_paths": [
    "run.json",
    "reports/gitleaks.json",
    "reports/semgrep.json",
    "reports/findings.json",
    "manifest.json"
  ]
}
```

Absolute paths belong to the scanning machine. Join `run_path` with an
`artifact_paths` entry to locate a file. `flican ci collect` verifies workspace
containment and copies files to relative bundle paths for archiving. The reference
itself is not one of the run's attested artifacts.

## Behavior

| Situation | Final reference | Process exit |
| --- | --- | --- |
| Scans complete, policy passed | `completed`, `allow`, complete run paths | `0` |
| Scans complete, policy blocked | `completed`, `block`, complete run paths | `1` |
| Scanner error/timeout | `failed`, `incomplete`, usable artifacts preserved | `2` |
| Handled Ctrl+C | `cancelled`, `incomplete`, available artifacts preserved | `2` |
| Invalid config/prerequisite inside command | `failed`, `incomplete`; run paths `null` if no run created | `2` |
| Output destination rejected/uncreatable | No new usable reference | `2` |
| Final publication fails | Last checkpoint lacks final verdict; scan reports retained | `2` |

CLI syntax errors occur before entering the command. Unknown options, missing
arguments, and Typer path rejection can return `2` without a file. Forced stops
can leave `running` or no file. CI must treat missing, unfinished, or inconsistent
references as errors, never `allow`.

Preserve the **real process exit code**. Proceed only with at least process `0`
and this invocation's final reference containing `status: completed`,
`decision: allow`, `exit_code: 0`, and a finish timestamp. An old file or an
`allow` string alone is insufficient. Collect artifacts before propagating
blocks/errors.

## Writing and integrity

`core/scan_result.py` prepares private temporary JSON and publishes it atomically.
Initial publication is exclusive; updates replace only this invocation's file.
External replacement/modification is rejected. File mode is `0600`; existing
directory permissions are not changed.

The reference starts `running` before config loading. Once a journal exists,
it identifies the run before scanners start. Finalization follows report writing
and, for complete runs, attestation. The detailed stage journal remains
[run.json](RUN_EXECUTION.md).

The reference includes paths and a summary, not tokens or embedded native reports.
It is not portable integrity proof: DefectDojo still requires manifests, hashes,
and private registered state. Incomplete source runs remain local.
If only final reference publication fails, completed reports and attestation
remain intact, but the command returns `2` without a final `allow` reference.

## Verification

```bash
python -m unittest discover -s tests -p test_scan_result.py -v
python -m unittest discover -s tests -q
```

Tests cover all three result codes, preflight without run, timeout, cancellation,
reference availability before scanning, snapshot exclusion, stale files,
protected paths, symlinks, concurrent publication, external changes, failed atomic
replacement, and preserved reports after export failure. No credentials are required.
