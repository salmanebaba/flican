"""Create disposable, synthetic projects for real CLI/CI gate validation."""

import argparse
import shutil
from pathlib import Path


def prepare_project(scenario: str, output: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    if scenario not in ("allow", "block", "incomplete"):
        raise ValueError("Choose allow, block or incomplete.")
    if output.exists():
        raise ValueError("The disposable demo destination must be fresh.")
    shutil.copytree(root / "tests/fixtures/projects/calculator", output,
                    ignore=shutil.ignore_patterns(".flican", "__pycache__"))
    if scenario in {"block", "incomplete"}:
        (output / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    if scenario == "allow":
        fixtures = root / "tests/fixtures/checkov"
        shutil.copyfile(fixtures / "corrected/main.tf", output / "infra/main.tf")
        shutil.copyfile(fixtures / "dockerfile/corrected/Dockerfile", output / "Dockerfile")
        (output / "requirements.txt").write_text("# This synthetic passing fixture has no dependencies.\n")
    elif scenario == "incomplete":
        (output / "Dockerfile").write_text("FROM\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["allow", "block", "incomplete"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare_project(args.scenario, args.output)
    print(f"Prepared synthetic {args.scenario} project: {args.output}")
