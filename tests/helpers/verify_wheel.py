"""Check that a Flican wheel contains the current runtime and no extra packages."""

import argparse
import configparser
from email.parser import BytesParser
import hashlib
from pathlib import Path
import tomllib
from zipfile import BadZipFile, ZipFile


def verify_wheel(wheel: Path, root: Path) -> dict:
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    expected = {
        path.relative_to(root / "src").as_posix(): path
        for path in (root / "src/flican").rglob("*")
        if path.is_file() and path.suffix in {".py", ".yaml"}
    }
    if not expected:
        raise ValueError("No runtime sources found in src/flican/.")
    with ZipFile(wheel) as archive:
        names = [entry.filename for entry in archive.infolist() if not entry.is_dir()]
        if len(names) != len(set(names)):
            raise ValueError("Wheel contains duplicate paths.")
        metadata_files = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_files) != 1:
            raise ValueError("Expected exactly one distribution metadata record.")
        metadata_path = metadata_files[0]
        metadata_root = metadata_path.rsplit("/", 1)[0] + "/"
        metadata_bytes = archive.read(metadata_path).replace(b"\r\n", b"\n")
        metadata = BytesParser().parsebytes(metadata_bytes)
        if metadata["Name"] != project["name"] or metadata["Version"] != project["version"]:
            raise ValueError("Wheel name/version do not match pyproject.toml.")
        if not metadata_root.startswith("flican-") or any(
            not name.startswith(("flican/", metadata_root)) for name in names
        ):
            raise ValueError("Wheel contains unexpected files outside Flican and its metadata.")
        actual = {name for name in names if name.startswith("flican/")}
        if actual != set(expected):
            raise ValueError(
                f"Runtime file mismatch: missing={sorted(set(expected) - actual)}, "
                f"extra={sorted(actual - set(expected))}"
            )
        for name, source in expected.items():
            if archive.read(name) != source.read_bytes():
                raise ValueError(f"Wheel differs from runtime source: {name}")
        readme = (root / project["readme"]).read_text(encoding="utf-8")
        if metadata_bytes.partition(b"\n\n")[2].decode("utf-8").strip() != readme.strip():
            raise ValueError("Embedded README does not match the current README.")
        entry_points = configparser.ConfigParser()
        entry_points.read_string(archive.read(metadata_root + "entry_points.txt").decode("utf-8"))
        if not entry_points.has_section("console_scripts") or dict(
            entry_points["console_scripts"]
        ) != project["scripts"]:
            raise ValueError("Console scripts do not match pyproject.toml.")
    return {"runtime_files": len(expected), "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    args = parser.parse_args()
    try:
        result = verify_wheel(args.wheel, Path(__file__).resolve().parents[2])
    except (OSError, ValueError, KeyError, BadZipFile) as error:
        parser.exit(1, f"Invalid wheel: {error}\n")
    print(f"Verified wheel: {args.wheel.name} ({result['runtime_files']} runtime files)")
    print(f"SHA256: {result['sha256']}")


if __name__ == "__main__":
    main()
