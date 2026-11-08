from pathlib import Path

LANGUAGE_BY_EXTENSION = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
}


def discover_files(
    project_path: Path,
    excluded_names: set[str],
) -> list[Path]:
    """Discover regular files using the supplied exclusions."""
    files = []

    for entry in project_path.iterdir():
        if entry.is_symlink() or entry.name in excluded_names:
            continue

        if entry.is_dir():
            files.extend(discover_files(entry, excluded_names))
        elif entry.is_file():
            files.append(entry)

    return sorted(files)

def detect_languages(files: list[Path]) -> list[str]:
    """Detect languages from recognized file extensions."""
    languages = set()

    for file in files:
        extension = file.suffix.lower()
        language = LANGUAGE_BY_EXTENSION.get(extension)

        if language is not None:
            languages.add(language)

    return sorted(languages)