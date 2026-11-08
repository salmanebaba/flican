from pathlib import PurePosixPath


def normalize_source_path(raw_path: str) -> str:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("Finding file path must be a non-empty string.")

    file_path = PurePosixPath(raw_path)

    if ".." in file_path.parts:
        raise ValueError("Finding file path contains '..'.")

    if file_path.is_absolute():
        try:
            file_path = file_path.relative_to("/src")
        except ValueError as error:
            raise ValueError(
                "Finding file path is outside /src."
            ) from error

    if not file_path.parts:
        raise ValueError("Finding file path is empty.")

    return file_path.as_posix()