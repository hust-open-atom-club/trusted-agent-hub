"""Helpers for normalizing generated files in benchmark fixtures."""

from __future__ import annotations

from pathlib import Path, PurePosixPath


GENERATED_ARTIFACT_DIR_NAMES = frozenset({"__pycache__"})
GENERATED_ARTIFACT_EXTENSIONS = frozenset({".pyc", ".pyo"})


def generated_artifact_source_path(path: str | Path) -> str | None:
    """Return the source path associated with a generated Python cache."""
    normalized = (
        path.as_posix()
        if isinstance(path, Path)
        else str(path).replace("\\", "/")
    )
    pure_path = PurePosixPath(normalized)
    if pure_path.suffix.casefold() not in GENERATED_ARTIFACT_EXTENSIONS:
        return None

    cache_index = next(
        (
            index
            for index, part in enumerate(pure_path.parts)
            if part.casefold() in GENERATED_ARTIFACT_DIR_NAMES
        ),
        None,
    )
    if cache_index is None:
        return None

    module_name = pure_path.stem.split(".", 1)[0]
    if not module_name:
        return None
    return PurePosixPath(
        *pure_path.parts[:cache_index],
        f"{module_name}.py",
    ).as_posix()


def is_generated_artifact_path(
    path: str | Path,
    *,
    source_exists: bool | None = None,
) -> bool:
    """Return whether a generated cache has a matching source file."""
    return (
        generated_artifact_source_path(path) is not None
        and source_exists is True
    )
