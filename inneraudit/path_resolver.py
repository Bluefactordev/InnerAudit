"""Path resolution: normalize, validate, and expand input paths.

Operates within a defined root directory and prevents path traversal.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterable, List, Optional

logger = logging.getLogger(__name__)

# Directories that are always ignored when expanding folders.
_IGNORED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__",
        "dist",
        "build",
        ".cache",
        "cache",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
    }
)


class PathResolutionError(ValueError):
    """Raised when a path cannot be safely resolved."""


def _is_ignored_dir(part: str) -> bool:
    return part in _IGNORED_DIRS


def resolve_paths(
    raw_paths: Iterable[str],
    root: Optional[str] = None,
) -> List[str]:
    """Resolve and validate input paths, expanding folders into files.

    Parameters
    ----------
    raw_paths:
        User-supplied paths (files or directories).  May be absolute or
        relative; relative paths are resolved against *root*.
    root:
        The allowed root directory.  Paths outside this root are rejected.
        Defaults to the current working directory.

    Returns
    -------
    list[str]
        Sorted, deduplicated list of absolute file paths.
    """
    root_path = Path(root).resolve() if root else Path.cwd().resolve()
    seen: set[Path] = set()
    result: list[Path] = []

    for raw in raw_paths:
        try:
            candidate = Path(raw)
            if not candidate.is_absolute():
                candidate = (root_path / candidate).resolve()
            else:
                candidate = candidate.resolve()
        except (OSError, ValueError) as exc:
            logger.warning("Cannot resolve path %r: %s", raw, exc)
            continue

        # Prevent traversal outside the root.
        try:
            candidate.relative_to(root_path)
        except ValueError:
            logger.warning(
                "Path %r is outside the root %r — skipped.", candidate, root_path
            )
            continue

        if not candidate.exists():
            logger.warning("Path does not exist: %s — skipped.", candidate)
            continue

        if candidate.is_file():
            if _is_readable(candidate) and candidate not in seen:
                seen.add(candidate)
                result.append(candidate)
        elif candidate.is_dir():
            for file_path in _expand_directory(candidate, root_path):
                if file_path not in seen:
                    seen.add(file_path)
                    result.append(file_path)
        else:
            logger.warning("Path is neither file nor directory: %s — skipped.", candidate)

    return sorted(str(p) for p in result)


def _expand_directory(directory: Path, root: Path) -> List[Path]:
    """Recursively yield all readable files inside *directory*, skipping ignored dirs."""
    files: list[Path] = []
    try:
        for entry in sorted(directory.rglob("*")):
            # Skip ignored directory components in the path relative to root.
            try:
                rel_parts = entry.relative_to(root).parts
            except ValueError:
                continue
            if any(_is_ignored_dir(part) for part in rel_parts):
                continue
            if entry.is_file() and _is_readable(entry):
                files.append(entry)
    except PermissionError as exc:
        logger.warning("Cannot read directory %s: %s", directory, exc)
    return files


def _is_readable(path: Path) -> bool:
    """Return True if the file exists and is readable."""
    try:
        return path.is_file() and os.access(path, os.R_OK)
    except OSError:
        return False
