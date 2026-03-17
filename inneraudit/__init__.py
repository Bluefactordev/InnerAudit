"""Public Python API for targeted audit selection.

Usage::

    from inneraudit import resolve_audit_targets

    manifest = resolve_audit_targets(
        paths=["src/foo.py", "src/bar/"],
        include_imports=True,
        include_importers=False,
        depth=1,
    )
    print(manifest.to_dict())
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Optional

from .dependency_graph import DEFAULT_MAX_RELATED, DependencyGraph
from .manifest_builder import Manifest, build_manifest
from .path_resolver import resolve_paths

logger = logging.getLogger(__name__)

__all__ = ["resolve_audit_targets", "Manifest"]


def resolve_audit_targets(
    paths: List[str],
    *,
    root: Optional[str] = None,
    include_imports: bool = True,
    include_importers: bool = False,
    depth: int = 1,
    max_related: int = DEFAULT_MAX_RELATED,
) -> Manifest:
    """Resolve a list of file/folder paths into a structured audit manifest.

    Parameters
    ----------
    paths:
        File and/or directory paths to audit.  Relative paths are resolved
        against *root*.
    root:
        Project root.  Defaults to the current working directory.
    include_imports:
        When *True*, include files that the targets import.
    include_importers:
        When *True*, include files that import the targets.
    depth:
        How many hops to follow (0 = only the targets themselves).
    max_related:
        Hard cap on total related files.

    Returns
    -------
    Manifest
        Structured, JSON-serialisable description of the audit selection.

    Raises
    ------
    ValueError
        If *depth* is negative.
    """
    if depth < 0:
        raise ValueError(f"depth must be >= 0, got {depth!r}")

    effective_root = str(Path(root).resolve()) if root else str(Path.cwd().resolve())

    # --- Step 1: resolve & expand input paths ---
    expanded = resolve_paths(paths, root=effective_root)

    logger.info(
        "Resolved %d input path(s) → %d file(s).", len(paths), len(expanded)
    )

    # --- Step 2: expand dependency graph ---
    # Collect all project files so the importer index can be built.
    all_project_files = resolve_paths([effective_root], root=effective_root)

    graph = DependencyGraph(
        root=effective_root,
        all_files=all_project_files,
        max_related=max_related,
    )

    imports_list, importers_list = graph.resolve_relations(
        targets=expanded,
        include_imports=include_imports,
        include_importers=include_importers,
        depth=depth,
    )

    logger.info(
        "Dependencies: %d imports, %d importers.",
        len(imports_list),
        len(importers_list),
    )

    # --- Step 3: placeholder for future context preparation ---
    # Context preparation (semantic summarisation, chunking, etc.) will be
    # inserted here once implemented.  The pipeline is:
    #   1. resolve targets      ← done above
    #   2. expand graph         ← done above
    #   3. prepare context      ← TODO (future step)
    #   4. run audit            ← caller's responsibility

    # --- Step 4: build manifest ---
    manifest = build_manifest(
        manual_targets=list(paths),
        expanded_targets=expanded,
        imports=imports_list,
        importers=importers_list,
    )

    return manifest
