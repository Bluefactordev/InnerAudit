"""Dependency / relation resolution for Python files.

Supports:
- ``imports``  — files that a given file depends on
- ``importers`` — files that depend on a given file

Uses AST-based static analysis with a regex fallback.
"""

from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Reasonable upper-bound on total related files returned.
DEFAULT_MAX_RELATED = 200

# Regex fallback for non-parseable Python files.
_IMPORT_RE = re.compile(
    r"^\s*(?:import\s+([\w\.]+)|from\s+([\w\.]+)\s+import)",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Low-level import extraction
# ---------------------------------------------------------------------------


def _extract_imports_ast(source: str) -> List[str]:
    """Return a list of module names imported by *source* via AST."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return _extract_imports_regex(source)

    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                # level > 0 means relative import — keep the module name as-is
                modules.append(node.module)
    return modules


def _extract_imports_regex(source: str) -> List[str]:
    """Fallback regex-based import extractor."""
    modules: list[str] = []
    for m in _IMPORT_RE.finditer(source):
        name = m.group(1) or m.group(2)
        if name:
            modules.append(name)
    return modules


# ---------------------------------------------------------------------------
# Module name → file path resolution
# ---------------------------------------------------------------------------


def _module_to_possible_paths(module: str, root: Path) -> List[Path]:
    """Given a dotted module name, return candidate absolute file paths."""
    parts = module.split(".")
    base = root.joinpath(*parts)
    return [
        base.with_suffix(".py"),
        base / "__init__.py",
    ]


def _resolve_module(module: str, root: Path) -> Optional[Path]:
    """Return the resolved Path for a local module, or None if not found."""
    for candidate in _module_to_possible_paths(module, root):
        if candidate.exists():
            return candidate.resolve()
    return None


# ---------------------------------------------------------------------------
# Dependency graph builder
# ---------------------------------------------------------------------------


class DependencyGraph:
    """Builds import/importer relationships for a collection of files.

    Parameters
    ----------
    root:
        Project root used to resolve relative module names.
    all_files:
        All files in the project scope (used for importer discovery).
    max_related:
        Cap on total related files collected across all targets.
    """

    def __init__(
        self,
        root: str,
        all_files: Iterable[str],
        max_related: int = DEFAULT_MAX_RELATED,
    ) -> None:
        self._root = Path(root).resolve()
        self._all_files: FrozenSet[Path] = frozenset(
            Path(f).resolve() for f in all_files
        )
        self._max_related = max_related
        # Lazy-built reverse index: path → set of files that import it
        self._importer_index: Optional[Dict[Path, Set[Path]]] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get_imports(self, file_path: str) -> List[str]:
        """Return absolute paths of local files imported by *file_path*."""
        path = Path(file_path).resolve()
        return [str(p) for p in self._direct_imports(path)]

    def get_importers(self, file_path: str) -> List[str]:
        """Return absolute paths of files that import *file_path*."""
        path = Path(file_path).resolve()
        index = self._build_importer_index()
        return sorted(str(p) for p in index.get(path, set()))

    def resolve_relations(
        self,
        targets: Iterable[str],
        include_imports: bool = True,
        include_importers: bool = False,
        depth: int = 1,
    ) -> Tuple[List[str], List[str]]:
        """Expand *targets* by following import/importer edges up to *depth*.

        Returns
        -------
        (imports_list, importers_list)
            Both lists contain absolute path strings, deduplicated, sorted,
            and capped at ``max_related``.
        """
        if depth < 0:
            raise ValueError(f"depth must be >= 0, got {depth!r}")

        target_set: FrozenSet[str] = frozenset(targets)
        imports_found: Set[str] = set()
        importers_found: Set[str] = set()

        def _expand(current: Set[str], getter) -> Set[str]:
            frontier = set(current)
            visited: Set[str] = set()
            collected: Set[str] = set()
            for _ in range(depth):
                next_frontier: Set[str] = set()
                for f in frontier:
                    if f in visited:
                        continue
                    visited.add(f)
                    for rel in getter(f):
                        if rel not in target_set:
                            collected.add(rel)
                            next_frontier.add(rel)
                frontier = next_frontier
                if not frontier:
                    break
            return collected

        if include_imports and depth > 0:
            imports_found = _expand(target_set, self.get_imports)
        if include_importers and depth > 0:
            importers_found = _expand(target_set, self.get_importers)

        # Apply global cap.
        all_related = (imports_found | importers_found) - target_set
        if len(all_related) > self._max_related:
            logger.warning(
                "Related-file count %d exceeds max_related=%d; truncating.",
                len(all_related),
                self._max_related,
            )
            all_related = set(sorted(all_related)[: self._max_related])
            imports_found &= all_related
            importers_found &= all_related

        return sorted(imports_found), sorted(importers_found)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _direct_imports(self, path: Path) -> List[Path]:
        """Return local file paths directly imported by *path*."""
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", path, exc)
            return []

        modules = _extract_imports_ast(source)
        resolved: list[Path] = []
        for module in modules:
            candidate = _resolve_module(module, self._root)
            if candidate and candidate != path:
                resolved.append(candidate)
        return resolved

    def _build_importer_index(self) -> Dict[Path, Set[Path]]:
        """Build (lazily) the reverse index: file → set of its importers."""
        if self._importer_index is not None:
            return self._importer_index

        index: Dict[Path, Set[Path]] = {}
        for src_path in self._all_files:
            for dep in self._direct_imports(src_path):
                index.setdefault(dep, set()).add(src_path)
        self._importer_index = index
        return index
