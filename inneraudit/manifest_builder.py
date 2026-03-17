"""Manifest builder: assembles the structured audit selection manifest."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class RelatedFiles:
    imports: List[str] = field(default_factory=list)
    importers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, List[str]]:
        return {"imports": self.imports, "importers": self.importers}


@dataclass
class ManifestStats:
    manual_count: int = 0
    expanded_count: int = 0
    related_count: int = 0
    final_count: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "manual_count": self.manual_count,
            "expanded_count": self.expanded_count,
            "related_count": self.related_count,
            "final_count": self.final_count,
        }


@dataclass
class Manifest:
    """Structured, JSON-serialisable description of an audit selection.

    Fields
    ------
    manual_targets:
        Raw paths exactly as supplied by the user (files or directories).
    expanded_targets:
        Concrete file paths derived from the manual targets after folder
        expansion and path normalisation.
    related_files:
        Import / importer relationships discovered from the expanded targets.
    final_audit_set:
        De-duplicated union of expanded_targets and related_files used as
        the actual input to the audit engine.
    stats:
        Convenience counts for quick summary display.
    """

    manual_targets: List[str] = field(default_factory=list)
    expanded_targets: List[str] = field(default_factory=list)
    related_files: RelatedFiles = field(default_factory=RelatedFiles)
    final_audit_set: List[str] = field(default_factory=list)
    stats: ManifestStats = field(default_factory=ManifestStats)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manual_targets": self.manual_targets,
            "expanded_targets": self.expanded_targets,
            "related_files": self.related_files.to_dict(),
            "final_audit_set": self.final_audit_set,
            "stats": self.stats.to_dict(),
        }


def build_manifest(
    manual_targets: List[str],
    expanded_targets: List[str],
    imports: List[str],
    importers: List[str],
) -> Manifest:
    """Assemble a :class:`Manifest` from its constituent parts.

    The *final_audit_set* is the sorted, de-duplicated union of
    *expanded_targets*, *imports*, and *importers*.

    Parameters
    ----------
    manual_targets:
        Raw user-supplied paths (files and/or directories).
    expanded_targets:
        Resolved file paths after folder expansion.
    imports:
        Files that expanded targets depend on.
    importers:
        Files that depend on the expanded targets.
    """
    related = RelatedFiles(imports=sorted(imports), importers=sorted(importers))
    all_related = sorted(set(imports) | set(importers))
    final_set = sorted(set(expanded_targets) | set(all_related))

    stats = ManifestStats(
        manual_count=len(manual_targets),
        expanded_count=len(expanded_targets),
        related_count=len(all_related),
        final_count=len(final_set),
    )

    return Manifest(
        manual_targets=list(manual_targets),
        expanded_targets=expanded_targets,
        related_files=related,
        final_audit_set=final_set,
        stats=stats,
    )
