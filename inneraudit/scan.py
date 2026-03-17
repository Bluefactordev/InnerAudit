"""CLI entrypoint for targeted audit selection.

Usage::

    python -m inneraudit.scan \\
        --paths path1 path2 \\
        --include-imports \\
        --include-importers \\
        --depth 1

    # JSON output:
    python -m inneraudit.scan --paths src/ --json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

# Allow running as ``python -m inneraudit.scan`` from the repo root.
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from inneraudit import resolve_audit_targets  # noqa: E402


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inneraudit.scan",
        description="Resolve audit targets and build a selection manifest.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--paths",
        nargs="+",
        required=True,
        metavar="PATH",
        help="One or more file or directory paths to audit.",
    )
    parser.add_argument(
        "--root",
        default=None,
        metavar="DIR",
        help="Project root directory (default: current working directory).",
    )
    parser.add_argument(
        "--include-imports",
        action="store_true",
        default=False,
        help="Include files imported by the targets.",
    )
    parser.add_argument(
        "--include-importers",
        action="store_true",
        default=False,
        help="Include files that import the targets.",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=1,
        metavar="N",
        help="Dependency-graph traversal depth (default: 1).",
    )
    parser.add_argument(
        "--max-related",
        type=int,
        default=200,
        metavar="N",
        help="Maximum number of related files to include (default: 200).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        dest="output_json",
        help="Print the manifest as JSON instead of a human-readable summary.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose logging.",
    )
    return parser


def _print_summary(manifest) -> None:
    stats = manifest.stats
    print("\n=== InnerAudit Scan Manifest ===")
    print(f"  Manual targets   : {stats.manual_count}")
    print(f"  Expanded files   : {stats.expanded_count}")
    print(f"  Related files    : {stats.related_count}")
    print(f"  Final audit set  : {stats.final_count}")

    if manifest.expanded_targets:
        print("\nExpanded targets:")
        for p in manifest.expanded_targets:
            print(f"  {p}")

    if manifest.related_files.imports:
        print("\nImports (dependencies):")
        for p in manifest.related_files.imports:
            print(f"  {p}")

    if manifest.related_files.importers:
        print("\nImporters (reverse dependencies):")
        for p in manifest.related_files.importers:
            print(f"  {p}")

    print(f"\nFinal audit set ({stats.final_count} file(s)):")
    for p in manifest.final_audit_set:
        print(f"  {p}")


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.depth < 0:
        parser.error("--depth must be >= 0")

    try:
        manifest = resolve_audit_targets(
            paths=args.paths,
            root=args.root,
            include_imports=args.include_imports,
            include_importers=args.include_importers,
            depth=args.depth,
            max_related=args.max_related,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.output_json:
        print(json.dumps(manifest.to_dict(), indent=2))
    else:
        _print_summary(manifest)

    return 0


if __name__ == "__main__":
    sys.exit(main())
