"""ProposalEngine – orchestrates the scan → detect → persist pipeline."""

import fnmatch
import logging
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from .backlog import BacklogManager
from .detector import BaseDetector, build_detectors
from .models import Proposal
from .trace_adapter import TraceAdapter

logger = logging.getLogger("ProposalEngine")

# File extensions processed by the static detectors.
_SUPPORTED_EXTENSIONS = {".py", ".php", ".js", ".ts"}


def _matches_pattern(file_path: Path, project_path: Path, patterns: List[str]) -> bool:
    """Mirror AuditEngine._matches_pattern for consistent file filtering.

    Supports both fnmatch wildcards and case-insensitive substring / path-part
    matching so that patterns such as "node_modules", "*.min.js", or
    "src/generated" all work as expected.
    """
    if not patterns:
        return False

    relative_path = file_path.relative_to(project_path).as_posix()
    basename = file_path.name
    relative_parts = relative_path.lower().split("/")
    candidates = [
        relative_path,
        relative_path.lower(),
        basename,
        basename.lower(),
        file_path.as_posix(),
        file_path.as_posix().lower(),
    ]

    for raw_pattern in patterns:
        pattern = raw_pattern.strip().replace("\\", "/")
        if not pattern:
            continue

        normalized_pattern = pattern.lower()
        if normalized_pattern in relative_parts:
            return True

        for candidate in candidates:
            if fnmatch.fnmatch(candidate, pattern):
                return True
            if normalized_pattern in candidate.lower():
                return True

    return False


class ProposalEngine:
    """
    Minimal Proposal Engine for the Software Improvement Pipeline.

    Pipeline::

        observe (file discovery)
            → detect (static detectors on each file)
                → propose (build Proposal objects)
                    → persist (BacklogManager)
                        → trace (InnerTrace events)

    The engine intentionally does **not** auto-fix code.  All proposals
    remain in the ``detected`` state until a human or a stronger model
    promotes them through the backlog workflow.
    """

    def __init__(
        self,
        backlog_manager: BacklogManager,
        trace_adapter: Optional[TraceAdapter] = None,
        detector_configs: Optional[Dict[str, Any]] = None,
        file_filtering: Union[Dict[str, Any], Callable[[], Dict[str, Any]], None] = None,
    ):
        self.backlog = backlog_manager
        self.tracer = trace_adapter or TraceAdapter()
        self.detectors: List[BaseDetector] = build_detectors(detector_configs or {})

        # Accept either a static dict or a callable that returns the current
        # filtering configuration.  Using a callable means changes made via
        # /api/file-filtering are picked up on the *next* scan without a
        # process restart.
        if callable(file_filtering):
            self._file_filtering_source: Callable[[], Dict[str, Any]] = file_filtering
        else:
            # Make a shallow copy so that mutations to the caller's dict after
            # construction do not affect this engine.  If live-reload behaviour
            # is needed, pass a callable instead.
            _static: Dict[str, Any] = dict(file_filtering) if file_filtering else {}
            self._file_filtering_source = lambda: _static

        logger.info(
            "ProposalEngine initialised with %d detector(s): %s",
            len(self.detectors),
            [d.rule_id for d in self.detectors],
        )

    def _get_file_filtering(self) -> Dict[str, Any]:
        """Return the current file-filtering configuration."""
        return self._file_filtering_source()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run_proposal_scan(
        self,
        project_path: str,
        *,
        file_paths: Optional[List[str]] = None,
        scan_id: Optional[str] = None,
    ) -> List[Proposal]:
        """
        Scan *project_path* (or a specific list of *file_paths*) and return
        newly-generated proposals.

        Args:
            project_path: Root directory of the project to scan.
            file_paths:   Optional pre-filtered list of files.  When supplied
                          the engine skips its own discovery step.
            scan_id:      Optional caller-supplied scan identifier; one is
                          generated when omitted.

        Returns:
            List of Proposal objects that were generated and persisted.
        """
        scan_id = scan_id or str(uuid.uuid4())
        logger.info("Starting proposal scan %s on %s", scan_id, project_path)

        # ---- tracing ----
        self.tracer.start_scan(project_path=project_path, scan_id=scan_id)

        proposals: List[Proposal] = []
        status = "ok"

        try:
            # 1. Discover files
            paths = file_paths or self._discover_files(project_path)
            logger.info("Proposal scan will process %d file(s).", len(paths))

            # 2. Run detectors per file
            for file_path in paths:
                file_proposals = self._scan_file(
                    file_path=file_path,
                    scan_id=scan_id,
                )
                proposals.extend(file_proposals)

            # 3. Persist
            if proposals:
                self.backlog.save_proposals(proposals, scan_id=scan_id)
                logger.info(
                    "Proposal scan %s complete: %d proposal(s) generated.",
                    scan_id,
                    len(proposals),
                )
            else:
                logger.info("Proposal scan %s complete: no proposals generated.", scan_id)

        except Exception as exc:
            status = "error"
            logger.error("Proposal scan %s failed: %s", scan_id, exc, exc_info=True)
            raise

        finally:
            self.tracer.end_scan(
                status=status,
                proposal_count=len(proposals),
                scan_id=scan_id,
            )

        return proposals

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _discover_files(self, project_path: str) -> List[str]:
        """Return source files eligible for proposal scanning.

        Mirrors ``AuditEngine.discover_files`` so that ``include_patterns``,
        ``exclude_patterns``, and ``default_behavior`` (include_all / include_only
        / exclude_only) are all honoured — not just ``exclude_patterns``.
        """
        root = Path(project_path)
        filtering = self._get_file_filtering()
        include_patterns: List[str] = filtering.get("include_patterns", [])
        exclude_patterns: List[str] = filtering.get("exclude_patterns", [])
        default_behavior: str = filtering.get("default_behavior", "include_all")

        files: set = set()
        for ext in _SUPPORTED_EXTENSIONS:
            for path in root.rglob(f"*{ext}"):
                if path.is_file():
                    files.add(path.resolve())

        filtered: List[str] = []
        for file_path in sorted(files):
            include_match = _matches_pattern(file_path, root, include_patterns)
            exclude_match = _matches_pattern(file_path, root, exclude_patterns)

            if default_behavior == "include_only":
                keep_file = bool(include_patterns) and include_match and not exclude_match
            else:
                keep_file = not exclude_match

            if keep_file:
                filtered.append(str(file_path))

        logger.info(
            "Proposal scan discovered %d file(s) (filtering mode: %s).",
            len(filtered),
            default_behavior,
        )
        return filtered

    def _scan_file(self, file_path: str, scan_id: str) -> List[Proposal]:
        """Run all enabled detectors on a single file."""
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            return []

        file_proposals: List[Proposal] = []

        with self.tracer.file_scan_span(file_path):
            for detector in self.detectors:
                try:
                    hits = detector.detect(
                        file_path=file_path,
                        content=content,
                        scan_id=scan_id,
                    )
                except Exception as exc:
                    logger.warning(
                        "Detector %s raised on %s: %s",
                        detector.rule_id,
                        file_path,
                        exc,
                    )
                    continue

                for proposal in hits:
                    # Emit per-violation trace event (first evidence item)
                    ev = proposal.evidence[0] if proposal.evidence else {}
                    self.tracer.emit_violation(
                        rule_id=detector.rule_id,
                        file_path=file_path,
                        severity=proposal.severity,
                        line_number=ev.get("line_number"),
                    )
                    # Emit per-proposal trace event
                    self.tracer.emit_proposal(
                        proposal_id=proposal.id,
                        proposal_type=proposal.type,
                        severity=proposal.severity,
                        file_path=file_path,
                    )
                    file_proposals.append(proposal)

        return file_proposals
