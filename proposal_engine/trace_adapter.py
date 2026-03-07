"""InnerTrace adapter with graceful fallback.

Wraps the InnerTrace Tracer so the rest of the proposal engine never
needs to worry about whether the package is installed.  If InnerTrace
is not available all tracing calls become no-ops and the engine
continues to function normally.
"""

import logging
from contextlib import contextmanager
from typing import Any, Dict, Optional

logger = logging.getLogger("TraceAdapter")

# Try to import InnerTrace; fall back silently if not installed.
try:
    from innertrace.tracing.tracer import Tracer as _Tracer  # type: ignore

    _INNERTRACE_AVAILABLE = True
except ImportError:
    _Tracer = None  # type: ignore
    _INNERTRACE_AVAILABLE = False


class TraceAdapter:
    """
    Thin wrapper around InnerTrace's Tracer.

    Emits the following custom event types used by the proposal engine:

    ``proposal.scan.start``
        Emitted at the beginning of a proposal scan run.

    ``proposal.scan.end``
        Emitted at the end of a proposal scan run.

    ``proposal.violation``
        Emitted when a detector finds a rule violation in a file.

    ``proposal.generated``
        Emitted when a proposal is created and persisted.

    ``proposal.validation``
        Emitted when a validation decision (approve / reject) is recorded.
    """

    ACTOR = "proposal_engine"

    def __init__(self, events_path: Optional[str] = None):
        self._tracer = None
        if _INNERTRACE_AVAILABLE:
            path = events_path or "traces/events.jsonl"
            try:
                self._tracer = _Tracer(path)
                logger.info("InnerTrace tracing enabled -> %s", path)
            except Exception as exc:
                logger.warning("Could not initialise InnerTrace tracer: %s", exc)

    @property
    def available(self) -> bool:
        return self._tracer is not None

    # ------------------------------------------------------------------
    # Run lifecycle
    # ------------------------------------------------------------------

    def start_scan(
        self,
        project_path: str,
        scan_id: str,
    ) -> Optional[str]:
        """Start a tracing run for the given scan.  Returns run_id or None."""
        if not self._tracer:
            return None
        try:
            run_id = self._tracer.start_run(
                entrypoint="proposal_engine.scan",
                args={"project_path": project_path, "scan_id": scan_id},
            )
            self._tracer.emit(
                type="proposal.scan.start",
                actor=self.ACTOR,
                payload={"scan_id": scan_id, "project_path": project_path},
            )
            return run_id
        except Exception as exc:
            logger.debug("TraceAdapter.start_scan error: %s", exc)
            return None

    def end_scan(
        self,
        status: str = "ok",
        proposal_count: int = 0,
        scan_id: Optional[str] = None,
    ) -> None:
        """End the current tracing run."""
        if not self._tracer:
            return
        try:
            self._tracer.emit(
                type="proposal.scan.end",
                actor=self.ACTOR,
                payload={
                    "status": status,
                    "proposal_count": proposal_count,
                    "scan_id": scan_id,
                },
            )
            self._tracer.end_run(status=status)
        except Exception as exc:
            logger.debug("TraceAdapter.end_scan error: %s", exc)

    # ------------------------------------------------------------------
    # Span helpers
    # ------------------------------------------------------------------

    @contextmanager
    def file_scan_span(self, file_path: str):
        """Context manager wrapping a single-file scan span."""
        if not self._tracer:
            yield None
            return
        try:
            with self._tracer.span(
                name=f"scan_file:{file_path}",
                actor=self.ACTOR,
                kind="tool",
                tags=["proposal_engine", "file_scan"],
            ) as span_id:
                yield span_id
        except Exception as exc:
            logger.debug("TraceAdapter.file_scan_span error: %s", exc)
            yield None

    # ------------------------------------------------------------------
    # Custom events
    # ------------------------------------------------------------------

    def emit_violation(
        self,
        rule_id: str,
        file_path: str,
        severity: str,
        line_number: Optional[int] = None,
    ) -> None:
        """Emit a rule-violation detection event."""
        if not self._tracer:
            return
        try:
            payload: Dict[str, Any] = {
                "rule_id": rule_id,
                "file_path": file_path,
                "severity": severity,
            }
            if line_number is not None:
                payload["line_number"] = line_number
            self._tracer.emit(
                type="proposal.violation",
                actor=self.ACTOR,
                level="warn" if severity in {"high", "critical"} else "info",
                tags=["proposal_engine", rule_id],
                payload=payload,
            )
        except Exception as exc:
            logger.debug("TraceAdapter.emit_violation error: %s", exc)

    def emit_proposal(
        self,
        proposal_id: str,
        proposal_type: str,
        severity: str,
        file_path: str,
    ) -> None:
        """Emit a proposal-generated event."""
        if not self._tracer:
            return
        try:
            self._tracer.emit(
                type="proposal.generated",
                actor=self.ACTOR,
                level="info",
                tags=["proposal_engine", proposal_type],
                payload={
                    "proposal_id": proposal_id,
                    "proposal_type": proposal_type,
                    "severity": severity,
                    "file_path": file_path,
                },
            )
        except Exception as exc:
            logger.debug("TraceAdapter.emit_proposal error: %s", exc)

    def emit_validation(
        self,
        proposal_id: str,
        decision: str,
        reason: Optional[str] = None,
    ) -> None:
        """Emit a validation-decision event."""
        if not self._tracer:
            return
        try:
            payload: Dict[str, Any] = {
                "proposal_id": proposal_id,
                "decision": decision,
            }
            if reason:
                payload["reason"] = reason
            self._tracer.emit(
                type="proposal.validation",
                actor=self.ACTOR,
                level="info",
                tags=["proposal_engine", "validation"],
                payload=payload,
            )
        except Exception as exc:
            logger.debug("TraceAdapter.emit_validation error: %s", exc)
