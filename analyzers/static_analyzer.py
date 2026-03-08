"""StaticAnalyzer – deterministic, dependency-free analysis using rule detectors.

This analyzer requires no external services, no LLM, and no network access.
It is always available and is the default backend for InnerAudit.
"""

import logging
from typing import Any, Dict, List, Optional

from .base import AnalysisResult, BaseAnalyzer

logger = logging.getLogger("StaticAnalyzer")


class StaticAnalyzer(BaseAnalyzer):
    """Pure-Python static analysis backend.

    Delegates to the deterministic rule detectors in
    ``proposal_engine.detector``.  Because all logic is local regex/heuristic
    analysis, this analyzer has no runtime dependencies beyond the standard
    library and is always available.
    """

    analyzer_id = "static"
    requires_external_service = False

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        detector_configs: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(config)
        from proposal_engine.detector import build_detectors

        self._detectors = build_detectors(detector_configs or {})
        logger.debug(
            "StaticAnalyzer initialised with %d detector(s).",
            len(self._detectors),
        )

    def is_available(self) -> bool:
        return True

    def analyze_file(
        self,
        file_path: str,
        content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AnalysisResult:
        findings: List[Dict[str, Any]] = []

        for detector in self._detectors:
            try:
                proposals = detector.detect(file_path=file_path, content=content)
                for p in proposals:
                    findings.append(
                        {
                            "rule_id": detector.rule_id,
                            "severity": p.severity,
                            "title": p.title,
                            "description": p.description,
                            "evidence": p.evidence,
                            "recommendation": p.recommendation,
                            "confidence": p.confidence,
                        }
                    )
            except Exception as exc:
                logger.warning(
                    "StaticAnalyzer: detector %r raised on %s: %s",
                    detector.rule_id,
                    file_path,
                    exc,
                )

        return AnalysisResult(
            file_path=file_path,
            analyzer_id=self.analyzer_id,
            findings=findings,
            success=True,
        )
