"""Static analyzer backend for deterministic local heuristics."""

import logging
from typing import Any, Dict, List, Optional

from .base import AnalysisResult, BaseAnalyzer

logger = logging.getLogger("StaticAnalyzer")


class StaticAnalyzer(BaseAnalyzer):
    """Local heuristic analyzer backed by proposal-engine detectors."""

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
                for proposal in proposals:
                    findings.append(
                        {
                            "rule_id": detector.rule_id,
                            "severity": proposal.severity,
                            "title": proposal.title,
                            "description": proposal.description,
                            "evidence": proposal.evidence,
                            "recommendation": proposal.recommendation,
                            "confidence": proposal.confidence,
                        }
                    )
            except Exception as exc:
                logger.warning(
                    "StaticAnalyzer: detector %s failed on %s: %s",
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
