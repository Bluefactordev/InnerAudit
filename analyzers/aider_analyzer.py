"""Aider-backed analyzer wrapper."""

import logging
import shutil
from typing import Any, Dict, Optional

from .base import AnalysisResult, BaseAnalyzer

logger = logging.getLogger("AiderAnalyzer")


class AiderAnalyzer(BaseAnalyzer):
    """Optional analyzer that delegates semantic audit work to Aider."""

    analyzer_id = "aider"
    requires_external_service = True

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        model_config: Any = None,
    ) -> None:
        super().__init__(config)
        self._model_config = model_config
        self._integration = None

        if self.enabled and model_config is not None:
            self._try_init()

    def _try_init(self) -> None:
        try:
            from audit_engine import AiderIntegration

            self._integration = AiderIntegration(self.config, self._model_config)
        except Exception as exc:
            logger.warning("AiderAnalyzer init failed: %s", exc)

    def is_available(self) -> bool:
        if not self.enabled:
            return False
        return shutil.which(self.config.get("command", "aider")) is not None

    def analyze_file(
        self,
        file_path: str,
        content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AnalysisResult:
        if not self.is_available() or self._integration is None:
            return AnalysisResult(
                file_path=file_path,
                analyzer_id=self.analyzer_id,
                success=False,
                error="Aider is not available or not configured.",
            )

        context = context or {}
        analysis_type = context.get("analysis_type")
        project_path = context.get("project_path", ".")

        if analysis_type is None:
            return AnalysisResult(
                file_path=file_path,
                analyzer_id=self.analyzer_id,
                success=False,
                error="AiderAnalyzer requires 'analysis_type' in context.",
            )

        try:
            success, parsed_json, raw_output = self._integration.run_analysis(
                file_path=file_path,
                analysis_type=analysis_type,
                project_path=project_path,
            )
            findings, score = self._integration.extract_findings_and_score(parsed_json)
        except Exception as exc:
            logger.error("AiderAnalyzer failed on %s: %s", file_path, exc)
            return AnalysisResult(
                file_path=file_path,
                analyzer_id=self.analyzer_id,
                success=False,
                error=str(exc),
            )

        return AnalysisResult(
            file_path=file_path,
            analyzer_id=self.analyzer_id,
            findings=findings,
            success=success,
            raw_output=raw_output,
            score=score,
        )
