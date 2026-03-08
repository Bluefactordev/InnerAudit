"""AiderAnalyzer – optional analyzer backend wrapping the Aider CLI tool.

This analyzer requires Aider to be installed (``pip install aider-chat``).
When Aider is absent or disabled the system continues to work using the
StaticAnalyzer backend.

The class deliberately does **not** auto-fix code.  Its sole role is deep
semantic observation — it reads files and returns structured findings that
the Hypothesis/Proposal pipeline can consume.
"""

import logging
import shutil
from typing import Any, Dict, Optional

from .base import AnalysisResult, BaseAnalyzer

logger = logging.getLogger("AiderAnalyzer")


class AiderAnalyzer(BaseAnalyzer):
    """Optional analyzer that delegates to the Aider CLI for LLM-assisted analysis.

    Configuration keys (under ``analyzers.aider`` in ``audit_config.json``):

    ``enabled`` (bool, default False)
        Must be True for the analyzer to participate.

    ``command`` (str, default ``"aider"``)
        Path or name of the Aider executable.

    All other keys are forwarded to :class:`audit_engine.AiderIntegration`.
    """

    analyzer_id = "aider"
    requires_external_service = True

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        model_config: Any = None,
    ) -> None:
        super().__init__(config)
        self._model_config = model_config
        self._aider_integration = None

        if self.enabled and model_config is not None:
            self._try_init_aider()

    def _try_init_aider(self) -> None:
        try:
            from audit_engine import AiderIntegration

            self._aider_integration = AiderIntegration(self.config, self._model_config)
            logger.info("AiderAnalyzer: AiderIntegration initialised.")
        except Exception as exc:
            logger.warning("AiderAnalyzer: could not initialise AiderIntegration: %s", exc)

    def is_available(self) -> bool:
        """Return True only when Aider is enabled, installed, and on PATH."""
        if not self.enabled:
            return False
        cmd = self.config.get("command", "aider")
        available = shutil.which(cmd) is not None
        if not available:
            logger.debug("AiderAnalyzer: command %r not found on PATH.", cmd)
        return available

    def analyze_file(
        self,
        file_path: str,
        content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AnalysisResult:
        """Run Aider analysis on *file_path*.

        ``context`` must contain:
        ``analysis_type``
            An :class:`audit_engine.AnalysisType` instance.
        ``project_path``
            Root path of the project being scanned.
        """
        if not self.is_available() or self._aider_integration is None:
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
            success, parsed_json, raw_output = self._aider_integration.run_analysis(
                file_path=file_path,
                analysis_type=analysis_type,
                project_path=project_path,
            )
        except Exception as exc:
            logger.error("AiderAnalyzer failed on %s: %s", file_path, exc)
            return AnalysisResult(
                file_path=file_path,
                analyzer_id=self.analyzer_id,
                success=False,
                error=str(exc),
            )

        findings = []
        score = None
        if parsed_json:
            for key in ("findings", "vulnerabilities", "issues", "performance_issues"):
                if key in parsed_json:
                    findings = parsed_json[key]
                    break
            for score_key in (
                "overall_score",
                "security_score",
                "quality_score",
                "performance_score",
            ):
                if score_key in parsed_json:
                    score = parsed_json[score_key]
                    break

        return AnalysisResult(
            file_path=file_path,
            analyzer_id=self.analyzer_id,
            findings=findings,
            success=success,
            raw_output=raw_output,
            score=score,
        )
