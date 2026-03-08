"""ExternalLLMAnalyzer – optional analyzer that calls any OpenAI-compatible endpoint.

Unlike AiderAnalyzer, this backend communicates directly with an LLM API
without requiring the Aider CLI.  It is suitable for semantic analysis when
a compatible model endpoint is configured.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from .base import AnalysisResult, BaseAnalyzer

logger = logging.getLogger("ExternalLLMAnalyzer")


class ExternalLLMAnalyzer(BaseAnalyzer):
    """Analyzer that calls an OpenAI-compatible chat completion endpoint.

    Configuration keys (under ``analyzers.llm`` in ``audit_config.json``):

    ``enabled`` (bool, default False)
        Must be True to participate.

    ``model_role`` (str, default ``"scanner_model"``)
        Key into ``model_roles`` that resolves the model to use.

    ``timeout`` (int, default 120)
        Request timeout in seconds.
    """

    analyzer_id = "llm"
    requires_external_service = True

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        model_config: Any = None,
    ) -> None:
        super().__init__(config)
        self._model_config = model_config

    def is_available(self) -> bool:
        """Return True when the openai package is importable and a model is configured."""
        if not self.enabled:
            return False
        if self._model_config is None:
            return False
        try:
            import openai  # noqa: F401

            return True
        except ImportError:
            logger.debug("ExternalLLMAnalyzer: 'openai' package not installed.")
            return False

    def analyze_file(
        self,
        file_path: str,
        content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AnalysisResult:
        """Send *content* to the configured LLM endpoint and parse findings."""
        if not self.is_available():
            return AnalysisResult(
                file_path=file_path,
                analyzer_id=self.analyzer_id,
                success=False,
                error="ExternalLLMAnalyzer is not available.",
            )

        try:
            import openai

            mc = self._model_config
            api_key = mc.api_key
            if api_key.startswith("$"):
                import os

                api_key = os.getenv(api_key[1:], "sk-dummy")

            client = openai.OpenAI(
                api_key=api_key,
                base_url=mc.api_base,
                timeout=self.config.get("timeout", 120),
            )

            system_msg = (
                "You are a senior code auditor. "
                "Analyse the provided file for security, quality, and improvement opportunities. "
                "Respond ONLY with valid JSON: "
                '{"findings": [{"severity": "critical|high|medium|low", '
                '"description": "...", "line_number": N, "recommendation": "..."}], '
                '"overall_score": 0-100}'
            )

            response = client.chat.completions.create(
                model=mc.model_name,
                messages=[
                    {"role": "system", "content": system_msg},
                    {
                        "role": "user",
                        "content": f"File: {file_path}\n\n```\n{content}\n```",
                    },
                ],
                max_tokens=getattr(mc, "max_tokens", 4096),
                temperature=getattr(mc, "temperature", 0.2),
            )

            raw_output = response.choices[0].message.content or ""
            parsed: Optional[Dict[str, Any]] = None
            try:
                parsed = json.loads(raw_output)
            except json.JSONDecodeError:
                import re

                match = re.search(r"\{.*\}", raw_output, re.DOTALL)
                if match:
                    try:
                        parsed = json.loads(match.group(0))
                    except json.JSONDecodeError:
                        pass

            findings: List[Dict[str, Any]] = []
            score: Optional[int] = None
            if parsed:
                findings = parsed.get("findings", [])
                score = parsed.get("overall_score")

            return AnalysisResult(
                file_path=file_path,
                analyzer_id=self.analyzer_id,
                findings=findings,
                success=True,
                raw_output=raw_output,
                score=score,
            )

        except Exception as exc:
            logger.error("ExternalLLMAnalyzer failed on %s: %s", file_path, exc)
            return AnalysisResult(
                file_path=file_path,
                analyzer_id=self.analyzer_id,
                success=False,
                error=str(exc),
            )
