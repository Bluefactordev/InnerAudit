"""Analyzer registry and factory helpers."""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAnalyzer
from .static_analyzer import StaticAnalyzer

logger = logging.getLogger("AnalyzerRegistry")


def build_analyzer(
    analyzer_id: str,
    config: Dict[str, Any],
    **kwargs: Any,
) -> Optional[BaseAnalyzer]:
    """Instantiate one analyzer backend."""
    if analyzer_id == "static":
        return StaticAnalyzer(
            config=config,
            detector_configs=kwargs.get("detector_configs"),
        )

    if analyzer_id == "aider":
        try:
            from .aider_analyzer import AiderAnalyzer

            return AiderAnalyzer(config=config, model_config=kwargs.get("model_config"))
        except Exception as exc:
            logger.warning("Could not instantiate AiderAnalyzer: %s", exc)
            return None

    if analyzer_id == "llm":
        try:
            from .llm_analyzer import ExternalLLMAnalyzer

            return ExternalLLMAnalyzer(
                config=config,
                model_config=kwargs.get("model_config"),
            )
        except Exception as exc:
            logger.warning("Could not instantiate ExternalLLMAnalyzer: %s", exc)
            return None

    logger.warning("Unknown analyzer_id %r; skipping.", analyzer_id)
    return None


def build_analyzers_from_config(
    analyzers_config: Dict[str, Any],
    *,
    inject_static_fallback: bool = True,
    **kwargs: Any,
) -> List[BaseAnalyzer]:
    """Build enabled analyzers from configuration.

    ``inject_static_fallback`` is intentionally configurable so the AI audit
    path can fail loudly instead of silently degrading to heuristic-only scans.
    """
    if not analyzers_config:
        if not inject_static_fallback:
            return []
        logger.info("No analyzer config provided; using StaticAnalyzer only.")
        return [StaticAnalyzer(config={}, detector_configs=kwargs.get("detector_configs"))]

    analyzers: List[BaseAnalyzer] = []
    for analyzer_id, cfg in analyzers_config.items():
        if not isinstance(cfg, dict):
            continue

        if not cfg.get("enabled", True):
            logger.debug("Analyzer %r is disabled in config.", analyzer_id)
            continue

        analyzer = build_analyzer(analyzer_id, cfg, **kwargs)
        if analyzer is None:
            continue

        if analyzer.is_available():
            analyzers.append(analyzer)
            logger.info("Analyzer %r registered and available.", analyzer_id)
        else:
            logger.info("Analyzer %r registered but unavailable.", analyzer_id)

    if not analyzers and inject_static_fallback:
        logger.info("No analyzers available; falling back to StaticAnalyzer.")
        analyzers.append(
            StaticAnalyzer(config={}, detector_configs=kwargs.get("detector_configs"))
        )

    return analyzers
