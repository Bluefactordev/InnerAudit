"""Analyzer registry and factory functions."""

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
    """Instantiate a single analyzer by *analyzer_id*.

    Keyword arguments are forwarded to the analyzer constructor:
    ``detector_configs``
        Passed to :class:`StaticAnalyzer`.
    ``model_config``
        Passed to :class:`AiderAnalyzer` and :class:`ExternalLLMAnalyzer`.
    """
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
    **kwargs: Any,
) -> List[BaseAnalyzer]:
    """Build a list of enabled and available analyzers from configuration.

    ``analyzers_config`` is the value of the ``"analyzers"`` key in
    ``audit_config.json``.  Each entry is keyed by ``analyzer_id`` and
    contains per-analyzer configuration.

    Analyzers are included only when:
    1. ``config["enabled"]`` is True (or absent, defaulting to True).
    2. ``analyzer.is_available()`` returns True.

    ``StaticAnalyzer`` is always added as a fallback when no analyzers are
    configured, ensuring the system produces useful output even in the most
    minimal deployment.
    """
    if not analyzers_config:
        logger.info("No analyzer config provided; using StaticAnalyzer only.")
        return [StaticAnalyzer(config={}, detector_configs=kwargs.get("detector_configs"))]

    analyzers: List[BaseAnalyzer] = []
    for aid, cfg in analyzers_config.items():
        if not cfg.get("enabled", True):
            logger.debug("Analyzer %r is disabled in config.", aid)
            continue

        analyzer = build_analyzer(aid, cfg, **kwargs)
        if analyzer is None:
            continue

        if analyzer.is_available():
            analyzers.append(analyzer)
            logger.info("Analyzer %r registered and available.", aid)
        else:
            logger.info(
                "Analyzer %r registered but not available (skipped).", aid
            )

    if not analyzers:
        logger.info(
            "No analyzers are available after config check; "
            "falling back to StaticAnalyzer."
        )
        analyzers.append(
            StaticAnalyzer(config={}, detector_configs=kwargs.get("detector_configs"))
        )

    return analyzers
