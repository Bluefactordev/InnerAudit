"""Analyzer abstraction package for InnerAudit.

Provides a clean hierarchy of analysis backends:

- :class:`BaseAnalyzer`          – abstract base class
- :class:`StaticAnalyzer`        – deterministic, zero external deps
- :class:`AiderAnalyzer`         – optional, wraps the Aider CLI
- :class:`ExternalLLMAnalyzer`   – optional, calls any OpenAI-compatible API
- :func:`build_analyzer`         – factory for a single backend
- :func:`build_analyzers_from_config` – builds the active list from config
"""

from .base import AnalysisResult, BaseAnalyzer
from .registry import build_analyzer, build_analyzers_from_config
from .static_analyzer import StaticAnalyzer

__all__ = [
    "AnalysisResult",
    "BaseAnalyzer",
    "StaticAnalyzer",
    "build_analyzer",
    "build_analyzers_from_config",
]
