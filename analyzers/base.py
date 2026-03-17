"""Base analyzer abstraction for InnerAudit."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AnalysisResult:
    """Structured result returned by analyzer backends."""

    file_path: str
    analyzer_id: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    success: bool = True
    error: Optional[str] = None
    raw_output: Optional[str] = None
    score: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAnalyzer(ABC):
    """Abstract base class for InnerAudit analyzers."""

    analyzer_id: str = "base"
    requires_external_service: bool = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled = bool(self.config.get("enabled", True))

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the analyzer can run in the current environment."""

    @abstractmethod
    def analyze_file(
        self,
        file_path: str,
        content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AnalysisResult:
        """Analyze one file and return structured findings."""
