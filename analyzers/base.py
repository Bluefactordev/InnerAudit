"""Base analyzer abstraction for InnerAudit.

All analyzer backends must extend BaseAnalyzer.  The system treats any
backend that reports is_available() == False as gracefully absent and
continues without it.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AnalysisResult:
    """Structured result returned by any analyzer backend."""

    file_path: str
    analyzer_id: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    success: bool = True
    error: Optional[str] = None
    raw_output: Optional[str] = None
    score: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "analyzer_id": self.analyzer_id,
            "findings": self.findings,
            "success": self.success,
            "error": self.error,
            "raw_output": self.raw_output,
            "score": self.score,
            "metadata": self.metadata,
        }


class BaseAnalyzer(ABC):
    """Abstract base class for all InnerAudit analyzer backends.

    Concrete implementations must declare:
    - ``analyzer_id``  – unique string name used in config and logs.
    - ``requires_external_service`` – True if a network/process call is needed.

    And must implement:
    - ``is_available()`` – returns True only when all dependencies are present.
    - ``analyze_file()``  – perform analysis on a single file and return findings.
    """

    analyzer_id: str = "base"
    requires_external_service: bool = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.enabled: bool = bool(self.config.get("enabled", True))

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this analyzer's runtime dependencies are present."""

    @abstractmethod
    def analyze_file(
        self,
        file_path: str,
        content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AnalysisResult:
        """Analyze a single file and return an AnalysisResult."""

    def analyze_files(
        self,
        file_paths: List[str],
        context: Optional[Dict[str, Any]] = None,
    ) -> List[AnalysisResult]:
        """Analyze multiple files.

        The default implementation calls :meth:`analyze_file` once per file.
        Subclasses may override for batching or concurrency.
        """
        results: List[AnalysisResult] = []
        for fp in file_paths:
            try:
                with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                results.append(self.analyze_file(fp, content, context))
            except OSError as exc:
                results.append(
                    AnalysisResult(
                        file_path=fp,
                        analyzer_id=self.analyzer_id,
                        success=False,
                        error=str(exc),
                    )
                )
        return results
