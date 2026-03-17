"""Hypothesis layer between detector hits and persisted proposals."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_SEVERITY_RANK: Dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


@dataclass
class RawSignal:
    """Atomic observation before backlog lifecycle is applied."""

    rule_id: str
    file_path: str
    severity: str
    confidence: float
    source_detector: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    context: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "context": self.context,
            "severity": self.severity,
            "confidence": self.confidence,
            "source_detector": self.source_detector,
        }


@dataclass
class Hypothesis:
    """Aggregated observation from one or more raw signals."""

    rule_id: str
    file_path: str
    source_analyzer: str = "static"
    signals: List[RawSignal] = field(default_factory=list)
    severity: str = "medium"
    confidence: float = 0.5
    validated: bool = False
    notes: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def primary_signal(self) -> Optional[RawSignal]:
        return self.signals[0] if self.signals else None

    def add_signal(self, signal: RawSignal) -> None:
        self.signals.append(signal)
        if _SEVERITY_RANK.get(signal.severity, 0) > _SEVERITY_RANK.get(self.severity, 0):
            self.severity = signal.severity
        self.confidence = sum(item.confidence for item in self.signals) / len(self.signals)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "severity": self.severity,
            "confidence": self.confidence,
            "validated": self.validated,
            "created_at": self.created_at,
            "notes": self.notes,
            "source_analyzer": self.source_analyzer,
            "signals": [signal.to_dict() for signal in self.signals],
        }


class HypothesisBuilder:
    """Group signals by rule and file."""

    def __init__(self) -> None:
        self._buckets: Dict[tuple, Hypothesis] = {}

    def add(self, signal: RawSignal, source_analyzer: str = "static") -> None:
        key = (signal.rule_id, signal.file_path)
        if key not in self._buckets:
            self._buckets[key] = Hypothesis(
                rule_id=signal.rule_id,
                file_path=signal.file_path,
                source_analyzer=source_analyzer,
                severity=signal.severity,
                confidence=signal.confidence,
            )
        self._buckets[key].add_signal(signal)

    def build(self) -> List[Hypothesis]:
        return list(self._buckets.values())

    def reset(self) -> None:
        self._buckets.clear()
