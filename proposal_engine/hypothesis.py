"""Hypothesis layer – intermediate concept between raw detector signals and proposals.

Pipeline::

    observe (file discovery)
        → detect (detectors produce RawSignals)
            → HypothesisBuilder (aggregates signals by rule + file)
                → Hypothesis (normalised, multi-source evidence bundle)
                    → Proposal.create() (backlog entry with lifecycle state)

The Hypothesis layer decouples observation from proposal creation so that:
- Multiple detectors (or external analyzers) can contribute signals to the
  same hypothesis before a proposal is committed.
- Severity and confidence are normalised across contributing signals.
- Future validation by stronger models can operate on Hypothesis objects
  before they become permanent backlog entries.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# Severity rank used for escalation logic.
_SEVERITY_RANK: Dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


@dataclass
class RawSignal:
    """A single observation produced by a detector or external analyzer.

    RawSignals are the atomic unit of evidence before aggregation.  They
    carry just enough information to build or enrich a Hypothesis, without
    any backlog lifecycle state.
    """

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
    """Aggregated observation derived from one or more raw detector signals.

    A Hypothesis sits between raw detector hits and a fully-formed Proposal.
    It accumulates evidence from multiple sources (static detectors, external
    analyzers) before being converted into a Proposal for the backlog.

    Key invariants:
    - Severity is *escalated* (never downgraded) as new signals arrive.
    - Confidence is averaged across contributing signals.
    - The primary signal is the first one added.
    """

    rule_id: str
    file_path: str
    source_analyzer: str = "static"
    signals: List[RawSignal] = field(default_factory=list)
    severity: str = "medium"
    confidence: float = 0.5
    validated: bool = False
    notes: Optional[str] = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def primary_signal(self) -> Optional[RawSignal]:
        """Return the first contributing signal, or None if empty."""
        return self.signals[0] if self.signals else None

    def add_signal(self, signal: RawSignal) -> None:
        """Add a new signal, escalating severity and averaging confidence."""
        self.signals.append(signal)
        if _SEVERITY_RANK.get(signal.severity, 0) > _SEVERITY_RANK.get(self.severity, 0):
            self.severity = signal.severity
        self.confidence = sum(s.confidence for s in self.signals) / len(self.signals)

    def to_evidence_list(self) -> List[Dict[str, Any]]:
        """Convert signals to the evidence format expected by Proposal.create()."""
        return [
            {
                "file_path": s.file_path,
                "line_number": s.line_number,
                "code_snippet": s.code_snippet,
                "context": s.context,
            }
            for s in self.signals
        ]

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
            "signals": [s.to_dict() for s in self.signals],
        }


class HypothesisBuilder:
    """Groups raw signals into Hypothesis objects keyed by (rule_id, file_path).

    Usage::

        builder = HypothesisBuilder()
        for signal in raw_signals:
            builder.add(signal)
        hypotheses = builder.build()
    """

    def __init__(self) -> None:
        self._buckets: Dict[tuple, Hypothesis] = {}

    def add(self, signal: RawSignal, source_analyzer: str = "static") -> None:
        """Add a signal, creating a new Hypothesis bucket when needed."""
        key = (signal.rule_id, signal.file_path)
        if key not in self._buckets:
            self._buckets[key] = Hypothesis(
                rule_id=signal.rule_id,
                file_path=signal.file_path,
                source_analyzer=source_analyzer,
                severity=signal.severity,
                confidence=signal.confidence,
            )
        hyp = self._buckets[key]
        hyp.add_signal(signal)

    def build(self) -> List[Hypothesis]:
        """Return all accumulated hypotheses."""
        return list(self._buckets.values())

    def reset(self) -> None:
        """Clear internal state (useful when reusing across files)."""
        self._buckets.clear()
