"""Proposal data model for the Software Improvement Engine."""

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

# Fixed namespace UUID used to derive deterministic proposal IDs.
# This is a project-specific UUID (not a standard IANA namespace) chosen
# to scope proposal IDs to InnerAudit.  Changing this value would
# invalidate all previously-stored IDs.
_PROPOSAL_NAMESPACE = uuid.UUID("7ba4b810-9dad-11d1-80b4-00c04fd430c8")


def make_proposal_id(
    rule_id: str,
    file_path: str,
    line_number: Optional[int] = None,
) -> str:
    """Return a deterministic proposal ID derived from rule + file location.

    Two detections of the same rule violation at the same file/line always
    produce the same ID, which makes the backlog idempotent across repeated
    scans of unchanged code.
    """
    key = f"{rule_id}:{file_path}:{line_number if line_number is not None else ''}"
    return str(uuid.uuid5(_PROPOSAL_NAMESPACE, key))


class ProposalState(str, Enum):
    """Lifecycle states for a proposal."""

    DETECTED = "detected"
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    PLANNED = "planned"
    REJECTED = "rejected"


# Valid state transitions
ALLOWED_TRANSITIONS: Dict[str, List[str]] = {
    ProposalState.DETECTED: [ProposalState.CANDIDATE, ProposalState.REJECTED],
    ProposalState.CANDIDATE: [ProposalState.VALIDATED, ProposalState.REJECTED],
    ProposalState.VALIDATED: [ProposalState.PLANNED, ProposalState.REJECTED],
    ProposalState.PLANNED: [ProposalState.REJECTED],
    ProposalState.REJECTED: [],
}


@dataclass
class Evidence:
    """Code evidence supporting a proposal."""

    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    context: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "context": self.context,
        }


@dataclass
class Proposal:
    """A structured improvement proposal generated from code analysis."""

    id: str
    type: str
    title: str
    description: str
    evidence: List[Dict[str, Any]]
    severity: str          # critical | high | medium | low
    priority: str          # p0 | p1 | p2 | p3
    confidence: float      # 0.0 – 1.0
    risk_level: str        # low | medium | high
    autofixable: bool
    recommendation: str
    state: str             # ProposalState value
    created_at: str
    updated_at: str
    source_analysis: Optional[str] = None   # analysis_type that triggered this
    source_rule: Optional[str] = None       # detector rule_id
    scan_id: Optional[str] = None           # backlog scan that produced it

    @classmethod
    def create(
        cls,
        proposal_type: str,
        title: str,
        description: str,
        evidence: List[Dict[str, Any]],
        severity: str,
        priority: str,
        confidence: float,
        risk_level: str,
        autofixable: bool,
        recommendation: str,
        source_analysis: Optional[str] = None,
        source_rule: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> "Proposal":
        now = datetime.now(timezone.utc).isoformat()
        # Derive a deterministic ID from the primary evidence location so that
        # repeated scans of the same violation do not create duplicate entries.
        primary = evidence[0] if evidence else {}
        proposal_id = make_proposal_id(
            source_rule or proposal_type,
            primary.get("file_path", ""),
            primary.get("line_number"),
        )
        return cls(
            id=proposal_id,
            type=proposal_type,
            title=title,
            description=description,
            evidence=evidence,
            severity=severity,
            priority=priority,
            confidence=confidence,
            risk_level=risk_level,
            autofixable=autofixable,
            recommendation=recommendation,
            state=ProposalState.DETECTED,
            created_at=now,
            updated_at=now,
            source_analysis=source_analysis,
            source_rule=source_rule,
            scan_id=scan_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "severity": self.severity,
            "priority": self.priority,
            "confidence": self.confidence,
            "risk_level": self.risk_level,
            "autofixable": self.autofixable,
            "recommendation": self.recommendation,
            "state": self.state,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "source_analysis": self.source_analysis,
            "source_rule": self.source_rule,
            "scan_id": self.scan_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Proposal":
        return cls(
            id=data["id"],
            type=data["type"],
            title=data["title"],
            description=data["description"],
            evidence=data.get("evidence", []),
            severity=data.get("severity", "medium"),
            priority=data.get("priority", "p2"),
            confidence=float(data.get("confidence", 0.5)),
            risk_level=data.get("risk_level", "medium"),
            autofixable=bool(data.get("autofixable", False)),
            recommendation=data.get("recommendation", ""),
            state=data.get("state", ProposalState.DETECTED),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            source_analysis=data.get("source_analysis"),
            source_rule=data.get("source_rule"),
            scan_id=data.get("scan_id"),
        )

    def can_transition_to(self, new_state: str) -> bool:
        """Return True if this proposal may move to new_state."""
        allowed = ALLOWED_TRANSITIONS.get(self.state, [])
        return new_state in allowed
