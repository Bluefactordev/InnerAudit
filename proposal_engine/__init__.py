"""Proposal Engine – Software Improvement Engine for InnerAudit."""

from .backlog import BacklogManager
from .engine import ProposalEngine
from .models import ALLOWED_TRANSITIONS, Proposal, ProposalState, make_proposal_id
from .trace_adapter import TraceAdapter

__all__ = [
    "ProposalEngine",
    "Proposal",
    "ProposalState",
    "ALLOWED_TRANSITIONS",
    "make_proposal_id",
    "BacklogManager",
    "TraceAdapter",
]
