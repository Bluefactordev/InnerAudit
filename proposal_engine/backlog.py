"""Backlog manager – persists proposals and handles state transitions."""

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import ALLOWED_TRANSITIONS, Proposal, ProposalState

logger = logging.getLogger("BacklogManager")


class BacklogManager:
    """
    Persists proposals as JSON files under *backlog_dir*.

    Layout::

        backlog_dir/
            proposals.json          # index of all proposals
            scans/
                <scan_id>.json      # per-scan summary

    The index file is a JSON object::

        {
            "proposals": { "<id>": <proposal-dict>, ... }
        }
    """

    INDEX_FILENAME = "proposals.json"
    SCANS_SUBDIR = "scans"

    def __init__(self, backlog_dir: str | Path):
        self.backlog_dir = Path(backlog_dir)
        self.backlog_dir.mkdir(parents=True, exist_ok=True)
        (self.backlog_dir / self.SCANS_SUBDIR).mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    # Index helpers
    # ------------------------------------------------------------------

    @property
    def _index_path(self) -> Path:
        return self.backlog_dir / self.INDEX_FILENAME

    def _load_index(self) -> Dict[str, Any]:
        if self._index_path.exists():
            try:
                with open(self._index_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Could not read backlog index: %s", exc)
        return {"proposals": {}}

    def _save_index(self, index: Dict[str, Any]) -> None:
        with open(self._index_path, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save_proposals(
        self,
        proposals: List[Proposal],
        scan_id: Optional[str] = None,
    ) -> None:
        """Persist *proposals* into the backlog index (merge, not overwrite)."""
        index = self._load_index()
        for proposal in proposals:
            index["proposals"][proposal.id] = proposal.to_dict()
        self._save_index(index)

        if scan_id:
            self._save_scan_summary(proposals, scan_id)

        logger.info("Saved %d proposals to backlog.", len(proposals))

    def load_proposals(self) -> List[Proposal]:
        """Return all proposals from the index."""
        index = self._load_index()
        return [
            Proposal.from_dict(d)
            for d in index.get("proposals", {}).values()
        ]

    def get_proposal(self, proposal_id: str) -> Optional[Proposal]:
        """Return a single proposal by ID, or None."""
        index = self._load_index()
        data = index.get("proposals", {}).get(proposal_id)
        if data is None:
            return None
        return Proposal.from_dict(data)

    def transition_state(self, proposal_id: str, new_state: str) -> Optional[Proposal]:
        """
        Attempt a state transition.

        Returns the updated proposal, or None if the transition is invalid.
        """
        index = self._load_index()
        raw = index.get("proposals", {}).get(proposal_id)
        if raw is None:
            logger.warning("Proposal %s not found in backlog.", proposal_id)
            return None

        proposal = Proposal.from_dict(raw)
        if not proposal.can_transition_to(new_state):
            logger.warning(
                "Invalid transition %s → %s for proposal %s.",
                proposal.state,
                new_state,
                proposal_id,
            )
            return None

        proposal.state = new_state
        proposal.updated_at = datetime.now(timezone.utc).isoformat()
        index["proposals"][proposal_id] = proposal.to_dict()
        self._save_index(index)

        logger.info("Proposal %s transitioned to %s.", proposal_id, new_state)
        return proposal

    def list_proposals(self, state: Optional[str] = None) -> List[Proposal]:
        """
        Return proposals, optionally filtered by *state*.

        Results are sorted newest-first by created_at.
        """
        proposals = self.load_proposals()
        if state:
            proposals = [p for p in proposals if p.state == state]
        proposals.sort(key=lambda p: p.created_at, reverse=True)
        return proposals

    # ------------------------------------------------------------------
    # Per-scan summary
    # ------------------------------------------------------------------

    def _save_scan_summary(
        self,
        proposals: List[Proposal],
        scan_id: str,
    ) -> None:
        scan_file = self.backlog_dir / self.SCANS_SUBDIR / f"{scan_id}.json"
        summary = {
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "proposal_count": len(proposals),
            "proposals": [p.to_dict() for p in proposals],
        }
        with open(scan_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

    def get_scan_summary(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Return the scan summary dict, or None if not found."""
        scan_file = self.backlog_dir / self.SCANS_SUBDIR / f"{scan_id}.json"
        if not scan_file.exists():
            return None
        with open(scan_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def list_scans(self) -> List[Dict[str, Any]]:
        """Return lightweight metadata for all persisted scan summaries."""
        scans_dir = self.backlog_dir / self.SCANS_SUBDIR
        results = []
        for scan_file in sorted(scans_dir.glob("*.json"), reverse=True):
            try:
                with open(scan_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                results.append(
                    {
                        "scan_id": data.get("scan_id", scan_file.stem),
                        "timestamp": data.get("timestamp", ""),
                        "proposal_count": data.get("proposal_count", 0),
                    }
                )
            except (json.JSONDecodeError, OSError):
                continue
        return results
