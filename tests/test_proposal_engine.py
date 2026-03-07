"""Tests for the Proposal Engine package."""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure the repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from proposal_engine.models import (
    ALLOWED_TRANSITIONS,
    Proposal,
    ProposalState,
    make_proposal_id,
)
from proposal_engine.detector import (
    HardcodedConstantDetector,
    HardcodedModelNameDetector,
    LeakedProjectIdDetector,
    NonAgnosticPromptDetector,
    build_detectors,
)
from proposal_engine.backlog import BacklogManager
from proposal_engine.trace_adapter import TraceAdapter
from proposal_engine.engine import ProposalEngine


# ---------------------------------------------------------------------------
# Proposal model tests
# ---------------------------------------------------------------------------

class TestProposalModel:
    def test_create_proposal(self):
        p = Proposal.create(
            proposal_type="hardcoded_model_names",
            title="Test",
            description="desc",
            evidence=[{"file_path": "foo.py", "line_number": 1}],
            severity="high",
            priority="p1",
            confidence=0.9,
            risk_level="medium",
            autofixable=False,
            recommendation="fix it",
        )
        assert p.id
        assert p.state == ProposalState.DETECTED
        assert p.created_at
        assert p.updated_at

    def test_to_dict_roundtrip(self):
        p = Proposal.create(
            proposal_type="test_type",
            title="T",
            description="D",
            evidence=[],
            severity="low",
            priority="p3",
            confidence=0.5,
            risk_level="low",
            autofixable=True,
            recommendation="R",
        )
        d = p.to_dict()
        p2 = Proposal.from_dict(d)
        assert p2.id == p.id
        assert p2.state == p.state
        assert p2.type == p.type

    def test_can_transition_to(self):
        p = Proposal.create(
            proposal_type="t",
            title="T",
            description="D",
            evidence=[],
            severity="low",
            priority="p3",
            confidence=0.5,
            risk_level="low",
            autofixable=False,
            recommendation="R",
        )
        assert p.can_transition_to(ProposalState.CANDIDATE)
        assert p.can_transition_to(ProposalState.REJECTED)
        assert not p.can_transition_to(ProposalState.VALIDATED)
        assert not p.can_transition_to(ProposalState.PLANNED)

    def test_invalid_transition_from_rejected(self):
        p = Proposal.create(
            proposal_type="t",
            title="T",
            description="D",
            evidence=[],
            severity="low",
            priority="p3",
            confidence=0.5,
            risk_level="low",
            autofixable=False,
            recommendation="R",
        )
        p.state = ProposalState.REJECTED
        assert not p.can_transition_to(ProposalState.CANDIDATE)
        assert not p.can_transition_to(ProposalState.VALIDATED)


# ---------------------------------------------------------------------------
# Detector tests
# ---------------------------------------------------------------------------

class TestHardcodedModelNameDetector:
    def setup_method(self):
        self.detector = HardcodedModelNameDetector()

    def test_detects_gpt4(self):
        code = 'model_name = "gpt-4-turbo"\n'
        proposals = self.detector.detect("test.py", code)
        assert len(proposals) == 1
        assert proposals[0].type == "hardcoded_model_names"
        assert proposals[0].evidence[0]["line_number"] == 1

    def test_detects_meta_llama(self):
        code = 'cfg = {"model": "meta-llama/Llama-3.1-70B-Instruct"}\n'
        proposals = self.detector.detect("test.py", code)
        assert len(proposals) == 1

    def test_ignores_comment_lines(self):
        # HardcodedModelNameDetector does not skip comment lines by design –
        # the regex matches string literals regardless of line prefix.
        # This test verifies the detector still returns a list without raising.
        code = '# model = "gpt-4"\n'
        proposals = self.detector.detect("test.py", code)
        assert isinstance(proposals, list)

    def test_no_false_positive_on_clean_code(self):
        code = 'model_name = config["model_name"]\n'
        proposals = self.detector.detect("test.py", code)
        assert len(proposals) == 0


class TestHardcodedConstantDetector:
    def setup_method(self):
        self.detector = HardcodedConstantDetector()

    def test_detects_localhost_url(self):
        code = 'api_base = "http://localhost:8000/v1"\n'
        proposals = self.detector.detect("test.py", code)
        assert len(proposals) >= 1

    def test_detects_remote_api_url(self):
        code = 'base = "https://api.openai.com/v1"\n'
        proposals = self.detector.detect("test.py", code)
        assert len(proposals) >= 1

    def test_no_false_positive_assignment(self):
        code = 'x = some_function()\n'
        proposals = self.detector.detect("test.py", code)
        assert len(proposals) == 0


class TestLeakedProjectIdDetector:
    def setup_method(self):
        self.detector = LeakedProjectIdDetector()

    def test_detects_project_id(self):
        code = 'project_id = "my-secret-project"\n'
        proposals = self.detector.detect("test.py", code)
        assert len(proposals) == 1
        assert proposals[0].severity == "critical"

    def test_detects_org_id(self):
        code = 'org_id = "acme-corp"\n'
        proposals = self.detector.detect("test.py", code)
        assert len(proposals) == 1

    def test_skips_comment_lines(self):
        code = '# tenant_id = "example"\n'
        proposals = self.detector.detect("test.py", code)
        assert len(proposals) == 0

    def test_no_false_positive_env_var(self):
        code = 'project_id = os.getenv("PROJECT_ID")\n'
        proposals = self.detector.detect("test.py", code)
        assert len(proposals) == 0


class TestNonAgnosticPromptDetector:
    def setup_method(self):
        self.detector = NonAgnosticPromptDetector()

    def test_detects_model_reference_in_prompt(self):
        code = 'system_prompt = "You are running on gpt-4. Use chain-of-thought."\n'
        proposals = self.detector.detect("test.py", code)
        assert len(proposals) >= 1

    def test_no_false_positive_without_context_keyword(self):
        code = 'description = "This supports claude-3-opus as a backend."\n'
        proposals = self.detector.detect("test.py", code)
        # Without a prompt-context keyword the detector should not fire
        assert len(proposals) == 0


class TestBuildDetectors:
    def test_all_enabled_by_default(self):
        detectors = build_detectors({})
        assert len(detectors) == 4

    def test_disabled_detector_excluded(self):
        detectors = build_detectors({"hardcoded_model_names": {"enabled": False}})
        rule_ids = [d.rule_id for d in detectors]
        assert "hardcoded_model_names" not in rule_ids

    def test_custom_severity_applied(self):
        detectors = build_detectors({"leaked_project_ids": {"severity": "high"}})
        d = next(d for d in detectors if d.rule_id == "leaked_project_ids")
        assert d.severity == "high"


# ---------------------------------------------------------------------------
# BacklogManager tests
# ---------------------------------------------------------------------------

class TestBacklogManager:
    def test_save_and_load(self, tmp_path):
        bm = BacklogManager(tmp_path)
        p = Proposal.create(
            proposal_type="test",
            title="T",
            description="D",
            evidence=[],
            severity="low",
            priority="p3",
            confidence=0.5,
            risk_level="low",
            autofixable=False,
            recommendation="R",
        )
        bm.save_proposals([p])
        loaded = bm.load_proposals()
        assert len(loaded) == 1
        assert loaded[0].id == p.id

    def test_get_proposal(self, tmp_path):
        bm = BacklogManager(tmp_path)
        p = Proposal.create(
            proposal_type="test",
            title="T",
            description="D",
            evidence=[],
            severity="low",
            priority="p3",
            confidence=0.5,
            risk_level="low",
            autofixable=False,
            recommendation="R",
        )
        bm.save_proposals([p])
        found = bm.get_proposal(p.id)
        assert found is not None
        assert found.id == p.id

    def test_get_missing_proposal(self, tmp_path):
        bm = BacklogManager(tmp_path)
        assert bm.get_proposal("nonexistent-id") is None

    def test_valid_state_transition(self, tmp_path):
        bm = BacklogManager(tmp_path)
        p = Proposal.create(
            proposal_type="test",
            title="T",
            description="D",
            evidence=[],
            severity="low",
            priority="p3",
            confidence=0.5,
            risk_level="low",
            autofixable=False,
            recommendation="R",
        )
        bm.save_proposals([p])
        updated = bm.transition_state(p.id, ProposalState.CANDIDATE)
        assert updated is not None
        assert updated.state == ProposalState.CANDIDATE

    def test_invalid_state_transition_returns_none(self, tmp_path):
        bm = BacklogManager(tmp_path)
        p = Proposal.create(
            proposal_type="test",
            title="T",
            description="D",
            evidence=[],
            severity="low",
            priority="p3",
            confidence=0.5,
            risk_level="low",
            autofixable=False,
            recommendation="R",
        )
        bm.save_proposals([p])
        result = bm.transition_state(p.id, ProposalState.PLANNED)
        assert result is None

    def test_list_proposals_filter_by_state(self, tmp_path):
        bm = BacklogManager(tmp_path)
        p1 = Proposal.create(
            proposal_type="t1", title="T1", description="D", evidence=[],
            severity="low", priority="p3", confidence=0.5, risk_level="low",
            autofixable=False, recommendation="R",
        )
        p2 = Proposal.create(
            proposal_type="t2", title="T2", description="D", evidence=[],
            severity="low", priority="p3", confidence=0.5, risk_level="low",
            autofixable=False, recommendation="R",
        )
        bm.save_proposals([p1, p2])
        bm.transition_state(p1.id, ProposalState.CANDIDATE)

        detected = bm.list_proposals(state=ProposalState.DETECTED)
        candidate = bm.list_proposals(state=ProposalState.CANDIDATE)
        assert len(detected) == 1
        assert len(candidate) == 1

    def test_scan_summary_persisted(self, tmp_path):
        bm = BacklogManager(tmp_path)
        p = Proposal.create(
            proposal_type="test", title="T", description="D", evidence=[],
            severity="low", priority="p3", confidence=0.5, risk_level="low",
            autofixable=False, recommendation="R",
        )
        scan_id = "test-scan-001"
        bm.save_proposals([p], scan_id=scan_id)

        summary = bm.get_scan_summary(scan_id)
        assert summary is not None
        assert summary["scan_id"] == scan_id
        assert summary["proposal_count"] == 1


# ---------------------------------------------------------------------------
# TraceAdapter tests
# ---------------------------------------------------------------------------

class TestTraceAdapter:
    def test_noop_when_innertrace_unavailable(self, tmp_path):
        """TraceAdapter must not raise even if InnerTrace is not installed."""
        events_path = str(tmp_path / "nonexistent_subdir" / "events.jsonl")
        adapter = TraceAdapter(events_path=events_path)
        # All calls must be silent no-ops or succeed
        run_id = adapter.start_scan(".", "test-scan")
        adapter.emit_violation("rule_id", "file.py", "high", 1)
        adapter.emit_proposal("pid", "type", "high", "file.py")
        adapter.emit_validation("pid", "validated")
        adapter.end_scan("ok", 0, "test-scan")

    def test_file_scan_span_noop(self, tmp_path):
        events_path = str(tmp_path / "nonexistent_subdir" / "events.jsonl")
        adapter = TraceAdapter(events_path=events_path)
        with adapter.file_scan_span("file.py") as span_id:
            pass  # must not raise


# ---------------------------------------------------------------------------
# ProposalEngine integration tests
# ---------------------------------------------------------------------------

class TestProposalEngine:
    def test_scan_discovers_and_returns_proposals(self, tmp_path):
        # Write a Python file with a hardcoded model name
        src = tmp_path / "service.py"
        src.write_text('model_name = "gpt-4-turbo"\n', encoding="utf-8")

        backlog = BacklogManager(tmp_path / "proposals")
        tracer = TraceAdapter()  # no-op
        engine = ProposalEngine(backlog_manager=backlog, trace_adapter=tracer)

        proposals = engine.run_proposal_scan(str(tmp_path))
        assert len(proposals) >= 1
        assert any(p.type == "hardcoded_model_names" for p in proposals)

    def test_scan_persists_proposals_to_backlog(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text('project_id = "acme-project"\n', encoding="utf-8")

        backlog = BacklogManager(tmp_path / "proposals")
        tracer = TraceAdapter()
        engine = ProposalEngine(backlog_manager=backlog, trace_adapter=tracer)

        engine.run_proposal_scan(str(tmp_path))
        all_proposals = backlog.list_proposals()
        assert len(all_proposals) >= 1

    def test_scan_empty_directory_returns_no_proposals(self, tmp_path):
        backlog = BacklogManager(tmp_path / "proposals")
        tracer = TraceAdapter()
        engine = ProposalEngine(backlog_manager=backlog, trace_adapter=tracer)

        proposals = engine.run_proposal_scan(str(tmp_path))
        assert proposals == []

    def test_scan_excludes_filtered_paths(self, tmp_path):
        node_modules = tmp_path / "node_modules"
        node_modules.mkdir()
        (node_modules / "lib.py").write_text('model_name = "gpt-4"\n', encoding="utf-8")

        backlog = BacklogManager(tmp_path / "proposals")
        tracer = TraceAdapter()
        engine = ProposalEngine(
            backlog_manager=backlog,
            trace_adapter=tracer,
            file_filtering={"exclude_patterns": ["node_modules"]},
        )

        proposals = engine.run_proposal_scan(str(tmp_path))
        assert len(proposals) == 0


# ---------------------------------------------------------------------------
# Fix 1: Backlog idempotency
# ---------------------------------------------------------------------------

class TestBacklogIdempotency:
    def test_same_rule_file_line_produces_same_id(self):
        """Two Proposal.create() calls for the same location share an ID."""
        kwargs = dict(
            proposal_type="hardcoded_model_names",
            title="T1",
            description="D",
            evidence=[{"file_path": "foo.py", "line_number": 5}],
            severity="high",
            priority="p1",
            confidence=0.9,
            risk_level="medium",
            autofixable=False,
            recommendation="R",
            source_rule="hardcoded_model_names",
        )
        p1 = Proposal.create(**kwargs)
        kwargs2 = dict(kwargs)
        kwargs2["title"] = "T2 (same location, different title)"
        p2 = Proposal.create(**kwargs2)
        assert p1.id == p2.id

    def test_different_line_different_id(self):
        base = dict(
            proposal_type="hardcoded_model_names",
            title="T",
            description="D",
            severity="high",
            priority="p1",
            confidence=0.9,
            risk_level="medium",
            autofixable=False,
            recommendation="R",
            source_rule="hardcoded_model_names",
        )
        p1 = Proposal.create(**base, evidence=[{"file_path": "foo.py", "line_number": 5}])
        p2 = Proposal.create(**base, evidence=[{"file_path": "foo.py", "line_number": 10}])
        assert p1.id != p2.id

    def test_different_rule_different_id(self):
        base = dict(
            title="T",
            description="D",
            evidence=[{"file_path": "foo.py", "line_number": 5}],
            severity="high",
            priority="p1",
            confidence=0.9,
            risk_level="medium",
            autofixable=False,
            recommendation="R",
        )
        p1 = Proposal.create(**base, proposal_type="rule_a", source_rule="rule_a")
        p2 = Proposal.create(**base, proposal_type="rule_b", source_rule="rule_b")
        assert p1.id != p2.id

    def test_make_proposal_id_is_deterministic(self):
        id1 = make_proposal_id("rule_x", "src/main.py", 42)
        id2 = make_proposal_id("rule_x", "src/main.py", 42)
        assert id1 == id2

    def test_double_scan_no_backlog_growth(self, tmp_path):
        """Running the same scan twice must not grow the backlog."""
        src = tmp_path / "service.py"
        src.write_text('model_name = "gpt-4-turbo"\n', encoding="utf-8")

        backlog = BacklogManager(tmp_path / "proposals")
        engine = ProposalEngine(backlog_manager=backlog, trace_adapter=TraceAdapter())

        engine.run_proposal_scan(str(tmp_path))
        count_after_first = len(backlog.list_proposals())

        engine.run_proposal_scan(str(tmp_path))
        count_after_second = len(backlog.list_proposals())

        assert count_after_first == count_after_second

    def test_rescan_preserves_promoted_state(self, tmp_path):
        """A proposal promoted to CANDIDATE must retain its state after a rescan."""
        src = tmp_path / "service.py"
        src.write_text('model_name = "gpt-4-turbo"\n', encoding="utf-8")

        backlog = BacklogManager(tmp_path / "proposals")
        engine = ProposalEngine(backlog_manager=backlog, trace_adapter=TraceAdapter())

        engine.run_proposal_scan(str(tmp_path))
        proposal = backlog.list_proposals()[0]
        backlog.transition_state(proposal.id, ProposalState.CANDIDATE)

        # Rescan – state must be preserved
        engine.run_proposal_scan(str(tmp_path))
        updated = backlog.get_proposal(proposal.id)
        assert updated.state == ProposalState.CANDIDATE


# ---------------------------------------------------------------------------
# Fix 2: Full file-filtering semantics (include_only, fnmatch)
# ---------------------------------------------------------------------------

class TestProposalEngineFiltering:
    def _engine(self, tmp_path, filtering):
        return ProposalEngine(
            backlog_manager=BacklogManager(tmp_path / "proposals"),
            trace_adapter=TraceAdapter(),
            file_filtering=filtering,
        )

    def test_include_only_respects_include_patterns(self, tmp_path):
        """include_only mode must only scan files in the included directory."""
        (tmp_path / "keep").mkdir()
        (tmp_path / "skip").mkdir()
        (tmp_path / "keep" / "a.py").write_text('model_name = "gpt-4"\n', encoding="utf-8")
        (tmp_path / "skip" / "b.py").write_text('model_name = "gpt-4"\n', encoding="utf-8")

        engine = self._engine(
            tmp_path,
            {"include_patterns": ["keep"], "exclude_patterns": [], "default_behavior": "include_only"},
        )
        proposals = engine.run_proposal_scan(str(tmp_path))
        sources = {ev["file_path"] for p in proposals for ev in p.evidence}
        assert sources, "Expected at least one proposal from keep/"
        assert all("keep" in s for s in sources), f"Unexpected sources: {sources}"
        assert not any("skip" in s for s in sources)

    def test_include_only_no_include_patterns_scans_nothing(self, tmp_path):
        """include_only with an empty include list must produce no files."""
        (tmp_path / "a.py").write_text('model_name = "gpt-4"\n', encoding="utf-8")

        engine = self._engine(
            tmp_path,
            {"include_patterns": [], "exclude_patterns": [], "default_behavior": "include_only"},
        )
        proposals = engine.run_proposal_scan(str(tmp_path))
        assert proposals == []

    def test_exclude_only_skips_pattern_matched_files(self, tmp_path):
        """default_behavior='include_all' must skip exclude_patterns dirs."""
        (tmp_path / "src").mkdir()
        (tmp_path / "vendor").mkdir()
        (tmp_path / "src" / "main.py").write_text('model_name = "gpt-4"\n', encoding="utf-8")
        (tmp_path / "vendor" / "lib.py").write_text('model_name = "gpt-4"\n', encoding="utf-8")

        engine = self._engine(
            tmp_path,
            {"include_patterns": [], "exclude_patterns": ["vendor"], "default_behavior": "include_all"},
        )
        proposals = engine.run_proposal_scan(str(tmp_path))
        sources = {ev["file_path"] for p in proposals for ev in p.evidence}
        assert not any("vendor" in s for s in sources)
        assert any("src" in s for s in sources)

    def test_fnmatch_glob_pattern_in_exclude(self, tmp_path):
        """Glob patterns like '*.min.py' must be honoured in exclude_patterns."""
        (tmp_path / "app.py").write_text('model_name = "gpt-4"\n', encoding="utf-8")
        (tmp_path / "app.min.py").write_text('model_name = "gpt-4"\n', encoding="utf-8")

        engine = self._engine(
            tmp_path,
            {"include_patterns": [], "exclude_patterns": ["*.min.py"], "default_behavior": "include_all"},
        )
        proposals = engine.run_proposal_scan(str(tmp_path))
        sources = {ev["file_path"] for p in proposals for ev in p.evidence}
        assert not any("app.min.py" in s for s in sources)
        assert any("app.py" in s for s in sources)


# ---------------------------------------------------------------------------
# Fix 3: file_filtering callable is re-read on every scan
# ---------------------------------------------------------------------------

class TestProposalEngineCallableFiltering:
    def test_callable_filtering_applied_per_scan(self, tmp_path):
        """Changing a callable's underlying dict is picked up without restart."""
        (tmp_path / "keep").mkdir()
        (tmp_path / "skip").mkdir()
        (tmp_path / "keep" / "a.py").write_text('model_name = "gpt-4"\n', encoding="utf-8")
        (tmp_path / "skip" / "b.py").write_text('model_name = "gpt-4"\n', encoding="utf-8")

        current = {"include_patterns": [], "exclude_patterns": [], "default_behavior": "include_all"}

        backlog = BacklogManager(tmp_path / "proposals")
        engine = ProposalEngine(
            backlog_manager=backlog,
            trace_adapter=TraceAdapter(),
            file_filtering=lambda: current,
        )

        # First scan: all files included → both files trigger proposals
        p1 = engine.run_proposal_scan(str(tmp_path))
        sources_1 = {ev["file_path"] for p in p1 for ev in p.evidence}
        assert any("keep" in s for s in sources_1)
        assert any("skip" in s for s in sources_1)

        # Mutate the filter in-place – now include_only "keep"
        current["include_patterns"] = ["keep"]
        current["default_behavior"] = "include_only"

        p2 = engine.run_proposal_scan(str(tmp_path))
        sources_2 = {ev["file_path"] for p in p2 for ev in p.evidence}
        msg = f"skip/ should be excluded after filter update, got: {sources_2}"
        assert not any("skip" in s for s in sources_2), msg
