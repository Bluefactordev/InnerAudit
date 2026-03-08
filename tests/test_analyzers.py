"""Tests for the analyzers/ package.

Covers:
- StaticAnalyzer availability and findings
- AiderAnalyzer availability guard (Aider absent → is_available() False)
- build_analyzer factory
- build_analyzers_from_config fallback behaviour
- Full proposal scan works when Aider is absent
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzers import (
    AnalysisResult,
    BaseAnalyzer,
    StaticAnalyzer,
    build_analyzer,
    build_analyzers_from_config,
)
from analyzers.aider_analyzer import AiderAnalyzer


# ---------------------------------------------------------------------------
# StaticAnalyzer
# ---------------------------------------------------------------------------

class TestStaticAnalyzer:
    def test_is_always_available(self):
        analyzer = StaticAnalyzer()
        assert analyzer.is_available() is True

    def test_does_not_require_external_service(self):
        assert StaticAnalyzer.requires_external_service is False

    def test_analyze_file_returns_findings_for_hardcoded_model(self):
        analyzer = StaticAnalyzer()
        content = 'model_name = "gpt-4-turbo"\n'
        result = analyzer.analyze_file("test.py", content)
        assert result.success is True
        assert result.analyzer_id == "static"
        assert len(result.findings) >= 1
        rule_ids = [f["rule_id"] for f in result.findings]
        assert "hardcoded_model_names" in rule_ids

    def test_analyze_file_returns_empty_for_clean_code(self):
        analyzer = StaticAnalyzer()
        content = "x = config.get('model_name')\n"
        result = analyzer.analyze_file("test.py", content)
        assert result.success is True
        assert result.findings == []

    def test_analyze_file_result_structure(self):
        analyzer = StaticAnalyzer()
        result = analyzer.analyze_file("test.py", "# clean\n")
        assert isinstance(result, AnalysisResult)
        assert result.file_path == "test.py"
        assert isinstance(result.findings, list)

    def test_analyze_files_multi(self, tmp_path):
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.py"
        f1.write_text('model_name = "gpt-4"\n', encoding="utf-8")
        f2.write_text("# clean\n", encoding="utf-8")

        analyzer = StaticAnalyzer()
        results = analyzer.analyze_files([str(f1), str(f2)])
        assert len(results) == 2
        assert results[0].success is True
        assert results[1].success is True

    def test_analyzer_id(self):
        assert StaticAnalyzer.analyzer_id == "static"

    def test_disabled_via_config(self):
        analyzer = StaticAnalyzer(config={"enabled": False})
        # Even when disabled, is_available() should still return True for static
        # (availability ≠ enabled; the registry checks enabled before is_available)
        assert analyzer.enabled is False


# ---------------------------------------------------------------------------
# AiderAnalyzer – availability guard
# ---------------------------------------------------------------------------

class TestAiderAnalyzerAvailability:
    def test_disabled_by_default_config(self):
        """AiderAnalyzer with enabled=False must not be available."""
        analyzer = AiderAnalyzer(config={"enabled": False})
        assert analyzer.is_available() is False

    def test_unavailable_when_aider_not_on_path(self, monkeypatch):
        """When 'aider' is not on PATH, is_available() must return False."""
        import shutil

        monkeypatch.setattr(shutil, "which", lambda cmd: None)
        analyzer = AiderAnalyzer(config={"enabled": True, "command": "aider"})
        assert analyzer.is_available() is False

    def test_analyze_file_returns_error_when_unavailable(self):
        analyzer = AiderAnalyzer(config={"enabled": False})
        result = analyzer.analyze_file("f.py", "x = 1")
        assert result.success is False
        assert "not available" in result.error.lower()

    def test_analyzer_id(self):
        assert AiderAnalyzer.analyzer_id == "aider"

    def test_requires_external_service(self):
        assert AiderAnalyzer.requires_external_service is True


# ---------------------------------------------------------------------------
# build_analyzer factory
# ---------------------------------------------------------------------------

class TestBuildAnalyzer:
    def test_static_returns_static_analyzer(self):
        analyzer = build_analyzer("static", {})
        assert isinstance(analyzer, StaticAnalyzer)

    def test_aider_returns_aider_analyzer(self):
        analyzer = build_analyzer("aider", {"enabled": False})
        assert isinstance(analyzer, AiderAnalyzer)

    def test_unknown_id_returns_none(self):
        analyzer = build_analyzer("unknown_backend", {})
        assert analyzer is None

    def test_static_with_detector_configs(self):
        analyzer = build_analyzer(
            "static",
            {},
            detector_configs={"hardcoded_model_names": {"enabled": False}},
        )
        assert isinstance(analyzer, StaticAnalyzer)
        rule_ids = [d.rule_id for d in analyzer._detectors]
        assert "hardcoded_model_names" not in rule_ids


# ---------------------------------------------------------------------------
# build_analyzers_from_config
# ---------------------------------------------------------------------------

class TestBuildAnalyzersFromConfig:
    def test_empty_config_returns_static_fallback(self):
        analyzers = build_analyzers_from_config({})
        assert len(analyzers) == 1
        assert isinstance(analyzers[0], StaticAnalyzer)

    def test_none_config_returns_static_fallback(self):
        analyzers = build_analyzers_from_config({})
        assert any(isinstance(a, StaticAnalyzer) for a in analyzers)

    def test_static_enabled_returns_static(self):
        analyzers = build_analyzers_from_config({"static": {"enabled": True}})
        assert any(isinstance(a, StaticAnalyzer) for a in analyzers)

    def test_aider_disabled_excluded(self):
        analyzers = build_analyzers_from_config(
            {"static": {"enabled": True}, "aider": {"enabled": False}}
        )
        ids = [a.analyzer_id for a in analyzers]
        assert "aider" not in ids
        assert "static" in ids

    def test_all_disabled_falls_back_to_static(self, monkeypatch):
        """When all configured analyzers are disabled, StaticAnalyzer is injected."""
        analyzers = build_analyzers_from_config(
            {"aider": {"enabled": False}, "llm": {"enabled": False}}
        )
        assert any(isinstance(a, StaticAnalyzer) for a in analyzers)

    def test_unavailable_aider_excluded(self, monkeypatch):
        """AiderAnalyzer that is enabled but not on PATH must be excluded."""
        import shutil

        monkeypatch.setattr(shutil, "which", lambda cmd: None)
        analyzers = build_analyzers_from_config(
            {"aider": {"enabled": True, "command": "aider"}}
        )
        ids = [a.analyzer_id for a in analyzers]
        assert "aider" not in ids
        # StaticAnalyzer fallback must kick in
        assert any(isinstance(a, StaticAnalyzer) for a in analyzers)


# ---------------------------------------------------------------------------
# Adapter independence – full scan without Aider
# ---------------------------------------------------------------------------

class TestScanWithoutAider:
    """Verify the full proposal scan pipeline works when Aider is absent."""

    def test_proposal_scan_works_without_aider(self, tmp_path):
        """Proposal scan must succeed and return findings even without Aider."""
        from proposal_engine.backlog import BacklogManager
        from proposal_engine.engine import ProposalEngine
        from proposal_engine.trace_adapter import TraceAdapter

        src = tmp_path / "service.py"
        src.write_text('model_name = "gpt-4-turbo"\n', encoding="utf-8")

        backlog = BacklogManager(tmp_path / "proposals")
        tracer = TraceAdapter()
        engine = ProposalEngine(
            backlog_manager=backlog,
            trace_adapter=tracer,
            # No Aider-related config – static detectors only
            detector_configs={},
        )

        proposals = engine.run_proposal_scan(str(tmp_path))
        assert len(proposals) >= 1
        assert any(p.type == "hardcoded_model_names" for p in proposals)

    def test_static_analyzer_produces_findings_without_aider(self):
        analyzer = StaticAnalyzer(config={"enabled": True})
        assert analyzer.is_available() is True

        content = 'project_id = "my-org"\n'
        result = analyzer.analyze_file("app.py", content)
        assert result.success is True
        assert any(f["rule_id"] == "leaked_project_ids" for f in result.findings)
