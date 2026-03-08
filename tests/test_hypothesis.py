"""Tests for the Hypothesis layer (proposal_engine/hypothesis.py)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from proposal_engine.hypothesis import Hypothesis, HypothesisBuilder, RawSignal


def _signal(
    rule_id: str = "rule_x",
    file_path: str = "src/main.py",
    severity: str = "medium",
    confidence: float = 0.8,
    line_number: int = 10,
    source_detector: str = "detector_a",
) -> RawSignal:
    return RawSignal(
        rule_id=rule_id,
        file_path=file_path,
        severity=severity,
        confidence=confidence,
        source_detector=source_detector,
        line_number=line_number,
        code_snippet="x = 'hardcoded'",
        context="context text",
    )


# ---------------------------------------------------------------------------
# RawSignal tests
# ---------------------------------------------------------------------------

class TestRawSignal:
    def test_to_dict_contains_expected_keys(self):
        s = _signal()
        d = s.to_dict()
        assert d["rule_id"] == "rule_x"
        assert d["file_path"] == "src/main.py"
        assert d["severity"] == "medium"
        assert d["confidence"] == 0.8
        assert d["line_number"] == 10
        assert d["source_detector"] == "detector_a"

    def test_optional_fields_default_to_none(self):
        s = RawSignal(
            rule_id="r",
            file_path="f.py",
            severity="low",
            confidence=0.5,
            source_detector="d",
        )
        assert s.line_number is None
        assert s.code_snippet is None
        assert s.context is None


# ---------------------------------------------------------------------------
# Hypothesis tests
# ---------------------------------------------------------------------------

class TestHypothesis:
    def test_initial_state(self):
        h = Hypothesis(rule_id="rule_x", file_path="f.py")
        assert h.rule_id == "rule_x"
        assert h.file_path == "f.py"
        assert h.signals == []
        assert h.validated is False
        assert h.created_at

    def test_primary_signal_none_when_empty(self):
        h = Hypothesis(rule_id="r", file_path="f.py")
        assert h.primary_signal is None

    def test_primary_signal_returns_first(self):
        h = Hypothesis(rule_id="r", file_path="f.py", severity="low", confidence=0.5)
        s1 = _signal(severity="low", confidence=0.5)
        s2 = _signal(severity="high", confidence=0.9)
        h.add_signal(s1)
        h.add_signal(s2)
        assert h.primary_signal is s1

    def test_add_signal_escalates_severity(self):
        h = Hypothesis(rule_id="r", file_path="f.py", severity="low", confidence=0.5)
        h.add_signal(_signal(severity="low", confidence=0.5))
        assert h.severity == "low"
        h.add_signal(_signal(severity="critical", confidence=0.9))
        assert h.severity == "critical"

    def test_add_signal_never_downgrades_severity(self):
        h = Hypothesis(rule_id="r", file_path="f.py", severity="high", confidence=0.8)
        h.add_signal(_signal(severity="high", confidence=0.8))
        h.add_signal(_signal(severity="low", confidence=0.3))
        assert h.severity == "high"

    def test_add_signal_averages_confidence(self):
        h = Hypothesis(rule_id="r", file_path="f.py", severity="medium", confidence=0.5)
        h.add_signal(_signal(confidence=0.6))
        h.add_signal(_signal(confidence=0.8))
        expected = (0.6 + 0.8) / 2
        assert abs(h.confidence - expected) < 1e-9

    def test_to_evidence_list_maps_signals(self):
        h = Hypothesis(rule_id="r", file_path="f.py", severity="medium", confidence=0.5)
        h.add_signal(_signal(line_number=5))
        evidence = h.to_evidence_list()
        assert len(evidence) == 1
        assert evidence[0]["file_path"] == "src/main.py"
        assert evidence[0]["line_number"] == 5

    def test_to_dict_contains_expected_keys(self):
        h = Hypothesis(rule_id="r", file_path="f.py", severity="medium", confidence=0.6)
        h.add_signal(_signal())
        d = h.to_dict()
        assert d["rule_id"] == "r"
        assert d["file_path"] == "f.py"
        assert "signals" in d
        assert len(d["signals"]) == 1


# ---------------------------------------------------------------------------
# HypothesisBuilder tests
# ---------------------------------------------------------------------------

class TestHypothesisBuilder:
    def test_empty_builder_returns_empty_list(self):
        builder = HypothesisBuilder()
        assert builder.build() == []

    def test_single_signal_creates_one_hypothesis(self):
        builder = HypothesisBuilder()
        builder.add(_signal(rule_id="rule_a", file_path="f.py"))
        hypotheses = builder.build()
        assert len(hypotheses) == 1
        assert hypotheses[0].rule_id == "rule_a"

    def test_same_rule_same_file_merges_into_one_hypothesis(self):
        """Two signals for the same rule + file must merge into one hypothesis."""
        builder = HypothesisBuilder()
        builder.add(_signal(rule_id="rule_a", file_path="f.py", severity="low", confidence=0.5))
        builder.add(_signal(rule_id="rule_a", file_path="f.py", severity="high", confidence=0.9))
        hypotheses = builder.build()
        assert len(hypotheses) == 1
        assert len(hypotheses[0].signals) == 2
        assert hypotheses[0].severity == "high"

    def test_different_rules_create_separate_hypotheses(self):
        builder = HypothesisBuilder()
        builder.add(_signal(rule_id="rule_a", file_path="f.py"))
        builder.add(_signal(rule_id="rule_b", file_path="f.py"))
        hypotheses = builder.build()
        assert len(hypotheses) == 2

    def test_different_files_create_separate_hypotheses(self):
        builder = HypothesisBuilder()
        builder.add(_signal(rule_id="rule_a", file_path="a.py"))
        builder.add(_signal(rule_id="rule_a", file_path="b.py"))
        hypotheses = builder.build()
        assert len(hypotheses) == 2

    def test_reset_clears_state(self):
        builder = HypothesisBuilder()
        builder.add(_signal())
        builder.reset()
        assert builder.build() == []

    def test_source_analyzer_stored_on_hypothesis(self):
        builder = HypothesisBuilder()
        builder.add(_signal(), source_analyzer="my_analyzer")
        hyp = builder.build()[0]
        assert hyp.source_analyzer == "my_analyzer"
