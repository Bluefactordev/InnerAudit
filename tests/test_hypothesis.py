"""Tests for the hypothesis layer."""

import sys
from pathlib import Path

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


class TestHypothesis:
    def test_primary_signal_is_first(self):
        hyp = Hypothesis(rule_id="rule_x", file_path="f.py", severity="low", confidence=0.4)
        s1 = _signal(severity="low", confidence=0.4)
        s2 = _signal(severity="critical", confidence=0.9)
        hyp.add_signal(s1)
        hyp.add_signal(s2)
        assert hyp.primary_signal is s1
        assert hyp.severity == "critical"

    def test_confidence_is_averaged(self):
        hyp = Hypothesis(rule_id="rule_x", file_path="f.py", severity="medium", confidence=0.5)
        hyp.add_signal(_signal(confidence=0.5))
        hyp.add_signal(_signal(confidence=0.9))
        assert abs(hyp.confidence - 0.7) < 1e-9


class TestHypothesisBuilder:
    def test_same_rule_same_file_merges(self):
        builder = HypothesisBuilder()
        builder.add(_signal(rule_id="rule_a", file_path="f.py", severity="low", confidence=0.3))
        builder.add(_signal(rule_id="rule_a", file_path="f.py", severity="high", confidence=0.9))
        hypotheses = builder.build()
        assert len(hypotheses) == 1
        assert len(hypotheses[0].signals) == 2
        assert hypotheses[0].severity == "high"

    def test_different_rules_do_not_merge(self):
        builder = HypothesisBuilder()
        builder.add(_signal(rule_id="rule_a", file_path="f.py"))
        builder.add(_signal(rule_id="rule_b", file_path="f.py"))
        hypotheses = builder.build()
        assert len(hypotheses) == 2
