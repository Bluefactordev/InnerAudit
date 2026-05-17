"""Tests for analyzer backends and audit backend selection."""

import json
import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("FLASK_SECRET_KEY", "test")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from analyzers import StaticAnalyzer, build_analyzer, build_analyzers_from_config
from analyzers.aider_analyzer import AiderAnalyzer
from analyzers.llm_analyzer import ExternalLLMAnalyzer
from audit_engine import ConfigManager, AuditEngine
from audit_engine import ModelConfig


def _write_config(tmp_path: Path, mutate):
    base_config_path = Path(__file__).resolve().parent.parent / "audit_config.json"
    config = json.loads(base_config_path.read_text(encoding="utf-8"))
    mutate(config)
    config_path = tmp_path / "audit_config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    return config_path


class TestStaticAnalyzer:
    def test_is_always_available(self):
        analyzer = StaticAnalyzer()
        assert analyzer.is_available() is True

    def test_returns_findings(self):
        analyzer = StaticAnalyzer()
        result = analyzer.analyze_file("test.py", 'model_name = "gpt-4-turbo"\n')
        assert result.success is True
        assert any(item["rule_id"] == "hardcoded_model_names" for item in result.findings)


class TestAiderAnalyzer:
    def test_disabled_is_unavailable(self):
        analyzer = AiderAnalyzer(config={"enabled": False})
        assert analyzer.is_available() is False

    def test_unavailable_without_binary(self, monkeypatch):
        import shutil

        monkeypatch.setattr(shutil, "which", lambda command: None)
        analyzer = AiderAnalyzer(config={"enabled": True, "command": "aider"})
        assert analyzer.is_available() is False


class TestAnalyzerRegistry:
    def test_build_static(self):
        assert isinstance(build_analyzer("static", {}), StaticAnalyzer)

    def test_unknown_backend_returns_none(self):
        assert build_analyzer("unknown", {}) is None

    def test_default_fallback_is_static(self):
        analyzers = build_analyzers_from_config({})
        assert len(analyzers) == 1
        assert isinstance(analyzers[0], StaticAnalyzer)

    def test_can_disable_implicit_fallback(self):
        analyzers = build_analyzers_from_config({}, inject_static_fallback=False)
        assert analyzers == []


class TestExternalLLMAnalyzerNirodeepRuntime:
    def test_uses_model_provider_runtime_when_configured(self, monkeypatch):
        captured = {}

        async def _fake_generate_job(**kwargs):
            captured.update(kwargs)
            return {"result": '{"findings":[{"severity":"high","category":"logic","description":"x","recommendation":"y"}],"overall_score":77}'}

        monkeypatch.setattr(
            "utils.models.ModelProvider.generate_job",
            _fake_generate_job,
            raising=False,
        )

        analyzer = ExternalLLMAnalyzer(
            config={"enabled": True},
            model_config=ModelConfig(
                id="runtime-model",
                name="Runtime Model",
                type="vllm",
                api_base="",
                model_name="vllm/runtime-model",
                api_key="",
                runtime_options={
                    "adapter": "nirodeep",
                    "context": {
                        "project_id": "proj-1",
                        "user_id": "user-1",
                        "is_superuser": True,
                    },
                    "tool_names": ["filesystem_tree_from_dataset"],
                    "execution_mode": "agentic",
                    "depth": 0,
                    "agentic_max_iterations": 4,
                },
            ),
        )

        analysis_type = type(
            "AnalysisTypeStub",
            (),
            {"prompt_template": "Analizza {file_path}. Contesto: {context}"},
        )()

        result = analyzer.analyze_file(
            "services/app.py",
            "print('hello')\n",
            context={
                "analysis_type": analysis_type,
                "project_path": ".",
            },
        )

        assert analyzer.is_available() is True
        assert result.success is True
        assert result.score == 77
        assert result.findings[0]["severity"] == "high"
        assert captured["model_id"] == "vllm/runtime-model"
        assert captured["tools"] == ["filesystem_tree_from_dataset"]
        assert captured["context"]["execution_mode"] == "agentic"
        assert captured["context"]["is_superuser"] is True


class TestAuditEngineBackendSelection:
    def test_raises_when_no_audit_backend_available(self, tmp_path):
        config_path = _write_config(
            tmp_path,
            lambda cfg: cfg.update(
                {
                    "aider": {**cfg["aider"], "enabled": False},
                    "analyzers": {
                        "aider": {"enabled": False},
                        "llm": {"enabled": False},
                        "static": {"enabled": False},
                    },
                }
            ),
        )
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "bad.py").write_text('model_name = "gpt-4"\n', encoding="utf-8")

        config_manager = ConfigManager(config_path)
        engine = AuditEngine(config_manager)
        platform = config_manager.get_platform("python")
        model = config_manager.get_model_by_id(config_manager.config["default_model"])

        with pytest.raises(RuntimeError, match="No audit analyzers are available"):
            engine.run_audit(str(project_dir), model, platform, ["deep_scan"], use_linting=False)

    def test_static_backend_runs_only_when_explicitly_enabled(self, tmp_path):
        config_path = _write_config(
            tmp_path,
            lambda cfg: cfg.update(
                {
                    "aider": {**cfg["aider"], "enabled": False},
                    "analyzers": {
                        "aider": {"enabled": False},
                        "llm": {"enabled": False},
                        "static": {"enabled": True},
                    },
                }
            ),
        )
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "bad.py").write_text(
            'model_name = "gpt-4"\nproject_id = "acme"\n',
            encoding="utf-8",
        )

        config_manager = ConfigManager(config_path)
        engine = AuditEngine(config_manager)
        platform = config_manager.get_platform("python")
        model = config_manager.get_model_by_id(config_manager.config["default_model"])
        results = engine.run_audit(str(project_dir), model, platform, ["deep_scan"], use_linting=False)

        assert len(results) == 1
        assert results[0].success is True
        assert len(results[0].findings) >= 2
