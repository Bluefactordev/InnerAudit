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
from analyzers.base import AnalysisResult as BackendAnalysisResult
from analyzers.llm_analyzer import ExternalLLMAnalyzer
from audit_engine import (
    CUSTOM_PROMPT_ANALYSIS_TYPE_KEY,
    ConfigManager,
    AuditEngine,
)
from audit_engine import ModelConfig


def _write_config(tmp_path: Path, mutate):
    base_config_path = Path(__file__).resolve().parent.parent / "audit_config.json"
    config = json.loads(base_config_path.read_text(encoding="utf-8"))
    mutate(config)
    config_path = tmp_path / "audit_config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    return config_path


def _install_fake_audit_analyzer(monkeypatch, capture_callback):
    class FakeAnalyzer:
        analyzer_id = "fake"

        def analyze_file(self, file_path, content, context=None):
            capture_callback(file_path, content, context or {})
            return BackendAnalysisResult(
                file_path=file_path,
                analyzer_id=self.analyzer_id,
                success=True,
                findings=[],
            )

    monkeypatch.setattr(
        "analyzers.build_analyzers_from_config",
        lambda *args, **kwargs: [FakeAnalyzer()],
    )


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

        async def _fake_generate_for_top_level_run(**kwargs):
            captured.update(kwargs)
            return {"result": '{"findings":[{"severity":"high","category":"logic","description":"x","recommendation":"y"}],"overall_score":77}'}

        monkeypatch.setattr(
            "utils.models.ModelProvider.generate_for_top_level_run",
            _fake_generate_for_top_level_run,
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


class TestAuditEngineContextModes:
    def test_custom_prompt_runs_as_runtime_analysis_type_and_checkpoint_key(self, tmp_path, monkeypatch):
        captured_analysis_types = {}
        checkpoint_path = tmp_path / "checkpoint.jsonl"

        def _capture(file_path, _content, context):
            captured_analysis_types.setdefault(Path(file_path).name, set()).add(context["analysis_type_name"])
            if context["analysis_type_name"] == CUSTOM_PROMPT_ANALYSIS_TYPE_KEY:
                assert "autorizzazione" in context["analysis_type"].prompt_template

        _install_fake_audit_analyzer(monkeypatch, _capture)

        config_path = _write_config(
            tmp_path,
            lambda cfg: cfg.update(
                {
                    "aider": {**cfg["aider"], "enabled": False},
                    "analyzers": {
                        "llm": {"enabled": True},
                    },
                }
            ),
        )
        project_dir = tmp_path / "project"
        (project_dir / "pkg").mkdir(parents=True)
        (project_dir / "pkg" / "alpha.py").write_text("def alpha():\n    return 'alpha'\n", encoding="utf-8")
        (project_dir / "pkg" / "beta.py").write_text("def beta():\n    return 'beta'\n", encoding="utf-8")

        config_manager = ConfigManager(config_path)
        engine = AuditEngine(config_manager)
        platform = config_manager.get_platform("python")
        model = config_manager.get_model_by_id(config_manager.config["default_model"])

        results = engine.run_audit(
            str(project_dir),
            model,
            platform,
            ["performance"],
            use_linting=False,
            checkpoint_file=str(checkpoint_path),
            custom_audit_prompt="Controlla regressioni di autorizzazione e permessi impliciti.",
        )

        assert sorted(result.analysis_type for result in results) == [
            CUSTOM_PROMPT_ANALYSIS_TYPE_KEY,
            CUSTOM_PROMPT_ANALYSIS_TYPE_KEY,
            "performance",
            "performance",
        ]
        assert captured_analysis_types["alpha.py"] == {"performance", CUSTOM_PROMPT_ANALYSIS_TYPE_KEY}
        checkpoint_entries = [
            json.loads(line)
            for line in checkpoint_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert {entry["analysis_type"] for entry in checkpoint_entries} == {
            "performance",
            CUSTOM_PROMPT_ANALYSIS_TYPE_KEY,
        }

    def test_single_file_mode_keeps_only_runtime_guidance(self, tmp_path, monkeypatch):
        captured_contexts = {}
        _install_fake_audit_analyzer(
            monkeypatch,
            lambda file_path, _content, context: captured_contexts.__setitem__(
                Path(file_path).name,
                str(context.get("analysis_context") or ""),
            ),
        )

        config_path = _write_config(
            tmp_path,
            lambda cfg: cfg.update(
                {
                    "aider": {**cfg["aider"], "enabled": False},
                    "analyzers": {
                        "llm": {"enabled": True},
                    },
                }
            ),
        )
        project_dir = tmp_path / "project"
        (project_dir / "pkg").mkdir(parents=True)
        (project_dir / "pkg" / "alpha.py").write_text("def alpha():\n    return 'alpha'\n", encoding="utf-8")
        (project_dir / "pkg" / "beta.py").write_text("def beta():\n    return 'beta'\n", encoding="utf-8")

        config_manager = ConfigManager(config_path)
        engine = AuditEngine(config_manager)
        platform = config_manager.get_platform("python")
        model = config_manager.get_model_by_id(config_manager.config["default_model"])

        engine.run_audit(
            str(project_dir),
            model,
            platform,
            ["performance"],
            use_linting=False,
            include_paths=["pkg"],
            context_mode="single_file",
            base_analysis_context="Solo repo tools",
        )

        assert captured_contexts["alpha.py"] == "## Runtime guidance\nSolo repo tools"
        assert captured_contexts["beta.py"] == "## Runtime guidance\nSolo repo tools"

    def test_invalid_context_mode_normalizes_to_single_file(self, tmp_path, monkeypatch):
        captured_contexts = {}
        _install_fake_audit_analyzer(
            monkeypatch,
            lambda file_path, _content, context: captured_contexts.__setitem__(
                Path(file_path).name,
                str(context.get("analysis_context") or ""),
            ),
        )

        config_path = _write_config(
            tmp_path,
            lambda cfg: cfg.update(
                {
                    "aider": {**cfg["aider"], "enabled": False},
                    "analyzers": {
                        "llm": {"enabled": True},
                    },
                }
            ),
        )
        project_dir = tmp_path / "project"
        (project_dir / "pkg").mkdir(parents=True)
        (project_dir / "pkg" / "alpha.py").write_text("def alpha():\n    return 'alpha'\n", encoding="utf-8")
        (project_dir / "pkg" / "beta.py").write_text("def beta():\n    return 'beta'\n", encoding="utf-8")

        config_manager = ConfigManager(config_path)
        engine = AuditEngine(config_manager)
        platform = config_manager.get_platform("python")
        model = config_manager.get_model_by_id(config_manager.config["default_model"])

        engine.run_audit(
            str(project_dir),
            model,
            platform,
            ["performance"],
            use_linting=False,
            include_paths=["pkg"],
            context_mode="qualcosa-di-non-valido",
            base_analysis_context="Solo base context",
        )

        assert captured_contexts["alpha.py"] == "## Runtime guidance\nSolo base context"
        assert captured_contexts["beta.py"] == "## Runtime guidance\nSolo base context"

    def test_subsystem_mode_shares_context_once_and_injects_it(self, tmp_path, monkeypatch):
        captured_contexts = {}
        _install_fake_audit_analyzer(
            monkeypatch,
            lambda file_path, _content, context: captured_contexts.__setitem__(
                Path(file_path).name,
                str(context.get("analysis_context") or ""),
            ),
        )

        config_path = _write_config(
            tmp_path,
            lambda cfg: cfg.update(
                {
                    "aider": {**cfg["aider"], "enabled": False},
                    "analyzers": {
                        "llm": {"enabled": True},
                    },
                }
            ),
        )
        project_dir = tmp_path / "project"
        (project_dir / "pkg").mkdir(parents=True)
        (project_dir / "pkg" / "alpha.py").write_text("def alpha():\n    return 'alpha'\n", encoding="utf-8")
        (project_dir / "pkg" / "beta.py").write_text("def beta():\n    return 'beta'\n", encoding="utf-8")

        config_manager = ConfigManager(config_path)
        engine = AuditEngine(config_manager)
        platform = config_manager.get_platform("python")
        model = config_manager.get_model_by_id(config_manager.config["default_model"])

        engine.run_audit(
            str(project_dir),
            model,
            platform,
            ["performance"],
            use_linting=False,
            include_paths=["pkg"],
            context_mode="subsystem",
            base_analysis_context="Repo deep search attivo",
            checkpoint_file=str(tmp_path / "shared_context_checkpoint.jsonl"),
        )

        alpha_context = captured_contexts["alpha.py"]
        beta_context = captured_contexts["beta.py"]
        assert alpha_context == beta_context
        assert "## Runtime guidance" in alpha_context
        assert "## Subsystem context" in alpha_context
        assert "Scope selezionato: pkg" in alpha_context
        assert "alpha.py" in alpha_context
        assert "beta.py" in alpha_context

    def test_subsystem_mode_respects_analysis_types_without_subsystem_scope(self, tmp_path, monkeypatch):
        captured_contexts = {}
        _install_fake_audit_analyzer(
            monkeypatch,
            lambda file_path, _content, context: captured_contexts.__setitem__(
                Path(file_path).name,
                str(context.get("analysis_context") or ""),
            ),
        )

        config_path = _write_config(
            tmp_path,
            lambda cfg: cfg.update(
                {
                    "aider": {**cfg["aider"], "enabled": False},
                    "analyzers": {
                        "llm": {"enabled": True},
                    },
                }
            ),
        )
        project_dir = tmp_path / "project"
        (project_dir / "pkg").mkdir(parents=True)
        (project_dir / "pkg" / "alpha.py").write_text("def alpha():\n    return 'alpha'\n", encoding="utf-8")
        (project_dir / "pkg" / "beta.py").write_text("def beta():\n    return 'beta'\n", encoding="utf-8")

        config_manager = ConfigManager(config_path)
        engine = AuditEngine(config_manager)
        platform = config_manager.get_platform("python")
        model = config_manager.get_model_by_id(config_manager.config["default_model"])

        engine.run_audit(
            str(project_dir),
            model,
            platform,
            ["code_quality"],
            use_linting=False,
            include_paths=["pkg"],
            context_mode="subsystem",
            base_analysis_context="Solo base context",
        )

        assert captured_contexts["alpha.py"] == "## Runtime guidance\nSolo base context"
        assert captured_contexts["beta.py"] == "## Runtime guidance\nSolo base context"

    def test_subsystem_context_is_bounded_and_deterministic(self, tmp_path, monkeypatch):
        captured_contexts = []

        def _capture(_file_path, _content, context):
            captured_contexts.append(str(context.get("analysis_context") or ""))

        _install_fake_audit_analyzer(monkeypatch, _capture)

        config_path = _write_config(
            tmp_path,
            lambda cfg: cfg.update(
                {
                    "aider": {**cfg["aider"], "enabled": False},
                    "analyzers": {
                        "llm": {"enabled": True},
                    },
                }
            ),
        )
        project_dir = tmp_path / "project"
        (project_dir / "pkg").mkdir(parents=True)
        for idx in range(4):
            big_content = (f"# file-{idx}\n" + ("x" * 400) + "\n") * 6
            (project_dir / "pkg" / f"module_{idx}.py").write_text(big_content, encoding="utf-8")

        config_manager = ConfigManager(config_path)
        engine = AuditEngine(config_manager)
        platform = config_manager.get_platform("python")
        model = config_manager.get_model_by_id(config_manager.config["default_model"])

        engine.run_audit(
            str(project_dir),
            model,
            platform,
            ["performance"],
            use_linting=False,
            include_paths=["pkg"],
            context_mode="subsystem",
            subsystem_context_options={
                "max_total_chars": 1_500,
                "max_file_chars": 200,
                "max_files": 2,
            },
            checkpoint_file=str(tmp_path / "deterministic_first.jsonl"),
        )
        first_context = captured_contexts[0]
        captured_contexts.clear()
        engine.run_audit(
            str(project_dir),
            model,
            platform,
            ["performance"],
            use_linting=False,
            include_paths=["pkg"],
            context_mode="subsystem",
            subsystem_context_options={
                "max_total_chars": 1_500,
                "max_file_chars": 200,
                "max_files": 2,
            },
            checkpoint_file=str(tmp_path / "deterministic_second.jsonl"),
        )
        second_context = captured_contexts[0]

        assert first_context == second_context
        assert len(first_context) <= 1_500
        assert "## Included files manifest" in first_context
        assert "## Context budget notes" in first_context
        assert "[... excerpt troncato a 200 caratteri ...]" in first_context
        assert "File omessi per budget totale o limite estratti" in first_context
