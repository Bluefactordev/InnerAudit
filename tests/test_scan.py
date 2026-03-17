"""Tests for the inneraudit targeted-audit-selection feature."""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

# Ensure repo root is on sys.path regardless of how pytest is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from inneraudit.path_resolver import resolve_paths
from inneraudit.dependency_graph import (
    DependencyGraph,
    _extract_imports_ast,
    _extract_imports_regex,
)
from inneraudit.manifest_builder import build_manifest
from inneraudit import resolve_audit_targets
from inneraudit.scan import main as scan_main


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture()
def simple_project(tmp_path: Path) -> Path:
    """Create a minimal fake Python project for testing."""
    # pkg/__init__.py
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")

    # pkg/utils.py
    (tmp_path / "pkg" / "utils.py").write_text(
        textwrap.dedent("""\
            def helper():
                pass
        """),
        encoding="utf-8",
    )

    # pkg/core.py — imports utils
    (tmp_path / "pkg" / "core.py").write_text(
        textwrap.dedent("""\
            from pkg.utils import helper

            def run():
                helper()
        """),
        encoding="utf-8",
    )

    # main.py — imports core
    (tmp_path / "main.py").write_text(
        textwrap.dedent("""\
            from pkg.core import run

            if __name__ == "__main__":
                run()
        """),
        encoding="utf-8",
    )

    # ignored dirs
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "utils.cpython-311.pyc").write_bytes(b"")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "something.js").write_text("", encoding="utf-8")

    return tmp_path


# ===========================================================================
# A. Path resolution
# ===========================================================================


class TestPathResolver:
    def test_resolve_single_file(self, simple_project: Path):
        files = resolve_paths(
            [str(simple_project / "main.py")], root=str(simple_project)
        )
        assert len(files) == 1
        assert files[0].endswith("main.py")

    def test_expand_directory(self, simple_project: Path):
        files = resolve_paths([str(simple_project)], root=str(simple_project))
        # Should contain main.py, pkg/__init__.py, pkg/utils.py, pkg/core.py
        basenames = {Path(f).name for f in files}
        assert "main.py" in basenames
        assert "utils.py" in basenames
        assert "core.py" in basenames
        assert "__init__.py" in basenames

    def test_ignores_pycache(self, simple_project: Path):
        files = resolve_paths([str(simple_project)], root=str(simple_project))
        for f in files:
            assert "__pycache__" not in f

    def test_ignores_node_modules(self, simple_project: Path):
        files = resolve_paths([str(simple_project)], root=str(simple_project))
        for f in files:
            parts = Path(f).parts
            assert "node_modules" not in parts

    def test_rejects_traversal_outside_root(self, simple_project: Path, tmp_path: Path):
        outside = tmp_path.parent / "outside.py"
        outside.write_text("x = 1", encoding="utf-8")
        # root is simple_project; outside is one level up
        files = resolve_paths([str(outside)], root=str(simple_project))
        assert files == []

    def test_nonexistent_path_is_skipped(self, simple_project: Path):
        files = resolve_paths(
            [str(simple_project / "nonexistent.py")], root=str(simple_project)
        )
        assert files == []

    def test_deduplicates(self, simple_project: Path):
        main = str(simple_project / "main.py")
        files = resolve_paths([main, main, main], root=str(simple_project))
        assert files.count(files[0]) == 1

    def test_sorted_output(self, simple_project: Path):
        files = resolve_paths([str(simple_project)], root=str(simple_project))
        assert files == sorted(files)


# ===========================================================================
# B. Import detection
# ===========================================================================


class TestImportExtraction:
    def test_ast_simple_import(self):
        source = "import os\nimport sys\n"
        assert "os" in _extract_imports_ast(source)
        assert "sys" in _extract_imports_ast(source)

    def test_ast_from_import(self):
        source = "from pathlib import Path\n"
        assert "pathlib" in _extract_imports_ast(source)

    def test_ast_relative_import(self):
        source = "from .utils import helper\n"
        # relative import has level>0 but module='utils'
        mods = _extract_imports_ast(source)
        assert "utils" in mods

    def test_ast_fallback_on_syntax_error(self):
        invalid_syntax = "def foo(:\n    pass\n"
        # Should not raise; falls back to regex
        result = _extract_imports_ast(invalid_syntax)
        assert isinstance(result, list)

    def test_regex_fallback(self):
        source = "import os\nfrom sys import argv\n"
        mods = _extract_imports_regex(source)
        assert "os" in mods
        assert "sys" in mods


# ===========================================================================
# C. Dependency graph — imports / importers
# ===========================================================================


class TestDependencyGraph:
    def _make_graph(self, project: Path) -> DependencyGraph:
        all_files = resolve_paths([str(project)], root=str(project))
        return DependencyGraph(root=str(project), all_files=all_files)

    def test_get_imports_of_core(self, simple_project: Path):
        graph = self._make_graph(simple_project)
        core = str(simple_project / "pkg" / "core.py")
        imports = graph.get_imports(core)
        # core imports pkg.utils → utils.py
        assert any("utils.py" in p for p in imports)

    def test_get_importers_of_utils(self, simple_project: Path):
        graph = self._make_graph(simple_project)
        utils = str(simple_project / "pkg" / "utils.py")
        importers = graph.get_importers(utils)
        assert any("core.py" in p for p in importers)

    def test_depth_zero_returns_empty(self, simple_project: Path):
        graph = self._make_graph(simple_project)
        core = str(simple_project / "pkg" / "core.py")
        imp, importers = graph.resolve_relations(
            [core], include_imports=True, depth=0
        )
        assert imp == []
        assert importers == []

    def test_depth_one_imports(self, simple_project: Path):
        graph = self._make_graph(simple_project)
        main = str(simple_project / "main.py")
        imp, _ = graph.resolve_relations([main], include_imports=True, depth=1)
        # main → core
        assert any("core.py" in p for p in imp)
        # utils should NOT appear at depth=1 from main
        assert not any("utils.py" in p for p in imp)

    def test_depth_two_imports(self, simple_project: Path):
        graph = self._make_graph(simple_project)
        main = str(simple_project / "main.py")
        imp, _ = graph.resolve_relations([main], include_imports=True, depth=2)
        # main → core → utils (depth 2)
        assert any("core.py" in p for p in imp)
        assert any("utils.py" in p for p in imp)

    def test_importers_discovery(self, simple_project: Path):
        graph = self._make_graph(simple_project)
        utils = str(simple_project / "pkg" / "utils.py")
        _, importers = graph.resolve_relations(
            [utils], include_importers=True, depth=1
        )
        assert any("core.py" in p for p in importers)

    def test_no_duplicate_results(self, simple_project: Path):
        graph = self._make_graph(simple_project)
        main = str(simple_project / "main.py")
        imp, _ = graph.resolve_relations([main], include_imports=True, depth=2)
        assert len(imp) == len(set(imp))

    def test_invalid_depth_raises(self, simple_project: Path):
        graph = self._make_graph(simple_project)
        with pytest.raises(ValueError):
            graph.resolve_relations([], depth=-1)


# ===========================================================================
# D. Manifest builder
# ===========================================================================


class TestManifestBuilder:
    def test_basic_structure(self):
        manifest = build_manifest(
            manual_targets=["src/"],
            expanded_targets=["src/a.py", "src/b.py"],
            imports=["src/c.py"],
            importers=[],
        )
        d = manifest.to_dict()
        assert "manual_targets" in d
        assert "expanded_targets" in d
        assert "related_files" in d
        assert "imports" in d["related_files"]
        assert "importers" in d["related_files"]
        assert "final_audit_set" in d
        assert "stats" in d

    def test_stats_counts(self):
        manifest = build_manifest(
            manual_targets=["src/"],
            expanded_targets=["a.py", "b.py"],
            imports=["c.py"],
            importers=["d.py"],
        )
        s = manifest.stats
        assert s.manual_count == 1
        assert s.expanded_count == 2
        assert s.related_count == 2  # c.py + d.py
        assert s.final_count == 4    # a + b + c + d

    def test_final_audit_set_deduplication(self):
        # expanded and imports share a file
        manifest = build_manifest(
            manual_targets=["src/"],
            expanded_targets=["a.py", "b.py"],
            imports=["b.py", "c.py"],
            importers=[],
        )
        assert manifest.final_audit_set.count("b.py") == 1

    def test_json_serialisable(self):
        manifest = build_manifest(
            manual_targets=["src/"],
            expanded_targets=["a.py"],
            imports=[],
            importers=[],
        )
        # Must not raise
        json.dumps(manifest.to_dict())


# ===========================================================================
# E. Public API — resolve_audit_targets
# ===========================================================================


class TestResolveAuditTargets:
    def test_returns_manifest(self, simple_project: Path):
        manifest = resolve_audit_targets(
            paths=[str(simple_project / "main.py")],
            root=str(simple_project),
            include_imports=True,
            depth=1,
        )
        assert manifest.stats.manual_count == 1
        assert manifest.stats.expanded_count >= 1

    def test_manual_targets_preserved(self, simple_project: Path):
        raw = str(simple_project / "main.py")
        manifest = resolve_audit_targets(
            paths=[raw], root=str(simple_project)
        )
        assert manifest.manual_targets == [raw]

    def test_negative_depth_raises(self, simple_project: Path):
        with pytest.raises(ValueError):
            resolve_audit_targets(
                paths=[str(simple_project)], root=str(simple_project), depth=-1
            )

    def test_depth_zero_no_related(self, simple_project: Path):
        manifest = resolve_audit_targets(
            paths=[str(simple_project / "main.py")],
            root=str(simple_project),
            include_imports=True,
            depth=0,
        )
        assert manifest.related_files.imports == []
        assert manifest.related_files.importers == []


# ===========================================================================
# F. CLI interface
# ===========================================================================


class TestCLI:
    def test_json_output(self, simple_project: Path):
        argv = [
            "--paths", str(simple_project / "main.py"),
            "--root", str(simple_project),
            "--include-imports",
            "--depth", "1",
            "--json",
        ]
        # Capture stdout
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = scan_main(argv)
        assert rc == 0
        data = json.loads(buf.getvalue())
        assert "final_audit_set" in data
        assert "stats" in data

    def test_summary_output(self, simple_project: Path, capsys):
        argv = [
            "--paths", str(simple_project / "main.py"),
            "--root", str(simple_project),
        ]
        rc = scan_main(argv)
        assert rc == 0
        out = capsys.readouterr().out
        assert "Final audit set" in out

    def test_invalid_depth_exits(self, simple_project: Path):
        argv = [
            "--paths", str(simple_project / "main.py"),
            "--depth", "-1",
        ]
        with pytest.raises(SystemExit) as exc_info:
            scan_main(argv)
        assert exc_info.value.code != 0


# ===========================================================================
# G. AuditEngine.run_audit — precomputed_files parameter
# ===========================================================================


class TestAuditEnginePrecomputed:
    def test_precomputed_files_skips_discovery(self, tmp_path: Path, monkeypatch):
        """When precomputed_files is provided, discover_files should not be called."""
        import json as _json
        from audit_engine import AuditEngine, ConfigManager, PlatformConfig, ModelConfig

        config_src = Path(__file__).resolve().parent.parent / "audit_config.json"
        cfg = _json.loads(config_src.read_text(encoding="utf-8"))
        cfg_path = tmp_path / "audit_config.json"
        cfg_path.write_text(_json.dumps(cfg), encoding="utf-8")

        config_manager = ConfigManager(config_path=cfg_path)
        engine = AuditEngine(config_manager)

        discovery_called = []

        def _fake_discover(project_path, platform):
            discovery_called.append(True)
            return []

        monkeypatch.setattr(engine, "discover_files", _fake_discover)

        # Supply a precomputed list (empty → returns early, but discovery skipped)
        result = engine.run_audit(
            project_path=str(tmp_path),
            model=ModelConfig(
                id="test",
                name="test",
                type="static",
                api_base="",
                model_name="",
                api_key="",
            ),
            platform=PlatformConfig(
                name="python",
                file_extensions=[".py"],
                linters={},
                analysis_types={},
            ),
            analysis_types=[],
            precomputed_files=[],
        )
        assert result == []
        assert not discovery_called, "discover_files should NOT have been called"
