#!/usr/bin/env python3
"""Audit Engine - core audit functionality."""

import fnmatch
import json
import logging
import os
import re
import subprocess
import time
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
logger = logging.getLogger("AuditEngine")


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class ModelConfig:
    """Configuration for a model endpoint"""
    id: str
    name: str
    type: str
    api_base: str
    model_name: str
    api_key: str
    timeout: int = 120
    max_tokens: int = 4096
    temperature: float = 0.3
    extra_body: Optional[Dict[str, Any]] = None
    aider_model: Optional[str] = None
    env_overrides: Optional[Dict[str, str]] = None
    # Lista di capability del modello lette da models.json (es. ["thinking","vision"]).
    # Usata per decidere parametri di chiamata — MAI usare il nome del modello.
    capabilities: Optional[List[str]] = None
    # Se True, disabilita il thinking mode via chat_template_kwargs.
    # Va impostato dalla route leggendo models.json, MAI dal nome del modello.
    disable_thinking: bool = False


@dataclass
class LinterConfig:
    """Configuration for a linter tool"""
    enabled: bool
    command: str
    args: List[str]
    severity_threshold: str = "error"


@dataclass
class AnalysisType:
    """Configuration for an analysis type"""
    name: str
    scope: List[str]
    prompt_template: str


@dataclass
class PlatformConfig:
    """Configuration for a programming language platform"""
    name: str
    file_extensions: List[str]
    linters: Dict[str, LinterConfig]
    analysis_types: Dict[str, AnalysisType]


@dataclass
class AnalysisResult:
    """Result of an analysis"""
    file_path: str
    analysis_type: str
    success: bool
    findings: List[Dict[str, Any]]
    linter_results: Optional[Dict[str, Any]] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    score: Optional[int] = None


# ============================================================================
# Configuration Manager
# ============================================================================

class ConfigManager:
    """Manages loading and accessing configuration"""
    
    def __init__(self, config_path: Path | str = BASE_DIR / "audit_config.json"):
        self.config_path = Path(config_path)
        if not self.config_path.is_absolute():
            self.config_path = (BASE_DIR / self.config_path).resolve()
        self.config: Dict[str, Any] = {}
        self._load_config()
    
    def _load_config(self):
        """Load configuration from JSON file"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            self.config = json.load(f)
    
    def get_models(self) -> List[ModelConfig]:
        """Get all configured models"""
        models = []
        for m in self.config.get('models', []):
            models.append(ModelConfig(**m))
        return models
    
    def get_model_by_id(self, model_id: str) -> Optional[ModelConfig]:
        """Get a specific model by ID"""
        for m in self.config.get('models', []):
            if m['id'] == model_id:
                return ModelConfig(**m)
        return None
    
    def get_platform(self, platform_name: str) -> Optional[PlatformConfig]:
        """Get platform configuration"""
        platform_data = self.config.get('platforms', {}).get(platform_name)
        if not platform_data:
            return None
        
        linters = {
            k: LinterConfig(**v)
            for k, v in platform_data.get('linters', {}).items()
        }
        
        analysis_types = {
            k: AnalysisType(**v)
            for k, v in platform_data.get('analysis_types', {}).items()
        }
        
        return PlatformConfig(
            name=platform_data['name'],
            file_extensions=platform_data['file_extensions'],
            linters=linters,
            analysis_types=analysis_types
        )
    
    def get_file_filtering(self) -> Dict[str, Any]:
        """Get file filtering configuration"""
        return self.config.get('file_filtering', {})
    
    def get_aider_config(self) -> Dict[str, Any]:
        """Get aider configuration"""
        return self.config.get('aider', {})

    def get_analyzers_config(self) -> Dict[str, Any]:
        """Get analyzer backend configuration."""
        return self.config.get('analyzers', {})

    def get_model_roles(self) -> Dict[str, Any]:
        """Get configured conceptual model roles."""
        return self.config.get('model_roles', {})
    
    def get_output_config(self) -> Dict[str, Any]:
        """Get output configuration"""
        return self.config.get('output', {})


# ============================================================================
# Aider Integration
# ============================================================================

class AiderIntegration:
    """Integration with Aider for code analysis"""
    
    JSON_PATTERN = re.compile(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', re.DOTALL)
    
    def __init__(self, config: Dict[str, Any], model_config: ModelConfig):
        self.config = config
        self.model_config = model_config
        self.aider_command = config.get('command', 'aider')
        self.aider_args = list(config.get('args', ['--no-git', '--no-auto-commits', '--yes']))
        if '--no-show-release-notes' not in self.aider_args:
            self.aider_args.append('--no-show-release-notes')
        self.timeout = config.get('timeout', 300)
        self.max_retries = config.get('max_retries', 2)
        self._build_aider_command()

    def _append_flag(self, flag: str, value: Optional[str]):
        """Append a CLI flag only once."""
        if not value:
            return
        prefix = f"{flag}="
        if any(arg == flag or arg.startswith(prefix) for arg in self.aider_args):
            return
        self.aider_args.append(f"{flag}={value}")

    def _resolve_api_key(self) -> str:
        """Resolve API key from config or environment."""
        api_key = self.model_config.api_key
        if api_key.startswith("$"):
            return os.getenv(api_key[1:], "")
        if api_key == "YOUR_OPENAI_API_KEY":
            return os.getenv("OPENAI_API_KEY", "")
        return api_key

    def _build_aider_command(self):
        """Build the Aider command with model and endpoint configuration."""
        model_name = self.model_config.aider_model or self.model_config.model_name
        self._append_flag("--model", model_name)
        self._append_flag("--openai-api-base", self.model_config.api_base)
        self._append_flag("--openai-api-key", self._resolve_api_key())

    def _build_environment(self) -> Dict[str, str]:
        """Build subprocess environment for provider-specific overrides.
        Disables browser popups (aider opens https://aider.chat/docs/llms/warnings.html otherwise).
        """
        env = os.environ.copy()
        env["DISPLAY"] = ""
        env["BROWSER"] = ""
        for key, value in (self.model_config.env_overrides or {}).items():
            if value:
                env[key] = value
        return env

    @staticmethod
    def extract_findings_and_score(
        parsed_json: Optional[Dict[str, Any]],
    ) -> Tuple[List[Dict[str, Any]], Optional[int]]:
        """Normalize supported JSON payloads into findings and score."""
        if not parsed_json:
            return [], None

        findings: List[Dict[str, Any]] = []
        score: Optional[int] = None

        for key in ["findings", "vulnerabilities", "issues", "performance_issues"]:
            if key in parsed_json:
                findings = parsed_json[key]
                break

        for score_key in ["overall_score", "security_score", "quality_score", "performance_score"]:
            if score_key in parsed_json:
                score = parsed_json[score_key]
                break

        return findings, score
    
    def _load_best_practices(self, project_path: str = ".") -> str:
        """Load best practices"""
        candidate_paths = [
            BASE_DIR / "audit_best_practices.md",
            Path(project_path) / "audit_best_practices.md",
        ]

        for practices_path in candidate_paths:
            if practices_path.exists():
                try:
                    with open(practices_path, 'r', encoding='utf-8') as f:
                        return f.read()
                except Exception as e:
                    logger.warning(f"Failed to load best practices from {practices_path}: {e}")
        return ""
    
    def _build_system_prompt(self, analysis_type: AnalysisType, best_practices: str = "") -> str:
        """Build system prompt"""
        role_instructions = """Sei un Auditor di Codice Senior.
Analizza il codice e identifica problemi, vulnerabilità e opportunità di miglioramento.

IMPORTANTE:
- RISPONDI SOLO IN FORMATO JSON VALIDO
- Non includere testo prima o dopo il JSON
- Il JSON deve essere parseabile direttamente
"""
        
        best_practices_section = ""
        if best_practices:
            best_practices_section = f"""
BEST PRACTICES DA VERIFICARE:
{best_practices}

Verifica che il codice rispetti queste best practices. Per ogni violazione:
- severity: critical/high/medium/low
- category: categoria della best practice violata
- description: descrizione della violazione
- line_number: numero di riga
- code_snippet: snippet del codice
- recommendation: come correggere
- reference: quale best practice è stata violata
"""
        
        return role_instructions + best_practices_section
    
    def extract_json_from_output(self, output: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from output"""
        try:
            json_matches = self.JSON_PATTERN.findall(output)
            
            for json_str in json_matches:
                try:
                    parsed = json.loads(json_str)
                    if isinstance(parsed, dict):
                        return parsed
                except json.JSONDecodeError:
                    continue
            
            # Try parsing whole output
            try:
                parsed = json.loads(output.strip())
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass
            
            return None
        except Exception as e:
            logger.error(f"Error extracting JSON: {e}")
            return None

    def build_prompt(
        self,
        file_path: str,
        analysis_type: AnalysisType,
        project_path: str = ".",
    ) -> str:
        """Build the full prompt shared by Aider and direct-LLM analyzers."""
        best_practices = self._load_best_practices(project_path)
        system_prompt = self._build_system_prompt(analysis_type, best_practices)
        user_prompt = (
            analysis_type.prompt_template
            .replace("{file_path}", file_path)
            .replace("{context}", "")
        )
        return f"{system_prompt}\n\n{user_prompt}"
    
    def run_analysis(
        self,
        file_path: str,
        analysis_type: AnalysisType,
        project_path: str = "."
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """Run Aider analysis on a file"""
        full_prompt = self.build_prompt(
            file_path=file_path,
            analysis_type=analysis_type,
            project_path=project_path,
        )
        
        cmd = [self.aider_command] + self.aider_args + [file_path]
        
        logger.info(f"Running Aider analysis on {file_path}")
        
        for attempt in range(self.max_retries + 1):
            try:
                result = subprocess.run(
                    cmd,
                    input=full_prompt,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    shell=False,
                    env=self._build_environment(),
                )
                
                raw_output = result.stdout + result.stderr
                parsed_json = self.extract_json_from_output(raw_output)
                
                if parsed_json:
                    logger.info(f"Successfully analyzed {file_path}")
                    return True, parsed_json, raw_output
                else:
                    logger.warning(f"No valid JSON in output for {file_path}")
                    if attempt < self.max_retries:
                        time.sleep(2)
                        continue
                    return False, None, raw_output
            
            except subprocess.TimeoutExpired:
                logger.error(f"Aider timed out on {file_path}")
                return False, None, f"Analysis timed out after {self.timeout}s"
            except Exception as e:
                logger.error(f"Aider failed on {file_path}: {e}")
                if attempt < self.max_retries:
                    time.sleep(2)
                    continue
                return False, None, str(e)
        
        return False, None, "Max retries exceeded"
    
    def test_connection(self) -> Tuple[bool, str]:
        """Test Aider connection"""
        test_file = None
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.py',
                prefix='aider_test_',
                delete=False,
                encoding='utf-8',
            ) as temp_file:
                test_file = temp_file.name
                temp_file.write("# Test file\nprint('Hello')\n")

            cmd = [self.aider_command] + self.aider_args + [test_file]
            prompt = "Say 'OK' if you can read this file."

            start_time = time.time()
            result = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=30,
                env=self._build_environment(),
            )
            elapsed = time.time() - start_time

            if "OK" in result.stdout or "OK" in result.stderr:
                return True, f"Connected successfully in {elapsed:.2f}s"
            return False, f"Unexpected output: {result.stdout[:200]}"

        except subprocess.TimeoutExpired:
            return False, "Connection timed out"
        except FileNotFoundError:
            return False, f"Aider command '{self.aider_command}' not found"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"
        finally:
            if test_file:
                try:
                    os.remove(test_file)
                except OSError:
                    pass


# ============================================================================
# Audit Engine
# ============================================================================

class AuditEngine:
    """Main audit engine"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager

    def _matches_pattern(self, file_path: Path, project_path: Path, patterns: List[str]) -> bool:
        """Match a file path against wildcard and substring-based filters."""
        if not patterns:
            return False

        relative_path = file_path.relative_to(project_path).as_posix()
        basename = file_path.name
        relative_parts = relative_path.lower().split("/")
        candidates = [
            relative_path,
            relative_path.lower(),
            basename,
            basename.lower(),
            file_path.as_posix(),
            file_path.as_posix().lower(),
        ]

        for raw_pattern in patterns:
            pattern = raw_pattern.strip().replace("\\", "/")
            if not pattern:
                continue

            normalized_pattern = pattern.lower()
            if normalized_pattern in relative_parts:
                return True

            for candidate in candidates:
                if fnmatch.fnmatch(candidate, pattern):
                    return True
                if normalized_pattern in candidate.lower():
                    return True

        return False

    def _run_linters(self, file_path: str, platform: PlatformConfig) -> Dict[str, Dict[str, Any]]:
        """Run enabled linters for the selected platform."""
        results: Dict[str, Dict[str, Any]] = {}

        for linter_name, linter in platform.linters.items():
            if not linter.enabled:
                continue

            cmd = [linter.command] + list(linter.args) + [file_path]

            try:
                completed = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    shell=False,
                )
                results[linter_name] = {
                    "available": True,
                    "success": completed.returncode == 0,
                    "returncode": completed.returncode,
                    "stdout": completed.stdout.strip(),
                    "stderr": completed.stderr.strip(),
                }
            except FileNotFoundError:
                results[linter_name] = {
                    "available": False,
                    "success": None,
                    "error": f"{linter.command} not found in PATH",
                }
            except subprocess.TimeoutExpired:
                results[linter_name] = {
                    "available": True,
                    "success": False,
                    "error": "Linter timed out after 60s",
                }
            except Exception as e:
                results[linter_name] = {
                    "available": True,
                    "success": False,
                    "error": str(e),
                }

        return results
    
    def discover_files(self, project_path: str, platform: PlatformConfig) -> List[str]:
        """Discover files to analyze"""
        project_path = Path(project_path)

        files = set()
        for ext in platform.file_extensions:
            for file_path in project_path.rglob(f"*{ext}"):
                if file_path.is_file():
                    files.add(file_path.resolve())

        file_filtering = self.config_manager.get_file_filtering()
        include_patterns = file_filtering.get('include_patterns', [])
        exclude_patterns = file_filtering.get('exclude_patterns', [])
        default_behavior = file_filtering.get('default_behavior', 'include_all')

        filtered_files = []
        for file_path in sorted(files):
            include_match = self._matches_pattern(file_path, project_path, include_patterns)
            exclude_match = self._matches_pattern(file_path, project_path, exclude_patterns)

            if default_behavior == 'include_only':
                keep_file = bool(include_patterns) and include_match and not exclude_match
            else:
                keep_file = not exclude_match

            if keep_file:
                filtered_files.append(str(file_path))

        logger.info(
            "Discovered %s files for analysis (filtering mode: %s)",
            len(filtered_files),
            default_behavior,
        )
        return filtered_files
    
    def run_audit(
        self,
        project_path: str,
        model: ModelConfig,
        platform: PlatformConfig,
        analysis_types: List[str],
        use_linting: bool = True,
        progress_callback: Optional[Any] = None,
    ) -> List[AnalysisResult]:
        """Run audit on a project using configured analyzer backends."""
        logger.info(f"Starting audit on {project_path}")
        
        # Discover files
        files = self.discover_files(project_path, platform)
        
        if not files:
            logger.warning("No files found for analysis")
            return []
        
        analyzers_config = self.config_manager.get_analyzers_config()
        aider_config = self.config_manager.get_aider_config()
        if not analyzers_config and aider_config.get("enabled", True):
            analyzers_config = {"aider": aider_config}

        from analyzers import build_analyzers_from_config

        active_analyzers = build_analyzers_from_config(
            analyzers_config,
            inject_static_fallback=False,
            detector_configs=self.config_manager.config.get("proposal_engine", {}).get("detectors", {}),
            model_config=model,
        )

        if not active_analyzers:
            raise RuntimeError(
                "No audit analyzers are available. "
                "Configure an enabled backend or install its runtime dependency."
            )

        # Semaforo condiviso — limita le chiamate LLM simultanee a MAX_CONCURRENT
        try:
            import sys as _sys
            _ia_dir = str(Path(__file__).resolve().parent)
            if _ia_dir not in _sys.path:
                _sys.path.insert(0, _ia_dir)
            from concurrency import AuditConcurrencyLimiter, MAX_CONCURRENT_LLM_CALLS
            limiter = AuditConcurrencyLimiter.get_instance()
            max_workers = MAX_CONCURRENT_LLM_CALLS
        except Exception:
            limiter = None
            max_workers = 4

        # Cartella per salvataggio progressivo dei risultati
        checkpoint_dir = Path(BASE_DIR) / "audit_checkpoints"
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        checkpoint_file = checkpoint_dir / f"checkpoint_{int(time.time())}.jsonl"

        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed

        all_results: List[AnalysisResult] = []
        results_lock = threading.Lock()
        total_tasks = len(files) * len(analysis_types)
        done_counter = [0]  # lista per mutabilità in closure

        def _save_checkpoint(result: AnalysisResult) -> None:
            """Salva un risultato su disco in modo atomico (append JSONL)."""
            try:
                entry = {
                    "file_path": result.file_path,
                    "analysis_type": result.analysis_type,
                    "success": result.success,
                    "findings": result.findings,
                    "score": result.score,
                    "error": result.error,
                    "execution_time": result.execution_time,
                }
                with open(checkpoint_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except Exception as exc:
                logger.warning("Checkpoint write failed: %s", exc)

        def _analyze_one(file_path: str, analysis_type_name: str) -> AnalysisResult:
            """Analizza un singolo file/tipo — eseguito in thread pool."""
            analysis_type = platform.analysis_types.get(analysis_type_name)
            if not analysis_type:
                return AnalysisResult(
                    file_path=file_path,
                    analysis_type=analysis_type_name,
                    success=False,
                    findings=[],
                    error="analysis_type non trovato nella piattaforma",
                )

            linter_results = self._run_linters(file_path, platform) if use_linting else None

            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError as e:
                return AnalysisResult(
                    file_path=file_path,
                    analysis_type=analysis_type_name,
                    success=False,
                    findings=[],
                    linter_results=linter_results,
                    error=str(e),
                )

            start_time = time.time()
            findings: List[Dict[str, Any]] = []
            raw_outputs: List[str] = []
            score: Optional[int] = None
            success = False
            errors: List[str] = []

            def _run():
                nonlocal success, score
                for analyzer in active_analyzers:
                    ar = analyzer.analyze_file(
                        file_path=file_path,
                        content=content,
                        context={
                            "analysis_type": analysis_type,
                            "analysis_type_name": analysis_type_name,
                            "project_path": project_path,
                        },
                    )
                    if ar.success:
                        success = True
                        findings.extend(ar.findings)
                        if ar.raw_output:
                            raw_outputs.append(ar.raw_output)
                        if ar.score is not None:
                            score = ar.score
                    elif ar.error:
                        errors.append(f"{analyzer.analyzer_id}: {ar.error}")

            try:
                if limiter:
                    with limiter.acquire():
                        _run()
                else:
                    _run()
            except Exception as e:
                logger.error("Error analyzing %s [%s]: %s", file_path, analysis_type_name, e)
                errors.append(str(e))

            return AnalysisResult(
                file_path=file_path,
                analysis_type=analysis_type_name,
                success=success,
                findings=findings,
                linter_results=linter_results,
                raw_output="\n\n".join(raw_outputs) if raw_outputs else None,
                error=None if success else ("; ".join(errors) or "Analysis failed"),
                execution_time=time.time() - start_time,
                score=score,
            )

        # Costruisce lista di task (file × analysis_type)
        tasks = [
            (fp, at)
            for fp in files
            for at in analysis_types
        ]

        logger.info(
            "Avvio audit parallelo: %d task, %d worker, checkpoint=%s",
            len(tasks), max_workers, checkpoint_file.name,
        )

        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="inneraudit") as pool:
            future_to_task = {
                pool.submit(_analyze_one, fp, at): (fp, at)
                for fp, at in tasks
            }
            for future in as_completed(future_to_task):
                fp, at = future_to_task[future]
                try:
                    result = future.result()
                except Exception as exc:
                    logger.error("Future exception %s [%s]: %s", fp, at, exc)
                    result = AnalysisResult(
                        file_path=fp,
                        analysis_type=at,
                        success=False,
                        findings=[],
                        error=str(exc),
                    )

                with results_lock:
                    all_results.append(result)
                    done_counter[0] += 1
                    done_now = done_counter[0]

                # Salvataggio progressivo su disco
                _save_checkpoint(result)

                if progress_callback:
                    try:
                        progress_callback(done_now, total_tasks, fp)
                    except Exception:
                        pass

        logger.info(
            "Audit completato: %d/%d task, checkpoint=%s",
            done_counter[0], total_tasks, checkpoint_file.name,
        )
        return all_results
    
    def generate_report(
        self,
        results: List[AnalysisResult],
        model: ModelConfig,
        platform: PlatformConfig,
        project_path: str
    ) -> Path:
        """Generate audit report"""
        output_config = self.config_manager.get_output_config()
        report_dir = Path(output_config.get('report_dir', 'audit_reports'))
        if not report_dir.is_absolute():
            report_dir = BASE_DIR / report_dir
        report_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        platform_slug = re.sub(r'[^a-z0-9]+', '_', platform.name.lower()).strip('_') or 'platform'
        report_file = report_dir / f"audit_{platform_slug}_{timestamp}.json"
        
        total_findings = sum(len(r.findings) for r in results)
        critical_findings = sum(
            1 for r in results
            for f in r.findings
            if f.get('severity') in ['critical', 'high']
        )
        
        report = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "project_path": project_path,
                "model": {
                    "id": model.id,
                    "name": model.name,
                    "type": model.type
                },
                "platform": platform.name,
                "total_files": len(set(r.file_path for r in results)),
                "total_analyses": len(results),
                "successful_analyses": sum(1 for r in results if r.success),
                "failed_analyses": sum(1 for r in results if not r.success),
                "total_findings": total_findings,
                "critical_findings": critical_findings
            },
            "results": []
        }
        
        for result in results:
            result_dict = {
                "file_path": result.file_path,
                "analysis_type": result.analysis_type,
                "success": result.success,
                "execution_time": result.execution_time,
                "findings": result.findings
            }
            
            if result.score is not None:
                result_dict["score"] = result.score
            if result.linter_results:
                result_dict["linter_results"] = result.linter_results
            if result.error:
                result_dict["error"] = result.error
            
            report["results"].append(result_dict)
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Report generated: {report_file}")
        return report_file
    
    def test_model_connection(self, model: ModelConfig) -> Tuple[bool, str]:
        """Test configured model connectivity."""
        aider_config = self.config_manager.get_aider_config()
        if aider_config.get("enabled", True):
            from analyzers import build_analyzer

            analyzer = build_analyzer("aider", aider_config, model_config=model)
            if analyzer is not None and analyzer.is_available():
                aider = AiderIntegration(aider_config, model)
                return aider.test_connection()

        try:
            import ssl
            import urllib.request

            api_key = model.api_key
            if api_key.startswith("$"):
                api_key = os.getenv(api_key[1:], "sk-dummy")

            if not model.api_base:
                return True, f"Model {model.id} selected with provider-managed endpoint."

            request = urllib.request.Request(
                model.api_base.rstrip("/"),
                headers={"Authorization": f"Bearer {api_key or 'sk-dummy'}"},
            )
            with urllib.request.urlopen(
                request,
                timeout=10,
                context=ssl.create_default_context(),
            ):
                pass
            return True, f"Endpoint {model.api_base} is reachable."
        except Exception as exc:
            safe_message = str(exc)
            if model.api_key:
                safe_message = safe_message.replace(model.api_key, "***")
            return False, f"Endpoint check failed: {safe_message}"
