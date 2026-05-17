"""
Direct LLM analyzer — chiama direttamente l'endpoint OpenAI-compatible.
Nessun subprocess, nessun Aider.
"""

import asyncio
import json
import logging
import os
import re
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional, Tuple

from .base import AnalysisResult, BaseAnalyzer

logger = logging.getLogger("ExternalLLMAnalyzer")

MAX_FILE_CHARS = 40_000  # tronca file molto grandi per non saturare il context


class ExternalLLMAnalyzer(BaseAnalyzer):
    """Analyzer che chiama direttamente un endpoint OpenAI-compatible (vLLM, OpenAI, ecc.)."""

    analyzer_id = "llm"
    requires_external_service = True

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        model_config: Any = None,
    ) -> None:
        super().__init__(config)
        self._model_config = model_config
        self._max_retries = int((config or {}).get("max_retries", 2))

    def is_available(self) -> bool:
        if not self.enabled or self._model_config is None:
            return False
        if self._uses_nirodeep_runtime():
            try:
                from utils.models import ModelProvider  # noqa: F401
                return True
            except Exception:
                return False
        api_base = getattr(self._model_config, "api_base", None)
        return bool(api_base)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _api_base(self) -> str:
        return (getattr(self._model_config, "api_base", "") or "").rstrip("/")

    def _api_key(self) -> str:
        mc = self._model_config
        # Prova env_overrides prima
        for key, value in (getattr(mc, "env_overrides", None) or {}).items():
            if key.endswith("_API_KEY") and value:
                return value
        api_key = getattr(mc, "api_key", "") or ""
        if api_key.startswith("$"):
            return os.getenv(api_key[1:], "sk-dummy")
        return api_key or "sk-dummy"

    def _model_name(self) -> str:
        return getattr(self._model_config, "model_name", "") or ""

    def _runtime_options(self) -> Dict[str, Any]:
        runtime_options = getattr(self._model_config, "runtime_options", None)
        return runtime_options if isinstance(runtime_options, dict) else {}

    def _uses_nirodeep_runtime(self) -> bool:
        return str(self._runtime_options().get("adapter") or "").strip().lower() == "nirodeep"

    def _build_prompt(
        self,
        file_path: str,
        content: str,
        analysis_type: Any,
        project_path: str,
        analysis_context: str = "",
    ) -> Tuple[str, str]:
        """Restituisce (system_prompt, user_prompt)."""
        # Carica best practices se disponibili
        best_practices = ""
        try:
            bp_path = os.path.join(os.path.dirname(__file__), "..", "audit_best_practices.md")
            bp_path = os.path.normpath(bp_path)
            if os.path.exists(bp_path):
                with open(bp_path, encoding="utf-8") as f:
                    best_practices = f.read()[:8000]
        except Exception:
            pass

        # Tronca file grandi
        if len(content) > MAX_FILE_CHARS:
            content = content[:MAX_FILE_CHARS] + f"\n\n[... file troncato a {MAX_FILE_CHARS} caratteri ...]"

        template = getattr(analysis_type, "prompt_template", "") or ""
        rel_path = os.path.relpath(file_path, project_path) if project_path else file_path
        normalized_analysis_context = str(analysis_context or "").strip()

        system = (
            "Sei un auditor di codice senior. "
            "Rispondi SOLO con JSON valido, senza testo prima o dopo. "
            "Non aggiungere markdown, backtick o spiegazioni."
        )
        if best_practices:
            system += f"\n\nBest practices di riferimento:\n{best_practices}"

        if template:
            user = template.replace("{file_path}", rel_path).replace("{context}", normalized_analysis_context)
            user += f"\n\nContenuto del file `{rel_path}`:\n```\n{content}\n```"
        else:
            user = (
                f"Analizza il file `{rel_path}` e restituisci un JSON con:\n"
                f"- findings: lista di problemi trovati (severity, category, description, recommendation)\n"
                f"- overall_score: punteggio 0-100\n"
                f"- summary: breve riepilogo\n\n"
                f"Contenuto:\n```\n{content}\n```"
            )

        return system, user

    def _extract_runtime_content(self, raw_result: Any) -> str:
        if isinstance(raw_result, str):
            return raw_result
        if isinstance(raw_result, dict):
            for key in ("result", "output", "content", "message"):
                value = raw_result.get(key)
                if isinstance(value, str):
                    return value
                if isinstance(value, (dict, list)):
                    return json.dumps(value, ensure_ascii=False)
                if value is not None:
                    return str(value)
        return str(raw_result)

    def _call_nirodeep_runtime(self, system: str, user: str) -> Tuple[bool, Optional[str], float]:
        """Call the canonical BF/Nirodeep runtime through ModelProvider."""
        from utils.models import ModelProvider

        runtime_options = self._runtime_options()
        runtime_context = dict(runtime_options.get("context") or {})
        execution_mode = str(runtime_options.get("execution_mode") or "").strip().lower()
        if execution_mode:
            runtime_context["execution_mode"] = execution_mode
        if runtime_options.get("agentic_max_iterations") is not None:
            runtime_context["agentic_max_iterations"] = int(runtime_options["agentic_max_iterations"])

        tool_names = [
            str(tool_name).strip()
            for tool_name in (runtime_options.get("tool_names") or [])
            if str(tool_name).strip()
        ]
        depth = int(runtime_options.get("depth", 0) or 0)
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        timeout = int(getattr(self._model_config, "timeout", 300))

        async def _invoke_runtime() -> Any:
            return await asyncio.wait_for(
                ModelProvider.generate_job(
                    model_id=self._model_name(),
                    messages=messages,
                    tools=tool_names or None,
                    context=runtime_context,
                    depth=depth,
                    temperature=getattr(self._model_config, "temperature", None),
                    max_tokens=getattr(self._model_config, "max_tokens", None),
                ),
                timeout=timeout,
            )

        t0 = time.time()
        try:
            raw_result = asyncio.run(_invoke_runtime())
            elapsed = time.time() - t0
            return True, self._extract_runtime_content(raw_result), elapsed
        except Exception as exc:
            elapsed = time.time() - t0
            logger.error("Nirodeep runtime errore: %s (%.1fs)", exc, elapsed)
            return False, None, elapsed

    def _call_api(self, system: str, user: str) -> Tuple[bool, Optional[str], float]:
        """
        Chiama l'endpoint OpenAI-compatible via urllib (no dipendenze extra).
        Restituisce (success, raw_content, elapsed_seconds).
        """
        if self._uses_nirodeep_runtime():
            return self._call_nirodeep_runtime(system, user)

        url = f"{self._api_base()}/chat/completions"
        mc = self._model_config

        payload: Dict[str, Any] = {
            "model": self._model_name(),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": float(getattr(mc, "temperature", 0.2)),
        }

        # extra_body: parametri aggiuntivi opzionali passati dall'esterno
        # (es. chat_template_kwargs, guided_json, ecc.) — InnerAudit
        # non sa cosa contengono, li passa trasparentemente all'endpoint.
        extra_body = getattr(mc, "extra_body", None)
        if extra_body and isinstance(extra_body, dict):
            payload.update(extra_body)

        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._api_key()}",
        }
        timeout = int(getattr(mc, "timeout", 300))
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")

        t0 = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8")
            elapsed = time.time() - t0
            data = json.loads(raw)
            content = data["choices"][0]["message"]["content"]
            return True, content, elapsed
        except urllib.error.HTTPError as exc:
            elapsed = time.time() - t0
            body_err = exc.read().decode("utf-8", errors="replace")[:500]
            logger.error("LLM API HTTP %s: %s (%.1fs)", exc.code, body_err, elapsed)
            return False, None, elapsed
        except Exception as exc:
            elapsed = time.time() - t0
            logger.error("LLM API errore: %s (%.1fs)", exc, elapsed)
            return False, None, elapsed

    def _parse_json(self, raw: str) -> Optional[Dict[str, Any]]:
        """Prova a estrarre JSON dalla risposta del modello."""
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
        # Fallback: cerca il primo blocco JSON nella stringa
        match = re.search(r'\{[\s\S]*\}', raw)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return None

    def _extract_findings(self, parsed: Dict[str, Any]) -> Tuple[List[Dict], Optional[int]]:
        findings: List[Dict] = []
        for key in ("findings", "vulnerabilities", "issues", "performance_issues"):
            if key in parsed and isinstance(parsed[key], list):
                findings = parsed[key]
                break
        score = None
        for key in ("overall_score", "security_score", "quality_score", "performance_score"):
            if key in parsed:
                try:
                    score = int(parsed[key])
                except (TypeError, ValueError):
                    pass
                break
        return findings, score

    # ------------------------------------------------------------------
    # Main
    # ------------------------------------------------------------------

    def analyze_file(
        self,
        file_path: str,
        content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AnalysisResult:
        if not self.is_available():
            return AnalysisResult(
                file_path=file_path,
                analyzer_id=self.analyzer_id,
                success=False,
                error="ExternalLLMAnalyzer non disponibile (runtime Nirodeep o api_base mancante, oppure analyzer disabilitato).",
            )

        context = context or {}
        analysis_type = context.get("analysis_type")
        project_path = context.get("project_path", ".")
        analysis_context = context.get("analysis_context") or self._runtime_options().get("prompt_context") or ""

        if analysis_type is None:
            return AnalysisResult(
                file_path=file_path,
                analyzer_id=self.analyzer_id,
                success=False,
                error="ExternalLLMAnalyzer richiede 'analysis_type' nel context.",
            )

        system, user = self._build_prompt(
            file_path,
            content,
            analysis_type,
            project_path,
            analysis_context=analysis_context,
        )
        prompt_chars = len(system) + len(user)

        for attempt in range(self._max_retries + 1):
            t_start = time.time()
            success, raw, elapsed_llm = self._call_api(system, user)
            t_total = time.time() - t_start

            logger.info(
                "LLM %s | file=%s | attempt=%d | llm=%.1fs | prompt_chars=%d | ok=%s",
                self._model_name(),
                os.path.basename(file_path),
                attempt + 1,
                elapsed_llm,
                prompt_chars,
                success,
            )

            if not success:
                if attempt < self._max_retries:
                    time.sleep(2)
                    continue
                return AnalysisResult(
                    file_path=file_path,
                    analyzer_id=self.analyzer_id,
                    success=False,
                    error=f"Chiamata LLM fallita dopo {self._max_retries + 1} tentativi",
                )

            parsed = self._parse_json(raw)
            if parsed is None:
                logger.warning("Nessun JSON valido nella risposta per %s", file_path)
                if attempt < self._max_retries:
                    time.sleep(2)
                    continue
                return AnalysisResult(
                    file_path=file_path,
                    analyzer_id=self.analyzer_id,
                    success=False,
                    raw_output=raw,
                    error="Nessun JSON valido nella risposta del modello",
                )

            findings, score = self._extract_findings(parsed)
            return AnalysisResult(
                file_path=file_path,
                analyzer_id=self.analyzer_id,
                success=True,
                findings=findings,
                raw_output=raw,
                score=score,
            )

        return AnalysisResult(
            file_path=file_path,
            analyzer_id=self.analyzer_id,
            success=False,
            error="Max retries superato",
        )
