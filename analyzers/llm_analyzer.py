"""
Direct LLM analyzer — chiama direttamente l'endpoint OpenAI-compatible.
Nessun subprocess, nessun Aider.
"""

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

    def _build_prompt(
        self,
        file_path: str,
        content: str,
        analysis_type: Any,
        project_path: str,
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

        template = getattr(analysis_type, "prompt_template", "") or ""
        rel_path = os.path.relpath(file_path, project_path) if project_path else file_path

        system = (
            "Sei un auditor di codice senior. "
            "Rispondi SOLO con JSON valido, senza testo prima o dopo. "
            "Non aggiungere markdown, backtick o spiegazioni."
        )
        if best_practices:
            system += f"\n\nBest practices di riferimento:\n{best_practices}"

        if template:
            user = template.replace("{file_path}", rel_path).replace("{context}", "")
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

    def _call_api(self, system: str, user: str) -> Tuple[bool, Optional[str], float]:
        """
        Chiama l'endpoint OpenAI-compatible via urllib (no dipendenze extra).
        Restituisce (success, raw_content, elapsed_seconds).
        """
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
                error="ExternalLLMAnalyzer non disponibile (api_base mancante o analyzer disabilitato).",
            )

        context = context or {}
        analysis_type = context.get("analysis_type")
        project_path = context.get("project_path", ".")

        if analysis_type is None:
            return AnalysisResult(
                file_path=file_path,
                analyzer_id=self.analyzer_id,
                success=False,
                error="ExternalLLMAnalyzer richiede 'analysis_type' nel context.",
            )

        system, user = self._build_prompt(file_path, content, analysis_type, project_path)
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
