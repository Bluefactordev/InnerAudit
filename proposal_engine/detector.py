"""Static-analysis detectors that convert code observations into proposal hypotheses."""

import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .models import Proposal


# ---------------------------------------------------------------------------
# Base detector
# ---------------------------------------------------------------------------

class BaseDetector(ABC):
    """Abstract base for all proposal detectors."""

    rule_id: str = ""
    rule_name: str = ""
    default_severity: str = "medium"
    default_priority: str = "p2"
    default_risk_level: str = "medium"
    default_confidence: float = 0.8
    autofixable: bool = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        self.enabled = cfg.get("enabled", True)
        self.severity = cfg.get("severity", self.default_severity)
        self.priority = cfg.get("priority", self.default_priority)
        self.risk_level = cfg.get("risk_level", self.default_risk_level)
        self.confidence = float(cfg.get("confidence", self.default_confidence))

    @abstractmethod
    def detect(
        self,
        file_path: str,
        content: str,
        scan_id: Optional[str] = None,
    ) -> List[Proposal]:
        """Scan file content and return a list of proposals."""

    def _make_proposal(
        self,
        title: str,
        description: str,
        evidence: List[Dict[str, Any]],
        recommendation: str,
        scan_id: Optional[str] = None,
    ) -> Proposal:
        return Proposal.create(
            proposal_type=self.rule_id,
            title=title,
            description=description,
            evidence=evidence,
            severity=self.severity,
            priority=self.priority,
            confidence=self.confidence,
            risk_level=self.risk_level,
            autofixable=self.autofixable,
            recommendation=recommendation,
            source_rule=self.rule_id,
            scan_id=scan_id,
        )


# ---------------------------------------------------------------------------
# Detector: hardcoded model names
# ---------------------------------------------------------------------------

# Model name string-literal patterns that should come from config
_MODEL_NAME_RE = re.compile(
    r'"('
    r'gpt-4[^"]*'
    r'|gpt-3\.5[^"]*'
    r'|gpt-4o[^"]*'
    r'|o[13]-[^"]*'
    r'|claude-[23]-[^"]*'
    r'|claude-3[^"]*'
    r'|meta-llama/[^"]*'
    r'|Llama-[^"]*'
    r'|Qwen/[^"]*'
    r'|Qwen[23]-[^"]*'
    r'|mistral[^"]*'
    r'|gemini-[^"]*'
    r'|palm-[^"]*'
    r'|deepseek[^"]*'
    r'|phi-[^"]*'
    r'|mixtral[^"]*'
    r')"',
    re.IGNORECASE,
)


class HardcodedModelNameDetector(BaseDetector):
    """Detects hardcoded model-name string literals in source files."""

    rule_id = "hardcoded_model_names"
    rule_name = "Hardcoded Model Name"
    default_severity = "high"
    default_priority = "p1"
    default_risk_level = "medium"
    default_confidence = 0.85
    autofixable = False

    def detect(
        self,
        file_path: str,
        content: str,
        scan_id: Optional[str] = None,
    ) -> List[Proposal]:
        proposals: List[Proposal] = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, 1):
            for match in _MODEL_NAME_RE.finditer(line):
                model_literal = match.group(0)
                evidence = [
                    {
                        "file_path": file_path,
                        "line_number": lineno,
                        "code_snippet": line.strip(),
                        "context": f"Found hardcoded model name: {model_literal}",
                    }
                ]
                proposals.append(
                    self._make_proposal(
                        title=f"Hardcoded model name {model_literal} in {file_path}",
                        description=(
                            f"The model name {model_literal} is hardcoded at line {lineno}. "
                            "Model names should be read from the configuration so they can be "
                            "swapped without code changes."
                        ),
                        evidence=evidence,
                        recommendation=(
                            "Move the model name to the configuration file (e.g., audit_config.json) "
                            "and reference it via the model/provider abstraction already present in "
                            "ConfigManager."
                        ),
                        scan_id=scan_id,
                    )
                )

        return proposals


# ---------------------------------------------------------------------------
# Detector: hardcoded constants (URLs, API bases, ports) outside config/JSON
# ---------------------------------------------------------------------------

# Patterns for config-like values hardcoded in Python source
_HARDCODED_URL_RE = re.compile(
    r'''(?:['"])(https?://(?:localhost|(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))[^'"]*?)(?:['"])''',
    re.IGNORECASE,
)
_HARDCODED_REMOTE_API_RE = re.compile(
    r'''(?:['"])(https?://api\.[a-z0-9\-]+\.[a-z]{2,}/v\d[^'"]*?)(?:['"])''',
    re.IGNORECASE,
)


class HardcodedConstantDetector(BaseDetector):
    """Detects hardcoded URLs / API base addresses in source files."""

    rule_id = "hardcoded_constants"
    rule_name = "Hardcoded Constant"
    default_severity = "medium"
    default_priority = "p2"
    default_risk_level = "low"
    default_confidence = 0.75
    autofixable = False

    def detect(
        self,
        file_path: str,
        content: str,
        scan_id: Optional[str] = None,
    ) -> List[Proposal]:
        proposals: List[Proposal] = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, 1):
            # Skip comment lines
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern in (_HARDCODED_URL_RE, _HARDCODED_REMOTE_API_RE):
                for match in pattern.finditer(line):
                    value = match.group(1)
                    evidence = [
                        {
                            "file_path": file_path,
                            "line_number": lineno,
                            "code_snippet": line.strip(),
                            "context": f"Found hardcoded URL/endpoint: {value}",
                        }
                    ]
                    proposals.append(
                        self._make_proposal(
                            title=f"Hardcoded URL/endpoint at {file_path}:{lineno}",
                            description=(
                                f"The value '{value}' at line {lineno} appears to be a hardcoded "
                                "URL or API endpoint. Such values should be externalised to "
                                "configuration so they can be changed without code modifications."
                            ),
                            evidence=evidence,
                            recommendation=(
                                "Move this value to the configuration file and reference it via the "
                                "existing ConfigManager. Consider adding an 'endpoints' section to "
                                "audit_config.json."
                            ),
                            scan_id=scan_id,
                        )
                    )

        return proposals


# ---------------------------------------------------------------------------
# Detector: non-model-agnostic prompts
# ---------------------------------------------------------------------------

# Long string literals or f-strings referencing model-specific capabilities
_PROMPT_MODEL_REF_RE = re.compile(
    r'''(?:f?['"].*?)(?:gpt-4|gpt-3\.5|claude|llama|qwen|mistral|gemini|palm)(?:.*?['"])''',
    re.IGNORECASE,
)
_PROMPT_CONTEXT_KEYWORDS = re.compile(
    r'''\b(?:system_prompt|user_prompt|prompt_template|PROMPT|instruction)\b''',
    re.IGNORECASE,
)


class NonAgnosticPromptDetector(BaseDetector):
    """Detects prompts that reference specific model names or behaviours."""

    rule_id = "non_agnostic_prompts"
    rule_name = "Non-Model-Agnostic Prompt"
    default_severity = "high"
    default_priority = "p1"
    default_risk_level = "medium"
    default_confidence = 0.70
    autofixable = False

    def detect(
        self,
        file_path: str,
        content: str,
        scan_id: Optional[str] = None,
    ) -> List[Proposal]:
        proposals: List[Proposal] = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Only flag lines that are in a prompt context AND contain a model reference
            if _PROMPT_CONTEXT_KEYWORDS.search(line) and _PROMPT_MODEL_REF_RE.search(line):
                evidence = [
                    {
                        "file_path": file_path,
                        "line_number": lineno,
                        "code_snippet": stripped[:200],
                        "context": "Prompt variable contains a model-specific reference",
                    }
                ]
                proposals.append(
                    self._make_proposal(
                        title=f"Non-model-agnostic prompt at {file_path}:{lineno}",
                        description=(
                            f"Line {lineno} contains a prompt that references a specific model name. "
                            "Prompts should be model-agnostic so they work across different providers."
                        ),
                        evidence=evidence,
                        recommendation=(
                            "Remove model-specific references from prompt templates. "
                            "Use generic instructions that work across providers."
                        ),
                        scan_id=scan_id,
                    )
                )

        return proposals


# ---------------------------------------------------------------------------
# Detector: leaked project / organisation identifiers
# ---------------------------------------------------------------------------

_PROJECT_ID_RE = re.compile(
    r'''\b(?:project_id|project_name|org_id|organization_id|tenant_id|workspace_id|client_id)\s*=\s*(?:f?['"])([^'"]{3,})(?:['"])''',
    re.IGNORECASE,
)


class LeakedProjectIdDetector(BaseDetector):
    """Detects hardcoded project/org/tenant IDs that could leak into model calls."""

    rule_id = "leaked_project_ids"
    rule_name = "Leaked Project / Org Identifier"
    default_severity = "critical"
    default_priority = "p0"
    default_risk_level = "high"
    default_confidence = 0.90
    autofixable = False

    def detect(
        self,
        file_path: str,
        content: str,
        scan_id: Optional[str] = None,
    ) -> List[Proposal]:
        proposals: List[Proposal] = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for match in _PROJECT_ID_RE.finditer(line):
                value = match.group(1)
                var_name = match.group(0).split("=")[0].strip()
                evidence = [
                    {
                        "file_path": file_path,
                        "line_number": lineno,
                        "code_snippet": stripped[:200],
                        "context": f"Variable '{var_name}' assigned literal value '{value}'",
                    }
                ]
                proposals.append(
                    self._make_proposal(
                        title=f"Hardcoded identifier '{var_name}' at {file_path}:{lineno}",
                        description=(
                            f"The variable '{var_name}' is assigned a literal value '{value}' "
                            f"at line {lineno}. Identifiers such as project_id, org_id, or "
                            "tenant_id must not be hardcoded because they could inadvertently "
                            "leak into LLM prompts or API calls."
                        ),
                        evidence=evidence,
                        recommendation=(
                            "Read this identifier from an environment variable or a dedicated "
                            "secrets configuration. Never commit literal org/project IDs to source code."
                        ),
                        scan_id=scan_id,
                    )
                )

        return proposals


# ---------------------------------------------------------------------------
# Detector registry
# ---------------------------------------------------------------------------

DETECTOR_REGISTRY: Dict[str, type] = {
    HardcodedModelNameDetector.rule_id: HardcodedModelNameDetector,
    HardcodedConstantDetector.rule_id: HardcodedConstantDetector,
    NonAgnosticPromptDetector.rule_id: NonAgnosticPromptDetector,
    LeakedProjectIdDetector.rule_id: LeakedProjectIdDetector,
}


def build_detectors(detector_configs: Dict[str, Any]) -> List[BaseDetector]:
    """
    Instantiate detectors from configuration.

    Args:
        detector_configs: dict keyed by rule_id with per-detector config values.

    Returns:
        List of enabled detector instances.
    """
    detectors: List[BaseDetector] = []
    for rule_id, detector_cls in DETECTOR_REGISTRY.items():
        cfg = detector_configs.get(rule_id, {})
        detector = detector_cls(cfg)
        if detector.enabled:
            detectors.append(detector)
    return detectors
