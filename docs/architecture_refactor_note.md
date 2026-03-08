# InnerAudit — Architecture Refactor Note

## Current State (before this refactor)

InnerAudit was drifting toward a generic AI-coding platform.  The key
symptoms were:

* **Aider was architecturally central** — `AuditEngine.run_audit()` directly
  instantiated `AiderIntegration` with no abstraction layer.
  `test_model_connection()` hard-wired Aider as the only way to validate a
  model endpoint.  The top-level config description read *"Aider-Centric"*.

* **No hypothesis layer** — the pipeline was a direct short-circuit:
  `detector → Proposal`.  A single detector hit immediately became a persisted
  backlog entry with no intermediate aggregation, normalization, or opportunity
  for multi-source validation.

* **`proposal_engine/detector.py` returned `List[Proposal]`** — detectors
  created fully-formed proposal objects, coupling observation to backlog
  structure.

### Parts that were already strong
* Deterministic proposal IDs (`make_proposal_id` via `uuid5`)
* Idempotent backlog upserts (state preserved across rescans)
* Proposal lifecycle + state machine (`DETECTED → CANDIDATE → VALIDATED …`)
* Scan summaries persisted under `proposals/scans/<scan_id>.json`
* `TraceAdapter` with graceful fallback when InnerTrace is absent
* Full file-filtering semantics (include_only, exclude, fnmatch glob)
* Callable file-filtering that is re-read on every scan

---

## Target State (after this refactor)

InnerAudit is now a **focused repository-observation and proposal-generation
subsystem** that can later be orchestrated by BFPersonal.

### Core responsibilities (InnerAudit owns)
| Concern | Component |
|---|---|
| Repository scanning / file discovery | `ProposalEngine._discover_files` |
| Static heuristic observation | `analyzers.StaticAnalyzer` + `proposal_engine.detector` |
| Optional external semantic analysis | `analyzers.AiderAnalyzer`, `analyzers.ExternalLLMAnalyzer` |
| Hypothesis creation / aggregation | `proposal_engine.hypothesis` |
| Structured proposal generation | `proposal_engine.models.Proposal` |
| Proposal state lifecycle | `proposal_engine.models.ALLOWED_TRANSITIONS` |
| Backlog persistence | `proposal_engine.backlog.BacklogManager` |
| Scan summaries | `BacklogManager._save_scan_summary` |
| Trace/event emission | `proposal_engine.trace_adapter.TraceAdapter` |

### Optional / external responsibilities (abstracted behind adapters)
* Deep semantic LLM analysis → `analyzers.AiderAnalyzer` or `analyzers.ExternalLLMAnalyzer`
* Code editing / patch generation → out of scope for InnerAudit
* Autonomous code modification → BFPersonal or a dedicated execution backend
* Multi-agent orchestration → BFPersonal

---

## What Was Changed

### 1 — Hypothesis layer introduced (`proposal_engine/hypothesis.py`)

A new intermediate concept sits between raw detector signals and fully-formed
proposals:

```
observe → detect → RawSignal → Hypothesis → Proposal → BacklogManager
```

* `RawSignal` — a single detector observation (rule_id, file, line, snippet).
* `Hypothesis` — aggregates one or more `RawSignal` objects for the same
  location.  Severity is escalated if a stronger signal arrives; confidence is
  averaged.  Provides `to_evidence_list()` for downstream proposal creation.
* `HypothesisBuilder` — groups raw signals into hypotheses keyed by
  `(rule_id, file_path)`.

`ProposalEngine._scan_file` now converts detector hits into hypotheses via
`HypothesisBuilder` before calling `Proposal.create()`.

### 2 — Analyzer abstraction introduced (`analyzers/`)

A clean hierarchy replaces the hard-wired Aider dependency:

```
BaseAnalyzer (ABC)
  ├── StaticAnalyzer       — deterministic, zero external deps
  ├── ExternalLLMAnalyzer  — calls any OpenAI-compatible endpoint
  └── AiderAnalyzer        — optional, wraps AiderIntegration
```

All analyzers implement `is_available() → bool`, so the engine can skip
unavailable backends gracefully.

`build_analyzers_from_config()` builds the active analyzer list from config;
only `StaticAnalyzer` is enabled by default.

### 3 — Aider repositioned as optional backend

* `AuditEngine.run_audit()` now uses `build_analyzers_from_config()` so the
  analyzer backend is determined by configuration, not hard-coded.
* `AuditEngine.test_model_connection()` tries `AiderAnalyzer` only when Aider
  is enabled and available; falls back to a direct HTTP connectivity check
  otherwise.
* `requirements.txt` — `aider-chat` is now marked as optional.
* `audit_config.json` — the `"aider"` section has `"enabled": false` by
  default; a new top-level `"analyzers"` section declares which backends are
  active.

### 4 — Configuration updated

`audit_config.json` gains a top-level `"analyzers"` section:

```json
"analyzers": {
  "static": { "enabled": true },
  "aider":  { "enabled": false },
  "llm":    { "enabled": false }
}
```

The `"description"` field no longer says *"Aider-Centric"*.

### 5 — Tests extended

* `tests/test_hypothesis.py` — unit tests for `RawSignal`, `Hypothesis`,
  `HypothesisBuilder`.
* `tests/test_analyzers.py` — tests for `StaticAnalyzer`, `AiderAnalyzer`
  availability guard, and the registry factory.
* Additional test in `tests/test_proposal_engine.py` verifies the full
  pipeline works when Aider is absent.

---

## What Was Preserved

* All 44 original tests continue to pass unchanged.
* Deterministic proposal IDs — no change.
* Idempotent backlog upserts — no change.
* Proposal state machine — no change.
* Scan summaries — no change.
* TraceAdapter — no change.
* File-filtering semantics (callable, include_only, fnmatch) — no change.
* `proposal_engine/detector.py` public API — no change.

---

## What Remains for Later

| Area | Notes |
|---|---|
| **Stronger validation** | Hypotheses can be forwarded to a `validator_model` via `ExternalLLMAnalyzer` before promotion to CANDIDATE. Stub exists in config (`validator_model` role). |
| **BFPersonal integration** | Backlog proposals should be emittable as structured events consumable by BFPersonal's orchestration layer. Trace events already provide a basis. |
| **Patch generation / execution** | `AiderAnalyzer` provides the scaffolding; a `PatchExecutor` adapter could wrap `aider --apply-patch` without touching InnerAudit's core. |
| **Commit regression analysis** | `BacklogManager` scan summaries and proposal IDs are stable across rescans — useful as anchors for commit-diff correlation. |
| **Trace-driven continuous improvement** | `TraceAdapter` already emits `proposal.scan.*`, `proposal.violation`, `proposal.generated`, `proposal.validation` events. BFPersonal could consume these to drive a feedback loop. |
