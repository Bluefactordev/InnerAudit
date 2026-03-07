# InnerAudit

InnerAudit e un micro-servizio Flask per audit di codice assistito da AI. Scansiona un progetto, applica filtri ai file, lancia un pre-flight linting opzionale e delega l'analisi semantica ad Aider, salvando report JSON consultabili da interfaccia web.

## Stato attuale

- Funziona come tool standalone dentro `external/inneraudit`
- Usa configurazione locale, non quella del monorepo
- Supporta modelli OpenAI-compatible locali o cloud tramite `api_base` e `api_key`
- Salva output in `audit_reports/` e log in `inneraudit.log`

## Funzionalita principali

- UI web per avviare audit e leggere report
- Filtri `include` e `exclude` con wildcard semplici
- Configurazione modelli via `audit_config.json`
- Best practices editabili via `audit_best_practices.md`
- Report JSON con metadata, findings, errori e risultati linting

## Quick start

```bash
cd external/inneraudit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Server di default: `http://127.0.0.1:5100`

Se preferisci usare variabili ambiente, parti da `.env.example`.

## Configurazione

### 1. Modelli

Configura i modelli in `audit_config.json`.

Esempio per endpoint OpenAI-compatible locale:

```json
{
  "id": "qwen-local",
  "name": "Qwen Local",
  "type": "vllm",
  "api_base": "http://localhost:8000/v1",
  "api_key": "sk-dummy",
  "model_name": "Qwen/Qwen2.5-Coder-32B-Instruct"
}
```

Esempio per OpenAI cloud:

```bash
export OPENAI_API_KEY="..."
```

Nel config:

```json
{
  "id": "openai-gpt4",
  "type": "openai",
  "api_base": "https://api.openai.com/v1",
  "api_key": "$OPENAI_API_KEY",
  "model_name": "gpt-4o"
}
```

InnerAudit passa `model`, `openai-api-base` e `openai-api-key` ad Aider al momento dell'esecuzione.

### 2. Best practices

Modifica `audit_best_practices.md` per aggiungere regole di progetto, vincoli architetturali o controlli di sicurezza.

### 3. File filtering

`file_filtering` supporta tre modalita:

- `include_all`: prende tutti i file compatibili, poi applica solo gli exclude
- `include_only`: prende solo i file che matchano gli include, poi applica gli exclude
- `exclude_only`: equivalente pratico a "tutti meno gli exclude"

Pattern tipici:

- directory o segmenti: `utils`, `routes`, `src/api`
- wildcard: `*.py`, `*.egg-info`
- directory da ignorare: `node_modules`, `.git`, `__pycache__`

## Uso dalla UI

1. Apri `http://127.0.0.1:5100/audit`
2. Inserisci il path del progetto da analizzare
3. Seleziona modello, piattaforma e tipi di analisi
4. Salva eventuali filtri
5. Avvia l'audit
6. Consulta il risultato in `Reports`

## Endpoint principali

- `GET /api/config`
- `GET /api/platform/<name>`
- `GET /api/best-practices`
- `POST /api/best-practices`
- `GET /api/file-filtering`
- `POST /api/file-filtering`
- `POST /api/audit/run`
- `POST /api/audit/test-model`
- `GET /api/reports`
- `GET /api/reports/<filename>`

## Variabili ambiente utili

```bash
export INNERAUDIT_SECRET_KEY="change-me"
export INNERAUDIT_HOST="0.0.0.0"
export INNERAUDIT_PORT="5100"
export INNERAUDIT_DEBUG="false"
```

## Struttura progetto

```text
inneraudit/
├── app.py
├── audit_engine.py
├── audit_best_practices.md
├── audit_config.json
├── templates/
├── audit_reports/
├── .gitignore
└── README.md
```

## Note operative

- Se `pylint`, `flake8`, `phpcs` o `phpstan` non sono installati, il report lo segnala ma l'audit continua
- I report sono protetti contro path traversal sugli endpoint di lettura
- Il progetto non dipende piu dalla working directory del monorepo per trovare config, log e report
