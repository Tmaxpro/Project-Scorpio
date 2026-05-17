# ARIA — Autonomous REST API Intelligence Agent

A local multi-agent REST API penetration-testing system targeting the
OWASP API Security Top 10 (2023). Runs entirely on-device using Cisco
Foundation-Sec SLMs via Ollama.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  SLM LAYER  (reasoning — decides WHAT and WHY)          │
│  Coordinator → Attack Agents → Validator → Reporter     │
│  All agents = same Foundation-Sec-Reasoning SLM         │
│               with per-OWASP-category system prompts    │
└─────────────────────────────────────────────────────────┘
          │ AgentDecision (typed dataclass)
          ▼
┌─────────────────────────────────────────────────────────┐
│  DETERMINISTIC LAYER  (execution — builds and sends)    │
│  Payload Factory → HTTP Engine → Rule Validator         │
│  SLM never generates raw payloads or HTTP requests      │
└─────────────────────────────────────────────────────────┘
```

**Model assignment:**

| Task | Model |
|------|-------|
| Coordinator planning, Agent decisions | Foundation-Sec-8B-Reasoning |
| Validator review, Report remediation | Foundation-Sec-1.1-8B-Instruct |
| JSON-parse recovery (after 3 failures) | Qwen2.5:7b |

---

## Quickstart

### 1 — Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### 2 — Pull the required models

```bash
# Primary reasoning model (~8 GB, Q8 quantization)
ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF

# Instruct model for validation/reporting (~5 GB, Q4_K_M quantization)
ollama pull hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF

# Fallback model
ollama pull qwen2.5:7b
```

Verify all three are available:
```bash
ollama list
```

### 3 — Install Python dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4 — Start the backend

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The legacy single-page UI is available at `http://localhost:8000`.

### 5 — Start the frontend (optional)

The React frontend lives in `aria-fontend/` and connects to the backend at port 8000.

```bash
cd aria-fontend
npm install
npm run dev        # starts Vite dev server on http://localhost:5173
```

Or build for production:
```bash
npm run build
```

---

## API reference

### Submit a scan

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "spec": "<OpenAPI 3.x YAML or JSON content>",
    "target_url": "http://target-api:8080",
    "auth_type": "bearer",
    "credentials": {"token": "eyJ..."},
    "owasp_filter": ["API1", "API2", "API6", "API8"],
    "max_payloads_per_endpoint": 20
  }'
```

**Auth types:** `bearer` · `apikey` (credentials: `{name, value, in: header|query}`) · `basic` (credentials: `{username, password}`) · `none`

**Response:** `{ "scan_id": "<uuid>", "message": "Scan queued" }`

### Poll status

```bash
curl http://localhost:8000/api/scan/{scan_id}
```

Returns `status` (`pending` → `running` → `completed` | `failed`), `progress` (0–1), `message`, `target`, timing fields, and counts.

### Real-time events (SSE)

```bash
curl -N http://localhost:8000/api/scan/{scan_id}/events
```

Stream of newline-delimited JSON events:

| Event type | Data fields |
|-----------|-------------|
| `scan_info` | `total_tasks` |
| `task_started` | `task_id`, `endpoint`, `method`, `vuln_category`, `agent` |
| `task_completed` | `task_id`, `endpoint`, `progress` |
| `finding` | `finding` (full TaskResult object) |
| `scan_completed` | `vulnerable_count`, `total_requests` |
| `error` | `message` |

### Get findings

```bash
curl http://localhost:8000/api/scan/{scan_id}/results
```

Returns `findings[]` with `endpoint`, `method`, `vuln_category`, `owasp_ref`, `severity`, `confidence`, `rule_ids`, `evidence`, `remediation`, `confirmed_by_slm`.

### Download report

```bash
curl "http://localhost:8000/api/scan/{scan_id}/report" -o report.html
curl "http://localhost:8000/api/scan/{scan_id}/report?format=markdown" -o report.md
```

### List all scans

```bash
curl http://localhost:8000/api/scan
```

### Benchmarks

```bash
# List stored benchmark runs
curl http://localhost:8000/api/benchmarks

# Trigger a dry-run benchmark (no Ollama required)
curl -X POST http://localhost:8000/api/benchmarks/run \
  -H "Content-Type: application/json" \
  -d '{"spec_name": "fixture"}'
```

---

## Docker

```bash
docker compose up --build
```

This starts both Ollama and ARIA. Pull models into the running Ollama container:

```bash
docker exec -it project_scorpio-ollama-1 \
  ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF

docker exec -it project_scorpio-ollama-1 \
  ollama pull hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF

docker exec -it project_scorpio-ollama-1 \
  ollama pull qwen2.5:7b
```

Open `http://localhost:8000` once models are pulled.

---

## Running tests

```bash
pytest tests/unit/       # no Ollama required (all mocked)
pytest tests/integration # requires a running target API (VAmPI / DVAPI)
```

---

## Configuration

All settings live in `config.yaml`. Key knobs:

| Setting | Default | Effect |
|---------|---------|--------|
| `llm.max_retries` | 3 | Retries per model before escalating to fallback |
| `scan.rate_limit_delay` | 0.5 s | Delay between requests to the same host |
| `scan.max_concurrent_agents` | 3 | Parallel OWASP agents |
| `scan.max_payloads_per_endpoint` | 50 | Cap on generated payloads |
| `rag.top_k` | 5 | OWASP context chunks injected per agent prompt |

Override the Ollama URL for Docker:
```bash
OLLAMA_URL=http://ollama:11434 uvicorn app.main:app
```

---

## Project structure

```
app/               FastAPI backend — routers, schemas, scan runner
app/routers/       scan (CRUD + SSE) and benchmarks endpoints
aria-fontend/      React + TanStack Router frontend (Vite)
core/llm/          LLMClient — unified SLM interface with retry/fallback
core/parser/       OpenAPI YAML parser + endpoint enricher
core/coordinator/  Scan planner (LLM-based + rule-based fallback)
core/agents/       Per-OWASP-category attack agents (same SLM, diff prompts)
core/payload_factory/  Deterministic payload builder + exploit modules
core/http_engine/      Async HTTP client with auth injection + rate control
core/validator/        Rule-based + SLM-assisted finding validation
core/rag/              ChromaDB vector store for OWASP knowledge
core/reporter/         HTML + Markdown report generation
benchmarks/        Dry-run pipeline evaluation and LLM usage metrics
data/owasp/        OWASP API Top 10 markdown (RAG knowledge base)
```

---

## Academic benchmarking

Run the pipeline in dry mode (no Ollama or live target required):

```bash
# Built-in fixture (5-endpoint VAmPI-like spec)
python benchmarks/run_benchmark.py

# Custom spec
python benchmarks/run_benchmark.py --spec path/to/openapi.yaml
```

View aggregated LLM usage metrics from past scans:

```bash
python benchmarks/metrics.py                          # all runs in benchmarks/runs/
python benchmarks/metrics.py --file benchmarks/runs/<scan_id>.jsonl
```

Metrics logged per scan to `benchmarks/runs/{scan_id}.jsonl`:
`timestamp`, `task_id`, `model_used`, `task_type`, `tokens_in`, `tokens_out`,
`latency_ms`, `success`.
