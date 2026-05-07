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

### 4 — Start the server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000` in your browser.

### 5 — Run a scan (API)

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "openapi_yaml": "<paste spec here>",
    "base_url": "http://target-api:8080",
    "auth_type": "bearer",
    "credentials": {"token": "eyJ..."},
    "context": "Internal staging API, user roles: admin/user",
    "owasp_categories": ["API1", "API2", "API6", "API8"]
  }'
```

---

## Docker

```bash
docker compose up --build
```

This starts both Ollama and ARIA. Pull models into the running container:

```bash
docker exec -it aria_ollama_1 \
  ollama pull hf.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q8_0-GGUF
```

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
app/          FastAPI entry point, routers, schemas, static UI
core/llm/     LLMClient — unified SLM interface with retry/fallback
core/parser/  OpenAPI YAML parser + endpoint enricher
core/coordinator/  Scan planner (LLM-based + rule-based fallback)
core/agents/  Per-OWASP-category attack agents (same SLM, diff prompts)
core/payload_factory/  Deterministic payload builder + exploit modules
core/http_engine/      Async HTTP client with auth injection
core/validator/        Rule-based + SLM-assisted finding validation
core/rag/              ChromaDB vector store for OWASP knowledge
core/reporter/         HTML + Markdown report generation
benchmarks/   Academic evaluation scripts and metrics
data/owasp/   OWASP API Top 10 markdown (RAG knowledge base)
```

---

## Academic benchmarking

```bash
python benchmarks/run_benchmark.py --target http://localhost:5000 \
  --spec tests/fixtures/vampi_openapi.yaml
```

Metrics logged per scan to `benchmarks/runs/{scan_id}.jsonl`:
`timestamp`, `task_id`, `model_used`, `tokens_in`, `tokens_out`,
`latency_ms`, `success`.
