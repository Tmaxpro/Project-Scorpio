"""ARIA FastAPI web application."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.routers.benchmarks import router as benchmarks_router
from app.routers.models import router as models_router
from app.routers.scan import router as scan_router
from app import state

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Pre-load the embedding model once at startup so scans don't reload it."""
    import yaml
    from core.rag.owasp_rag import OWASPRag

    try:
        with open("config.yaml") as fh:
            cfg = yaml.safe_load(fh)
        chroma_dir = cfg.get("rag", {}).get("chroma_persist_dir", "./data/chroma")
        embedding_model = cfg.get("rag", {}).get("embedding_model", "all-MiniLM-L6-v2")
        docs_dir = "./data/owasp"

        logger.info("Pre-loading RAG embedding model '%s'…", embedding_model)
        rag = OWASPRag(persist_dir=chroma_dir, embedding_model=embedding_model)
        rag.index_documents(docs_dir)
        state.owasp_rag = rag
        logger.info("RAG ready — %d OWASP documents indexed", rag._collection.count() if rag._collection else 0)
    except Exception as exc:  # noqa: BLE001
        logger.warning("RAG pre-load failed (%s) — will retry at first scan", exc)

    yield


app = FastAPI(
    title="ARIA — Autonomous REST API Intelligence Agent",
    description=(
        "Local multi-agent REST API pentesting system targeting "
        "OWASP API Security Top 10"
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# Allow the Vite dev server (port 5173/5174) and Wrangler (8787) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_STATIC_DIR = Path(__file__).parent / "static"
_STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

app.include_router(scan_router)
app.include_router(benchmarks_router)
app.include_router(models_router)


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/static/index.html")


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok", "service": "ARIA"}
