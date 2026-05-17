"""ARIA FastAPI web application."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.routers.benchmarks import router as benchmarks_router
from app.routers.scan import router as scan_router

app = FastAPI(
    title="ARIA — Autonomous REST API Intelligence Agent",
    description=(
        "Local multi-agent REST API pentesting system targeting "
        "OWASP API Security Top 10"
    ),
    version="0.1.0",
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


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse(url="/static/index.html")


@app.get("/health", tags=["meta"])
async def health() -> dict:
    return {"status": "ok", "service": "ARIA"}
