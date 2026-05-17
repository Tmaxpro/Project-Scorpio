"""Model configuration router — dynamic SLM assignment via /api/models."""
from __future__ import annotations

import os
from pathlib import Path

import httpx
import yaml
from fastapi import APIRouter, HTTPException

from app.schemas.models import (
    AvailableModelsResponse,
    ModelConfig,
    ModelRole,
    ModelUpdateRequest,
    ModelUpdateResponse,
    ModelsResponse,
    OllamaModelInfo,
)

router = APIRouter(prefix="/api/models", tags=["models"])

_CONFIG_PATH = Path(os.environ.get("ARIA_CONFIG", "config.yaml"))

_ROLE_KEYS: list[ModelRole] = ["reasoning_model", "instruct_model", "fallback_model"]


def _load_config() -> dict:
    with _CONFIG_PATH.open() as fh:
        return yaml.safe_load(fh)


def _save_config(cfg: dict) -> None:
    with _CONFIG_PATH.open("w") as fh:
        yaml.dump(cfg, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)


def _model_config_from_yaml(raw: dict) -> ModelConfig:
    return ModelConfig(
        name=raw["name"],
        temperature=raw["temperature"],
        max_tokens=raw["max_tokens"],
        use_for=raw.get("use_for", []),
    )


@router.get("", response_model=ModelsResponse)
async def get_models_config() -> ModelsResponse:
    """Return the current model-role assignments from config.yaml."""
    cfg = _load_config()
    llm = cfg["llm"]
    return ModelsResponse(
        provider=llm.get("provider", "ollama"),
        base_url=llm.get("base_url", "http://localhost:11434"),
        max_retries=llm.get("max_retries", 3),
        models={
            role: _model_config_from_yaml(llm[role])
            for role in _ROLE_KEYS
        },
    )


@router.put("/{role}", response_model=ModelUpdateResponse)
async def update_model(role: ModelRole, body: ModelUpdateRequest) -> ModelUpdateResponse:
    """Update the model name and inference parameters for a given pipeline role."""
    cfg = _load_config()
    llm = cfg["llm"]

    if role not in llm:
        raise HTTPException(status_code=404, detail=f"Role '{role}' not found in config")

    llm[role]["name"] = body.name
    llm[role]["temperature"] = body.temperature
    llm[role]["max_tokens"] = body.max_tokens

    _save_config(cfg)

    updated = _model_config_from_yaml(llm[role])
    return ModelUpdateResponse(
        role=role,
        model=updated,
        message=f"Updated {role} → {body.name}",
    )


@router.get("/available", response_model=AvailableModelsResponse)
async def get_available_models() -> AvailableModelsResponse:
    """Proxy Ollama's /api/tags to list locally available models."""
    cfg = _load_config()
    base_url = cfg["llm"].get("base_url", "http://localhost:11434").rstrip("/")

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(f"{base_url}/api/tags")
            resp.raise_for_status()
            data = resp.json()
    except httpx.ConnectError:
        raise HTTPException(
            status_code=502,
            detail=f"Cannot reach Ollama at {base_url} — is it running?",
        )
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"Ollama error: {exc.response.text}")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=str(exc))

    models: list[OllamaModelInfo] = []
    for m in data.get("models", []):
        details = m.get("details", {})
        size_bytes = m.get("size", 0)
        size_str = _fmt_bytes(size_bytes)
        models.append(
            OllamaModelInfo(
                name=m.get("name", ""),
                size=size_str,
                parameter_size=details.get("parameter_size", ""),
                quantization=details.get("quantization_level", ""),
                modified_at=m.get("modified_at", ""),
            )
        )

    return AvailableModelsResponse(models=models)


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
