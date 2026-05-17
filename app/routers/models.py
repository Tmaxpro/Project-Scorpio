"""FastAPI router — LLM model configuration management."""
from __future__ import annotations

import logging
from enum import Enum
from pathlib import Path

import yaml
import ollama

from fastapi import APIRouter, HTTPException

from app.schemas.models import (
    AvailableModelsResponse,
    ModelConfig,
    ModelUpdateRequest,
    ModelUpdateResponse,
    ModelsResponse,
    OllamaModelInfo,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/models", tags=["models"])

CONFIG_PATH = Path("config.yaml")

VALID_ROLES = ("reasoning_model", "instruct_model", "fallback_model")


class ModelRole(str, Enum):
    reasoning_model = "reasoning_model"
    instruct_model = "instruct_model"
    fallback_model = "fallback_model"


# ── Helpers ──────────────────────────────────────────────────────────────────


def _read_config() -> dict:
    """Read and return the full config.yaml as a dict."""
    with CONFIG_PATH.open() as fh:
        return yaml.safe_load(fh)


def _write_config(cfg: dict) -> None:
    """Persist the config dict back to config.yaml."""
    with CONFIG_PATH.open("w") as fh:
        yaml.dump(cfg, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)


def _model_cfg_to_schema(role: str, raw: dict) -> ModelConfig:
    """Convert a raw config dict section to a ModelConfig schema."""
    return ModelConfig(
        name=raw["name"],
        temperature=raw.get("temperature", 0.2),
        max_tokens=raw.get("max_tokens", 2048),
        use_for=raw.get("use_for", []),
    )


def _format_size(size_bytes: int) -> str:
    """Format bytes into a human-readable string."""
    if size_bytes <= 0:
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.get("", response_model=ModelsResponse)
async def get_models_config() -> ModelsResponse:
    """Return the current LLM model configuration."""
    try:
        cfg = _read_config()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read config: {exc}")

    llm = cfg.get("llm", {})
    models: dict[str, ModelConfig] = {}
    for role in VALID_ROLES:
        raw = llm.get(role)
        if raw:
            models[role] = _model_cfg_to_schema(role, raw)

    return ModelsResponse(
        provider=llm.get("provider", "ollama"),
        base_url=llm.get("base_url", "http://localhost:11434"),
        max_retries=llm.get("max_retries", 3),
        models=models,
    )


@router.put("/{role}", response_model=ModelUpdateResponse)
async def update_model(role: ModelRole, body: ModelUpdateRequest) -> ModelUpdateResponse:
    """Update the model assigned to a given role.

    Persists the change to config.yaml immediately.
    """
    try:
        cfg = _read_config()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read config: {exc}")

    llm = cfg.get("llm", {})
    existing = llm.get(role.value)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Role '{role.value}' not found in config")

    # Preserve use_for from existing config
    use_for = existing.get("use_for", [])

    # Update the model entry
    llm[role.value] = {
        "name": body.name,
        "temperature": body.temperature,
        "max_tokens": body.max_tokens,
    }
    if use_for:
        llm[role.value]["use_for"] = use_for

    cfg["llm"] = llm

    try:
        _write_config(cfg)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to write config: {exc}")

    updated = ModelConfig(
        name=body.name,
        temperature=body.temperature,
        max_tokens=body.max_tokens,
        use_for=use_for,
    )

    logger.info("Model role '%s' updated to '%s'", role.value, body.name)

    return ModelUpdateResponse(
        role=role.value,
        model=updated,
        message=f"Model for '{role.value}' updated to '{body.name}'",
    )


@router.get("/available", response_model=AvailableModelsResponse)
async def get_available_models() -> AvailableModelsResponse:
    """List models currently available on the local Ollama instance."""
    try:
        cfg = _read_config()
        base_url = cfg.get("llm", {}).get("base_url", "http://localhost:11434")
        client = ollama.Client(host=base_url)
        response = client.list()

        models: list[OllamaModelInfo] = []
        model_list = getattr(response, "models", None) or response.get("models", []) if isinstance(response, dict) else []

        for m in model_list:
            # Handle both object-style and dict-style responses
            if hasattr(m, "model"):
                name = m.model or getattr(m, "name", "")
            elif isinstance(m, dict):
                name = m.get("model", m.get("name", ""))
            else:
                name = str(m)

            details = getattr(m, "details", None) or (m.get("details", {}) if isinstance(m, dict) else {})
            if hasattr(details, "parameter_size"):
                param_size = details.parameter_size or ""
                quant = details.quantization_level or ""
            elif isinstance(details, dict):
                param_size = details.get("parameter_size", "")
                quant = details.get("quantization_level", "")
            else:
                param_size = ""
                quant = ""

            size_val = getattr(m, "size", 0) if hasattr(m, "size") else (m.get("size", 0) if isinstance(m, dict) else 0)
            modified = ""
            if hasattr(m, "modified_at"):
                modified = str(m.modified_at) if m.modified_at else ""
            elif isinstance(m, dict):
                modified = str(m.get("modified_at", ""))

            models.append(OllamaModelInfo(
                name=name,
                size=_format_size(int(size_val) if size_val else 0),
                parameter_size=param_size,
                quantization=quant,
                modified_at=modified,
            ))

        return AvailableModelsResponse(models=models)

    except Exception as exc:
        logger.error("Failed to list Ollama models: %s", exc)
        raise HTTPException(
            status_code=503,
            detail=f"Cannot reach Ollama server: {exc}",
        )
