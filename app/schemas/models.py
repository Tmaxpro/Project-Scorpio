"""Pydantic schemas for the ARIA model management API."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ModelConfig(BaseModel):
    """Configuration for a single LLM model."""

    name: str = Field(..., description="Ollama model name / tag")
    temperature: float = Field(0.2, ge=0.0, le=2.0)
    max_tokens: int = Field(2048, ge=128, le=16384)
    use_for: list[str] = Field(default_factory=list)


class ModelUpdateRequest(BaseModel):
    """Payload for updating a model assignment."""

    name: str = Field(..., min_length=1, description="Ollama model name / tag")
    temperature: float = Field(0.2, ge=0.0, le=2.0)
    max_tokens: int = Field(2048, ge=128, le=16384)


class ModelsResponse(BaseModel):
    """Full model configuration returned by GET /api/models."""

    provider: str
    base_url: str
    max_retries: int
    models: dict[str, ModelConfig]


class OllamaModelInfo(BaseModel):
    """Summary of a model available on the local Ollama instance."""

    name: str
    size: str = ""
    parameter_size: str = ""
    quantization: str = ""
    modified_at: str = ""


class AvailableModelsResponse(BaseModel):
    """List of models pulled on the Ollama server."""

    models: list[OllamaModelInfo]


class ModelUpdateResponse(BaseModel):
    """Response after a successful model update."""

    role: str
    model: ModelConfig
    message: str = "Model updated successfully"
