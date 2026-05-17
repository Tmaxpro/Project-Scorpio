"""Pydantic schemas for model configuration endpoints."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

ModelRole = Literal["reasoning_model", "instruct_model", "fallback_model"]


class ModelConfig(BaseModel):
    name: str
    temperature: float
    max_tokens: int
    use_for: list[str] = Field(default_factory=list)


class ModelsResponse(BaseModel):
    provider: str
    base_url: str
    max_retries: int
    models: dict[ModelRole, ModelConfig]


class ModelUpdateRequest(BaseModel):
    name: str
    temperature: float = Field(ge=0.0, le=2.0)
    max_tokens: int = Field(ge=128, le=32768)


class ModelUpdateResponse(BaseModel):
    role: ModelRole
    model: ModelConfig
    message: str


class OllamaModelInfo(BaseModel):
    name: str
    size: str
    parameter_size: str
    quantization: str
    modified_at: str


class AvailableModelsResponse(BaseModel):
    models: list[OllamaModelInfo]


class RunningModelInfo(BaseModel):
    name: str
    size_vram: str
    expires_at: str


class RunningModelsResponse(BaseModel):
    models: list[RunningModelInfo]


class UnloadRequest(BaseModel):
    name: str


class UnloadResponse(BaseModel):
    name: str
    message: str
