"""Unified LLM client for ARIA.

Routes calls to the appropriate Cisco Foundation-Sec model based on task type,
enforces JSON output, handles retries, and automatically escalates to the
fallback model (Qwen2.5:7b) after three consecutive JSON-parse failures.
"""
from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
import ollama

_EventCB = Callable[[str, dict], Awaitable[None]]

logger = logging.getLogger(__name__)

_JSON_SYSTEM = (
    "You are a security testing assistant. "
    "Always respond with valid JSON only. "
    "No markdown fences, no text outside the JSON object or array."
)


class LLMClient:
    """Unified interface for all SLM calls in ARIA.

    Three public methods map to three model tiers:
      - reason()   → Foundation-Sec-8B-Reasoning  (coordinator, agents)
      - instruct() → Foundation-Sec-1.1-8B-Instruct (validator, reporter)
      - fallback() → qwen2.5:7b                    (JSON-parse recovery)

    All methods always return a dict. On total failure they return
    {"error": "<reason>"} — they never raise.
    """

    def __init__(
        self,
        config_path: str = "config.yaml",
        scan_id: str | None = None,
        scan_mode: str | None = None,
    ) -> None:
        with open(config_path) as fh:
            cfg = yaml.safe_load(fh)

        llm = cfg["llm"]
        self._max_retries: int = llm["max_retries"]
        self._base_url: str = llm["base_url"]

        rm = llm["reasoning_model"]
        self._reasoning_model: str = rm["name"]
        self._reasoning_opts: dict = {
            "temperature": rm["temperature"],
            "num_predict": rm["max_tokens"],
        }

        im = llm["instruct_model"]
        self._instruct_model: str = im["name"]
        self._instruct_opts: dict = {
            "temperature": im["temperature"],
            "num_predict": im["max_tokens"],
        }

        fm = llm["fallback_model"]
        self._fallback_model: str = fm["name"]
        self._fallback_opts: dict = {
            "temperature": fm["temperature"],
            "num_predict": fm["max_tokens"],
        }

        self._client = ollama.AsyncClient(host=self._base_url)

        self.scan_id: str | None = scan_id
        self._usage_log: list[dict] = []
        self._event_cb: _EventCB | None = None

        bench = cfg.get("benchmarking", {})
        self._log_dir = Path(bench.get("log_path", "./benchmarks/runs/"))

        scan_cfg = cfg.get("scan", {})
        self._scan_mode: str = scan_mode or scan_cfg.get("mode", "fast")
        self._scan_modes: dict = scan_cfg.get("modes", {})

    # ── Public API ────────────────────────────────────────────────────────── #

    async def reason(
        self,
        prompt: str,
        context: dict | None = None,
        task_id: str = "",
    ) -> dict:
        """Call Foundation-Sec-Reasoning for coordinator and agent decisions."""
        return await self._dispatch(
            self._reasoning_model,
            self._reasoning_opts,
            prompt,
            context,
            task_id,
            task_type="reason",
            allow_fallback=True,
        )

    async def instruct(
        self,
        prompt: str,
        context: dict | None = None,
        task_id: str = "",
    ) -> dict:
        """Call Foundation-Sec-Instruct for validator and reporter tasks."""
        return await self._dispatch(
            self._instruct_model,
            self._instruct_opts,
            prompt,
            context,
            task_id,
            task_type="instruct",
            allow_fallback=True,
        )

    async def fallback(
        self,
        prompt: str,
        context: dict | None = None,
        task_id: str = "",
    ) -> dict:
        """Call Qwen2.5:7b as last-resort fallback. No further escalation."""
        return await self._dispatch(
            self._fallback_model,
            self._fallback_opts,
            prompt,
            context,
            task_id,
            task_type="fallback",
            allow_fallback=False,
        )

    def set_scan_id(self, scan_id: str) -> None:
        """Attach a scan ID so usage is appended to benchmarks/runs/{scan_id}.jsonl."""
        self.scan_id = scan_id

    def set_event_cb(self, cb: _EventCB) -> None:
        """Wire an SSE emitter so LLM calls appear in the live scan log."""
        self._event_cb = cb

    def should_use_llm_for_agents(self, task_priority: int = 2) -> bool:
        """Return True if the current scan mode calls for LLM agent decisions."""
        agents_llm = self._scan_modes.get(self._scan_mode, {}).get("agents_use_llm", False)
        if agents_llm is False:
            return False
        if agents_llm is True:
            return True
        if agents_llm == "priority_only":
            return task_priority == 1
        return False

    def should_use_llm_for_validator(self) -> bool:
        """Return True if the current scan mode calls for SLM validation."""
        return bool(self._scan_modes.get(self._scan_mode, {}).get("validator_uses_llm", False))

    def get_usage_log(self) -> list[dict]:
        """Return a copy of the in-memory usage log accumulated by this instance."""
        return list(self._usage_log)

    # ── Internal ──────────────────────────────────────────────────────────── #

    async def _emit_llm(self, data: dict) -> None:
        if self._event_cb:
            try:
                await self._event_cb("llm_call", data)
            except Exception:  # noqa: BLE001
                pass

    async def _dispatch(
        self,
        model: str,
        options: dict,
        prompt: str,
        context: dict | None,
        task_id: str,
        task_type: str,
        allow_fallback: bool,
    ) -> dict:
        """Core retry loop shared by all three public methods.

        Escalates to fallback() when json_fails reaches max_retries and
        allow_fallback is True.  On exhaustion with allow_fallback=False,
        returns {"error": "..."}.
        """
        full_prompt = self._build_prompt(prompt, context)
        json_fails = 0

        await self._emit_llm({"status": "calling", "model": model, "task_id": task_id, "phase": task_type})

        for attempt in range(self._max_retries):
            t0 = time.monotonic()
            try:
                raw = await self._client.chat(
                    model=model,
                    messages=[
                        {"role": "system", "content": _JSON_SYSTEM},
                        {"role": "user", "content": full_prompt},
                    ],
                    options=options,
                    format="json",
                )
                elapsed = (time.monotonic() - t0) * 1000
                content = self._extract_content(raw)
                tokens_in, tokens_out = self._extract_tokens(raw)

                parsed = self._parse_json(content)
                if parsed is not None:
                    self._record(task_id, model, task_type, tokens_in, tokens_out, elapsed, True)
                    await self._emit_llm({
                        "status": "done", "model": model, "task_id": task_id,
                        "phase": task_type, "elapsed_ms": round(elapsed),
                        "tokens_in": tokens_in, "tokens_out": tokens_out,
                    })
                    return parsed

                json_fails += 1
                self._record(
                    task_id, model, task_type, tokens_in, tokens_out, elapsed,
                    False, reason="json_parse_failed",
                )
                logger.warning(
                    "JSON parse failed (attempt %d/%d, total_json_fails=%d) "
                    "task=%s model=%s",
                    attempt + 1, self._max_retries, json_fails, task_id, model,
                )
                if json_fails >= self._max_retries and allow_fallback:
                    logger.warning(
                        "Escalating to fallback after %d JSON failures. task=%s primary=%s",
                        json_fails, task_id, model,
                    )
                    await self._emit_llm({
                        "status": "fallback", "model": model, "task_id": task_id,
                        "phase": task_type, "fallback_to": self._fallback_model,
                        "reason": f"{json_fails} JSON parse failures",
                    })
                    return await self.fallback(prompt, context, task_id)

            except Exception as exc:  # noqa: BLE001
                elapsed = (time.monotonic() - t0) * 1000
                self._record(task_id, model, task_type, 0, 0, elapsed, False, reason=str(exc))
                logger.error(
                    "LLM call error (attempt %d/%d) task=%s model=%s: %s",
                    attempt + 1, self._max_retries, task_id, model, exc,
                )
                await self._emit_llm({
                    "status": "error", "model": model, "task_id": task_id,
                    "phase": task_type, "elapsed_ms": round(elapsed), "error": str(exc),
                })

        if allow_fallback:
            logger.warning(
                "All %d attempts exhausted; escalating to fallback. task=%s model=%s",
                self._max_retries, task_id, model,
            )
            await self._emit_llm({
                "status": "fallback", "model": model, "task_id": task_id,
                "phase": task_type, "fallback_to": self._fallback_model,
                "reason": "all attempts exhausted",
            })
            return await self.fallback(prompt, context, task_id)

        return {"error": f"All attempts failed for task '{task_id}' using {model}"}

    # ── Static helpers ────────────────────────────────────────────────────── #

    @staticmethod
    def _build_prompt(prompt: str, context: dict | None) -> str:
        if not context:
            return prompt
        return f"{prompt}\n\nAdditional context:\n{json.dumps(context, indent=2)}"

    @staticmethod
    def _extract_content(response: Any) -> str:
        try:
            return response.message.content
        except AttributeError:
            return response["message"]["content"]

    @staticmethod
    def _extract_tokens(response: Any) -> tuple[int, int]:
        try:
            return (
                getattr(response, "prompt_eval_count", 0) or 0,
                getattr(response, "eval_count", 0) or 0,
            )
        except Exception:  # noqa: BLE001
            try:
                return (
                    response.get("prompt_eval_count", 0) or 0,
                    response.get("eval_count", 0) or 0,
                )
            except Exception:  # noqa: BLE001
                return 0, 0

    @staticmethod
    def _parse_json(content: str) -> dict | list | None:
        """Extract a JSON object or array from the model's raw text output.

        Handles markdown fences (```json ... ```) and salvages JSON embedded
        in surrounding prose via regex as a last resort.
        """
        text = content.strip()

        # Strip ```json…``` or ```…``` fences
        if text.startswith("```"):
            lines = text.splitlines()
            inner = lines[1:]
            if inner and inner[-1].strip() == "```":
                inner = inner[:-1]
            text = "\n".join(inner).strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Salvage a JSON object or array embedded in surrounding text
        for pattern in (r"(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})", r"(\[.*\])"):
            m = re.search(pattern, text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(1))
                except json.JSONDecodeError:
                    continue

        return None

    def _record(
        self,
        task_id: str,
        model: str,
        task_type: str,
        tokens_in: int,
        tokens_out: int,
        latency_ms: float,
        success: bool,
        reason: str = "",
    ) -> None:
        entry: dict = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "task_id": task_id,
            "model_used": model,
            "task_type": task_type,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "latency_ms": round(latency_ms, 1),
            "success": success,
        }
        if reason:
            entry["reason"] = reason

        self._usage_log.append(entry)

        if self.scan_id:
            log_file = self._log_dir / f"{self.scan_id}.jsonl"
            log_file.parent.mkdir(parents=True, exist_ok=True)
            with log_file.open("a") as fh:
                fh.write(json.dumps(entry) + "\n")
