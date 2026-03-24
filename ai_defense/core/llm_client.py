from __future__ import annotations

import json
import logging
from typing import Any

from openai import OpenAI

from .config import LLMConfig

log = logging.getLogger("ai_defense.llm")


class LLMClient:
    """Thin wrapper around OpenAI-compatible chat completions (works with Ollama too)."""

    def __init__(self, cfg: LLMConfig) -> None:
        self._cfg = cfg
        self._client = OpenAI(
            api_key=cfg.resolve_api_key() or "ollama",
            base_url=cfg.resolve_base_url(),
            timeout=cfg.timeout,
        )

    def chat(self, system: str, user: str, temperature: float | None = None) -> str:
        resp = self._client.chat.completions.create(
            model=self._cfg.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature if temperature is not None else self._cfg.temperature,
        )
        if not resp.choices:
            log.warning("LLM returned empty choices")
            return ""
        return resp.choices[0].message.content or ""

    def chat_json(self, system: str, user: str, temperature: float | None = None) -> dict[str, Any]:
        raw = self.chat(system, user, temperature)
        raw = raw.strip().lstrip("\ufeff")
        if "```" in raw:
            lines = raw.splitlines()
            inside = False
            extracted = []
            for line in lines:
                if line.startswith("```"):
                    inside = not inside
                    continue
                if inside:
                    extracted.append(line)
            if extracted:
                raw = "\n".join(extracted)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            log.warning("LLM returned non-JSON: %s", raw[:300])
            return {"error": "invalid_json", "raw": raw}
