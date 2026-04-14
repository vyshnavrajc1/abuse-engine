"""
Abuse Engine LLM Client

Thin wrapper around any OpenAI-compatible endpoint.
Primary target: Ollama (http://localhost:11434/v1) running qwen2.5:7b.
Can target any other OpenAI-compatible server (vLLM, LM Studio, actual
OpenAI, Groq, etc.) by changing base_url + model.

Usage:
    from engine.llm.client import LLMClient

    client = LLMClient(
        base_url="http://localhost:11434/v1",
        model="qwen2.5:7b",
    )
    result = client.reason(system_prompt="...", user_prompt="...")
    # result is a dict (parsed from LLM's JSON output)
"""

from __future__ import annotations
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LLMClient
# ---------------------------------------------------------------------------

class LLMClient:
    """
    Calls any OpenAI-compatible chat endpoint and returns parsed JSON.

    The LLM is always asked to return a JSON object (response_format enforced).
    If the model doesn't support response_format, set force_json=False and the
    client will attempt best-effort JSON extraction from the raw response.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        model: str = "qwen2.5:7b",
        api_key: str = "ollama",          # Ollama ignores the key; vLLM may need "EMPTY"
        temperature: float = 0.1,         # low temp = consistent structured output
        timeout: float = 60.0,
        force_json: bool = True,          # use response_format=json_object if supported
    ):
        try:
            from openai import OpenAI
        except ImportError as e:
            raise ImportError(
                "openai package is required. Install with: pip install openai"
            ) from e

        self.model = model
        self.temperature = temperature
        self.force_json = force_json
        self._client = OpenAI(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
        )
        logger.info("[LLMClient] Initialised — model=%s endpoint=%s", model, base_url)

    # ── Public interface ───────────────────────────────────────────────────

    def reason(
        self,
        system_prompt: str,
        user_prompt: str,
        extra_temperature: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Send a system + user message pair and return a parsed JSON dict.

        Raises:
            LLMError: if the API call fails or the response can't be parsed.
        """
        temp = extra_temperature if extra_temperature is not None else self.temperature
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            "temperature": temp,
        }
        if self.force_json:
            kwargs["response_format"] = {"type": "json_object"}

        try:
            response = self._client.chat.completions.create(**kwargs)
            raw = response.choices[0].message.content or ""
            return self._parse_json(raw)
        except Exception as exc:
            raise LLMError(f"LLM call failed: {exc}") from exc

    def is_available(self) -> bool:
        """Probe the endpoint with a minimal request. Returns False on any error."""
        try:
            self._client.models.list()
            return True
        except Exception:
            return False

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_json(raw: str) -> Dict[str, Any]:
        raw = raw.strip()
        if not raw:
            raise LLMError("LLM returned empty response")
        # Try direct parse first
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
        # Fallback: extract first {...} block
        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start != -1 and end > start:
            try:
                return json.loads(raw[start:end])
            except json.JSONDecodeError:
                pass
        raise LLMError(f"Could not parse JSON from LLM response: {raw[:200]}")


class LLMError(Exception):
    """Raised when the LLM client cannot produce a usable response."""
