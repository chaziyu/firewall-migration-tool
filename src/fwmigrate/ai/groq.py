"""Groq's OpenAI-compatible structured output endpoint."""

import json
import logging
import os
import time

import requests

from .config import AISettings
from .errors import AIConfigurationError, AIInvalidResponseError, AIProviderError, AIRateLimitError, AITimeoutError
from .provider import AIStructuredResult

_LOGGER = logging.getLogger(__name__)
_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"


class GroqProvider:
    def __init__(self, settings: AISettings, *, api_key=None, session=requests):
        self.settings = settings
        self._api_key = api_key if api_key is not None else os.environ.get("GROQ_API_KEY", "")
        self._session = session

    def generate_structured(self, *, system_prompt, payload, schema_name, schema):
        if not self._api_key:
            raise AIConfigurationError("AI assistance is not configured")
        body = {
            "model": self.settings.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False, separators=(",", ":"))},
            ],
            "reasoning_effort": self.settings.reasoning_effort,
            "response_format": {"type": "json_schema", "json_schema": {
                "name": schema_name, "strict": True, "schema": schema,
            }},
        }
        started = time.perf_counter()
        try:
            response = self._session.post(
                _ENDPOINT,
                headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
                json=body,
                timeout=self.settings.timeout_seconds,
            )
        except requests.Timeout as exc:
            raise AITimeoutError("AI provider request timed out") from exc
        except requests.RequestException as exc:
            raise AIProviderError("AI provider request failed") from exc
        status = response.status_code
        if status == 429:
            raise AIRateLimitError("AI provider rate limit reached")
        if status == 504:
            raise AITimeoutError("AI provider request timed out")
        if status < 200 or status >= 300:
            _LOGGER.info("AI provider failure provider=groq model=%s status_class=%s duration_ms=%d",
                         self.settings.model, status // 100, int((time.perf_counter() - started) * 1000))
            raise AIProviderError("AI provider request failed")
        try:
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError("structured response must be an object")
        except (ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError) as exc:
            raise AIInvalidResponseError("AI provider returned an invalid structured response") from exc
        usage = result.get("usage") or {}
        return AIStructuredResult(data, "groq", self.settings.model, result.get("id"),
                                  usage.get("prompt_tokens"), usage.get("completion_tokens"))
