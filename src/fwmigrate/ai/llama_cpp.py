"""llama.cpp implementation of the application structured-generation contract."""

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .config import AISettings
from .errors import AIInvalidResponseError, AIProviderError, AIRateLimitError, AITimeoutError
from .provider import AIStructuredResult


class LlamaCppProvider:
    def __init__(self, settings: AISettings, *, runtime_manager):
        self.settings = settings
        self.runtime_manager = runtime_manager

    def generate_structured(self, *, system_prompt, payload, schema_name, schema):
        runtime = self.runtime_manager.ensure_ready()
        body = {"model": runtime.model_id,
                "messages": [{"role": "system", "content": system_prompt},
                             {"role": "user", "content": json.dumps(payload, ensure_ascii=False, separators=(",", ":"))}],
                "temperature": 0.3,
                "max_tokens": 500 if payload.get("operation") == "explain" else 700,
                "response_format": {"type": "json_schema", "json_schema": {
                    "name": schema_name, "strict": True, "schema": schema}}}
        request = Request(runtime.base_url + "/v1/chat/completions", data=json.dumps(body).encode(),
                          headers={"Authorization": f"Bearer {runtime.api_key}",
                                   "Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(request, timeout=self.settings.local_timeout_seconds) as response:
                result = json.loads(response.read())
        except json.JSONDecodeError as exc:
            raise AIInvalidResponseError("Local AI returned an invalid structured response") from exc
        except HTTPError as exc:
            if exc.code == 429:
                raise AIRateLimitError("Local AI request was rate limited") from exc
            if exc.code in {502, 503, 504}:
                raise AITimeoutError("Local AI runtime is temporarily unavailable") from exc
            raise AIProviderError("Local AI request failed") from exc
        except TimeoutError as exc:
            raise AITimeoutError("Local AI request timed out") from exc
        except (URLError, OSError) as exc:
            raise AIProviderError("Local AI request failed") from exc
        try:
            content = result["choices"][0]["message"]["content"]
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ValueError
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            raise AIInvalidResponseError("Local AI returned an invalid structured response") from exc
        usage = result.get("usage") or {}
        return AIStructuredResult(data, "local", self.settings.local_model, result.get("id"),
                                  usage.get("prompt_tokens"), usage.get("completion_tokens"))
