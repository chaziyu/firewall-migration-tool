import json

import pytest
import requests

from fwmigrate.ai.config import AISettings, get_ai_settings
from fwmigrate.ai.errors import AIConfigurationError, AIInvalidResponseError, AIProviderError, AIRateLimitError, AITimeoutError
from fwmigrate.ai.groq import GroqProvider


class Response:
    status_code = 200
    def __init__(self, data): self.data = data
    def json(self): return self.data


class Session:
    def __init__(self, response): self.response, self.kwargs = response, None
    def post(self, url, **kwargs): self.kwargs = (url, kwargs); return self.response


def test_ai_is_disabled_by_default_and_key_is_not_a_setting(monkeypatch):
    monkeypatch.delenv("AI_ASSIST_ENABLED", raising=False)
    settings = get_ai_settings()
    assert settings.enabled is True
    assert settings.provider == "local"
    assert settings.local_model == "qwen3-1.7b-q4_k_m"
    assert "api_key" not in settings.__dataclass_fields__


def test_groq_sends_strict_schema_with_timeout_and_extracts_usage():
    session = Session(Response({"id": "req-1", "choices": [{"message": {"content": '{"ok":true}'}}],
                               "usage": {"prompt_tokens": 12, "completion_tokens": 4}}))
    result = GroqProvider(AISettings(enabled=True), api_key="secret-value", session=session).generate_structured(
        system_prompt="rules", payload={"data": "safe"}, schema_name="result",
        schema={"type": "object", "additionalProperties": False})
    url, request = session.kwargs
    assert url == "https://api.groq.com/openai/v1/chat/completions"
    assert request["timeout"] == 30
    assert request["headers"]["Authorization"] == "Bearer secret-value"
    assert request["json"]["response_format"]["json_schema"]["strict"] is True
    assert json.loads(request["json"]["messages"][1]["content"]) == {"data": "safe"}
    assert (result.data, result.input_tokens, result.output_tokens) == ({"ok": True}, 12, 4)


@pytest.mark.parametrize("status,error", [(429, AIRateLimitError), (504, AITimeoutError), (500, AIProviderError)])
def test_groq_normalizes_http_errors(status, error):
    response = Response({}); response.status_code = status
    with pytest.raises(error) as caught:
        GroqProvider(AISettings(enabled=True), api_key="secret-value", session=Session(response)).generate_structured(
            system_prompt="", payload={}, schema_name="s", schema={})
    assert "secret-value" not in str(caught.value)


def test_groq_rejects_missing_key_timeout_and_malformed_json():
    with pytest.raises(AIConfigurationError):
        GroqProvider(AISettings(enabled=True), api_key="", session=Session(Response({}))).generate_structured(
            system_prompt="", payload={}, schema_name="s", schema={})

    class TimeoutSession:
        def post(self, *args, **kwargs): raise requests.Timeout("secret-value")
    with pytest.raises(AITimeoutError) as caught:
        GroqProvider(AISettings(enabled=True), api_key="secret-value", session=TimeoutSession()).generate_structured(
            system_prompt="", payload={}, schema_name="s", schema={})
    assert "secret-value" not in str(caught.value)

    with pytest.raises(AIInvalidResponseError):
        GroqProvider(AISettings(enabled=True), api_key="x", session=Session(Response({"choices": []}))).generate_structured(
            system_prompt="", payload={}, schema_name="s", schema={})
