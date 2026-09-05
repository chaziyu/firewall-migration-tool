import json
from pathlib import Path

from fwmigrate.parsers.checkpoint.extractor import extract_checkpoint_config


FIXTURES = Path(__file__).parent / "fixtures" / "checkpoint"
_SECRET_KEYS = {"password", "passphrase", "shared-secret", "sic-password", "private-key", "api-token", "session-id"}
_STATUSES = {"OK", "SUCCESS_WITH_DATA", "SUCCESS_EMPTY", "UNSUPPORTED_COMMAND", "PERMISSION_DENIED", "API_ERROR", "TRANSPORT_ERROR"}


def fixture(name):
    path = FIXTURES / name
    data = json.loads(path.read_text(encoding="utf-8"))
    if "responses" not in data:
        assert data.get("command")
        _assert_safe(data)
        return path, data
    assert isinstance(data["responses"], list)
    for response in data["responses"]:
        assert response.get("command")
        assert response.get("collection_status", "OK") in _STATUSES
        _assert_safe(response)
    return path, data


def extract_fixture(name):
    path, data = fixture(name)
    return path, extract_checkpoint_config(json.dumps(data, sort_keys=True))


def _assert_safe(value):
    if isinstance(value, dict):
        for key, child in value.items():
            assert str(key).lower() not in _SECRET_KEYS
            _assert_safe(child)
    elif isinstance(value, list):
        for child in value:
            _assert_safe(child)
