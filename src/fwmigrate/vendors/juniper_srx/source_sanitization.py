"""Sanitize copied Juniper source state before reporting."""

from typing import Any
from fwmigrate.extraction.sanitize import sanitize_raw_text


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_raw_text(value)
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize(item) for key, item in value.items()}
    fields = getattr(type(value), "model_fields", None)
    if fields is not None:
        for name in fields:
            setattr(value, name, _sanitize(getattr(value, name)))
    return value


