"""Helpers for retaining safe FortiGate source attributes during extraction."""

from typing import Any, Dict, Mapping


_SENSITIVE_SETTING_PARTS = (
    "password",
    "passwd",
    "secret",
    "psksecret",
    "private_key",
    "community",
    "auth_key",
)


def sanitize_source_attributes(attributes: Mapping[str, Any]) -> Dict[str, Any]:
    """Retain explicitly configured fields while removing credential values."""
    sanitized: Dict[str, Any] = {}
    for key, value in attributes.items():
        normalized_key = str(key).lower().replace("-", "_")
        if any(part in normalized_key for part in _SENSITIVE_SETTING_PARTS):
            sanitized[normalized_key] = "[REDACTED]"
        else:
            sanitized[normalized_key] = value
    return sanitized
