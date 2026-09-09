"""Helpers for retaining safe FortiGate source attributes during extraction."""

from typing import Any, Dict, Mapping
from fwmigrate.security.redaction import redact_sensitive


_SENSITIVE_SETTING_PARTS = (
    "password",
    "passwd",
    "secret",
    "psksecret",
    "private_key",
    "community",
    "auth_key",
    "token",
    "credential",
    "certificate",
    "ssl_cert",
    "api_key",
)


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return sanitize_source_attributes(value)
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    return redact_sensitive(value) if isinstance(value, str) else value


def sanitize_source_attributes(attributes: Mapping[str, Any]) -> Dict[str, Any]:
    """Retain explicitly configured fields while removing credential values."""
    sanitized: Dict[str, Any] = {}
    for key, value in attributes.items():
        normalized_key = str(key).lower().replace("-", "_")
        if any(part in normalized_key for part in _SENSITIVE_SETTING_PARTS):
            sanitized[normalized_key] = "[REDACTED]"
        else:
            sanitized[normalized_key] = _sanitize_value(value)
    return sanitized
