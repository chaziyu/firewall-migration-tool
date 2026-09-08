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
    "token",
    "credential",
    "certificate",
    "ssl_cert",
    "api_key",
)


def sanitize_source_attributes(attributes: Mapping[str, Any]) -> Dict[str, Any]:
    """Retain explicitly configured fields while removing credential values."""
    sanitized: Dict[str, Any] = {}
    for key, value in attributes.items():
        normalized_key = str(key).lower().replace("-", "_")
        if any(part in normalized_key for part in _SENSITIVE_SETTING_PARTS):
            sanitized[normalized_key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[normalized_key] = sanitize_source_attributes(value)
        elif isinstance(value, list):
            sanitized[normalized_key] = [sanitize_source_attributes(v) if isinstance(v, dict) else v for v in value]
        else:
            from fwmigrate.security.redaction import redact_sensitive
            sanitized[normalized_key] = redact_sensitive(value) if isinstance(value, str) else value
    return sanitized
