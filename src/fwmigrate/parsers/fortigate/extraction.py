"""Helpers for retaining safe FortiGate source attributes during extraction."""

from typing import Any, Dict, Mapping


_SENSITIVE_SETTING_PARTS = (
    "password",
    "passwd",
    "secret",
    "psk",
    "psksecret",
    "private_key",
    "community",
    "auth_key",
    "token",
    "api_key",
)


def sanitize_source_attributes(
    attributes: Mapping[str, Any],
) -> Dict[str, Any]:
    """
    Retain explicitly configured FortiGate source fields while
    redacting credential or secret-like values.

    Keys are normalized to underscore form before being stored so
    source settings remain consistent with parser attribute naming.
    """

    sanitized: Dict[str, Any] = {}

    for key, value in attributes.items():
        normalized_key = (
            str(key)
            .lower()
            .replace("-", "_")
        )

        if any(
            part in normalized_key
            for part in _SENSITIVE_SETTING_PARTS
        ):
            sanitized[normalized_key] = "[REDACTED]"
        else:
            sanitized[normalized_key] = value

    return sanitized