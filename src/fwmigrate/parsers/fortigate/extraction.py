"""Helpers for retaining safe FortiGate source attributes during extraction."""

from typing import Any, Dict, Mapping


_SENSITIVE_EXACT_KEYS = frozenset({
    "password",
    "passwd",
    "password_hash",
    "password2",
    "passwd_hash",
    "secret",
    "psk",
    "psksecret",
    "private_key",
    "seed",
    "activation_code",
    "community",
    "auth_key",
    "auth_pwd",
    "priv_pwd",
    "token",
    "api_key",
    "key",
    "key2",
    "key3",
    "key_string",
    "encryption_key",
    "authentication_key",
    "shared_secret",
    "radius_secret",
    "tacacs_secret",
    "secondary_key",
    "tertiary_key",
    "ddns_key",
})

_SENSITIVE_KEY_SUFFIXES = (
    "_password",
    "_passwd",
    "_secret",
    "_psk",
    "_psksecret",
    "_private_key",
    "_community",
    "_token",
    "_api_key",
    "_key_string",
    "_encryption_key",
    "_authentication_key",
    "_shared_secret",
    "_ddns_key",
)

NON_SECRET_CREDENTIAL_METADATA = frozenset({"passwd_time"})


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

        if normalized_key in NON_SECRET_CREDENTIAL_METADATA:
            sanitized[normalized_key] = value
        elif (
            normalized_key in _SENSITIVE_EXACT_KEYS
            or normalized_key.endswith(_SENSITIVE_KEY_SUFFIXES)
        ):
            sanitized[normalized_key] = "[REDACTED]"
        else:
            sanitized[normalized_key] = value

    return sanitized
