"""Helpers for retaining safe FortiGate source attributes during extraction."""

from functools import cache
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
    "psksecret_remote",
    "authpasswd",
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
    "keytab",
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

NON_SECRET_CREDENTIAL_METADATA = frozenset({
    "passwd_time",
    "has_password",
    "has_psk",
    "has_auth_password",
    "has_group_authentication_secret",
    "has_ppk_secret",
    "has_private_key",
})


def sanitize_source_attributes(
    attributes: Mapping[str, Any],
) -> Dict[str, Any]:
    """
    Retain explicitly configured FortiGate source fields while
    redacting credential or secret-like values.

    Keys are normalized to underscore form before being stored so
    source settings remain consistent with parser attribute naming.
    """

    return {
        _normalize_source_key(key): sanitize_source_value(key, value)
        for key, value in attributes.items()
    }


def sanitize_source_value(
    key: str,
    value: Any,
) -> Any:
    """Redact one source value using the shared source-key policy."""

    normalized_key = _normalize_source_key(key)

    classification = _classify_source_key(normalized_key)
    if classification == 1:
        return value
    if classification == 2:
        return "[REDACTED]"

    return value


def _normalize_source_key(key: str) -> str:
    return str(key).lower().replace("-", "_")


@cache
def _classify_source_key(normalized_key: str) -> int:
    if normalized_key in NON_SECRET_CREDENTIAL_METADATA:
        return 1
    if (
        normalized_key in _SENSITIVE_EXACT_KEYS
        or normalized_key.endswith(_SENSITIVE_KEY_SUFFIXES)
    ):
        return 2
    return 0
