"""Helpers for retaining safe FortiGate source attributes during extraction."""

from functools import cache
import re
from typing import Any, Dict, Mapping

_FORTIOS_ENC_VALUE_RE = re.compile(r"^\s*ENC\s+[A-Za-z0-9+/=]{16,}\s*$")
_FORTIOS_ENC_TOKEN_RE = re.compile(r"^[A-Za-z0-9+/=]{16,}$")
_HISTORY_KEY_RE = re.compile(r"^history\d+$")


_SENSITIVE_EXACT_KEYS = frozenset({
    "password",
    "passphrase",
    "passwd",
    "password_hash",
    "password2",
    "password3",
    "password4",
    "password5",
    "passwd_hash",
    "history0",
    "history1",
    "history2",
    "history3",
    "history4",
    "history5",
    "history6",
    "history7",
    "history8",
    "history9",
    "uploadpass",
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
    "_passphrase",
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
    "passwd_policy",
    "password_policy",
    "password_configured",
    "psk_configured",
    "auth_password_configured",
    "group_authentication_secret_configured",
    "ppk_secret_configured",
    "private_key_configured",
    "ssh_key_configured",
    "keytab_configured",
    "secret_configured",
    "secondary_secret_configured",
    "tertiary_secret_configured",
    "logon_password_configured",
    "sso_password_configured",
    "seed_configured",
    "activation_code_configured",
    "community_configured",
    "auth_pwd_configured",
    "priv_pwd_configured",
    "passphrase_configured",
    "fortitoken",
    "has_password",
    "has_psk",
    "has_auth_password",
    "has_group_authentication_secret",
    "has_ppk_secret",
    "has_private_key",
})


def sanitize_source_attributes(
    attributes: Mapping[str, Any],
    *,
    preserve_keys: bool = False,
) -> Dict[str, Any]:
    """
    Retain explicitly configured FortiGate source fields while
    redacting credential or secret-like values.

    Keys are normalized to underscore form before being stored so
    source settings remain consistent with parser attribute naming.
    """

    return {
        (str(key) if preserve_keys else _normalize_source_key(key)):
            sanitize_source_value(key, value, preserve_keys=preserve_keys)
        for key, value in attributes.items()
    }


def sanitize_source_value(
    key: str,
    value: Any,
    *,
    preserve_keys: bool = False,
) -> Any:
    """Redact one source value using the shared source-key policy."""

    normalized_key = _normalize_source_key(key)

    classification = _classify_source_key(normalized_key)
    if classification == 1:
        return value
    if classification == 2:
        return "[REDACTED]"
    if isinstance(value, str):
        if _FORTIOS_ENC_VALUE_RE.match(value):
            return "[REDACTED]"
        return value
    if isinstance(value, dict):
        return sanitize_source_attributes(value, preserve_keys=preserve_keys)
    if isinstance(value, list):
        if (
            len(value) == 2
            and value[0] == "ENC"
            and isinstance(value[1], str)
            and _FORTIOS_ENC_TOKEN_RE.match(value[1])
        ):
            return "[REDACTED]"
        return [
            "[REDACTED]"
            if isinstance(item, str) and _FORTIOS_ENC_VALUE_RE.match(item)
            else sanitize_source_attributes(item, preserve_keys=preserve_keys)
            if isinstance(item, (dict, Mapping))
            else item
            for item in value
        ]
    if isinstance(value, Mapping):
        return sanitize_source_attributes(value, preserve_keys=preserve_keys)
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
        or _HISTORY_KEY_RE.fullmatch(normalized_key) is not None
    ):
        return 2
    return 0
