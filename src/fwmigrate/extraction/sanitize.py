"""Centralized secret sanitization for configuration evidence and extraction metadata."""

from __future__ import annotations

import re
from typing import Any, Dict

SENSITIVE_KEY_PREFIXES = (
    "password",
    "passphrase",
    "password-hash",
    "password_hash",
    "phash",
    "api-key",
    "api_key",
    "apikey",
    "sid",
    "token",
    "set-cookie",
    "x-chkp-sid",
    "shared-secret",
    "shared_secret",
    "secret",
    "private-key",
    "private_key",
    "privatekey",
    "psk",
    "pre-shared-key",
    "preshared-key",
    "community",
    "sic-name",
    "sic_name",
    "sic-password",
    "sic_password",
    "sic-key",
    "sic_key",
    "one-time-password",
    "one_time_password",
    "passcode",
    "ddns-key",
    "ddns_key",
    "agent-user-override-key",
    "agent_user_override_key",
    "newpass",
    "new-pass",
    "new-password",
    "key",
)

SENSITIVE_EXACT_KEYS = {
    "authorization",
    "cookie",
    "private-key-data", "private_key_data", "key-data", "key_data",
    "activation-key", "activation_key", "sic-password-hash", "sic_password_hash",
    "otp", "pkcs12-password", "pkcs12_password", "one-time-password",
    "one_time_password",
}

REDACTED_PLACEHOLDER = "[REDACTED]"


def is_sensitive_key(key: str) -> bool:
    """Check if a dictionary key name matches sensitive prefixes/names."""
    k = key.strip().lower().replace("_", "-")
    if k in {item.replace("_", "-") for item in SENSITIVE_EXACT_KEYS}:
        return True
    if k.startswith("private-key-") or k.startswith("sic-password-"):
        return True
    for prefix in SENSITIVE_KEY_PREFIXES:
        p = prefix.replace("_", "-")
        if k == p or k.startswith(f"{p}-") or k.startswith(f"{p}_") or k.endswith(f"-{p}") or k.endswith(f"_{p}"):
            return True
    return False


def sanitize_source_value(key: str, value: Any) -> Any:
    """Sanitize a value if its key is sensitive, or recursively sanitize dicts and lists."""
    if is_sensitive_key(key):
        return REDACTED_PLACEHOLDER

    if isinstance(value, dict):
        return sanitize_source_attributes(value)
    if isinstance(value, list):
        return [sanitize_source_value(key, item) for item in value]
    if isinstance(value, str) and key.strip().lower().replace("_", "-") in {
        "raw", "raw-command", "cli-text", "error", "command-output"
    }:
        return sanitize_raw_text(value)
    return value


def sanitize_source_attributes(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively sanitize a dictionary of source attributes."""
    if not isinstance(attrs, dict):
        return attrs

    return {key: sanitize_source_value(str(key), value) for key, value in attrs.items()}


def sanitize_raw_text(text: str) -> str:
    """Sanitize secrets in raw command output, Gaia lines, or config text."""
    if not text:
        return text

    text = re.sub(r"(?im)^(\s*(?:authorization|cookie|set-cookie|x-chkp-sid)\s*:\s*).+$",
                  rf"\1{REDACTED_PLACEHOLDER}", text)

    # Mask password hashes or cleartext in known CLI patterns (e.g. set user admin password-hash ...)
    key_pattern = (
        r"password(?:-hash)?|phash|one-time-password|passcode|shared-secret|sic-name|sic-password|"
        r"secret|key|password|login-password|common-password|bind-password|new-?pass(?:word)?|pre-?shared-key|preshared-key|private-key|api-key|token|psk|community|ddns-key|ddns_key|agent-user-override-key|agent_user_override_key"
    )
    # Cisco-style credentials may place an encryption type between the key
    # and the secret (for example, ``password 0 value``).
    sanitized = re.sub(
        rf"((?:password|secret|pre-?shared-key|preshared-key))(\s+)(?:0|7)(\s+)(?:\"[^\"]*\"|'[^']*'|[^\s\r\n]+)",
        rf"\1\2[REDACTED]",
        text,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        rf"({key_pattern})(\s+)((?:ascii|plain-text|cleartext|hex|encrypted|0|7)\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s\r\n]+)",
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3) or ''}{REDACTED_PLACEHOLDER}",
        sanitized,
        flags=re.IGNORECASE,
    )
    # Also cover serialized Python/JSON dictionaries used in diagnostic raw_capture.
    sanitized = re.sub(
        rf"([\"'](?:{key_pattern})[\"']\s*:\s*)(?:\"[^\"]*\"|'[^']*'|[^,}}\r\n]+)",
        rf"\1'{REDACTED_PLACEHOLDER}'",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        rf"(<(?:{key_pattern}|bind-password|authentication-key)(?:\s[^>]*)?>).*?(</(?:{key_pattern}|bind-password|authentication-key)>)",
        rf"\1{REDACTED_PLACEHOLDER}\2",
        sanitized,
        flags=re.IGNORECASE | re.DOTALL,
    )
    sanitized = re.sub(
        r"(<[^>]*(?:password|secret|token|private-key|shared-secret|psk|community)[^>]*>).*?(</[^>]+>)",
        rf"\1{REDACTED_PLACEHOLDER}\2",
        sanitized,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return sanitized


