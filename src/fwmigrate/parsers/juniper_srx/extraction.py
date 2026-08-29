"""Helpers for secret sanitization and ExtractionResult helpers for Juniper SRX."""

from __future__ import annotations

import shlex
from typing import Any, Dict, List, Mapping, Sequence


_SENSITIVE_KEYWORDS = {
    "pre-shared-key",
    "encrypted-password",
    "plain-text-password",
    "simple-password",
    "authentication-key",
    "auth-password",
    "priv-password",
    "authentication-password",
    "privacy-password",
    "community",
    "secret",
    "password",
    "passwd",
    "private-key",
    "token",
    "api-key",
    "radius-secret",
    "tacacs-secret",
    "ike-user-type",
    "md5-password",
    "sha-password",
    "master-key",
    "passphrase",
}

_SENSITIVE_KEY_SET = {
    "pre_shared_key",
    "encrypted_password",
    "plain_text_password",
    "simple_password",
    "authentication_key",
    "auth_password",
    "priv_password",
    "authentication_password",
    "privacy_password",
    "community",
    "secret",
    "password",
    "passwd",
    "private_key",
    "token",
    "api_key",
    "radius_secret",
    "tacacs_secret",
    "ike_user_type",
    "md5_password",
    "sha_password",
    "master_key",
    "passphrase",
}

_SENSITIVE_SUB_KEYS = {
    "ascii-text",
    "hexadecimal",
    "text",
    "plain-text",
    "encrypted",
    "hash",
    "md5",
    "sha",
    "sha-256",
}

_FREE_TEXT_KEYS = {
    "description",
    "comment",
    "message",
    "system-message",
    "syslog",
    "announcement",
}


def sanitize_tokens(tokens: Sequence[str]) -> List[str]:
    """
    Sanitize token list by redacting sensitive values following sensitive keyword tokens.
    Token-aware, not substring-based (e.g. object named 'community-web' will not be redacted).
    """
    sanitized: List[str] = []
    redact_next = False
    skip_sub_keyword = False

    for i, token in enumerate(tokens):
        token_lower = token.lower()

        if redact_next:
            if token_lower in _SENSITIVE_SUB_KEYS and not skip_sub_keyword:
                # e.g. pre-shared-key ascii-text <secret>
                sanitized.append(token)
                skip_sub_keyword = True
                continue
            sanitized.append("[REDACTED]")
            redact_next = False
            skip_sub_keyword = False
            continue

        sanitized.append(token)

        if token_lower in _SENSITIVE_KEYWORDS:
            redact_next = True
            skip_sub_keyword = False

    return sanitized


def sanitize_junos_command(tokens: Sequence[str]) -> str:
    """Format sanitized tokens into a safe display-set command line."""
    sanitized = sanitize_tokens(tokens)
    parts: List[str] = []
    for t in sanitized:
        if " " in t or "\t" in t or '"' in t or "'" in t or not t:
            # Quote if contains spaces or special characters
            escaped = t.replace('"', '\\"')
            parts.append(f'"{escaped}"')
        else:
            parts.append(t)
    return " ".join(parts)


def is_sensitive_key(key: str) -> bool:
    """Check if key or its tokenized segments represent sensitive credential fields."""
    norm = str(key).lower().replace("-", "_")
    if norm in _SENSITIVE_KEY_SET:
        return True
    parts = norm.split("_")
    if any(p in ("password", "passwd", "secret", "pre_shared_key", "private_key", "api_key", "passphrase") for p in parts):
        return True
    if norm == "community" or norm.endswith("_community"):
        return True
    return False


def sanitize_source_attributes(attributes: Mapping[str, Any]) -> Dict[str, Any]:
    """Retain Juniper source fields while redacting credentials or secret-like values."""
    sanitized: Dict[str, Any] = {}
    for key, value in attributes.items():
        normalized_key = str(key).lower().replace("-", "_")
        if is_sensitive_key(key):
            sanitized[normalized_key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[normalized_key] = sanitize_source_attributes(value)
        elif isinstance(value, list):
            sanitized[normalized_key] = [
                sanitize_source_attributes(v) if isinstance(v, dict) else v
                for v in value
            ]
        else:
            sanitized[normalized_key] = value
    return sanitized


def has_access_denied_token(tokens: Sequence[str]) -> bool:
    """
    Detect if any token structurally matches JunOS ACCESS-DENIED placeholder.
    Excludes free-text positions like description/comment to avoid false positives.
    """
    for i, token in enumerate(tokens):
        if token.strip().upper() == "ACCESS-DENIED":
            # If the preceding token is a known free-text keyword, ignore
            if i > 0 and tokens[i - 1].lower() in _FREE_TEXT_KEYS:
                continue
            return True
    return False

