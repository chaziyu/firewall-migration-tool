"""Centralized secret sanitization for configuration evidence and extraction metadata."""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, List, Set, Union

from pydantic import BaseModel

from fwmigrate.extraction.models import (
    ExtractionResult,
    SourceInventoryItem,
    SourceSectionResult,
    UnsupportedItem,
)

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
    "ddns-key",
    "ddns_key",
    "agent-user-override-key",
    "agent_user_override_key",
)

SENSITIVE_EXACT_KEYS = {
    "private-key-data", "private_key_data", "key-data", "key_data",
    "activation-key", "activation_key", "sic-password-hash", "sic_password_hash",
    "otp", "pkcs12-password", "pkcs12_password", "one-time-password",
    "one_time_password",
}

REDACTED_PLACEHOLDER = "[REDACTED]"


def _is_sensitive_key(key: str) -> bool:
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
    if _is_sensitive_key(key):
        return REDACTED_PLACEHOLDER

    if isinstance(value, dict):
        return sanitize_source_attributes(value)
    elif isinstance(value, list):
        return [sanitize_source_value(key, item) if not isinstance(item, (dict, list)) else (sanitize_source_attributes(item) if isinstance(item, dict) else [sanitize_source_value(key, x) for x in item]) for item in value]
    return value


def sanitize_source_attributes(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively sanitize a dictionary of source attributes."""
    if not isinstance(attrs, dict):
        return attrs

    sanitized: Dict[str, Any] = {}
    for k, v in attrs.items():
        if _is_sensitive_key(str(k)):
            sanitized[k] = REDACTED_PLACEHOLDER
        elif isinstance(v, dict):
            sanitized[k] = sanitize_source_attributes(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_source_attributes(item) if isinstance(item, dict)
                else (REDACTED_PLACEHOLDER if _is_sensitive_key(str(k)) else item)
                for item in v
            ]
        elif isinstance(v, str) and str(k).strip().lower().replace("_", "-") in {
            "raw", "raw-command", "cli-text", "error", "command-output"
        }:
            sanitized[k] = sanitize_raw_text(v)
        else:
            sanitized[k] = v
    return sanitized


def sanitize_raw_text(text: str) -> str:
    """Sanitize secrets in raw command output, Gaia lines, or config text."""
    if not text:
        return text

    # Mask password hashes or cleartext in known CLI patterns (e.g. set user admin password-hash ...)
    key_pattern = (
        r"password(?:-hash)?|phash|one-time-password|shared-secret|sic-name|sic-password|"
        r"secret|key|password|login-password|common-password|bind-password|pre-?shared-key|preshared-key|private-key|api-key|token|psk|community|ddns-key|ddns_key|agent-user-override-key|agent_user_override_key"
    )
    sanitized = re.sub(
        rf"({key_pattern})(\s+)(?:\"[^\"]*\"|'[^']*'|[^\s\r\n]+)",
        rf"\1\2{REDACTED_PLACEHOLDER}",
        text,
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
    return sanitized


def _sanitize_canonical_evidence(value: Any, field_name: str = "") -> None:
    """Redact source-preservation fields inside canonical IR without changing semantics."""
    if isinstance(value, BaseModel):
        # PSKs are presence metadata only; plaintext is never portable IR.
        if hasattr(value, "psk") and getattr(value, "psk", None) is not None:
            if hasattr(value, "has_psk"):
                setattr(value, "has_psk", True)
            setattr(value, "psk", None)
        for name in value.__class__.model_fields:
            child = getattr(value, name, None)
            if isinstance(child, dict) and (
                name in {"source_attributes", "source_extra_settings"}
                or name.startswith("source_")
            ):
                setattr(value, name, sanitize_source_attributes(child))
            else:
                _sanitize_canonical_evidence(child, name)
    elif isinstance(value, list):
        for child in value:
            _sanitize_canonical_evidence(child, field_name)
    elif isinstance(value, dict) and (
        field_name in {"source_attributes", "source_extra_settings"}
        or field_name.startswith("source_")
    ):
        sanitized = sanitize_source_attributes(value)
        value.clear()
        value.update(sanitized)


def sanitize_inventory_item(item: SourceInventoryItem) -> SourceInventoryItem:
    """Sanitize a single SourceInventoryItem and its children."""
    item.source_attributes = sanitize_source_attributes(item.source_attributes)
    for cmd in item.commands:
        if _is_sensitive_key(cmd.key):
            cmd.values = [REDACTED_PLACEHOLDER]
    for child in item.children:
        sanitize_inventory_item(child)
    return item


def sanitize_extraction_result(result: ExtractionResult) -> ExtractionResult:
    """
    Recursively sanitize all sensitive metadata in an ExtractionResult before export or persistence.
    Operates on a deep copy to ensure clean separation.
    """
    res = result.model_copy(deep=True)

    # 1. Sanitize inventory items
    for item in res.inventory_items:
        sanitize_inventory_item(item)

    # 2. Sanitize unsupported items raw capture
    for unsupp in res.unsupported_items:
        if unsupp.raw_capture:
            unsupp.raw_capture = sanitize_raw_text(unsupp.raw_capture)

    # 3. Sanitize source sections notes if needed
    for sec in res.source_sections:
        sec.notes = [sanitize_raw_text(n) for n in sec.notes]

    # 4. Canonical IR can retain sanitized source evidence, but never credentials.
    if res.canonical_ir is not None:
        _sanitize_canonical_evidence(res.canonical_ir)

    return res
