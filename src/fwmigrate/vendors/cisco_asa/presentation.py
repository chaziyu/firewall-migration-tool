"""Secret-safe formatting shared by ASA workbook and web presentation."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
from typing import Any

from fwmigrate.extraction.sanitize import sanitize_raw_text

_SENSITIVE = ("password", "secret", "credential", "private", "token", "psk", "key")


def _safe_key(key: str, value: Any) -> bool:
    if isinstance(value, bool) and key.casefold().endswith(("_present", "_configured")):
        return True
    return not any(word in key.casefold() for word in _SENSITIVE)


def safe_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: safe_value(item) for key, item in value.items()
                if _safe_key(str(key), item)
                and str(key).casefold() not in {"raw_extra", "source_attributes"}}
    if isinstance(value, (list, tuple, set)):
        return tuple(safe_value(item) for item in value)
    model_fields = getattr(type(value), "model_fields", None)
    if model_fields:
        return {key: safe_value(getattr(value, key)) for key in model_fields
                if _safe_key(key, getattr(value, key))
                and key not in {"raw_extra", "source_attributes"}}
    if is_dataclass(value):
        return {field.name: safe_value(getattr(value, field.name)) for field in fields(value)
                if _safe_key(field.name, getattr(value, field.name))}
    if isinstance(value, str):
        return sanitize_raw_text(value)
    return value


def excel_value(value: Any) -> Any:
    value = safe_value(value)
    return str(value) if isinstance(value, (list, tuple, dict)) else value


def has_source_evidence(value: Any) -> bool:
    return bool(getattr(value, "explicit_fields", ()) or getattr(value, "raw_lines", ()) or
                getattr(value, "command_history", ()) or
                getattr(value, "source_attributes", {}).get("raw_commands"))
