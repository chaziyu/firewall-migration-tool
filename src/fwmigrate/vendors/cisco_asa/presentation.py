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


def source_value(record: Any, field_name: str) -> Any:
    """Return explicit ASA source state without presenting model defaults as configured."""
    value = getattr(record, field_name, None)
    explicit_fields = getattr(record, "explicit_fields", None)
    if explicit_fields is None or field_name in explicit_fields:
        return value
    model_field = getattr(type(record), "model_fields", {}).get(field_name)
    if model_field is not None and model_field.default is False and value is False:
        return None
    return value


def safe_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: safe_value(item) for key, item in value.items()
                if _safe_key(str(key), item)
                and str(key).casefold() not in {"raw_extra", "source_attributes"}}
    if isinstance(value, (list, tuple, set)):
        return tuple(safe_value(item) for item in value)
    model_fields = getattr(type(value), "model_fields", None)
    if model_fields:
        return {key: safe_value(source_value(value, key)) for key in model_fields
                if _safe_key(key, source_value(value, key))
                and key not in {"explicit_fields", "raw_extra", "source_attributes"}}
    if is_dataclass(value):
        return {field.name: safe_value(getattr(value, field.name)) for field in fields(value)
                if _safe_key(field.name, getattr(value, field.name))}
    if isinstance(value, str):
        return sanitize_raw_text(value)
    return value


def excel_value(value: Any) -> Any:
    value = safe_value(value)
    value = str(value) if isinstance(value, (list, tuple, dict)) else value
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + value
    return value


def has_source_evidence(value: Any) -> bool:
    return bool(getattr(value, "explicit_fields", ()) or getattr(value, "raw_lines", ()) or
                getattr(value, "command_history", ()) or
                getattr(value, "source_attributes", {}).get("raw_commands"))
