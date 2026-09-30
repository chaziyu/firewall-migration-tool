"""ASA command-family evaluators."""

from typing import Any


def _mark_explicit(record: Any, *field_names: str) -> None:
    record.explicit_fields.update(field_names)
