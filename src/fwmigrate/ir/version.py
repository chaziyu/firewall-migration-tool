from __future__ import annotations

from fwmigrate.ir.errors import IRSchemaError, UnsupportedIRSchemaError


IR_SCHEMA_VERSION = "1.7"
SUPPORTED_IR_SCHEMA_MAJOR = 1
SUPPORTED_IR_SCHEMA_MINOR = 7


def parse_schema_version(value: str) -> tuple[int, int]:
    if not isinstance(value, str):
        raise IRSchemaError(f"Invalid IR schema version: {value!r}")

    parts = value.split(".")
    if len(parts) != 2 or not all(part.isdecimal() for part in parts):
        raise IRSchemaError(f"Invalid IR schema version: {value!r}")

    return int(parts[0]), int(parts[1])


def validate_supported_schema_version(value: str) -> None:
    incoming_major, incoming_minor = parse_schema_version(value)
    current_major, current_minor = parse_schema_version(IR_SCHEMA_VERSION)

    if incoming_major != current_major or incoming_minor > current_minor:
        raise UnsupportedIRSchemaError(
            f"Unsupported IR schema version {value!r}; "
            f"this application supports {IR_SCHEMA_VERSION!r}."
        )

    if (incoming_major, incoming_minor) != (current_major, current_minor):
        raise UnsupportedIRSchemaError(
            f"IR schema version {value!r} requires an explicit migration "
            f"to {IR_SCHEMA_VERSION!r}."
        )
