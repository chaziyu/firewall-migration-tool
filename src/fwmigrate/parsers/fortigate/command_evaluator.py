"""Source-command evaluation shared by all FortiGate parser sections."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from fwmigrate.parsers.fortigate.extraction import sanitize_source_attributes


@dataclass(frozen=True)
class CommandEvaluation:
    attributes: dict[str, Any]
    explicit_fields: set[str] = field(default_factory=set)
    extra_settings: dict[str, Any] = field(default_factory=dict)


def normalize_key(key: str) -> str:
    normalized = key.replace("-", "_")
    return "threshold_default" if normalized == "threshold(default)" else normalized


def _raw(values: list[str], *, scalar: bool = False) -> Any:
    if not values:
        return True
    if len(values) == 1:
        return values[0]
    return " ".join(values) if scalar else list(values)


def _extend(mapping: dict[str, Any], key: str, values: list[Any]) -> None:
    if not values:
        return
    current = mapping.get(key)
    if current is None:
        mapping[key] = values[0] if len(values) == 1 else list(values)
    else:
        mapping[key] = [*(current if isinstance(current, list) else [current]), *values]


def evaluate_commands(
    commands: Iterable[Any],
    *,
    list_fields: Iterable[str] = (),
    integer_fields: Iterable[str] = (),
    integer_list_fields: Iterable[str] = (),
    scalar_fields: Iterable[str] = (),
    explicit_fields: Iterable[str] = (),
    secret_fields: Iterable[str] = (),
    initial: Mapping[str, Any] | None = None,
) -> CommandEvaluation:
    """Apply set/append/unset in source order without mutating source evidence."""

    list_fields = set(list_fields)
    integer_fields = set(integer_fields)
    integer_list_fields = set(integer_list_fields)
    scalar_fields = set(scalar_fields)
    declared_explicit = set(explicit_fields)
    secret_fields = set(secret_fields)
    typed_fields = list_fields | integer_fields | integer_list_fields | scalar_fields
    attributes = dict(initial or {})
    extras: dict[str, Any] = {}
    explicit: set[str] = set()

    for command in commands:
        key = normalize_key(command.key)
        operation = getattr(command, "operation", "set")
        values = list(command.values)
        unparsed = f"unparsed_{key}"
        unparsed_append = f"unparsed_append_{key}"

        if key in secret_fields:
            attributes.pop(key, None)
            extras.pop(key, None)
            extras.pop(unparsed, None)
            extras.pop(unparsed_append, None)
            continue

        if operation == "unset":
            attributes.pop(key, None)
            extras.pop(key, None)
            extras.pop(unparsed, None)
            extras.pop(unparsed_append, None)
            explicit.discard(key)
            continue

        if operation not in {"set", "append"}:
            _extend(extras, f"unparsed_operation_{operation}_{key}", values or [True])
            continue

        if key in declared_explicit:
            explicit.add(key)

        if key in integer_list_fields:
            parsed: list[int] = []
            malformed: list[str] = []
            for value in values:
                try:
                    parsed.append(int(value))
                except (TypeError, ValueError):
                    malformed.append(value)
            if operation == "set":
                attributes[key] = parsed
                extras.pop(unparsed, None)
                extras.pop(unparsed_append, None)
                if malformed:
                    extras[unparsed] = malformed
            else:
                current = attributes.get(key, [])
                attributes[key] = [*(current if isinstance(current, list) else []), *parsed]
                _extend(extras, unparsed_append, malformed)
            continue

        if key in integer_fields:
            if operation == "append":
                _extend(extras, unparsed_append, values or [True])
                continue
            attributes.pop(key, None)
            extras.pop(unparsed, None)
            extras.pop(unparsed_append, None)
            if len(values) != 1:
                extras[unparsed] = _raw(values)
            else:
                try:
                    attributes[key] = int(values[0])
                except (TypeError, ValueError):
                    extras[unparsed] = values[0]
            continue

        if key in list_fields:
            if operation == "set":
                attributes[key] = values
                extras.pop(unparsed_append, None)
            else:
                current = attributes.get(key, [])
                attributes[key] = [*(current if isinstance(current, list) else []), *values]
            continue

        if key in scalar_fields:
            if operation == "set":
                attributes[key] = _raw(values, scalar=True)
                extras.pop(unparsed_append, None)
            else:
                _extend(extras, unparsed_append, values or [True])
            continue

        if operation == "set":
            attributes[key] = _raw(values)
            extras[key] = attributes[key]
            extras.pop(unparsed_append, None)
        else:
            _extend(extras, unparsed_append, values or [True])

    for key, value in attributes.items():
        if key not in typed_fields:
            extras[key] = value

    return CommandEvaluation(
        attributes=sanitize_source_attributes(attributes),
        explicit_fields=explicit,
        extra_settings=sanitize_source_attributes(extras),
    )
