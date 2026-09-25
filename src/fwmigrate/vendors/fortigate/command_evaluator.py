"""Evaluate FortiGate source commands in source order."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .nodes import CommandNode, UnknownCommandNode


@dataclass(frozen=True, slots=True)
class CommandEvaluation:
    """
    Result of evaluating commands from one FortiGate source object.

    `values`
        Typed source values produced from declared primitive field types.

    `explicit_fields`
        Declared fields explicitly configured by set/append and still
        represented in the evaluated source state.

    `unset_fields`
        Fields explicitly unset in the final evaluated source state.

    `untyped_values`
        Source fields without a declared primitive type, malformed values
        that could not be converted, and unsupported source operations.
    """

    values: dict[str, Any] = field(default_factory=dict)
    explicit_fields: set[str] = field(default_factory=set)
    unset_fields: set[str] = field(default_factory=set)
    untyped_values: dict[str, Any] = field(default_factory=dict)


def _raw_value(
    values: list[str],
    *,
    scalar: bool = False,
) -> Any:
    """
    Preserve a source value without applying FortiOS semantics.

    Examples:
        []              -> True
        ["enable"]      -> "enable"
        ["a", "b"]      -> ["a", "b"]

    A declared scalar field joins multiple lexical values into one string.
    """

    if not values:
        return True

    if len(values) == 1:
        return values[0]

    if scalar:
        return " ".join(values)

    return list(values)


def _append_values(
    current: Any,
    values: list[Any],
) -> list[Any]:
    """Append values while tolerating a previously scalar value."""

    if current is None:
        return list(values)

    if isinstance(current, list):
        return [
            *current,
            *values,
        ]

    return [
        current,
        *values,
    ]


def _record_untyped(
    untyped_values: dict[str, Any],
    key: str,
    value: Any,
) -> None:
    """
    Preserve repeated unsupported source evidence without overwriting
    earlier evidence.
    """

    if key not in untyped_values:
        untyped_values[key] = value
        return

    current = untyped_values[key]

    if not isinstance(current, list):
        current = [current]

    if isinstance(value, list):
        untyped_values[key] = [
            *current,
            *value,
        ]
    else:
        untyped_values[key] = [
            *current,
            value,
        ]


def _mark_explicit(
    key: str,
    *,
    explicit_fields: set[str],
    unset_fields: set[str],
) -> None:
    """Mark a declared source field as explicitly effective."""

    explicit_fields.add(key)
    unset_fields.discard(key)


def evaluate_commands(
    commands: Iterable[
        CommandNode | UnknownCommandNode
    ],
    *,
    list_fields: Iterable[str] = (),
    integer_fields: Iterable[str] = (),
    integer_list_fields: Iterable[str] = (),
    scalar_fields: Iterable[str] = (),
    declared_fields: Iterable[str] | None = None,
    initial: Mapping[str, Any] | None = None,
) -> CommandEvaluation:
    """
    Apply set/append/unset operations in source order.

    Field names remain in original FortiGate CLI spelling.

    This function performs only:
        - source-order state evaluation
        - caller-declared primitive type conversion

    It does not:
        - normalize source keys
        - classify secrets
        - apply FortiOS defaults
        - resolve references
        - normalize vendor semantics
        - validate configuration
        - construct FortiGate models
    """

    if not isinstance(list_fields, (set, frozenset)):
        list_fields = frozenset(list_fields)
    if not isinstance(integer_fields, (set, frozenset)):
        integer_fields = frozenset(integer_fields)
    if not isinstance(integer_list_fields, (set, frozenset)):
        integer_list_fields = frozenset(integer_list_fields)
    if not isinstance(scalar_fields, (set, frozenset)):
        scalar_fields = frozenset(scalar_fields)
    if declared_fields is None:
        declared_fields = (
            list_fields
            | integer_fields
            | integer_list_fields
            | scalar_fields
        )

    initial_values = dict(
        initial or {}
    )

    evaluated_values: dict[str, Any] = dict(
        initial_values
    )

    untyped_values: dict[str, Any] = {}

    explicit_fields: set[str] = set()
    unset_fields: set[str] = set()

    for command in commands:
        # ----------------------------------------------------------
        # Unknown syntax
        # ----------------------------------------------------------

        if isinstance(
            command,
            UnknownCommandNode,
        ):
            _record_untyped(
                untyped_values,
                (
                    "unknown_command:"
                    f"{command.keyword}"
                ),
                list(command.values),
            )
            continue

        key = command.key
        operation = command.operation.lower()
        command_values = command.values

        # ----------------------------------------------------------
        # unset
        # ----------------------------------------------------------

        if operation == "unset":
            evaluated_values.pop(
                key,
                None,
            )

            untyped_values.pop(
                key,
                None,
            )

            untyped_values.pop(
                f"unparsed_{key}",
                None,
            )

            explicit_fields.discard(key)
            unset_fields.add(key)

            continue

        # ----------------------------------------------------------
        # Only set / append have source-state semantics here
        # ----------------------------------------------------------

        if operation not in {
            "set",
            "append",
        }:
            _record_untyped(
                untyped_values,
                (
                    "unsupported_operation:"
                    f"{operation}:{key}"
                ),
                (
                    command_values
                    if command_values
                    else True
                ),
            )
            continue

        # ----------------------------------------------------------
        # Integer list
        # ----------------------------------------------------------

        if key in integer_list_fields:
            parsed: list[int] = []
            malformed: list[str] = []

            for value in command_values:
                try:
                    parsed.append(
                        int(value)
                    )
                except (
                    TypeError,
                    ValueError,
                ):
                    malformed.append(
                        str(value)
                    )

            if operation == "set":
                evaluated_values[key] = (
                    parsed
                )
            else:
                evaluated_values[key] = (
                    _append_values(
                        evaluated_values.get(
                            key
                        ),
                        parsed,
                    )
                )

            _mark_explicit(
                key,
                explicit_fields=explicit_fields,
                unset_fields=unset_fields,
            )

            if malformed:
                _record_untyped(
                    untyped_values,
                    f"unparsed_{key}",
                    malformed,
                )

            continue

        # ----------------------------------------------------------
        # Integer scalar
        # ----------------------------------------------------------

        if key in integer_fields:
            if operation == "append":
                _record_untyped(
                    untyped_values,
                    f"unsupported_append_{key}",
                    (
                        command_values
                        if command_values
                        else True
                    ),
                )
                continue

            if len(command_values) != 1:
                evaluated_values.pop(
                    key,
                    None,
                )

                explicit_fields.discard(
                    key
                )
                unset_fields.discard(
                    key
                )

                _record_untyped(
                    untyped_values,
                    f"unparsed_{key}",
                    _raw_value(
                        command_values
                    ),
                )

                continue

            try:
                evaluated_values[key] = int(
                    command_values[0]
                )
            except (
                TypeError,
                ValueError,
            ):
                evaluated_values.pop(
                    key,
                    None,
                )

                explicit_fields.discard(
                    key
                )
                unset_fields.discard(
                    key
                )

                _record_untyped(
                    untyped_values,
                    f"unparsed_{key}",
                    command_values[0],
                )

                continue

            _mark_explicit(
                key,
                explicit_fields=explicit_fields,
                unset_fields=unset_fields,
            )

            continue

        # ----------------------------------------------------------
        # List
        # ----------------------------------------------------------

        if key in list_fields:
            if operation == "set":
                evaluated_values[key] = list(
                    command_values
                )
            else:
                evaluated_values[key] = (
                    _append_values(
                        evaluated_values.get(
                            key
                        ),
                        command_values,
                    )
                )

            _mark_explicit(
                key,
                explicit_fields=explicit_fields,
                unset_fields=unset_fields,
            )

            continue

        # ----------------------------------------------------------
        # Scalar
        # ----------------------------------------------------------

        if key in scalar_fields:
            if operation == "append":
                _record_untyped(
                    untyped_values,
                    f"unsupported_append_{key}",
                    (
                        command_values
                        if command_values
                        else True
                    ),
                )
                continue

            evaluated_values[key] = (
                _raw_value(
                    command_values,
                    scalar=True,
                )
            )

            _mark_explicit(
                key,
                explicit_fields=explicit_fields,
                unset_fields=unset_fields,
            )

            continue

        # ----------------------------------------------------------
        # Untyped / undeclared source field
        # ----------------------------------------------------------

        value = _raw_value(
            command_values
        )

        if operation == "set":
            untyped_values[key] = value
        else:
            untyped_values[key] = (
                _append_values(
                    untyped_values.get(key),
                    command_values,
                )
            )

        # This field is source-explicit, but it is not added to
        # `explicit_fields` because no declared typed model state
        # was produced for it.
        unset_fields.discard(key)

    # --------------------------------------------------------------
    # Defensive typed-result boundary
    # --------------------------------------------------------------

    evaluated_values = {
        key: value
        for key, value
        in evaluated_values.items()
        if (
            key in declared_fields
            or key in initial_values
        )
    }

    return CommandEvaluation(
        values=evaluated_values,
        explicit_fields=explicit_fields,
        unset_fields=unset_fields,
        untyped_values=untyped_values,
    )
