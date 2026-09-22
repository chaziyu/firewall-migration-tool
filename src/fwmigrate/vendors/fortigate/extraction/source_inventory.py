from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..nodes import (
    CommandNode,
    ConfigNode,
    EditNode,
    FortiGateConfigTree,
    UnknownCommandNode,
)
from .common import evaluate_config, evaluate_edit


@dataclass(frozen=True, slots=True)
class SourceCommandRecord:
    """One explicit source command retained for report traceability."""

    vdom: str
    source_path: str
    object_name: str | None
    parent_objects: tuple[str, ...]

    operation: str
    key: str
    values: tuple[str, ...]
    line_number: int | None


@dataclass(frozen=True, slots=True)
class SourceObjectRecord:
    """
    One evaluated FortiGate source block.

    This is extraction evidence only. It intentionally remains close to the
    FortiGate CLI and does not contain FortiOS defaults, relationship
    resolution, canonical normalization, or target-vendor semantics.
    """

    vdom: str
    source_path: str
    object_name: str | None
    parent_objects: tuple[str, ...]

    values: dict[str, Any]
    explicit_fields: tuple[str, ...]
    unset_fields: tuple[str, ...]

    commands: tuple[SourceCommandRecord, ...]

    start_line_number: int | None
    end_line_number: int | None


def capture_source_objects(
    tree: FortiGateConfigTree,
) -> tuple[SourceObjectRecord, ...]:
    """
    Capture all explicit config/edit blocks, including sections without a
    dedicated typed model.

    The typed FGConfig remains the source of truth for supported domains.
    These records exist so the report can retain complete FortiGate source
    evidence without reintroducing a vendor-neutral IR.
    """

    records: list[SourceObjectRecord] = []

    def walk_config(
        node: ConfigNode,
        *,
        vdom: str,
        parent_path: str | None,
        parent_objects: tuple[str, ...],
    ) -> None:
        if node.name == "vdom":
            for edit in node.edits:
                for child in edit.children:
                    walk_config(
                        child,
                        vdom=edit.name,
                        parent_path=None,
                        parent_objects=(),
                    )
            return

        source_path = (
            f"{parent_path} {node.name}"
            if parent_path
            else node.name
        )

        if node.commands:
            evaluation = evaluate_config(
                source_path,
                node,
            )
            records.append(
                _make_record(
                    vdom=vdom,
                    source_path=source_path,
                    object_name=None,
                    parent_objects=parent_objects,
                    commands=node.commands,
                    evaluation=evaluation,
                    start_line_number=node.start_line_number,
                    end_line_number=node.end_line_number,
                )
            )

        for edit in node.edits:
            evaluation = evaluate_edit(
                source_path,
                edit,
            )
            records.append(
                _make_record(
                    vdom=vdom,
                    source_path=source_path,
                    object_name=edit.name,
                    parent_objects=parent_objects,
                    commands=edit.commands,
                    evaluation=evaluation,
                    start_line_number=edit.start_line_number,
                    end_line_number=edit.end_line_number,
                )
            )

            for child in edit.children:
                walk_config(
                    child,
                    vdom=vdom,
                    parent_path=source_path,
                    parent_objects=(
                        *parent_objects,
                        edit.name,
                    ),
                )

        for child in node.children:
            walk_config(
                child,
                vdom=vdom,
                parent_path=source_path,
                parent_objects=parent_objects,
            )

    for root in tree.configs:
        walk_config(
            root,
            vdom="root",
            parent_path=None,
            parent_objects=(),
        )

    return tuple(records)


def _make_record(
    *,
    vdom: str,
    source_path: str,
    object_name: str | None,
    parent_objects: tuple[str, ...],
    commands: list[CommandNode | UnknownCommandNode],
    evaluation,
    start_line_number: int | None,
    end_line_number: int | None,
) -> SourceObjectRecord:
    settings = dict(evaluation.values)

    for key, value in evaluation.untyped_values.items():
        if key not in settings:
            settings[key] = value
            continue

        current = settings[key]
        if not isinstance(current, list):
            current = [current]
        if isinstance(value, list):
            settings[key] = [*current, *value]
        else:
            settings[key] = [*current, value]

    return SourceObjectRecord(
        vdom=vdom,
        source_path=source_path,
        object_name=object_name,
        parent_objects=parent_objects,
        values=settings,
        explicit_fields=tuple(sorted(evaluation.explicit_fields)),
        unset_fields=tuple(sorted(evaluation.unset_fields)),
        commands=tuple(
            _command_record(
                command,
                vdom=vdom,
                source_path=source_path,
                object_name=object_name,
                parent_objects=parent_objects,
            )
            for command in commands
        ),
        start_line_number=start_line_number,
        end_line_number=end_line_number,
    )


def _command_record(
    command: CommandNode | UnknownCommandNode,
    *,
    vdom: str,
    source_path: str,
    object_name: str | None,
    parent_objects: tuple[str, ...],
) -> SourceCommandRecord:
    if isinstance(command, UnknownCommandNode):
        return SourceCommandRecord(
            vdom=vdom,
            source_path=source_path,
            object_name=object_name,
            parent_objects=parent_objects,
            operation="unknown",
            key=command.keyword,
            values=tuple(command.values),
            line_number=command.line_number,
        )

    return SourceCommandRecord(
        vdom=vdom,
        source_path=source_path,
        object_name=object_name,
        parent_objects=parent_objects,
        operation=command.operation,
        key=command.key,
        values=tuple(command.values),
        line_number=command.line_number,
    )
