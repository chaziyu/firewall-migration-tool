from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from ..model.user import (
    FGLocalUser,
    FGUserGroup,
    FGUserGroupGuest,
    FGUserGroupMatch,
)
from ..nodes import (
    CommandNode,
    ConfigNode,
    UnknownCommandNode,
)

from .common import (
    evaluate_edit,
    get_child_config,
    iter_section_edits,
    source_model_kwargs,
)
from .section_index import SectionIndex


class UserConfig(Protocol):
    """Minimal destination required by user extraction."""

    local_users: list[FGLocalUser]
    user_groups: list[FGUserGroup]


def extract_users(
    tree: SectionIndex,
    config: UserConfig,
) -> None:
    _extract_local_users(tree, config)
    _extract_user_groups(tree, config)


def _extract_local_users(
    tree: SectionIndex,
    config: UserConfig,
) -> None:
    section_path = "user local"

    for source in iter_section_edits(
        tree,
        section_path,
    ):
        evaluation = evaluate_edit(
            section_path,
            source.edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGLocalUser,
            name=source.edit.name,
            vdom=source.vdom,
            field_map={
                "tacacs+-server": "tacacs_server",
            },
        )

        secret_state = _secret_presence(
            source.edit.commands,
            {
                "passwd",
                "ppk-secret",
            },
        )

        attributes["password_configured"] = (
            secret_state["passwd"]
        )
        attributes["ppk_secret_configured"] = (
            secret_state["ppk-secret"]
        )

        _remove_secret_values(
            attributes,
            {
                "passwd",
                "ppk-secret",
            },
        )

        config.local_users.append(
            FGLocalUser(**attributes)
        )


def _extract_user_groups(
    tree: SectionIndex,
    config: UserConfig,
) -> None:
    section_path = "user group"

    for source in iter_section_edits(
        tree,
        section_path,
    ):
        evaluation = evaluate_edit(
            section_path,
            source.edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGUserGroup,
            name=source.edit.name,
            vdom=source.vdom,
            field_map={
                "member": "members",
            },
        )

        match = get_child_config(
            source.edit,
            "match",
        )

        if match is not None:
            attributes["matches"] = (
                _extract_group_matches(match)
            )

        guest = get_child_config(
            source.edit,
            "guest",
        )

        if guest is not None:
            attributes["guests"] = (
                _extract_group_guests(guest)
            )

        config.user_groups.append(
            FGUserGroup(**attributes)
        )


def _extract_group_matches(
    section: ConfigNode,
) -> list[FGUserGroupMatch]:
    result: list[FGUserGroupMatch] = []

    section_path = "user group match"

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGUserGroupMatch,
        )

        _set_structural_id(
            attributes,
            edit.name,
        )

        result.append(
            FGUserGroupMatch(**attributes)
        )

    return result


def _extract_group_guests(
    section: ConfigNode,
) -> list[FGUserGroupGuest]:
    result: list[FGUserGroupGuest] = []

    section_path = "user group guest"

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGUserGroupGuest,
        )

        _set_structural_id(
            attributes,
            edit.name,
        )

        secret_state = _secret_presence(
            edit.commands,
            {
                "password",
            },
        )

        attributes["password_configured"] = (
            secret_state["password"]
        )

        _remove_secret_values(
            attributes,
            {
                "password",
            },
        )

        result.append(
            FGUserGroupGuest(**attributes)
        )

    return result


def _secret_presence(
    commands: Iterable[
        CommandNode | UnknownCommandNode
    ],
    fields: set[str],
) -> dict[str, bool]:
    """
    Evaluate secret configuration state without retaining secret values.
    """

    result = {
        field: False
        for field in fields
    }

    for command in commands:
        if isinstance(
            command,
            UnknownCommandNode,
        ):
            continue

        if command.key not in fields:
            continue

        operation = command.operation.lower()

        if operation == "unset":
            result[command.key] = False
        elif operation in {
            "set",
            "append",
        }:
            result[command.key] = True

    return result


def _remove_secret_values(
    attributes: dict,
    fields: set[str],
) -> None:
    """
    Ensure credential material cannot survive through raw_extra.
    """

    raw_extra = attributes.get("raw_extra")

    if not isinstance(raw_extra, dict):
        return

    for field in fields:
        raw_extra.pop(field, None)
        raw_extra.pop(
            field.replace("-", "_"),
            None,
        )


def _set_structural_id(
    attributes: dict,
    raw_id: str,
) -> None:
    try:
        attributes["id"] = int(raw_id)
    except ValueError:
        attributes["id"] = None
        attributes["raw_extra"][
            "unparsed_id"
        ] = raw_id
