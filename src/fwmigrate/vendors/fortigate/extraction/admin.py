from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from ..model.admin import (
    FGAdministrator,
    FGAdminFirewallPermission,
    FGAdminLogPermission,
    FGAdminNetworkPermission,
    FGAdminProfile,
    FGAdminSystemPermission,
    FGAdminUTMPermission,
)
from ..nodes import (
    CommandNode,
    ConfigNode,
    FortiGateConfigTree,
    UnknownCommandNode,
)

from .common import (
    evaluate_config,
    evaluate_edit,
    get_child_config,
    iter_section_edits,
    source_model_kwargs,
)


class AdminConfig(Protocol):
    """Minimal destination required by administrator extraction."""

    administrators: list[FGAdministrator]
    admin_profiles: list[FGAdminProfile]


def extract_admin(
    tree: FortiGateConfigTree,
    config: AdminConfig,
) -> None:
    _extract_administrators(tree, config)
    _extract_admin_profiles(tree, config)


def _extract_administrators(
    tree: FortiGateConfigTree,
    config: AdminConfig,
) -> None:
    section_path = "system admin"

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
            model_type=FGAdministrator,
            name=source.edit.name,
            field_map={
                "vdom": "vdoms",
            },
        )

        attributes["trusthosts"] = _numbered_values(
            source.edit.commands,
            prefix="trusthost",
            count=10,
        )

        attributes["ip6_trusthosts"] = _numbered_values(
            source.edit.commands,
            prefix="ip6-trusthost",
            count=10,
        )

        secret_state = _secret_presence(
            source.edit.commands,
            {
                "password",
                "ssh-public-key1",
                "ssh-public-key2",
                "ssh-public-key3",
            },
        )

        attributes["password_configured"] = (
            secret_state["password"]
        )

        attributes["ssh_key_configured"] = any(
            secret_state[key]
            for key in (
                "ssh-public-key1",
                "ssh-public-key2",
                "ssh-public-key3",
            )
        )

        _remove_sensitive_values(
            attributes,
            {
                "password",
                "ssh-public-key1",
                "ssh-public-key2",
                "ssh-public-key3",
            },
        )

        config.administrators.append(
            FGAdministrator(**attributes)
        )


def _extract_admin_profiles(
    tree: FortiGateConfigTree,
    config: AdminConfig,
) -> None:
    section_path = "system accprofile"

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
            model_type=FGAdminProfile,
            name=source.edit.name,
        )

        _add_permission_block(
            attributes,
            source.edit,
            child_name="fwgrp-permission",
            section_path=(
                "system accprofile fwgrp-permission"
            ),
            target_field="firewall_permission",
            model_type=FGAdminFirewallPermission,
        )

        _add_permission_block(
            attributes,
            source.edit,
            child_name="loggrp-permission",
            section_path=(
                "system accprofile loggrp-permission"
            ),
            target_field="log_permission",
            model_type=FGAdminLogPermission,
        )

        _add_permission_block(
            attributes,
            source.edit,
            child_name="netgrp-permission",
            section_path=(
                "system accprofile netgrp-permission"
            ),
            target_field="network_permission",
            model_type=FGAdminNetworkPermission,
        )

        _add_permission_block(
            attributes,
            source.edit,
            child_name="sysgrp-permission",
            section_path=(
                "system accprofile sysgrp-permission"
            ),
            target_field="system_permission",
            model_type=FGAdminSystemPermission,
        )

        _add_permission_block(
            attributes,
            source.edit,
            child_name="utmgrp-permission",
            section_path=(
                "system accprofile utmgrp-permission"
            ),
            target_field="utm_permission",
            model_type=FGAdminUTMPermission,
        )

        config.admin_profiles.append(
            FGAdminProfile(**attributes)
        )


def _add_permission_block(
    attributes: dict,
    edit,
    *,
    child_name: str,
    section_path: str,
    target_field: str,
    model_type,
) -> None:
    child = get_child_config(
        edit,
        child_name,
    )

    if child is None:
        return

    evaluation = evaluate_config(
        section_path,
        child,
    )

    values = source_model_kwargs(
        evaluation,
        model_type=model_type,
    )

    attributes[target_field] = model_type(
        **values
    )


def _numbered_values(
    commands: Iterable[
        CommandNode | UnknownCommandNode
    ],
    *,
    prefix: str,
    count: int,
) -> list[str]:
    """
    Evaluate numbered FortiOS scalar fields such as
    trusthost1..trusthost10 while preserving source order.
    """

    state: dict[str, str] = {}

    valid_fields = {
        f"{prefix}{index}"
        for index in range(1, count + 1)
    }

    for command in commands:
        if isinstance(
            command,
            UnknownCommandNode,
        ):
            continue

        if command.key not in valid_fields:
            continue

        operation = command.operation.lower()

        if operation == "unset":
            state.pop(command.key, None)
            continue

        if (
            operation == "set"
            and command.values
        ):
            state[command.key] = " ".join(
                command.values
            )

    return [
        state[f"{prefix}{index}"]
        for index in range(1, count + 1)
        if f"{prefix}{index}" in state
    ]


def _secret_presence(
    commands: Iterable[
        CommandNode | UnknownCommandNode
    ],
    fields: set[str],
) -> dict[str, bool]:
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


def _remove_sensitive_values(
    attributes: dict,
    fields: set[str],
) -> None:
    raw_extra = attributes.get(
        "raw_extra"
    )

    if not isinstance(
        raw_extra,
        dict,
    ):
        return

    for field in fields:
        raw_extra.pop(
            field,
            None,
        )
        raw_extra.pop(
            field.replace("-", "_"),
            None,
        )