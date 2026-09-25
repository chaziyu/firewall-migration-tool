from __future__ import annotations

from typing import Protocol

from ..model.vpn_ssl import (
    FGSSLVPNAuthenticationRule,
    FGSSLVPNHostCheckItem,
    FGSSLVPNHostCheckSoftware,
    FGSSLVPNPortal,
    FGSSLVPNSettings,
    FGSSLVPNRealm,
    FGSSLVPNClient,
    FGSSLVPNBookmark,
    FGSSLVPNBookmarkFormData,
    FGSSLVPNUserBookmark,
    FGSSLVPNUserGroupBookmark,
)
from ..nodes import (
    ConfigNode,
    CommandNode,
    EditNode,
)

from .common import (
    evaluate_config,
    evaluate_edit,
    get_child_config,
    iter_section_configs,
    iter_section_edits,
    source_model_kwargs,
)
from .section_index import SectionIndex


class SSLVPNConfig(Protocol):
    """Minimal destination required by SSL-VPN extraction."""

    ssl_vpn_settings: list[FGSSLVPNSettings]
    ssl_vpn_portals: list[FGSSLVPNPortal]
    ssl_vpn_host_check_software: list[FGSSLVPNHostCheckSoftware]
    ssl_vpn_realms: list[FGSSLVPNRealm]
    ssl_vpn_clients: list[FGSSLVPNClient]
    ssl_vpn_user_bookmarks: list[FGSSLVPNUserBookmark]
    ssl_vpn_user_group_bookmarks: list[FGSSLVPNUserGroupBookmark]


def extract_ssl_vpn(
    tree: SectionIndex,
    config: SSLVPNConfig,
) -> None:
    _extract_settings(tree, config)
    _extract_portals(tree, config)
    _extract_host_check_software(tree, config)
    _extract_realms(tree, config)
    _extract_clients(tree, config)
    _extract_bookmark_owners(tree, config, "vpn ssl web user-bookmark", "ssl_vpn_user_bookmarks", FGSSLVPNUserBookmark)
    _extract_bookmark_owners(tree, config, "vpn ssl web user-group-bookmark", "ssl_vpn_user_group_bookmarks", FGSSLVPNUserGroupBookmark)


def _extract_bookmark_owners(tree: SectionIndex, config: SSLVPNConfig, section_path: str, destination: str, model_type) -> None:
    for source in iter_section_edits(tree, section_path):
        evaluation = evaluate_edit(section_path, source.edit)
        owner_values = source_model_kwargs(evaluation, model_type=model_type, vdom=source.vdom)
        owner_values["owner_name"] = source.edit.name
        bookmarks_config = get_child_config(source.edit, "bookmarks")
        if bookmarks_config is not None:
            owner_values["bookmarks"] = [
                _extract_ssl_bookmark(item, f"{section_path} bookmarks")
                for item in bookmarks_config.edits
            ]
        getattr(config, destination).append(model_type(**owner_values))


def _extract_ssl_bookmark(edit: EditNode, section_path: str) -> FGSSLVPNBookmark:
    evaluation = evaluate_edit(section_path, edit)
    values = source_model_kwargs(evaluation, model_type=FGSSLVPNBookmark, name=edit.name)
    secret_state = {"logon-password": False, "sso-password": False}
    for command in edit.commands:
        if isinstance(command, CommandNode) and command.key in secret_state:
            if command.operation.lower() in {"set", "append"}:
                secret_state[command.key] = True
            elif command.operation.lower() == "unset":
                secret_state[command.key] = False
    values["logon_password_configured"] = secret_state["logon-password"]
    values["sso_password_configured"] = secret_state["sso-password"]
    values["raw_extra"].pop("logon-password", None)
    values["raw_extra"].pop("sso-password", None)
    form_data_config = get_child_config(edit, "form-data")
    if form_data_config is not None:
        values["form_data"] = []
        for data_edit in form_data_config.edits:
            data_eval = evaluate_edit(f"{section_path} form-data", data_edit)
            data_values = source_model_kwargs(data_eval, model_type=FGSSLVPNBookmarkFormData, name=data_edit.name)
            values["form_data"].append(FGSSLVPNBookmarkFormData(**data_values))
    return FGSSLVPNBookmark(**values)


def _extract_realms(tree: SectionIndex, config: SSLVPNConfig) -> None:
    section_path = "vpn ssl web realm"
    for source in iter_section_edits(tree, section_path):
        evaluation = evaluate_edit(section_path, source.edit)
        attributes = source_model_kwargs(
            evaluation, model_type=FGSSLVPNRealm, vdom=source.vdom,
        )
        attributes["url_path"] = source.edit.name
        config.ssl_vpn_realms.append(FGSSLVPNRealm(**attributes))


def _extract_clients(tree: SectionIndex, config: SSLVPNConfig) -> None:
    section_path = "vpn ssl client"
    for source in iter_section_edits(tree, section_path):
        evaluation = evaluate_edit(section_path, source.edit)
        attributes = source_model_kwargs(
            evaluation, model_type=FGSSLVPNClient,
            name=source.edit.name, vdom=source.vdom,
        )
        psk_configured = False
        for command in source.edit.commands:
            if isinstance(command, CommandNode) and command.key == "psk":
                psk_configured = command.operation.lower() in {"set", "append"}
        attributes["psk_configured"] = psk_configured
        attributes["raw_extra"].pop("psk", None)
        config.ssl_vpn_clients.append(FGSSLVPNClient(**attributes))


def _extract_settings(
    tree: SectionIndex,
    config: SSLVPNConfig,
) -> None:
    section_path = "vpn ssl settings"

    for source in iter_section_configs(
        tree,
        section_path,
    ):
        evaluation = evaluate_config(
            section_path,
            source.config,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGSSLVPNSettings,
            vdom=source.vdom,
        )

        authentication_rule = get_child_config(
            source.config,
            "authentication-rule",
        )

        if authentication_rule is not None:
            attributes["authentication_rules"] = (
                _extract_authentication_rules(
                    authentication_rule
                )
            )

        config.ssl_vpn_settings.append(
            FGSSLVPNSettings(**attributes)
        )


def _extract_authentication_rules(
    section: ConfigNode,
) -> list[FGSSLVPNAuthenticationRule]:
    result: list[FGSSLVPNAuthenticationRule] = []

    section_path = (
        "vpn ssl settings authentication-rule"
    )

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGSSLVPNAuthenticationRule,
        )

        _set_structural_id(
            attributes,
            edit.name,
        )

        result.append(
            FGSSLVPNAuthenticationRule(
                **attributes
            )
        )

    return result


def _extract_portals(
    tree: SectionIndex,
    config: SSLVPNConfig,
) -> None:
    section_path = "vpn ssl web portal"

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
            model_type=FGSSLVPNPortal,
            name=source.edit.name,
            vdom=source.vdom,
        )

        config.ssl_vpn_portals.append(
            FGSSLVPNPortal(**attributes)
        )


def _extract_host_check_software(
    tree: SectionIndex,
    config: SSLVPNConfig,
) -> None:
    section_path = (
        "vpn ssl web host-check-software"
    )

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
            model_type=FGSSLVPNHostCheckSoftware,
            name=source.edit.name,
            vdom=source.vdom,
        )

        check_items = get_child_config(
            source.edit,
            "check-item-list",
        )

        if check_items is not None:
            attributes["check_items"] = (
                _extract_host_check_items(
                    check_items
                )
            )

        config.ssl_vpn_host_check_software.append(
            FGSSLVPNHostCheckSoftware(
                **attributes
            )
        )


def _extract_host_check_items(
    section: ConfigNode,
) -> list[FGSSLVPNHostCheckItem]:
    result: list[FGSSLVPNHostCheckItem] = []

    section_path = (
        "vpn ssl web host-check-software "
        "check-item-list"
    )

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGSSLVPNHostCheckItem,
        )

        _set_structural_id(
            attributes,
            edit.name,
        )

        result.append(
            FGSSLVPNHostCheckItem(
                **attributes
            )
        )

    return result


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
