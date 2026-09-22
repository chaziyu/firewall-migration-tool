from __future__ import annotations

from typing import Protocol

from ..model.vpn_ssl import (
    FGSSLVPNAuthenticationRule,
    FGSSLVPNHostCheckItem,
    FGSSLVPNHostCheckSoftware,
    FGSSLVPNPortal,
    FGSSLVPNSettings,
)
from ..nodes import (
    ConfigNode,
    FortiGateConfigTree,
)

from .common import (
    evaluate_config,
    evaluate_edit,
    get_child_config,
    iter_section_configs,
    iter_section_edits,
    source_model_kwargs,
)


class SSLVPNConfig(Protocol):
    """Minimal destination required by SSL-VPN extraction."""

    ssl_vpn_settings: list[FGSSLVPNSettings]
    ssl_vpn_portals: list[FGSSLVPNPortal]
    ssl_vpn_host_check_software: list[FGSSLVPNHostCheckSoftware]


def extract_ssl_vpn(
    tree: FortiGateConfigTree,
    config: SSLVPNConfig,
) -> None:
    _extract_settings(tree, config)
    _extract_portals(tree, config)
    _extract_host_check_software(tree, config)


def _extract_settings(
    tree: FortiGateConfigTree,
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
    tree: FortiGateConfigTree,
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
    tree: FortiGateConfigTree,
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