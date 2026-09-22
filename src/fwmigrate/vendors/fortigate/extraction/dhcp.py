from __future__ import annotations

from typing import Protocol

from ..model.dhcp import (
    FGDHCPExcludeRange,
    FGDHCPIPRange,
    FGDHCPReservedAddress,
    FGDHCPServer,
)
from ..nodes import (
    ConfigNode,
    FortiGateConfigTree,
)

from .common import (
    evaluate_edit,
    get_child_config,
    iter_section_edits,
    source_model_kwargs,
)


class DHCPConfig(Protocol):
    """Minimal destination required by DHCP extraction."""

    dhcp_servers: list[FGDHCPServer]


def extract_dhcp(
    tree: FortiGateConfigTree,
    config: DHCPConfig,
) -> None:
    """Extract FortiGate DHCP server source objects."""

    section_path = "system dhcp server"

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
            model_type=FGDHCPServer,
            vdom=source.vdom,
        )

        try:
            attributes["id"] = int(
                source.edit.name
            )
        except ValueError:
            attributes["id"] = None
            attributes["raw_extra"][
                "unparsed_id"
            ] = source.edit.name

        ip_range = get_child_config(
            source.edit,
            "ip-range",
        )

        if ip_range is not None:
            attributes["ip_ranges"] = (
                _extract_ip_ranges(ip_range)
            )

        exclude_range = get_child_config(
            source.edit,
            "exclude-range",
        )

        if exclude_range is not None:
            attributes["exclude_ranges"] = (
                _extract_exclude_ranges(
                    exclude_range
                )
            )

        reserved_address = get_child_config(
            source.edit,
            "reserved-address",
        )

        if reserved_address is not None:
            attributes["reserved_addresses"] = (
                _extract_reserved_addresses(
                    reserved_address
                )
            )

        config.dhcp_servers.append(
            FGDHCPServer(**attributes)
        )


def _extract_ip_ranges(
    section: ConfigNode,
) -> list[FGDHCPIPRange]:
    result: list[FGDHCPIPRange] = []

    section_path = "system dhcp server ip-range"

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGDHCPIPRange,
        )

        _set_structural_id(
            attributes,
            edit.name,
        )

        result.append(
            FGDHCPIPRange(**attributes)
        )

    return result


def _extract_exclude_ranges(
    section: ConfigNode,
) -> list[FGDHCPExcludeRange]:
    result: list[FGDHCPExcludeRange] = []

    section_path = (
        "system dhcp server exclude-range"
    )

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGDHCPExcludeRange,
        )

        _set_structural_id(
            attributes,
            edit.name,
        )

        result.append(
            FGDHCPExcludeRange(**attributes)
        )

    return result


def _extract_reserved_addresses(
    section: ConfigNode,
) -> list[FGDHCPReservedAddress]:
    result: list[FGDHCPReservedAddress] = []

    section_path = (
        "system dhcp server reserved-address"
    )

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGDHCPReservedAddress,
        )

        _set_structural_id(
            attributes,
            edit.name,
        )

        result.append(
            FGDHCPReservedAddress(**attributes)
        )

    return result


def _set_structural_id(
    attributes: dict,
    raw_id: str,
) -> None:
    """
    Preserve FortiGate `edit <id>` identity without
    discarding malformed source entries.
    """

    try:
        attributes["id"] = int(raw_id)
    except ValueError:
        attributes["id"] = None
        attributes["raw_extra"][
            "unparsed_id"
        ] = raw_id