from __future__ import annotations

from typing import Protocol

from ..model.address import (
    FGAddress,
    FGAddressGroup,
    FGAddressGroupTaggingEntry,
    FGAddressTaggingEntry,
    FGWildcardFQDN,
)
from ..nodes import (
    ConfigNode,
)

from .common import (
    evaluate_edit,
    get_child_config,
    iter_section_edits,
    source_model_kwargs,
)
from .section_index import SectionIndex


class AddressConfig(Protocol):
    """
    Minimal destination required by address extraction.

    This avoids coupling the address extractor to a large aggregate
    configuration model.
    """

    addresses: list[FGAddress]
    address_groups: list[FGAddressGroup]
    wildcard_fqdns: list[FGWildcardFQDN]


def extract_addresses(
    tree: SectionIndex,
    config: AddressConfig,
) -> None:
    """Extract FortiGate address-domain source objects."""

    _extract_address_family(
        tree,
        config,
        section_path="firewall address",
        address_family="ipv4",
    )

    _extract_address_family(
        tree,
        config,
        section_path="firewall address6",
        address_family="ipv6",
    )

    _extract_address_groups(
        tree,
        config,
        section_path="firewall addrgrp",
        address_family="ipv4",
    )

    _extract_address_groups(
        tree,
        config,
        section_path="firewall addrgrp6",
        address_family="ipv6",
    )

    _extract_wildcard_fqdns(
        tree,
        config,
    )


def _extract_address_family(
    tree: SectionIndex,
    config: AddressConfig,
    *,
    section_path: str,
    address_family: str,
) -> None:
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
            model_type=FGAddress,
            name=source.edit.name,
            vdom=source.vdom,
        )

        attributes["address_family"] = address_family

        # Object tagging is currently declared for:
        #
        # config firewall address
        #     edit ...
        #         config tagging
        #
        # Do not invent equivalent address6 behavior unless it is
        # explicitly supported by the source registry/reference.
        if section_path == "firewall address":
            tagging = get_child_config(
                source.edit,
                "tagging",
            )

            attributes["tagging"] = (
                _extract_address_tagging(tagging)
                if tagging is not None
                else []
            )

        config.addresses.append(
            FGAddress(**attributes)
        )


def _extract_address_tagging(
    section: ConfigNode,
) -> list[FGAddressTaggingEntry]:
    result: list[FGAddressTaggingEntry] = []

    section_path = "firewall address tagging"

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGAddressTaggingEntry,
            name=edit.name,
        )

        result.append(
            FGAddressTaggingEntry(
                **attributes
            )
        )

    return result


def _extract_address_groups(
    tree: SectionIndex,
    config: AddressConfig,
    *,
    section_path: str,
    address_family: str,
) -> None:
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
            model_type=FGAddressGroup,
            name=source.edit.name,
            vdom=source.vdom,
            field_map={
                "member": "members",
                "exclude_member": "exclude_members",
            },
        )
        attributes["address_family"] = address_family

        # Tagging is currently explicitly declared for firewall addrgrp.
        if section_path == "firewall addrgrp":
            tagging = get_child_config(
                source.edit,
                "tagging",
            )

            attributes["tagging"] = (
                _extract_group_tagging(tagging)
                if tagging is not None
                else []
            )

        config.address_groups.append(
            FGAddressGroup(**attributes)
        )


def _extract_group_tagging(
    section: ConfigNode,
) -> list[FGAddressGroupTaggingEntry]:
    result: list[FGAddressGroupTaggingEntry] = []

    section_path = "firewall addrgrp tagging"

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGAddressGroupTaggingEntry,
            name=edit.name,
        )

        result.append(
            FGAddressGroupTaggingEntry(
                **attributes
            )
        )

    return result


def _extract_wildcard_fqdns(
    tree: SectionIndex,
    config: AddressConfig,
) -> None:
    section_path = "firewall wildcard-fqdn custom"

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
            model_type=FGWildcardFQDN,
            name=source.edit.name,
            vdom=source.vdom,
        )

        config.wildcard_fqdns.append(
            FGWildcardFQDN(**attributes)
        )
