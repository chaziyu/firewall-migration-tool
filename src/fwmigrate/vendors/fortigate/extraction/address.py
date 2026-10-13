from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from ..model.address import (
    FGAddress,
    FGAddressGroup,
    FGAddressGroupTaggingEntry,
    FGAddressTaggingEntry,
    FGWildcardFQDN,
)
from ..nodes import (
    EditNode,
)

from .common import (
    evaluate_edit_sequence,
    iter_grouped_section_edits,
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
    for source, edits in iter_grouped_section_edits(tree, section_path):
        evaluation = evaluate_edit_sequence(section_path, edits)

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
            attributes["tagging"] = _extract_address_tagging(
                child_edit for edit in edits for child in edit.children
                if child.name == "tagging" for child_edit in child.edits
            )

        config.addresses.append(
            FGAddress(**attributes)
        )


def _extract_address_tagging(
    edits: Iterable[EditNode],
) -> list[FGAddressTaggingEntry]:
    result: list[FGAddressTaggingEntry] = []

    section_path = "firewall address tagging"

    grouped: dict[str, list[EditNode]] = {}
    for edit in edits:
        grouped.setdefault(edit.name, []).append(edit)
    for name, matching_edits in grouped.items():
        evaluation = evaluate_edit_sequence(section_path, matching_edits)

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGAddressTaggingEntry,
            name=name,
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
    for source, edits in iter_grouped_section_edits(tree, section_path):
        evaluation = evaluate_edit_sequence(section_path, edits)

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
            attributes["tagging"] = _extract_group_tagging(
                child_edit for edit in edits for child in edit.children
                if child.name == "tagging" for child_edit in child.edits
            )

        config.address_groups.append(
            FGAddressGroup(**attributes)
        )


def _extract_group_tagging(
    edits: Iterable[EditNode],
) -> list[FGAddressGroupTaggingEntry]:
    result: list[FGAddressGroupTaggingEntry] = []

    section_path = "firewall addrgrp tagging"

    grouped: dict[str, list[EditNode]] = {}
    for edit in edits:
        grouped.setdefault(edit.name, []).append(edit)
    for name, matching_edits in grouped.items():
        evaluation = evaluate_edit_sequence(section_path, matching_edits)

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGAddressGroupTaggingEntry,
            name=name,
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

    for source, edits in iter_grouped_section_edits(tree, section_path):
        evaluation = evaluate_edit_sequence(section_path, edits)

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGWildcardFQDN,
            name=source.edit.name,
            vdom=source.vdom,
        )

        config.wildcard_fqdns.append(
            FGWildcardFQDN(**attributes)
        )
