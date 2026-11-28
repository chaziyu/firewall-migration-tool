from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from ..model.interface import (
    FGInterface,
    FGInterfaceIPv6,
    FGInterfaceSecondaryIP,
)
from ..nodes import (
    EditNode,
)

from .common import (
    combine_source_edits,
    evaluate_config,
    evaluate_edit_sequence,
    get_child_config,
    iter_section_edits,
    source_model_kwargs,
)
from .section_index import SectionIndex


class InterfaceConfig(Protocol):
    """Minimal destination required by interface extraction."""

    interfaces: list[FGInterface]


def extract_interfaces(
    tree: SectionIndex,
    config: InterfaceConfig,
) -> None:
    """Extract FortiGate system-interface source objects."""

    section_path = "system interface"

    grouped: dict[tuple[str | None, str, str], list[EditNode]] = {}
    for source in iter_section_edits(tree, section_path):
        grouped.setdefault((source.vdom, source.cli_scope, source.edit.name), []).append(source.edit)

    for (vdom, cli_scope, name), edits in grouped.items():
        evaluation = evaluate_edit_sequence(
            section_path,
            edits,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGInterface,
            name=name,
            vdom=vdom,
            field_map={
                "member": "members",
            },
        )

        attributes["cli_vdom"] = vdom
        attributes["cli_scope"] = cli_scope
        attributes["unset_fields"] = evaluation.unset_fields
        if "vdom" in evaluation.unset_fields or "unparsed_vdom" in evaluation.untyped_values:
            attributes["vdom"] = None

        attributes["secondary_ips"] = (
            _extract_secondary_ips(
                child_edit
                for edit in edits
                for child in edit.children
                if child.name == "secondaryip"
                for child_edit in child.edits
            )
        )
        combined = combine_source_edits(edits)
        ipv6_cfg = get_child_config(combined, "ipv6")
        if ipv6_cfg is not None:
            ipv6_eval = evaluate_config("system interface ipv6", ipv6_cfg)
            ipv6_attrs = source_model_kwargs(ipv6_eval, model_type=FGInterfaceIPv6)
            attributes["ipv6"] = FGInterfaceIPv6(**ipv6_attrs)

        config.interfaces.append(
            FGInterface(**attributes)
        )


def _extract_secondary_ips(
    edits: Iterable[EditNode],
) -> list[FGInterfaceSecondaryIP]:
    result: list[FGInterfaceSecondaryIP] = []

    section_path = "system interface secondaryip"
    grouped: dict[str, list[EditNode]] = {}
    for edit in edits:
        grouped.setdefault(edit.name, []).append(edit)

    for name, matching_edits in grouped.items():
        evaluation = evaluate_edit_sequence(
            section_path,
            matching_edits,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGInterfaceSecondaryIP,
        )

        try:
            attributes["id"] = int(name)
        except ValueError:
            attributes["id"] = None
            attributes["raw_extra"]["unparsed_id"] = (
                name
            )

        result.append(
            FGInterfaceSecondaryIP(**attributes)
        )

    return result
