from __future__ import annotations

from typing import Protocol

from ..model.interface import (
    FGInterface,
    FGInterfaceSecondaryIP,
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


class InterfaceConfig(Protocol):
    """Minimal destination required by interface extraction."""

    interfaces: list[FGInterface]


def extract_interfaces(
    tree: SectionIndex,
    config: InterfaceConfig,
) -> None:
    """Extract FortiGate system-interface source objects."""

    section_path = "system interface"

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
            model_type=FGInterface,
            name=source.edit.name,
            vdom=source.vdom,
            field_map={
                "member": "members",
            },
        )

        secondary_config = get_child_config(
            source.edit,
            "secondaryip",
        )

        attributes["secondary_ips"] = (
            _extract_secondary_ips(
                secondary_config,
            )
            if secondary_config is not None
            else []
        )

        config.interfaces.append(
            FGInterface(**attributes)
        )


def _extract_secondary_ips(
    section: ConfigNode,
) -> list[FGInterfaceSecondaryIP]:
    result: list[FGInterfaceSecondaryIP] = []

    section_path = "system interface secondaryip"

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGInterfaceSecondaryIP,
        )

        try:
            attributes["id"] = int(edit.name)
        except ValueError:
            attributes["id"] = None
            attributes["raw_extra"]["unparsed_id"] = (
                edit.name
            )

        result.append(
            FGInterfaceSecondaryIP(**attributes)
        )

    return result
