from __future__ import annotations

from typing import Protocol

from ..model.zone import (
    FGZone,
    FGZoneTaggingEntry,
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


class ZoneConfig(Protocol):
    """Minimal destination required by zone extraction."""

    zones: list[FGZone]


def extract_zones(
    tree: FortiGateConfigTree,
    config: ZoneConfig,
) -> None:
    """Extract FortiGate system-zone source objects."""

    section_path = "system zone"

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
            model_type=FGZone,
            name=source.edit.name,
            vdom=source.vdom,
            field_map={
                "interface": "members",
            },
        )

        tagging = get_child_config(
            source.edit,
            "tagging",
        )

        if tagging is not None:
            attributes["tagging"] = (
                _extract_tagging(tagging)
            )

        config.zones.append(
            FGZone(**attributes)
        )


def _extract_tagging(
    section: ConfigNode,
) -> list[FGZoneTaggingEntry]:
    result: list[FGZoneTaggingEntry] = []

    section_path = "system zone tagging"

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGZoneTaggingEntry,
            name=edit.name,
        )

        result.append(
            FGZoneTaggingEntry(**attributes)
        )

    return result