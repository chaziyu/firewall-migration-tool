from __future__ import annotations

from typing import Protocol

from ..model.vip import (
    FGVIP,
    FGVIPGroup,
    FGVIPRealServer,
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


class VIPConfig(Protocol):
    """Minimal destination required by VIP extraction."""

    vips: list[FGVIP]
    vip_groups: list[FGVIPGroup]


def extract_vips(
    tree: SectionIndex,
    config: VIPConfig,
) -> None:
    """Extract FortiGate VIP and VIP-group source objects."""

    _extract_vip_objects(tree, config)
    _extract_vip_groups(tree, config)


def _extract_vip_objects(
    tree: SectionIndex,
    config: VIPConfig,
) -> None:
    section_path = "firewall vip"

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
            model_type=FGVIP,
            name=source.edit.name,
            vdom=source.vdom,
        )

        realservers = get_child_config(
            source.edit,
            "realservers",
        )

        attributes["realservers"] = (
            _extract_realservers(realservers)
            if realservers is not None
            else []
        )

        config.vips.append(
            FGVIP(**attributes)
        )


def _extract_realservers(
    section: ConfigNode,
) -> list[FGVIPRealServer]:
    result: list[FGVIPRealServer] = []

    section_path = "firewall vip realservers"

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGVIPRealServer,
        )

        try:
            attributes["id"] = int(edit.name)
        except ValueError:
            attributes["id"] = None
            attributes["raw_extra"]["unparsed_id"] = (
                edit.name
            )

        result.append(
            FGVIPRealServer(**attributes)
        )

    return result


def _extract_vip_groups(
    tree: SectionIndex,
    config: VIPConfig,
) -> None:
    section_path = "firewall vipgrp"

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
            model_type=FGVIPGroup,
            name=source.edit.name,
            vdom=source.vdom,
            field_map={
                "member": "members",
            },
        )

        config.vip_groups.append(
            FGVIPGroup(**attributes)
        )
