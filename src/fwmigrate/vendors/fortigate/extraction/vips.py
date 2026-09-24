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
from ..model.vip6 import FGVIP6, FGVIPGroup6
from .section_index import SectionIndex


class VIPConfig(Protocol):
    """Minimal destination required by VIP extraction."""

    vips: list[FGVIP]
    vip_groups: list[FGVIPGroup]
    vips6: list[FGVIP6]
    vip_groups6: list[FGVIPGroup6]


def extract_vips(
    tree: SectionIndex,
    config: VIPConfig,
) -> None:
    """Extract FortiGate VIP and VIP-group source objects."""

    _extract_vip_objects(tree, config)
    _extract_vip_groups(tree, config)
    _extract_vip6_objects(tree, config)
    _extract_vip6_groups(tree, config)


def _extract_vip6_objects(tree: SectionIndex, config: VIPConfig) -> None:
    section_path = "firewall vip6"
    for source in iter_section_edits(tree, section_path):
        evaluation = evaluate_edit(section_path, source.edit)
        attributes = source_model_kwargs(
            evaluation, model_type=FGVIP6, name=source.edit.name, vdom=source.vdom
        )
        config.vips6.append(FGVIP6(**attributes))


def _extract_vip6_groups(tree: SectionIndex, config: VIPConfig) -> None:
    section_path = "firewall vipgrp6"
    for source in iter_section_edits(tree, section_path):
        evaluation = evaluate_edit(section_path, source.edit)
        attributes = source_model_kwargs(
            evaluation, model_type=FGVIPGroup6, name=source.edit.name, vdom=source.vdom,
            field_map={"member": "members"},
        )
        config.vip_groups6.append(FGVIPGroup6(**attributes))


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
