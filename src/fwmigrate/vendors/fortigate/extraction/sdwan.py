from __future__ import annotations

from typing import Protocol

from ..model.sdwan import (
    FGSDWAN,
    FGSDWANHealthCheck,
    FGSDWANMember,
    FGSDWANService,
    FGSDWANZone,
)
from ..nodes import (
    ConfigNode,
    FortiGateConfigTree,
)

from .common import (
    evaluate_config,
    evaluate_edit,
    iter_section_configs,
    source_model_kwargs,
)


class SDWANConfig(Protocol):
    """Minimal destination required by SD-WAN extraction."""

    sdwans: list[FGSDWAN]


def extract_sdwan(
    tree: FortiGateConfigTree,
    config: SDWANConfig,
) -> None:
    """
    Extract FortiGate SD-WAN source configuration.

    One FGSDWAN object is created for each VDOM containing
    `config system sdwan`.
    """

    section_path = "system sdwan"

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
            model_type=FGSDWAN,
            vdom=source.vdom,
        )

        sdwan = FGSDWAN(**attributes)

        for child in source.config.children:
            if child.name == "zone":
                sdwan.zones.extend(
                    _extract_zones(child)
                )

            elif child.name == "members":
                sdwan.members.extend(
                    _extract_members(child)
                )

            elif child.name == "health-check":
                sdwan.health_checks.extend(
                    _extract_health_checks(child)
                )

            elif child.name == "service":
                sdwan.services.extend(
                    _extract_services(child)
                )

        config.sdwans.append(sdwan)


def _extract_zones(
    section: ConfigNode,
) -> list[FGSDWANZone]:
    result: list[FGSDWANZone] = []

    section_path = "system sdwan zone"

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGSDWANZone,
            name=edit.name,
        )

        result.append(
            FGSDWANZone(**attributes)
        )

    return result


def _extract_members(
    section: ConfigNode,
) -> list[FGSDWANMember]:
    result: list[FGSDWANMember] = []

    section_path = "system sdwan members"

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGSDWANMember,
        )

        # FortiGate source identity:
        #
        # config members
        #     edit <seq-num>
        #
        try:
            attributes["seq_num"] = int(
                edit.name
            )
        except ValueError:
            attributes["seq_num"] = None
            attributes["raw_extra"][
                "unparsed_seq_num"
            ] = edit.name

        result.append(
            FGSDWANMember(**attributes)
        )

    return result


def _extract_health_checks(
    section: ConfigNode,
) -> list[FGSDWANHealthCheck]:
    result: list[FGSDWANHealthCheck] = []

    section_path = "system sdwan health-check"

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGSDWANHealthCheck,
            name=edit.name,
        )

        result.append(
            FGSDWANHealthCheck(**attributes)
        )

    return result


def _extract_services(
    section: ConfigNode,
) -> list[FGSDWANService]:
    result: list[FGSDWANService] = []

    section_path = "system sdwan service"

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGSDWANService,
        )

        # FortiGate source identity:
        #
        # config service
        #     edit <id>
        #
        try:
            attributes["id"] = int(
                edit.name
            )
        except ValueError:
            attributes["id"] = None
            attributes["raw_extra"][
                "unparsed_id"
            ] = edit.name

        result.append(
            FGSDWANService(**attributes)
        )

    return result