from __future__ import annotations

from typing import Protocol

from ..model.ips import (
    FGIPSExemptIP,
    FGIPSSensor,
    FGIPSSensorEntry,
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


class IPSConfig(Protocol):
    """Minimal destination required by IPS extraction."""

    ips_sensors: list[FGIPSSensor]


def extract_ips(
    tree: SectionIndex,
    config: IPSConfig,
) -> None:
    """Extract FortiGate IPS sensor source objects."""

    section_path = "ips sensor"

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
            model_type=FGIPSSensor,
            name=source.edit.name,
            vdom=source.vdom,
        )

        entries = get_child_config(
            source.edit,
            "entries",
        )

        if entries is not None:
            attributes["entries"] = _extract_entries(
                entries
            )

        config.ips_sensors.append(
            FGIPSSensor(**attributes)
        )


def _extract_entries(
    section: ConfigNode,
) -> list[FGIPSSensorEntry]:
    result: list[FGIPSSensorEntry] = []

    section_path = "ips sensor entries"

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGIPSSensorEntry,
        )

        # FortiGate source identity:
        #
        # config entries
        #     edit <id>
        #
        try:
            attributes["id"] = int(edit.name)
        except ValueError:
            attributes["id"] = None
            attributes["raw_extra"][
                "unparsed_id"
            ] = edit.name

        exempt_ip = get_child_config(
            edit,
            "exempt-ip",
        )

        if exempt_ip is not None:
            attributes["exempt_ips"] = (
                _extract_exempt_ips(
                    exempt_ip
                )
            )

        result.append(
            FGIPSSensorEntry(**attributes)
        )

    return result


def _extract_exempt_ips(
    section: ConfigNode,
) -> list[FGIPSExemptIP]:
    result: list[FGIPSExemptIP] = []

    section_path = (
        "ips sensor entries exempt-ip"
    )

    for edit in section.edits:
        evaluation = evaluate_edit(
            section_path,
            edit,
        )

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGIPSExemptIP,
        )

        # FortiGate source identity:
        #
        # config exempt-ip
        #     edit <id>
        #
        try:
            attributes["id"] = int(edit.name)
        except ValueError:
            attributes["id"] = None
            attributes["raw_extra"][
                "unparsed_id"
            ] = edit.name

        result.append(
            FGIPSExemptIP(**attributes)
        )

    return result
