from __future__ import annotations

from typing import Protocol

from ..model.service import (
    FGService,
    FGServiceCategory,
    FGServiceGroup,
)

from .common import (
    evaluate_edit,
    iter_section_edits,
    source_model_kwargs,
)
from .section_index import SectionIndex


class ServiceConfig(Protocol):
    """
    Minimal destination required by service extraction.

    Keeps this extractor independent from the aggregate configuration model.
    """

    service_categories: list[FGServiceCategory]
    services: list[FGService]
    service_groups: list[FGServiceGroup]


def extract_services(
    tree: SectionIndex,
    config: ServiceConfig,
) -> None:
    """Extract FortiGate service-domain source objects."""

    _extract_categories(tree, config)
    _extract_custom_services(tree, config)
    _extract_service_groups(tree, config)


def _extract_categories(
    tree: SectionIndex,
    config: ServiceConfig,
) -> None:
    section_path = "firewall service category"

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
            model_type=FGServiceCategory,
            name=source.edit.name,
            vdom=source.vdom,
        )

        config.service_categories.append(
            FGServiceCategory(**attributes)
        )


def _extract_custom_services(
    tree: SectionIndex,
    config: ServiceConfig,
) -> None:
    section_path = "firewall service custom"

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
            model_type=FGService,
            name=source.edit.name,
            vdom=source.vdom,
        )

        config.services.append(
            FGService(**attributes)
        )


def _extract_service_groups(
    tree: SectionIndex,
    config: ServiceConfig,
) -> None:
    section_path = "firewall service group"

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
            model_type=FGServiceGroup,
            name=source.edit.name,
            vdom=source.vdom,
            field_map={
                "member": "members",
            },
        )

        config.service_groups.append(
            FGServiceGroup(**attributes)
        )
