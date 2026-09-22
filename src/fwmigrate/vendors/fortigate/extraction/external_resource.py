from __future__ import annotations

from typing import Protocol

from ..model.external_resource import FGExternalResource
from ..nodes import FortiGateConfigTree

from .common import (
    evaluate_edit,
    iter_section_edits,
    source_model_kwargs,
)


class ExternalResourceConfig(Protocol):
    external_resources: list[FGExternalResource]


def extract_external_resources(
    tree: FortiGateConfigTree,
    config: ExternalResourceConfig,
) -> None:
    section_path = "system external-resource"

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
            model_type=FGExternalResource,
            name=source.edit.name,
            vdom=source.vdom,
        )

        # Never retain credential material.
        attributes["raw_extra"].pop(
            "password",
            None,
        )

        config.external_resources.append(
            FGExternalResource(**attributes)
        )