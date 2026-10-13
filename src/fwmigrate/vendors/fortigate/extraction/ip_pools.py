from __future__ import annotations

from typing import Protocol

from ..model.ippool import FGIPPool
from ..model.ippool6 import FGIPPool6

from .common import (
    evaluate_edit,
    iter_section_edits,
    source_model_kwargs,
)
from .section_index import SectionIndex


class IPPoolConfig(Protocol):
    """Minimal destination required by IP-pool extraction."""

    ip_pools: list[FGIPPool]
    ip_pools6: list[FGIPPool6]


def extract_ip_pools(
    tree: SectionIndex,
    config: IPPoolConfig,
) -> None:
    """Extract FortiGate firewall IP-pool source objects."""

    section_path = "firewall ippool"

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
            model_type=FGIPPool,
            name=source.edit.name,
            vdom=source.vdom,
        )

        config.ip_pools.append(
            FGIPPool(**attributes)
        )

    section_path = "firewall ippool6"
    for source in iter_section_edits(tree, section_path):
        evaluation = evaluate_edit(section_path, source.edit)
        attributes = source_model_kwargs(
            evaluation, model_type=FGIPPool6, name=source.edit.name, vdom=source.vdom
        )
        config.ip_pools6.append(FGIPPool6(**attributes))
