from __future__ import annotations

from typing import Protocol

from ..model.firewall_policy_extra import FGPerIPShaper
from .common import evaluate_edit, iter_section_edits, source_model_kwargs
from .section_index import SectionIndex


class ShaperConfig(Protocol):
    per_ip_shapers: list[FGPerIPShaper]


def extract_per_ip_shapers(tree: SectionIndex, config: ShaperConfig) -> None:
    section_path = "firewall shaper per-ip-shaper"
    for source in iter_section_edits(tree, section_path):
        evaluation = evaluate_edit(section_path, source.edit)
        attributes = source_model_kwargs(
            evaluation, model_type=FGPerIPShaper, name=source.edit.name, vdom=source.vdom
        )
        config.per_ip_shapers.append(FGPerIPShaper(**attributes))
