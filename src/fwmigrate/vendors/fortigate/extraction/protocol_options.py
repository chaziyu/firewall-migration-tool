from __future__ import annotations

from typing import Protocol

from ..model.firewall_policy_extra import FGProtocolOptionsProfile
from .common import evaluate_edit, iter_section_edits, source_model_kwargs
from .section_index import SectionIndex


class ProtocolOptionsConfig(Protocol):
    protocol_options: list[FGProtocolOptionsProfile]


def extract_protocol_options(tree: SectionIndex, config: ProtocolOptionsConfig) -> None:
    section_path = "firewall profile-protocol-options"
    for source in iter_section_edits(tree, section_path):
        evaluation = evaluate_edit(section_path, source.edit)
        attributes = source_model_kwargs(
            evaluation, model_type=FGProtocolOptionsProfile,
            name=source.edit.name, vdom=source.vdom,
        )
        config.protocol_options.append(FGProtocolOptionsProfile(**attributes))
