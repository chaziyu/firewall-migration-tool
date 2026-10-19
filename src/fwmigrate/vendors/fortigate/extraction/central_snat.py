"""Extract ordered central SNAT source structure without applying defaults."""

from ..model.central_snat import FGCentralSNAT
from .common import (
    evaluate_edit_sequence,
    iter_grouped_section_edits,
    source_model_kwargs,
)


def extract_central_snat(index, config):
    section = "firewall central-snat-map"
    for source, edits in iter_grouped_section_edits(index, section):
        attributes = source_model_kwargs(
            evaluate_edit_sequence(section, edits),
            model_type=FGCentralSNAT,
            vdom=source.vdom,
        )
        try:
            attributes["policy_id"] = int(source.edit.name)
        except ValueError:
            attributes["raw_extra"]["unparsed_policy_id"] = source.edit.name
        config.central_snat.append(FGCentralSNAT(**attributes))
