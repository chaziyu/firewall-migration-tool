from __future__ import annotations

from typing import Protocol

from ..model.session_helper import FGSessionHelper
from .common import evaluate_edit, iter_section_edits, source_model_kwargs
from .section_index import SectionIndex


class SessionHelperConfig(Protocol):
    session_helpers: list[FGSessionHelper]


def extract_session_helpers(tree: SectionIndex, config: SessionHelperConfig) -> None:
    section_path = "system session-helper"
    for source in iter_section_edits(tree, section_path):
        evaluation = evaluate_edit(section_path, source.edit)
        attributes = source_model_kwargs(
            evaluation, model_type=FGSessionHelper, vdom=source.vdom
        )
        try:
            attributes["id"] = int(source.edit.name)
        except ValueError:
            attributes["id"] = None
            attributes["raw_extra"]["unparsed_id"] = source.edit.name
        config.session_helpers.append(FGSessionHelper(**attributes))
