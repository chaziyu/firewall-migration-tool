from __future__ import annotations

from typing import Protocol

from ..model.security_profile import FGProfileGroup

from .common import (
    evaluate_edit,
    iter_section_edits,
    source_model_kwargs,
)
from .section_index import SectionIndex


class ProfileGroupConfig(Protocol):
    """Minimal destination required by profile-group extraction."""

    profile_groups: list[FGProfileGroup]


def extract_profile_groups(
    tree: SectionIndex,
    config: ProfileGroupConfig,
) -> None:
    """Extract FortiGate security profile-group source objects."""

    section_path = "firewall profile-group"

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
            model_type=FGProfileGroup,
            name=source.edit.name,
            vdom=source.vdom,
        )

        config.profile_groups.append(
            FGProfileGroup(**attributes)
        )
