from __future__ import annotations

from typing import Protocol

from ..model.firewall_policy_extra import FGSecurityPolicy
from .common import evaluate_edit, iter_section_edits, source_model_kwargs
from .section_index import SectionIndex


class SecurityPolicyConfig(Protocol):
    security_policies: list[FGSecurityPolicy]


def extract_security_policies(tree: SectionIndex, config: SecurityPolicyConfig) -> None:
    section_path = "firewall security-policy"
    for source in iter_section_edits(tree, section_path):
        evaluation = evaluate_edit(section_path, source.edit)
        attributes = source_model_kwargs(evaluation, model_type=FGSecurityPolicy, vdom=source.vdom)
        try:
            attributes["policy_id"] = int(source.edit.name)
        except ValueError:
            attributes["policy_id"] = None
            attributes["raw_extra"]["unparsed_policy_id"] = source.edit.name
        config.security_policies.append(FGSecurityPolicy(**attributes))
