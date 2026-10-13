from __future__ import annotations

from typing import Protocol

from ..model.policy import FGPolicy

from .common import (
    evaluate_edit_sequence,
    iter_grouped_section_edits,
    source_model_kwargs,
)
from .section_index import SectionIndex


class PolicyConfig(Protocol):
    """Minimal destination required by firewall-policy extraction."""

    policies: list[FGPolicy]


def extract_policies(
    tree: SectionIndex,
    config: PolicyConfig,
) -> None:
    """
    Extract FortiGate firewall-policy source objects.

    This layer does not:
        - resolve interfaces
        - resolve addresses/services
        - resolve VIPs
        - resolve IP pools
        - apply FortiOS defaults
        - derive NAT rules
        - derive policy semantics
        - validate references
    """

    section_path = "firewall policy"

    for source, edits in iter_grouped_section_edits(tree, section_path):
        evaluation = evaluate_edit_sequence(section_path, edits)

        attributes = source_model_kwargs(
            evaluation,
            model_type=FGPolicy,
            vdom=source.vdom,
        )

        # FortiGate source identity:
        #
        # config firewall policy
        #     edit <policyid>
        #
        # The policy ID is structural source data, not a set command.
        try:
            attributes["policy_id"] = int(
                source.edit.name
            )
        except ValueError:
            attributes["policy_id"] = None
            attributes["raw_extra"][
                "unparsed_policy_id"
            ] = source.edit.name

        config.policies.append(
            FGPolicy(**attributes)
        )
