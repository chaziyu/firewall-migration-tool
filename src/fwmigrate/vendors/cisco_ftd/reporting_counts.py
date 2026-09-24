"""Known nested record counts for Cisco FTD reports."""

from __future__ import annotations

from .model import CiscoFTDConfig


def count_acp_rules(config: CiscoFTDConfig) -> int:
    return sum(len(policy.rules or []) for policy in config.access_control_policies)


def count_nat_rules(config: CiscoFTDConfig) -> int:
    return sum(
        len(rules or [])
        for policy in config.nat_policies
        for rules in (policy.manual_rules_before_auto, policy.auto_rules, policy.manual_rules_after_auto,
                      policy.unclassified_manual_rules, policy.rules)
    )
