"""Registered PAN-OS parser with domain-safe effective-order synchronization."""
from __future__ import annotations

from .policy_nat_coverage import PANOSSourceParser as _CoveragePANOSSourceParser


_EFFECTIVE_ORDER_KEYS = (
    "effective_policy_layer",
    "effective_policy_rank",
    "effective_scope_chain",
    "effective_rule_index",
    "effective_order_complete",
    "pan_effective_order_by_context",
)


class PANOSSourceParser(_CoveragePANOSSourceParser):
    """Final registered PAN-OS parser."""

    @staticmethod
    def _sync_effective_order_to_ir(extraction) -> None:
        # Security and NAT source IDs intentionally use the same stable shape.
        # Keep their lookup domains separate so a same-name/same-index NAT rule
        # can never overwrite Security policy effective-order evidence.
        policy_by_id = {
            item.source_attributes.get("pan_source_rule_id"): item
            for item in extraction.inventory_items
            if item.domain == "policies" and item.source_attributes.get("pan_source_rule_id")
        }
        nat_by_id = {
            item.source_attributes.get("pan_source_rule_id"): item
            for item in extraction.inventory_items
            if item.domain == "nat" and item.source_attributes.get("pan_source_rule_id")
        }

        for policy in extraction.canonical_ir.policies:
            item = policy_by_id.get(policy.source_rule_id)
            if item is None:
                continue
            for key in _EFFECTIVE_ORDER_KEYS:
                if key in item.source_attributes:
                    policy.source_extra_settings[key] = item.source_attributes[key]
                else:
                    policy.source_extra_settings.pop(key, None)
            applicability = item.source_attributes.get("pan_target_applicability_by_context")
            if applicability is not None:
                policy.source_extra_settings["pan_target_applicability_by_context"] = applicability

        for rule in extraction.canonical_ir.nat_rules:
            item = nat_by_id.get(rule.source_rule_id)
            if item is None:
                continue
            for key in _EFFECTIVE_ORDER_KEYS:
                if key in item.source_attributes:
                    rule.source_attributes[key] = item.source_attributes[key]
                else:
                    rule.source_attributes.pop(key, None)
            applicability = item.source_attributes.get("pan_target_applicability_by_context")
            if applicability is not None:
                rule.source_attributes["pan_target_applicability_by_context"] = applicability
