"""Registered PAN-OS parser with domain-safe effective-order synchronization."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fwmigrate.extraction.models import ExtractionStatus

from .policy_nat_coverage import PANOSSourceParser as _CoveragePANOSSourceParser
from .source_model import PANScope


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

    def _enhance_nat_rule(self, scope: PANScope, entry, extraction, rule) -> None:
        super()._enhance_nat_rule(scope, entry, extraction, rule)
        if not rule.source_rule_id:
            return
        rule.source_attributes["pan_source_rule_id"] = rule.source_rule_id
        item = self._inventory_item(extraction, "nat", scope, entry.get("name"))
        if item is not None:
            item.source_attributes["pan_source_rule_id"] = rule.source_rule_id

    def _managed_nat_chain(self, device_group: Optional[str]) -> tuple[List[str], bool]:
        if not device_group:
            return [], True
        parents = dict(self.resolver._dg_parents)
        chain = [device_group]
        visited = {device_group}
        current = device_group
        complete = True
        while current in parents:
            parent = parents[current]
            if parent in visited:
                complete = False
                break
            visited.add(parent)
            chain.append(parent)
            current = parent
        chain.reverse()
        return chain, complete

    @staticmethod
    def _nat_rules_for_scope(
        extraction,
        kind: str,
        name: str,
        position: str,
        device_serial: Optional[str] = None,
    ) -> List[Any]:
        items = [
            item for item in extraction.inventory_items
            if item.domain == "nat"
            and item.source_attributes.get("scope_kind") == kind
            and item.source_attributes.get("scope_name") == name
            and item.source_attributes.get("pan_rulebase_position") == position
            and (
                (device_serial is None and not item.source_attributes.get("scope_device_serial"))
                or (
                    device_serial is not None
                    and item.source_attributes.get("scope_device_serial") == device_serial
                )
            )
        ]
        return sorted(
            items,
            key=lambda item: item.source_attributes.get("pan_source_rule_index", 2**31),
        )

    def _materialize_managed_nat_contexts(self, extraction) -> None:
        """Build effective NAT order for every managed firewall/VSYS.

        The base order builder discovers concrete NAT contexts from local VSYS
        NAT inventory.  A managed firewall may legitimately inherit all NAT
        rules from Panorama and therefore have no local NAT items.  Use the
        Panorama managed-VSYS topology instead so inherited-only NAT still has
        a device-qualified effective order and can be target-filtered safely.
        """
        hierarchy_error = any(
            item.domain == "panorama_hierarchy"
            and item.status == ExtractionStatus.PARSE_ERROR
            for item in extraction.inventory_items
        )

        for identity in self.resolver.managed_vsys_identities():
            serial = identity.device_serial
            vsys = identity.vsys_name
            device_group = self.resolver.device_group_for_vsys(vsys, serial)
            chain, chain_complete = self._managed_nat_chain(device_group)
            sequence: List[tuple[str, Any]] = []

            sequence.extend(
                ("shared-pre-nat-rules", item)
                for item in self._nat_rules_for_scope(
                    extraction, "shared", "shared", "pre"
                )
            )

            if device_group:
                for ancestor in chain[:-1]:
                    sequence.extend(
                        ("ancestor-device-group-pre-nat-rules", item)
                        for item in self._nat_rules_for_scope(
                            extraction, "device-group", ancestor, "pre"
                        )
                    )
                sequence.extend(
                    ("current-device-group-pre-nat-rules", item)
                    for item in self._nat_rules_for_scope(
                        extraction, "device-group", device_group, "pre"
                    )
                )

            for position, layer in (
                ("pre", "local-pre-nat-rules"),
                ("local", "local-nat-rules"),
                ("post", "local-post-nat-rules"),
            ):
                sequence.extend(
                    (layer, item)
                    for item in self._nat_rules_for_scope(
                        extraction, "vsys", vsys, position, serial
                    )
                )

            if device_group:
                sequence.extend(
                    ("current-device-group-post-nat-rules", item)
                    for item in self._nat_rules_for_scope(
                        extraction, "device-group", device_group, "post"
                    )
                )
                for ancestor in reversed(chain[:-1]):
                    sequence.extend(
                        ("ancestor-device-group-post-nat-rules", item)
                        for item in self._nat_rules_for_scope(
                            extraction, "device-group", ancestor, "post"
                        )
                    )

            sequence.extend(
                ("shared-post-nat-rules", item)
                for item in self._nat_rules_for_scope(
                    extraction, "shared", "shared", "post"
                )
            )

            context = f"device:{serial}:vsys:{vsys}"
            scope_chain = ["shared", *chain, context]
            complete = chain_complete and not hierarchy_error
            for rank, (layer, item) in enumerate(sequence):
                position = {
                    "effective_policy_layer": layer,
                    "effective_policy_rank": rank,
                    "effective_scope_chain": scope_chain,
                    "effective_rule_index": rank,
                    "effective_order_complete": complete,
                }
                item.source_attributes.setdefault(
                    "pan_effective_order_by_context", {}
                )[context] = position

    def _apply_target_applicability(self, extraction) -> None:
        # The coverage layer may run target filtering more than once as new
        # concrete managed-device contexts are materialized.  Preserve earlier
        # not-applicable/unknown audit results even after their order entries
        # have correctly been removed from the effective context map.
        previous = {
            item.source_record_id: dict(
                item.source_attributes.get("pan_target_applicability_by_context", {})
            )
            for item in extraction.inventory_items
            if item.domain in {"policies", "nat"}
        }
        super()._apply_target_applicability(extraction)
        for item in extraction.inventory_items:
            if item.domain not in {"policies", "nat"}:
                continue
            old = previous.get(item.source_record_id, {})
            current = item.source_attributes.get(
                "pan_target_applicability_by_context", {}
            )
            if old or current:
                item.source_attributes["pan_target_applicability_by_context"] = {
                    **old,
                    **current,
                }

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

    def extract(self, content: str, zone_mapping: Optional[Dict[str, str]] = None):
        extraction = super().extract(content, zone_mapping)

        # The parent layer has already derived base ordering and applied target
        # filtering.  Add managed-device NAT contexts sourced from Panorama
        # topology, then reapply target filtering/ranking for those contexts.
        self._materialize_managed_nat_contexts(extraction)
        self._apply_target_applicability(extraction)
        self._mark_nat_hierarchy_completeness(extraction)
        self._sync_effective_order_to_ir(extraction)
        self._refresh_extraction_accounting(extraction)
        return extraction
