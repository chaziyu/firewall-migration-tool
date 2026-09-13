"""Excel visibility for derived effective PBF ordering metadata."""

from __future__ import annotations

from typing import Any

from fwmigrate.report.excel_vendor_visibility import VendorAwareIRExcelExporter


class EffectiveOrderIRExcelExporter(VendorAwareIRExcelExporter):
    """Expose canonical PBF ordering evidence without changing rule semantics."""

    def _build_pbf_rules(self, workbook: Any) -> None:
        self._table_sheet(
            workbook,
            "PBF Rules",
            (
                "Rule #", "Name", "Source Context", "Rulebase Position", "Source Order",
                "Effective Layer", "Effective Rank", "Effective Scope Chain",
                "Effective Order Complete", "Effective Order by Context",
                "From Zones", "From Interfaces", "To", "Source", "Destination",
                "Source User", "Applications", "Services", "Action", "Forward to VSYS",
                "Egress Interface", "Next Hop Type", "Next Hop", "Next VR", "Monitor Profile",
                "Schedule", "Negate Source", "Negate Destination", "Symmetric Return",
                "Symmetric Return Next Hops",
                "Monitor IP", "Monitor Enabled", "Disable if Unreachable", "Enabled",
                "Migration Status", "Manual Review", "Review Reasons", "Description",
                "Priority", "Protocol", "Destination Port", "Routing Table",
                "Table Routes", "Table Next Hop", "Table Output Interface",
            ),
            (
                (
                    index, rule.name, rule.source_context, rule.rulebase_position,
                    rule.source_order,
                    rule.source_attributes.get("effective_policy_layer"),
                    rule.source_attributes.get("effective_policy_rank"),
                    rule.source_attributes.get("effective_scope_chain", []),
                    self._optional_bool_literal(
                        rule.source_attributes.get("effective_order_complete")
                    ),
                    self._format_settings(
                        rule.source_attributes.get("pan_effective_order_by_context", {})
                    ) if rule.source_attributes.get("pan_effective_order_by_context") else None,
                    rule.from_zone, rule.from_interface, rule.to,
                    rule.source, rule.destination, rule.source_user, rule.application,
                    rule.service, rule.action, rule.forward_to_vsys, rule.egress_interface,
                    rule.next_hop_type, rule.next_hop, rule.next_vr, rule.monitor_profile,
                    rule.schedule, self._optional_bool_literal(rule.source_negated),
                    self._optional_bool_literal(rule.destination_negated),
                    self._optional_bool_literal(
                        rule.symmetric_return.enabled
                        if rule.symmetric_return is not None
                        else rule.enforce_symmetric_return
                    ),
                    rule.symmetric_return.next_hop_addresses
                    if rule.symmetric_return is not None else [],
                    rule.monitor_ip, self._optional_bool_literal(rule.monitor_enabled),
                    self._optional_bool_literal(rule.disable_if_unreachable),
                    self._optional_bool_literal(rule.enabled), rule.migration_status,
                    self._optional_bool_literal(rule.requires_manual_review),
                    rule.review_reasons, rule.description, rule.priority, rule.protocol,
                    rule.destination_port, rule.routing_table,
                    self._format_pbr_table_routes(rule.source_attributes.get("table_routes", [])),
                    rule.table_next_hop,
                    rule.table_output_interface,
                )
                for index, rule in enumerate(self.ir.pbf_rules, 1)
            ),
            title="Policy-Based Forwarding Rules",
            note=(
                "PBF rules remain distinct from static routes. Source Order is the original "
                "rulebase index; Effective Rank and related fields are derived Panorama/VSYS "
                "evaluation-order evidence and do not replace source ordering."
            ),
        )
