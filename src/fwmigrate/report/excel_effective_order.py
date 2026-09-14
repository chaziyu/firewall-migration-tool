"""Excel visibility for derived effective PBF ordering metadata."""

from __future__ import annotations

from copy import copy
import json
from typing import Any

from fwmigrate.report.excel_vendor_visibility import VendorAwareIRExcelExporter


class EffectiveOrderIRExcelExporter(VendorAwareIRExcelExporter):
    """Expose PAN-OS ordering and source policy semantics for review."""

    def _build_policies(self, workbook: Any) -> None:
        super()._build_policies(workbook)
        if self._source_vendor() != "palo_alto" or "Policies" not in workbook.sheetnames:
            return

        sheet = workbook["Policies"]
        headers = {
            str(cell.value or "").strip(): cell.column
            for cell in sheet[3]
            if cell.value
        }
        if "Rule Type" in headers:
            return

        column = sheet.max_column + 1
        header = sheet.cell(3, column)
        header.value = "Rule Type"
        if column > 1:
            header._style = copy(sheet.cell(3, column - 1)._style)
        sheet.column_dimensions[header.column_letter].width = 14

        for row, policy in enumerate(self.ir.policies, start=4):
            cell = sheet.cell(row, column)
            if column > 1:
                cell._style = copy(sheet.cell(row, column - 1)._style)
            settings = policy.source_extra_settings or {}
            # Export only validated PAN-OS rule types here. Invalid source text
            # remains available in source evidence without creating an Excel
            # formula-injection surface.
            if settings.get("pan_rule_type_valid") is True:
                cell.value = settings.get("pan_rule_type")

    def _build_nat_rules(self, workbook: Any) -> None:
        super()._build_nat_rules(workbook)
        if self._source_vendor() != "palo_alto" or "NAT Rules" not in workbook.sheetnames:
            return

        sheet = workbook["NAT Rules"]
        columns = (
            "Service Matches", "Destination Distribution", "DNS Rewrite", "Device Binding",
            "Rulebase Position", "Source Order", "Effective Layer", "Effective Rank",
            "Effective Scope Chain", "Effective Order Complete", "Effective Order by Context",
        )
        start = sheet.max_column + 1
        for offset, name in enumerate(columns):
            column = start + offset
            header = sheet.cell(3, column, name)
            if column > 1:
                header._style = copy(sheet.cell(3, column - 1)._style)
            sheet.column_dimensions[header.column_letter].width = 22

        for row, rule in enumerate(self.ir.nat_rules, start=4):
            attrs = rule.source_attributes
            values = (
                json.dumps(
                    [match.model_dump(mode="json") for match in rule.service_matches],
                    sort_keys=True,
                )
                if rule.service_matches else None,
                rule.destination_translation_distribution.method
                if rule.destination_translation_distribution else None,
                self._format_settings(rule.destination_dns_rewrite.model_dump(mode="json"))
                if rule.destination_dns_rewrite else None,
                rule.source_device_binding,
                attrs.get("pan_rulebase_position"),
                attrs.get("pan_source_rule_index"),
                attrs.get("effective_policy_layer"),
                attrs.get("effective_policy_rank"),
                self._format_settings({"scope": attrs.get("effective_scope_chain", [])}),
                self._optional_bool_literal(attrs.get("effective_order_complete")),
                self._format_settings(attrs.get("pan_effective_order_by_context", {}))
                if attrs.get("pan_effective_order_by_context") else None,
            )
            for offset, value in enumerate(values):
                cell = sheet.cell(row, start + offset, value)
                if start + offset > 1:
                    cell._style = copy(sheet.cell(row, start + offset - 1)._style)

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
            empty_note="No policy-based forwarding rules were extracted.",
            subtitle=(
                "Policy-based forwarding inventory; source route tables remain separate from "
                "static routes. Source Order is the original rulebase index; Effective Rank "
                "and related fields are derived Panorama/VSYS evaluation-order evidence."
            ),
        )
