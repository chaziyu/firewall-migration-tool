"""Single-pass Excel exporter.

This layer keeps the openpyxl Workbook in memory across inventory generation and
review/readability post-processing. It avoids the historical save -> reload ->
save cycle while preserving the existing layered exporter behavior.
"""

from __future__ import annotations

import io

import fwmigrate.report.excel_exporter as _excel_exporter
from fwmigrate.report.excel_exporter import ExcelExportUnavailableError
from fwmigrate.report.excel_vendor_visibility import _BASE_SHEET_ORDER
from fwmigrate.report.fortigate_address_schedule_excel import (
    FortiGateAddressScheduleExcelExporter,
)


class SinglePassIRExcelExporter(FortiGateAddressScheduleExcelExporter):
    """Generate and post-process the source inventory with one XLSX serialization."""

    def _build_inventory_workbook(self):
        """Build the same base workbook as IRExcelExporter.generate, without saving it."""
        if _excel_exporter.Workbook is None:
            raise ExcelExportUnavailableError(
                "Excel export requires openpyxl. Install the project with the reports extra."
            )

        # The parent vendor-aware exporter historically resets to the complete base
        # order before building. Preserve that contract so ordering validation and
        # downstream tests remain unchanged.
        self.SHEET_ORDER = _BASE_SHEET_ORDER

        workbook = _excel_exporter.Workbook()
        workbook.remove(workbook.active)

        workbook.properties.title = "Firewall Source Inventory"
        workbook.properties.subject = "Vendor-neutral firewall configuration extraction"
        workbook.properties.creator = "Firewall Migration Tool"

        self._build_system_settings(workbook)
        self._build_ntp_settings(workbook)
        self._build_management_service_routes(workbook)

        self._build_interfaces(workbook)
        self._build_interface_secondary_ips(workbook)
        self._build_interface_source_settings(workbook)
        self._build_interface_nested_configuration(workbook)

        self._build_dhcp_servers(workbook)
        self._build_dhcp_ip_ranges(workbook)
        self._build_dhcp_reservations(workbook)

        self._build_zones(workbook)

        self._build_addresses(workbook)
        self._build_address_groups(workbook)
        self._build_address_group_tags(workbook)
        self._build_proxy_addresses(workbook)
        self._build_web_proxy_settings(workbook)

        self._build_service_categories(workbook)
        self._build_services(workbook)
        self._build_service_groups(workbook)
        self._build_session_helpers(workbook)
        self._build_session_ttl_settings(workbook)
        self._build_session_ttl_overrides(workbook)

        self._build_schedules(workbook)
        self._build_schedule_groups(workbook)
        self._build_traffic_shapers(workbook)
        self._build_policies(workbook)
        self._build_firewall_filters(workbook)
        self._build_checkpoint_access_rule_sheet(workbook)
        self._build_cisco_acp(workbook)
        self._build_default_security_rules(workbook)
        self._build_local_in_policies(workbook)
        self._build_security_policies(workbook)
        self._build_multicast_policies(workbook)
        self._build_firewall_policy_source_settings(workbook)
        self._build_ztna_providers(workbook)

        self._build_ip_pools(workbook)
        self._build_ipv6_eh_filter(workbook)
        self._build_virtual_ips(workbook)
        self._build_vip_real_servers(workbook)
        self._build_vip_groups(workbook)
        self._build_nat_rules(workbook)
        self._build_pbf_rules(workbook)

        self._build_vpn_tunnels(workbook)
        self._build_vpn_phase2(workbook)
        self._build_ssl_vpn(workbook)
        self._build_certificates(workbook)
        self._build_ssh_keys(workbook)

        self._build_routes(workbook)
        self._build_policy_routes(workbook)
        self._build_cisco_pbr(workbook)
        self._build_routing_protocols(workbook)
        self._build_routing_dependencies(workbook)
        self._build_sdwan(workbook)

        self._build_internet_services(workbook)
        self._build_internet_service_definitions(workbook)
        self._build_internet_service_extract_only(workbook)
        self._build_ips_sensors(workbook)
        self._build_ips_sensor_entries(workbook)

        self._build_security_profiles(workbook)
        self._build_security_profile_definitions(workbook)
        self._build_security_profile_rules(workbook)
        self._build_custom_url_categories(workbook)
        self._build_source_security_profiles(workbook)
        self._build_fortigate_source_configuration(workbook)

        self._build_identity_inventory(workbook)
        self._build_user_identity_settings(workbook)
        self._build_security_identity_dependencies(workbook)
        self._build_administrator_inventory(workbook)
        self._build_dos_inventory(workbook)
        self._build_firewall_sniffers(workbook)
        self._build_authentication_inventory(workbook)
        self._build_phase7_identity_sheets(workbook)
        self._build_globalprotect_sheets(workbook)
        self._build_pan_phase9_sheets(workbook)
        self._build_pan_sdwan_sheets(workbook)

        self._build_warnings(workbook)
        self._build_unsupported(workbook)
        self._build_source_inventory(workbook)
        self._build_extraction_coverage(workbook)
        self._build_unresolved_references(workbook)

        # Preserve the exact intermediate logical ordering used before the old
        # serialization round-trip. Review/evidence row ordering depends on it.
        self._build_summary(workbook)
        self._order_sheets(workbook)

        return workbook

    def generate(self) -> bytes:
        """Generate the final workbook without an intermediate save/reload."""
        workbook = self._build_inventory_workbook()

        active_order = self._active_sheet_order()
        active_sheets = set(active_order)

        for worksheet in list(workbook.worksheets):
            if worksheet.title not in active_sheets:
                workbook.remove(worksheet)

        self._apply_review_usability(workbook)

        # Rebuild Summary after filtering/usability processing, matching the
        # existing vendor-aware output contract.
        if "Summary" in workbook.sheetnames:
            workbook.remove(workbook["Summary"])

        self.SHEET_ORDER = self._workbook_sheet_order(active_order)
        self._build_summary(workbook)
        self._remove_inapplicable_summary_rows(workbook["Summary"])
        self._add_summary_visibility(workbook["Summary"], workbook)
        self._apply_sheet_view(workbook["Summary"])
        self._order_sheets(workbook)

        output = io.BytesIO()
        workbook.save(output)
        return output.getvalue()
