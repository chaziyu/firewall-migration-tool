"""Single-pass Excel exporter.

This layer keeps the openpyxl Workbook in memory across inventory generation and
review/readability post-processing. It avoids the historical save -> reload ->
save cycle while preserving the existing layered exporter behavior.
"""

from __future__ import annotations

import io
import logging
import time
from dataclasses import dataclass, field
from typing import BinaryIO, Callable

import fwmigrate.report.excel_exporter as _excel_exporter
from fwmigrate.report.excel_exporter import ExcelExportUnavailableError
from fwmigrate.report.excel_vendor_visibility import _BASE_SHEET_ORDER
from fwmigrate.report.excel_audit import ExcelAuditAccumulator
from fwmigrate.report.excel_serialization import save_workbook_with_compression
from fwmigrate.report.fortigate_address_schedule_excel import (
    FortiGateAddressScheduleExcelExporter,
)


logger = logging.getLogger(__name__)


@dataclass
class _ExcelExportMetrics:
    timings: dict[str, float] = field(default_factory=dict)
    worksheet_count: int = 0
    total_rows: int = 0
    rows_written: int = 0
    cells_written: int = 0
    nonempty_cells: int = 0
    populated_cells: int = 0
    largest_worksheets: tuple[tuple[str, int, int], ...] = ()
    worksheet_metrics: tuple["WorksheetExportMetric", ...] = ()
    output_bytes: int = 0


@dataclass(frozen=True)
class WorksheetExportMetric:
    name: str
    rows: int
    columns: int
    cells: int
    nonempty_cells: int
    build_seconds: float
    sizing_seconds: float


@dataclass(frozen=True)
class ExcelBuilderSpec:
    method_name: str
    produced_sheets: frozenset[str]
    vendors: frozenset[str] = frozenset()
    has_data: Callable[[object], bool] | None = None


def _has_globalprotect_data(exporter) -> bool:
    panos = exporter.ir.vendor_extensions.panos
    return bool(
        panos.global_protect_portals
        or panos.global_protect_gateways
        or panos.global_protect_network_gateways
    )


def _has_pan_phase9_data(exporter) -> bool:
    panos = exporter.ir.vendor_extensions.panos
    return any(
        getattr(panos, name)
        for name in (
            "pan_log_server_profiles",
            "pan_log_forwarding_profiles",
            "pan_dns_proxies",
            "pan_monitor_profiles",
            "pan_qos_profiles",
            "pan_vsys_settings",
            "pan_custom_reports",
        )
    ) or any(
        getattr(panos, name) is not None
        for name in (
            "pan_high_availability",
            "pan_device_operational_settings",
            "pan_botnet_report_settings",
        )
    )


def _has_pan_sdwan_data(exporter) -> bool:
    panos = exporter.ir.vendor_extensions.panos
    return any(
        getattr(panos, name)
        for name in (
            "pan_sdwan_interface_profiles",
            "pan_sdwan_link_settings",
            "pan_sdwan_path_quality_profiles",
            "pan_sdwan_traffic_distribution_profiles",
            "pan_sdwan_rules",
        )
    )


def _has_cisco_acp(exporter) -> bool:
    return any(str(item.source_context or "").startswith("fmc:") for item in exporter.ir.policies)


def _has_checkpoint_rules(exporter) -> bool:
    return any(str(item.source_context or "").startswith("checkpoint") for item in exporter.ir.policies)


def _has_policy_source_settings(exporter) -> bool:
    return any(item.source_extra_settings for item in exporter.ir.policies)


BUILDERS = (
    ExcelBuilderSpec(
        "_build_management_service_routes",
        frozenset({"Management Service Routes"}),
        frozenset({"palo_alto"}),
        lambda exporter: bool(exporter.ir.management_service_routes),
    ),
    ExcelBuilderSpec(
        "_build_cisco_acp",
        frozenset({"Cisco ACP"}),
        frozenset({"cisco_asa"}),
        _has_cisco_acp,
    ),
    ExcelBuilderSpec(
        "_build_checkpoint_access_rule_sheet",
        frozenset({"Checkpoint Access Rules"}),
        frozenset({"checkpoint"}),
        _has_checkpoint_rules,
    ),
    ExcelBuilderSpec(
        "_build_globalprotect_sheets",
        frozenset({
            "GlobalProtect Portals", "GlobalProtect Gateways", "GlobalProtect Client Auth",
            "GlobalProtect Portal Configs", "GlobalProtect External Gateways",
            "GlobalProtect App Settings", "GlobalProtect Root CAs", "GlobalProtect Gateway Roles",
            "GlobalProtect Tunnel Configs", "GlobalProtect Network Gateways",
        }),
        frozenset({"palo_alto"}),
        _has_globalprotect_data,
    ),
    ExcelBuilderSpec(
        "_build_pan_phase9_sheets",
        frozenset({
            "PAN Log Servers", "PAN Log Forwarding", "PAN Log Forward Matches",
            "PAN DNS Proxies", "PAN DNS Proxy Domains", "PAN Monitor Profiles", "PAN QoS Profiles",
            "PAN QoS Classes", "PAN High Availability", "PAN HA Monitoring", "PAN Device Settings",
            "PAN VSYS Settings", "PAN Botnet Report", "PAN Custom Reports",
        }),
        frozenset({"palo_alto"}),
        _has_pan_phase9_data,
    ),
    ExcelBuilderSpec(
        "_build_pan_sdwan_sheets",
        frozenset({
            "PAN SD-WAN Interface Profiles", "PAN SD-WAN Link Settings", "PAN SD-WAN Path Quality",
            "PAN SD-WAN Traffic Distribution", "PAN SD-WAN Rules",
        }),
        frozenset({"palo_alto"}),
        _has_pan_sdwan_data,
    ),
    ExcelBuilderSpec(
        "_build_security_profile_definitions",
        frozenset({"Security Profile Definitions"}),
        has_data=lambda exporter: bool(exporter.ir.security_profile_definitions),
    ),
    ExcelBuilderSpec(
        "_build_security_profile_rules",
        frozenset({"Security Profile Rules"}),
        has_data=lambda exporter: any(item.rules for item in exporter.ir.security_profile_definitions),
    ),
    ExcelBuilderSpec(
        "_build_custom_url_categories",
        frozenset({"Custom URL Categories"}),
        has_data=lambda exporter: bool(exporter.ir.custom_url_categories),
    ),
    ExcelBuilderSpec(
        "_build_fortigate_source_configuration",
        frozenset({"FortiGate Source Configuration"}),
        frozenset({"fortigate"}),
    ),
    ExcelBuilderSpec(
        "_build_firewall_policy_source_settings",
        frozenset({"Firewall Policy Source Settings"}),
        has_data=_has_policy_source_settings,
    ),
    ExcelBuilderSpec(
        "_build_interface_nested_configuration",
        frozenset({"Interface Nested Configuration"}),
        frozenset({"fortigate"}),
    ),
    ExcelBuilderSpec(
        "_build_vip_nested_configuration",
        frozenset({"VIP Nested Configuration"}),
        frozenset({"fortigate"}),
    ),
)
_BUILDER_SPECS = {spec.method_name: spec for spec in BUILDERS}


def _log_export_metrics(metrics: _ExcelExportMetrics, total: float) -> None:
    logger.debug(
        "Excel export metrics: %s; total=%.3fs; sheets=%d; rows=%d; "
        "populated_cells=%d; largest=%s; output_bytes=%d",
        ", ".join(
            f"{name}=%.3fs" % elapsed
            for name, elapsed in metrics.timings.items()
        ),
        total,
        metrics.worksheet_count,
        metrics.total_rows,
        metrics.populated_cells,
        metrics.largest_worksheets,
        metrics.output_bytes,
    )


class SinglePassIRExcelExporter(FortiGateAddressScheduleExcelExporter):
    """Generate and post-process the source inventory with one XLSX serialization."""

    # Enabled only during the optimized facade's finalization pass. Direct
    # readability calls retain their standalone presentation behavior.
    _preserve_column_order = False

    def _record_table_metrics(
        self,
        sheet_name: str,
        row_count: int,
        column_count: int,
        cells_written: int,
        nonempty_cells: int,
        build_seconds: float,
        sizing_seconds: float,
    ) -> None:
        metrics = getattr(self, "_last_export_metrics", None)
        if metrics is None:
            return
        worksheet_metric = WorksheetExportMetric(
            name=sheet_name,
            rows=row_count,
            columns=column_count,
            cells=cells_written,
            nonempty_cells=nonempty_cells,
            build_seconds=build_seconds,
            sizing_seconds=sizing_seconds,
        )
        metrics.worksheet_metrics = tuple(
            metric
            for metric in metrics.worksheet_metrics
            if metric.name != sheet_name
        ) + (worksheet_metric,)

    def _finalize_table_metrics(self, workbook) -> None:
        metrics = getattr(self, "_last_export_metrics", None)
        if metrics is None:
            return
        active_names = {sheet.title for sheet in workbook.worksheets}
        metrics.worksheet_metrics = tuple(
            metric
            for metric in metrics.worksheet_metrics
            if metric.name in active_names
        )
        metrics.worksheet_count = len(metrics.worksheet_metrics)
        metrics.rows_written = sum(
            metric.rows for metric in metrics.worksheet_metrics
        )
        metrics.cells_written = sum(
            metric.cells for metric in metrics.worksheet_metrics
        )
        metrics.nonempty_cells = sum(
            metric.nonempty_cells for metric in metrics.worksheet_metrics
        )
        metrics.total_rows = sum(
            metric.rows + 3 for metric in metrics.worksheet_metrics
        )
        metrics.populated_cells = metrics.nonempty_cells
        metrics.largest_worksheets = tuple(
            (metric.name, metric.rows, metric.columns)
            for metric in sorted(
                metrics.worksheet_metrics,
                key=lambda item: (item.rows, item.columns),
                reverse=True,
            )[:5]
        )

    def _build_inventory_workbook(self):
        """Build the same base workbook as IRExcelExporter.generate, without saving it."""
        if _excel_exporter.Workbook is None:
            raise ExcelExportUnavailableError(
                "Excel export requires openpyxl. Install the project with the reports extra."
            )

        active_sheets = set(self._active_sheet_order())
        self._audit_accumulator = ExcelAuditAccumulator()

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
        self._build_registered_if_active(
            workbook, active_sheets, "_build_management_service_routes"
        )

        self._build_interfaces(workbook)
        self._build_interface_secondary_ips(workbook)
        self._build_interface_source_settings(workbook)
        self._build_registered_if_active(
            workbook, active_sheets, "_build_interface_nested_configuration"
        )

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
        self._build_registered_if_active(
            workbook, active_sheets, "_build_checkpoint_access_rule_sheet"
        )
        self._build_registered_if_active(
            workbook, active_sheets, "_build_cisco_acp"
        )
        self._build_default_security_rules(workbook)
        self._build_local_in_policies(workbook)
        self._build_security_policies(workbook)
        self._build_multicast_policies(workbook)
        self._build_registered_if_active(
            workbook, active_sheets, "_build_firewall_policy_source_settings"
        )
        self._build_ztna_providers(workbook)

        self._build_ip_pools(workbook)
        self._build_ipv6_eh_filter(workbook)
        self._build_virtual_ips(workbook)
        self._build_vip_real_servers(workbook)
        self._build_registered_if_active(
            workbook, active_sheets, "_build_vip_nested_configuration"
        )
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
        self._build_registered_if_active(
            workbook, active_sheets, "_build_security_profile_definitions"
        )
        self._build_registered_if_active(
            workbook, active_sheets, "_build_security_profile_rules"
        )
        self._build_registered_if_active(
            workbook, active_sheets, "_build_custom_url_categories"
        )
        self._build_source_security_profiles(workbook)
        self._build_registered_if_active(
            workbook, active_sheets, "_build_fortigate_source_configuration"
        )

        self._build_identity_inventory(workbook)
        self._build_user_identity_settings(workbook)
        self._build_security_identity_dependencies(workbook)
        self._build_administrator_inventory(workbook)
        self._build_dos_inventory(workbook)
        self._build_firewall_sniffers(workbook)
        self._build_authentication_inventory(workbook)
        self._build_phase7_identity_sheets(workbook)
        self._build_registered_if_active(
            workbook, active_sheets, "_build_globalprotect_sheets"
        )
        self._build_registered_if_active(
            workbook, active_sheets, "_build_pan_phase9_sheets"
        )
        self._build_registered_if_active(
            workbook, active_sheets, "_build_pan_sdwan_sheets"
        )

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

    def _build_if_active(
        self,
        workbook,
        active_sheets: set[str],
        produced_sheets: set[str],
        builder_name: str,
    ) -> None:
        if active_sheets.intersection(produced_sheets):
            getattr(self, builder_name)(workbook)

    def _build_registered_if_active(
        self,
        workbook,
        active_sheets: set[str],
        builder_name: str,
    ) -> None:
        spec = _BUILDER_SPECS[builder_name]
        if not active_sheets.intersection(spec.produced_sheets):
            return
        vendor = self._source_vendor()
        if vendor in self._KNOWN_VENDORS:
            if spec.vendors and vendor not in spec.vendors:
                return
            if spec.has_data is not None and not spec.has_data(self):
                return
        getattr(self, builder_name)(workbook)

    def generate(self) -> bytes:
        """Generate the final workbook and return its bytes."""
        output = io.BytesIO()
        self.generate_to(output)
        return output.getvalue()

    def generate_to(self, output: BinaryIO) -> None:
        """Generate the final workbook directly into a file-like object."""
        debug_timings = logger.isEnabledFor(logging.DEBUG)
        metrics = _ExcelExportMetrics() if debug_timings else None
        self._last_export_metrics = metrics
        total_start = time.perf_counter() if debug_timings else 0.0

        stage_start = time.perf_counter() if debug_timings else 0.0
        workbook = self._build_inventory_workbook()
        if metrics is not None:
            metrics.timings["inventory workbook construction"] = (
                time.perf_counter() - stage_start
            )

        active_order = self._expanded_sheet_order(self._active_sheet_order())
        active_sheets = set(active_order)
        self._preserve_column_order = True

        stage_start = time.perf_counter() if debug_timings else 0.0
        for worksheet in list(workbook.worksheets):
            if worksheet.title not in active_sheets:
                workbook.remove(worksheet)
        if metrics is not None:
            metrics.timings["vendor filtering"] = time.perf_counter() - stage_start

        stage_start = time.perf_counter() if debug_timings else 0.0
        self._apply_review_usability(workbook)
        if metrics is not None:
            metrics.timings["review and readability processing"] = (
                time.perf_counter() - stage_start
            )

        # Rebuild Summary after filtering/usability processing, matching the
        # existing vendor-aware output contract.
        stage_start = time.perf_counter() if debug_timings else 0.0
        if "Summary" in workbook.sheetnames:
            workbook.remove(workbook["Summary"])

        self.SHEET_ORDER = self._workbook_sheet_order(active_order)
        self._build_summary(workbook)
        self._remove_inapplicable_summary_rows(workbook["Summary"])
        self._add_summary_visibility(workbook["Summary"], workbook)
        self._apply_sheet_view(workbook["Summary"])
        if metrics is not None:
            metrics.timings["summary reconstruction"] = (
                time.perf_counter() - stage_start
            )

        stage_start = time.perf_counter() if debug_timings else 0.0
        self._order_sheets(workbook)
        if metrics is not None:
            metrics.timings["sheet ordering"] = time.perf_counter() - stage_start

        self._finalize_table_metrics(workbook)

        stage_start = time.perf_counter() if debug_timings else 0.0
        compression_level = self._export_options.compression_level
        if compression_level is None:
            compression_level = 1 if self._is_fast_profile() else 6
        save_workbook_with_compression(workbook, output, compression_level)
        if metrics is not None:
            metrics.timings["final XLSX serialization"] = (
                time.perf_counter() - stage_start
            )
            metrics.output_bytes = output.tell()
            _log_export_metrics(metrics, time.perf_counter() - total_start)
        self._preserve_column_order = False
