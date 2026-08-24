"""Vendor-neutral Excel inventory export for :class:`IRConfig`."""

from __future__ import annotations

import io
import json
import re
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Sequence

from fwmigrate.ir.core import IRConfig
from fwmigrate.ir.enums import MigrationConfidence
from fwmigrate.security.redaction import redact_sensitive

try:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.utils import get_column_letter
except ImportError:  # pragma: no cover - exercised only without the reports dependency
    Workbook = None


XLSX_MIMETYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
_FORMULA_PREFIXES = ("=", "+", "-", "@")
_ILLEGAL_XML_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")
_MAX_CELL_TEXT = 32767


class ExcelExportUnavailableError(RuntimeError):
    """Raised when the optional workbook dependency is unavailable."""


class IRExcelExporter:
    """Render a source firewall inventory directly from vendor-neutral IR."""

    SHEET_ORDER = (
        "Summary",
        "Interfaces",
        "Interface Source Settings",
        "Zones",
        "Addresses",
        "Address Groups",
        "Services",
        "Service Groups",
        "Schedules",
        "Policies",
        "NAT Rules",
        "VPN Tunnels",
        "Routes",
        "Internet Services",
        "Security Profiles",
        "Warnings",
        "Unsupported",
        "Extraction Coverage",
    )

    _NAVY = "17324D"
    _TEAL = "0F766E"
    _LIGHT_TEAL = "D7F0EC"
    _LIGHT_BLUE = "E8F0F7"
    _LIGHT_AMBER = "FEF3C7"
    _LIGHT_RED = "FEE2E2"
    _WHITE = "FFFFFF"
    _TEXT = "1F2937"
    _MUTED = "64748B"
    _BORDER = "CBD5E1"

    def __init__(self, ir_config: IRConfig):
        self.ir = ir_config

    def generate(self) -> bytes:
        """Generate a complete ``.xlsx`` workbook and return its bytes."""
        if Workbook is None:
            raise ExcelExportUnavailableError(
                "Excel export requires openpyxl. Install the project with the reports extra."
            )

        workbook = Workbook()
        workbook.remove(workbook.active)
        workbook.properties.title = "Firewall Source Inventory"
        workbook.properties.subject = "Vendor-neutral firewall configuration extraction"
        workbook.properties.creator = "Firewall Migration Tool"

        self._build_summary(workbook)
        self._build_interfaces(workbook)
        self._build_interface_source_settings(workbook)
        self._build_zones(workbook)
        self._build_addresses(workbook)
        self._build_address_groups(workbook)
        self._build_services(workbook)
        self._build_service_groups(workbook)
        self._build_schedules(workbook)
        self._build_policies(workbook)
        self._build_nat_rules(workbook)
        self._build_vpn_tunnels(workbook)
        self._build_routes(workbook)
        self._build_internet_services(workbook)
        self._build_security_profiles(workbook)
        self._build_warnings(workbook)
        self._build_unsupported(workbook)
        self._build_extraction_coverage(workbook)

        workbook._sheets.sort(key=lambda sheet: self.SHEET_ORDER.index(sheet.title))
        output = io.BytesIO()
        workbook.save(output)
        return output.getvalue()

    def _build_summary(self, workbook: Any) -> None:
        sheet = workbook.create_sheet("Summary")
        sheet.sheet_view.showGridLines = False
        sheet.merge_cells("A1:D1")
        sheet["A1"] = "Firewall Source Inventory"
        sheet["A1"].font = Font(name="Aptos Display", size=20, bold=True, color=self._WHITE)
        sheet["A1"].fill = PatternFill("solid", fgColor=self._NAVY)
        sheet["A1"].alignment = Alignment(vertical="center")
        sheet.row_dimensions[1].height = 34

        sheet.merge_cells("A2:D2")
        sheet["A2"] = "Vendor-neutral extraction generated before migration optimization"
        sheet["A2"].font = Font(name="Aptos", size=10, italic=True, color=self._MUTED)
        sheet["A2"].alignment = Alignment(vertical="center")
        sheet.row_dimensions[2].height = 22

        unsupported_count = sum(
            1 for entry in self.ir.audit_entries if entry.confidence == MigrationConfidence.UNSUPPORTED
        )
        unresolved_count = sum(
            1 for entry in self.ir.audit_entries if "unresolved" in entry.message.lower()
        )
        if unsupported_count:
            extraction_status = "COMPLETE_WITH_UNSUPPORTED_ITEMS"
        elif self.ir.audit_entries:
            extraction_status = "COMPLETE_WITH_WARNINGS"
        else:
            extraction_status = "COMPLETE"

        metadata_rows = [
            ("Source Vendor", self.ir.metadata.source_vendor),
            ("Hostname", self.ir.metadata.hostname),
            ("Input Type", self.ir.metadata.input_type),
            ("Source Version", self.ir.metadata.source_version),
            ("Source Context", self.ir.metadata.source_context),
            ("Extracted At (UTC)", self.ir.metadata.migration_timestamp),
            ("Extraction Status", extraction_status),
        ]
        self._summary_section(sheet, 4, "Extraction Metadata", metadata_rows)

        inventory_rows = [
            ("Interfaces", len(self.ir.interfaces)),
            ("Zones", len(self.ir.zones)),
            ("Addresses", len(self.ir.addresses)),
            ("Address Groups", len(self.ir.address_groups)),
            ("Services", len(self.ir.services)),
            ("Service Groups", len(self.ir.service_groups)),
            ("Schedules", len(self.ir.schedules)),
            ("Policies", len(self.ir.policies)),
            ("NAT Rules", len(self.ir.nat_rules)),
            ("VPN Tunnels", len(self.ir.vpn_tunnels)),
            ("Routes", len(self.ir.routes)),
            ("Internet Services", len(self.ir.internet_services)),
            ("Security Profiles", len(self.ir.security_profile_groups)),
            ("Warnings", len(self.ir.audit_entries)),
            ("Unsupported Items", unsupported_count),
            ("Unresolved References", unresolved_count),
        ]
        self._summary_section(sheet, 13, "Inventory Counts", inventory_rows)

        sheet.column_dimensions["A"].width = 28
        sheet.column_dimensions["B"].width = 48
        sheet.column_dimensions["C"].width = 3
        sheet.column_dimensions["D"].width = 3
        sheet.freeze_panes = "A4"

    def _summary_section(
        self, sheet: Any, start_row: int, title: str, rows: Sequence[tuple[str, Any]]
    ) -> None:
        sheet.merge_cells(start_row=start_row, start_column=1, end_row=start_row, end_column=2)
        title_cell = sheet.cell(start_row, 1, title)
        title_cell.font = Font(name="Aptos", size=11, bold=True, color=self._WHITE)
        title_cell.fill = PatternFill("solid", fgColor=self._TEAL)
        title_cell.alignment = Alignment(vertical="center")
        sheet.row_dimensions[start_row].height = 23
        for row_index, (label, value) in enumerate(rows, start_row + 1):
            sheet.cell(row_index, 1, self._safe_value(label))
            sheet.cell(row_index, 2, self._safe_value(value))
            sheet.cell(row_index, 1).font = Font(name="Aptos", bold=True, color=self._TEXT)
            sheet.cell(row_index, 1).fill = PatternFill("solid", fgColor=self._LIGHT_BLUE)
            sheet.cell(row_index, 2).font = Font(name="Aptos", color=self._TEXT)
            sheet.cell(row_index, 2).alignment = Alignment(wrap_text=True, vertical="top")

    def _build_interfaces(self, workbook: Any) -> None:
        headers = (
            "Name", "Source VDOM", "Zone", "IP / Prefix", "Enabled", "Interface Type",
            "Role", "Addressing Mode", "DHCP Client", "Management Access", "Alias", "Parent",
            "Tag", "VLAN ID", "Management Profile", "PPPoE Mode", "PPPoE Username",
            "Description",
        )
        rows = [
            (
                item.name, item.source_vdom, item.zone, item.ip, item.status, item.interface_type,
                item.role, item.addressing_mode, item.dhcp_client, item.management_access,
                item.alias, item.parent, item.tag, item.vlanid, item.management_profile,
                item.pppoe_mode, item.pppoe_username, item.description,
            )
            for item in self.ir.interfaces
        ]
        self._table_sheet(workbook, "Interfaces", headers, rows)

    def _build_interface_source_settings(self, workbook: Any) -> None:
        """Expose every explicitly configured interface setting without reinterpreting it."""
        rows = []
        for item in self.ir.interfaces:
            for setting, value in item.source_attributes.items():
                display_setting = str(setting).replace("_", "-")
                if isinstance(value, set):
                    display_value = json.dumps(sorted(value), ensure_ascii=False, default=str)
                elif isinstance(value, (dict, list, tuple)):
                    display_value = json.dumps(
                        value, ensure_ascii=False, sort_keys=True, default=str
                    )
                else:
                    display_value = value
                rows.append(
                    (
                        item.name,
                        self.ir.metadata.source_vendor,
                        display_setting,
                        display_value,
                        "EXTRACT_ONLY",
                    )
                )

        self._table_sheet(
            workbook,
            "Interface Source Settings",
            ("Interface", "Source Vendor", "Setting", "Value", "Extraction Status"),
            rows,
            empty_note="No explicit source-interface settings were retained by the parser.",
            subtitle=(
                "Explicit source settings retained for inventory. These values are extraction-only "
                "and are not consumed by target generators."
            ),
        )

    def _build_zones(self, workbook: Any) -> None:
        rows = [(item.name, item.interfaces, item.description) for item in self.ir.zones]
        self._table_sheet(workbook, "Zones", ("Name", "Interfaces", "Description"), rows)

    def _build_addresses(self, workbook: Any) -> None:
        rows = [
            (
                item.name, item.type, item.value, item.is_ipv6, item.is_multicast, item.tags,
                item.requires_manual_review, item.audit_note, item.parse_error, item.description,
            )
            for item in self.ir.addresses
        ]
        self._table_sheet(
            workbook,
            "Addresses",
            (
                "Name", "Type", "Value", "IPv6", "Multicast", "Tags", "Manual Review",
                "Audit Note", "Parse Error", "Description",
            ),
            rows,
        )

    def _build_address_groups(self, workbook: Any) -> None:
        rows = [
            (item.name, item.members, item.is_dynamic, item.dynamic_filter, item.tags, item.description)
            for item in self.ir.address_groups
        ]
        self._table_sheet(
            workbook,
            "Address Groups",
            ("Name", "Members", "Dynamic", "Dynamic Filter", "Tags", "Description"),
            rows,
        )

    def _build_services(self, workbook: Any) -> None:
        rows = [(item.name, [self._format_port(port) for port in item.ports], item.description) for item in self.ir.services]
        self._table_sheet(workbook, "Services", ("Name", "Protocol / Port", "Description"), rows)

    def _build_service_groups(self, workbook: Any) -> None:
        rows = [(item.name, item.members, item.description) for item in self.ir.service_groups]
        self._table_sheet(workbook, "Service Groups", ("Name", "Members", "Description"), rows)

    def _build_schedules(self, workbook: Any) -> None:
        rows = [(item.name, item.start, item.end, item.days) for item in self.ir.schedules]
        self._table_sheet(workbook, "Schedules", ("Name", "Start", "End", "Days"), rows)

    def _build_policies(self, workbook: Any) -> None:
        rows = [
            (
                index, item.name, item.from_zone, item.to_zone, item.source, item.destination,
                item.service, item.action, item.schedule, item.disabled, item.log_start, item.log_end,
                item.applications, item.internet_service, item.security_profile_group,
                item.antivirus, item.ips_sensor, item.webfilter, item.application_list,
                item.ssl_ssh_profile, item.description,
            )
            for index, item in enumerate(self.ir.policies, 1)
        ]
        self._table_sheet(
            workbook,
            "Policies",
            (
                "Rule #", "Name", "From Zone", "To Zone", "Source", "Destination", "Service",
                "Action", "Schedule", "Disabled", "Log Start", "Log End", "Applications",
                "Internet Services", "Security Profile Group", "Antivirus", "IPS Sensor",
                "Web Filter", "Application List", "SSL/SSH Profile", "Description",
            ),
            rows,
        )

    def _build_nat_rules(self, workbook: Any) -> None:
        rows = [
            (
                item.name, item.type, item.from_zone, item.to_zone, item.source, item.destination,
                item.service, item.translated_source, item.translated_destination,
                item.translated_port, item.description,
            )
            for item in self.ir.nat_rules
        ]
        self._table_sheet(
            workbook,
            "NAT Rules",
            (
                "Name", "Type", "From Zone", "To Zone", "Original Source",
                "Original Destination", "Service", "Translated Source", "Translated Destination",
                "Translated Port", "Description",
            ),
            rows,
        )

    def _build_vpn_tunnels(self, workbook: Any) -> None:
        rows = [
            (
                item.name, item.peer_address, item.local_interface, item.ike_version,
                "Configured / Redacted" if item.psk else "Not configured",
                item.ike_crypto_profile, item.ipsec_crypto_profile, item.description,
            )
            for item in self.ir.vpn_tunnels
        ]
        self._table_sheet(
            workbook,
            "VPN Tunnels",
            (
                "Name", "Peer Address", "Local Interface", "IKE Version", "PSK",
                "IKE Crypto Profile", "IPsec Crypto Profile", "Description",
            ),
            rows,
        )

    def _build_routes(self, workbook: Any) -> None:
        rows = [
            (item.name, item.destination, item.interface, item.next_hop, item.metric, item.description)
            for item in self.ir.routes
        ]
        self._table_sheet(
            workbook, "Routes", ("Name", "Destination", "Interface", "Next Hop", "Metric", "Description"), rows
        )

    def _build_internet_services(self, workbook: Any) -> None:
        rows = [(item.name, item.description) for item in self.ir.internet_services]
        self._table_sheet(workbook, "Internet Services", ("Name", "Description"), rows)

    def _build_security_profiles(self, workbook: Any) -> None:
        rows = [
            (
                item.name, item.antivirus, item.vulnerability, item.anti_spyware,
                item.url_filtering, item.file_blocking, item.wildfire,
                item.ssl_decryption, item.description,
            )
            for item in self.ir.security_profile_groups
        ]
        self._table_sheet(
            workbook,
            "Security Profiles",
            (
                "Name", "Antivirus", "Vulnerability", "Anti-Spyware", "URL Filtering",
                "File Blocking", "WildFire", "SSL Decryption", "Description",
            ),
            rows,
        )

    def _build_warnings(self, workbook: Any) -> None:
        rows = [
            (item.id, item.category, item.confidence, item.message)
            for item in self.ir.audit_entries
        ]
        sheet = self._table_sheet(
            workbook, "Warnings", ("ID", "Category", "Confidence", "Message"), rows,
            empty_note="No audit warnings were reported. See Extraction Coverage before assuming extraction is complete.",
            subtitle="Audit and manual-review entries emitted while normalizing the source configuration.",
        )
        for row in range(4, sheet.max_row + 1):
            confidence = str(sheet.cell(row, 3).value or "").lower()
            if confidence in {"manual", "unsupported"}:
                fill = self._LIGHT_RED
            elif confidence == "partial":
                fill = self._LIGHT_AMBER
            else:
                continue
            for column in range(1, 5):
                sheet.cell(row, column).fill = PatternFill("solid", fgColor=fill)

    def _build_unsupported(self, workbook: Any) -> None:
        rows = [
            (
                item.category, item.id, "Unsupported", item.message, True,
                "Audit entry; raw source intentionally excluded from workbook",
            )
            for item in self.ir.audit_entries
            if item.confidence == MigrationConfidence.UNSUPPORTED
        ]
        sheet = self._table_sheet(
            workbook,
            "Unsupported",
            ("Section", "Item", "Status", "Reason", "Manual Review", "Raw Capture"),
            rows,
            empty_note="No unsupported items were reported. See Extraction Coverage before assuming extraction is complete.",
            subtitle="Unsupported audit entries are listed without raw source configuration or secrets.",
        )
        for row in range(4, sheet.max_row + 1):
            for column in range(1, 7):
                sheet.cell(row, column).fill = PatternFill("solid", fgColor=self._LIGHT_RED)

    def _build_extraction_coverage(self, workbook: Any) -> None:
        collections = (
            ("Interfaces", self.ir.interfaces),
            ("Zones", self.ir.zones),
            ("Addresses", self.ir.addresses),
            ("Address Groups", self.ir.address_groups),
            ("Services", self.ir.services),
            ("Service Groups", self.ir.service_groups),
            ("Schedules", self.ir.schedules),
            ("Policies", self.ir.policies),
            ("NAT Rules", self.ir.nat_rules),
            ("VPN Tunnels", self.ir.vpn_tunnels),
            ("Routes", self.ir.routes),
            ("Internet Services", self.ir.internet_services),
            ("Security Profiles", self.ir.security_profile_groups),
        )
        rows = [
            (
                name, None, len(items), "Not reported",
                "Populated" if items else "Empty / unknown",
                "Phase 1 exports IR only; source-section coverage awaits ExtractionResult in Phase 2.",
            )
            for name, items in collections
        ]
        note = "Source-section evidence is unavailable in IR; inferred counts are not proof of parser completeness."
        sheet = self._table_sheet(
            workbook,
            "Extraction Coverage",
            ("Source Section", "Found", "Objects", "Parser Status", "IR Status", "Notes"),
            rows,
            subtitle=note,
        )
        for row in range(4, sheet.max_row + 1):
            status = str(sheet.cell(row, 5).value or "").lower()
            if "unsupported" in status or "not transformed" in status:
                fill = self._LIGHT_RED
            elif "partial" in status or "unknown" in status:
                fill = self._LIGHT_AMBER
            else:
                continue
            for column in range(1, 7):
                sheet.cell(row, column).fill = PatternFill("solid", fgColor=fill)

    def _table_sheet(
        self,
        workbook: Any,
        title: str,
        headers: Sequence[str],
        rows: Iterable[Sequence[Any]],
        empty_note: str = "No objects were represented in this IR collection.",
        subtitle: str = "Vendor-neutral IR inventory exported before migration optimization.",
    ) -> Any:
        rows = list(rows)
        sheet = workbook.create_sheet(title)
        sheet.sheet_view.showGridLines = False
        last_column = get_column_letter(len(headers))
        sheet.merge_cells(f"A1:{last_column}1")
        sheet["A1"] = title
        sheet["A1"].font = Font(name="Aptos Display", size=16, bold=True, color=self._WHITE)
        sheet["A1"].fill = PatternFill("solid", fgColor=self._NAVY)
        sheet["A1"].alignment = Alignment(vertical="center")
        sheet.row_dimensions[1].height = 30

        sheet.merge_cells(f"A2:{last_column}2")
        sheet["A2"] = self._safe_value(subtitle if rows else empty_note)
        sheet["A2"].font = Font(name="Aptos", size=9, italic=True, color=self._MUTED)
        sheet["A2"].alignment = Alignment(wrap_text=True, vertical="center")
        sheet.row_dimensions[2].height = 26

        for column, header in enumerate(headers, 1):
            cell = sheet.cell(3, column, self._safe_value(header))
            cell.font = Font(name="Aptos", bold=True, color=self._WHITE)
            cell.fill = PatternFill("solid", fgColor=self._TEAL)
            cell.alignment = Alignment(wrap_text=True, vertical="center")
        sheet.row_dimensions[3].height = 28

        row_count = 0
        for row_count, values in enumerate(rows, 1):
            worksheet_row = row_count + 3
            for column, value in enumerate(values, 1):
                cell = sheet.cell(worksheet_row, column, self._safe_value(value))
                cell.font = Font(name="Aptos", size=10, color=self._TEXT)
                cell.alignment = Alignment(wrap_text=True, vertical="top")
            if row_count % 2 == 0:
                for column in range(1, len(headers) + 1):
                    sheet.cell(worksheet_row, column).fill = PatternFill("solid", fgColor="F8FAFC")

        sheet.auto_filter.ref = f"A3:{last_column}{max(3, row_count + 3)}"
        sheet.freeze_panes = "A4"
        self._size_table(sheet, len(headers), row_count)
        return sheet

    def _size_table(self, sheet: Any, column_count: int, row_count: int) -> None:
        thin = Side(style="thin", color=self._BORDER)
        for column in range(1, column_count + 1):
            header = str(sheet.cell(3, column).value or "")
            max_length = len(header)
            for row in range(4, min(row_count + 4, 204)):
                value = str(sheet.cell(row, column).value or "")
                max_length = max(max_length, max((len(line) for line in value.splitlines()), default=0))
            width_cap = 48 if any(token in header.lower() for token in ("description", "message", "note", "reason")) else 32
            sheet.column_dimensions[get_column_letter(column)].width = min(max(max_length + 2, 11), width_cap)
            sheet.cell(3, column).border = Border(bottom=thin)

        for row in range(4, row_count + 4):
            max_lines = max(
                (str(sheet.cell(row, column).value or "").count("\n") + 1 for column in range(1, column_count + 1)),
                default=1,
            )
            sheet.row_dimensions[row].height = min(15 * max_lines + 5, 90)

    def _format_port(self, port: Any) -> str:
        protocol = self._enum_value(port.protocol)
        result = f"{protocol}/{port.port}"
        details = []
        if port.icmptype is not None:
            details.append(f"type={port.icmptype}")
        if port.icmpcode is not None:
            details.append(f"code={port.icmpcode}")
        if details:
            result += f" ({', '.join(details)})"
        return result

    def _safe_value(self, value: Any) -> Any:
        if value is None:
            return ""
        if isinstance(value, bool):
            return "Yes" if value else "No"
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, datetime):
            value = value.isoformat()
        elif isinstance(value, Enum):
            value = value.value
        elif isinstance(value, (list, tuple, set)):
            value = "\n".join(str(self._enum_value(item)) for item in value)
        else:
            value = str(value)

        value = redact_sensitive(value)
        value = _ILLEGAL_XML_CHARS.sub(" ", value)
        if len(value) > _MAX_CELL_TEXT:
            suffix = "\n[truncated for Excel cell limit]"
            value = value[: _MAX_CELL_TEXT - len(suffix)] + suffix
        if value.lstrip().startswith(_FORMULA_PREFIXES):
            value = "'" + value
        return value

    @staticmethod
    def _enum_value(value: Any) -> Any:
        return value.value if isinstance(value, Enum) else value
