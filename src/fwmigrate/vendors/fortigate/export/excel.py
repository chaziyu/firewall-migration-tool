from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator, Mapping, Sequence

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from ..config import ExtractionConfig
from ..derived import DerivedViews, build_derived_views
from ..extraction.result import ExtractionResult
from ..extraction.source_inventory import SourceObjectRecord
from ..extraction.coverage import (
    build_typed_source_inventory,
    extraction_status,
    find_typed_source_object,
    supports_path,
)
from ..security.extraction import sanitize_source_attributes, sanitize_source_value
from ..section_registry import registered_sections
from ..validation.index import ValidationIssueIndex
from ..validation.models import ValidationIssue, ValidationResult
from .excel_schema import (
    DERIVED_COLUMNS_BY_SHEET,
    HIDDEN_COLUMNS_BY_DEFAULT,
    SHEET_HEADERS,
    SHEET_ORDER,
)


_TITLE_FILL = PatternFill("solid", fgColor="17324D")
_HEADER_FILL = PatternFill("solid", fgColor="0F766E")
_DERIVED_FILL = PatternFill("solid", fgColor="D7F0EC")
_REVIEW_FILL = PatternFill("solid", fgColor="FEF3C7")
_ERROR_FILL = PatternFill("solid", fgColor="FEE2E2")
_ALT_FILL = PatternFill("solid", fgColor="F8FAFC")
_WHITE_FONT = Font(color="FFFFFF", bold=True)
_TITLE_FONT = Font(color="FFFFFF", bold=True, size=14)
_HEADER_FONT = Font(color="FFFFFF", bold=True, size=10)
_MUTED_FONT = Font(color="667085", italic=True, size=9)
_LINK_FONT = Font(color="0563C1", underline="single")
_CELL_ALIGNMENT = Alignment(wrap_text=True, vertical="top")
_THIN = Side(style="thin", color="D9E2DF")
_BORDER = Border(bottom=_THIN)


_SOURCE_PATHS_BY_SHEET: dict[str, tuple[str, ...]] = {
    "DNS Settings": ("system dns",),
}

_SOURCE_HEADER_ALIASES: dict[str, tuple[str, ...]] = {
    "Alias": ("alias",),
    "IP / Prefix": ("ip",),
    "Interface Type": ("type",),
    "Role": ("role",),
    "Addressing Mode": ("mode",),
    "Management Access": ("allowaccess",),
    "VLAN ID": ("vlanid",),
    "Members": ("member", "members"),
    "Description": ("description", "comment", "comments"),
    "Protocol": ("protocol",),
    "Source Port": ("src-port", "source-port"),
    "Destination Port": ("dst-port", "destination-port"),
    "Auto Negotiate": ("auto-negotiate", "auto_negotiate"),
}

_SOURCE_INVENTORY_WIDTHS = {
    "Domain": 24,
    "VDOM": 14,
    "Scope Type": 14,
    "Source Path": 34,
    "Object": 32,
    "Parent / Subsection": 32,
    "Operation": 12,
    "Setting": 36,
    "Value": 60,
    "Primitive Registration": 20,
    "Extraction Status": 18,
    "Raw Extra Entries": 18,
}


def export_excel(
    *,
    extracted: ExtractionResult,
    validation: ValidationResult,
    output: BinaryIO | Path | str,
    config: ExtractionConfig | None = None,
    derived: DerivedViews | None = None,
    source_name: str | None = None,
) -> None:
    """Write the FortiGate configuration report."""

    del config

    derived = derived or build_derived_views(extracted.config)

    context = _ExcelContext(
        extracted=extracted,
        derived=derived,
        validation=validation,
        source_name=source_name,
    )

    workbook = _build_workbook(context)
    if isinstance(output, (str, Path)):
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        workbook.save(path)
        return

    workbook.save(output)


class _ExcelContext:
    def __init__(
        self,
        *,
        extracted: ExtractionResult,
        derived: DerivedViews,
        validation: ValidationResult,
        source_name: str | None,
    ) -> None:
        self.extracted = extracted
        self.config = extracted.config
        self.derived = derived
        self.validation = validation
        self.source_name = source_name or ""
        self.source_by_path: dict[str, list[SourceObjectRecord]] = defaultdict(list)
        self.source_by_vdom: dict[str, list[SourceObjectRecord]] = defaultdict(list)
        self.source_by_identity: dict[tuple[str, str, str | None], list[SourceObjectRecord]] = defaultdict(list)
        self.nested_source_by_parent: dict[tuple[str, str, str | None], list[SourceObjectRecord]] = defaultdict(list)

        for record in extracted.source_objects:
            self.source_by_path[record.source_path].append(record)
            self.source_by_vdom[record.vdom].append(record)
            self.source_by_identity[(record.vdom, record.source_path, record.object_name)].append(record)
            if record.source_path.startswith("system interface "):
                parent = record.parent_objects[0] if record.parent_objects else None
                self.nested_source_by_parent[(record.vdom, "system interface", parent)].append(record)

        self.source_paths = frozenset(self.source_by_path)
        self.vdoms = frozenset(self.source_by_vdom)
        self.registered_sections = frozenset(registered_sections())
        self.typed_source_inventory = build_typed_source_inventory(self.config)
        self.source_only_counts = {
            path: len(records)
            for path, records in self.source_by_path.items()
            if not supports_path(path)
        }
        self.ipv6_explicit = any(
            "ipv6" in _normalize_key(key) or "ip6" in _normalize_key(key)
            for record in extracted.source_objects
            for key in record.values
        )
        self.source_inventory_row_count = sum(
            max(1, len(record.commands))
            for record in extracted.source_objects
        )

        self.validation_index = ValidationIssueIndex(validation)

    def issues_for(
        self,
        *,
        vdom: str,
        names: Iterable[Any],
        domains: Iterable[str] | None = None,
    ) -> list[ValidationIssue]:
        found: list[ValidationIssue] = []
        seen: set[tuple[str, str, str]] = set()

        for issue in self.validation_index.issues_for(
            vdom,
            names,
            domains,
        ):
            key = (issue.domain, issue.field or "", issue.message)
            if key in seen:
                continue
            seen.add(key)
            found.append(issue)

        return found


def _build_workbook(context: _ExcelContext) -> Workbook:
    workbook = Workbook()
    workbook.remove(workbook.active)

    order = list(SHEET_ORDER)

    for sheet_name in order:
        if sheet_name == "Summary":
            _build_summary(workbook, context, order)
        elif sheet_name == "FortiGate Source Inventory":
            _write_source_inventory_sheet(workbook, context)
        else:
            headers = list(SHEET_HEADERS[sheet_name])
            _write_table_sheet(
                workbook,
                sheet_name,
                headers,
                _rows_for_sheet(sheet_name, context, headers),
                context=context,
            )

    return workbook

def _rows_for_sheet(
    sheet_name: str,
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterable[Mapping[str, Any]]:
    builders = {
        "Review Required": _review_rows,
        "Interfaces": _interface_rows,
        "Interface Secondary IPs": _interface_secondary_rows,
        "Zones": _zone_rows,
        "Addresses": _address_rows,
        "Wildcard FQDN": _wildcard_fqdn_rows,
        "Address Groups": _address_group_rows,
        "Services": _service_rows,
        "Service Groups": _service_group_rows,
        "Schedules": _schedule_rows,
        "Schedule Groups": _schedule_group_rows,
        "Policies": _policy_rows,
        "Security Policies": _security_policy_rows,
        "IP Pools": _ip_pool_rows,
        "Virtual IPs": _vip_rows,
        "VIP Real Servers": _vip_real_server_rows,
        "VIP Groups": _vip_group_rows,
        "NAT Rules": _nat_rows,
        "Routes": _route_rows,
        "VPN Tunnels": _vpn_phase1_rows,
        "Policy IPsec Phase 1": _policy_vpn_phase1_rows,
        "VPN Phase 2": _vpn_phase2_rows,
        "Policy IPsec Phase 2": _policy_vpn_phase2_rows,
        "DHCP Servers": _dhcp_server_rows,
        "DHCP IP Ranges": _dhcp_ip_range_rows,
        "DHCP Exclude Ranges": _dhcp_exclude_range_rows,
        "DHCP Reservations": _dhcp_reservation_rows,
        "SD-WAN": _sdwan_rows,
        "SD-WAN Zones": _sdwan_zone_rows,
        "SD-WAN Members": _sdwan_member_rows,
        "SD-WAN Health Checks": _sdwan_health_rows,
        "SD-WAN Rules": _sdwan_rule_rows,
        "SSL VPN Settings": _ssl_settings_rows,
        "SSL VPN Realms": _ssl_realm_rows,
        "SSL VPN Clients": _ssl_client_rows,
        "SSL VPN Bookmark Owners": _ssl_bookmark_owner_rows,
        "SSL VPN Bookmarks": _ssl_bookmark_rows,
        "SSL VPN Portals": _ssl_portal_rows,
        "SSL VPN Authentication Rules": _ssl_auth_rule_rows,
        "NTP Settings": _ntp_setting_rows,
        "NTP Servers": _ntp_server_rows,
        "Local Users": _local_user_rows,
        "User Groups": _user_group_rows,
        "User Group Matches": _user_group_match_rows,
        "Administrators": _administrator_rows,
        "Admin Profiles": _admin_profile_rows,
        "Admin Profile Permissions": _admin_permission_rows,
        "IPS Sensors": _ips_sensor_rows,
        "IPS Sensor Entries": _ips_entry_rows,
        "IPS Exempt IPs": _ips_exempt_rows,
        "Security Profiles": _security_profile_rows,
        "External Resources": _external_resource_rows,
        "Firewall Policy Source Settings": _policy_source_rows,
        "Interface Source Settings": _interface_source_rows,
        "Interface Nested Configuration": _interface_nested_rows,
        "Unresolved References": _unresolved_reference_rows,
        "Unsupported": _unsupported_rows,
        "Extraction Coverage": _coverage_rows,
    }

    builder = builders.get(sheet_name)

    if builder is not None:
        return builder(context, headers)

    return _generic_source_rows(sheet_name, context, headers)


def _build_summary(
    workbook: Workbook,
    context: _ExcelContext,
    order: Sequence[str],
) -> None:
    sheet = workbook.create_sheet("Summary")
    sheet.sheet_view.showGridLines = False
    sheet.freeze_panes = "A5"

    sheet.merge_cells("A1:F1")
    sheet["A1"] = "FortiGate Configuration Report"
    sheet["A1"].fill = _TITLE_FILL
    sheet["A1"].font = Font(color="FFFFFF", bold=True, size=18)
    sheet["A1"].alignment = Alignment(vertical="center")
    sheet.row_dimensions[1].height = 30

    metadata = [
        ("Source File", context.source_name),
        ("Hostname", _hostname(context)),
        ("FortiOS Version", context.extracted.source_metadata.fortios_version),
        ("VDOMs", "\n".join(_vdoms(context))),
        ("Generated UTC", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
        ("Validation Errors", len(context.validation.errors)),
        ("Validation Warnings", len(context.validation.warnings)),
    ]

    for row_number, (label, value) in enumerate(metadata, start=3):
        sheet.cell(row_number, 1, label).font = Font(bold=True, color="41504C")
        sheet.cell(row_number, 2, _excel_safe(value))
        sheet.cell(row_number, 2).alignment = Alignment(wrap_text=True, vertical="top")

    section_row = 11
    sheet.cell(section_row, 1, "Inventory")
    sheet.cell(section_row, 1).fill = _HEADER_FILL
    sheet.cell(section_row, 1).font = _WHITE_FONT
    sheet.merge_cells(start_row=section_row, start_column=1, end_row=section_row, end_column=3)

    counts = _inventory_counts(context)

    row_number = section_row + 1
    for label, count, target in counts:
        sheet.cell(row_number, 1, label)
        sheet.cell(row_number, 2, count)
        if target in order:
            cell = sheet.cell(row_number, 3, "Open sheet")
            cell.hyperlink = f"#'{target}'!A1"
            cell.font = _LINK_FONT
        row_number += 1

    indicator_row = row_number + 1
    sheet.cell(indicator_row, 1, "Migration Indicators")
    sheet.cell(indicator_row, 1).fill = _HEADER_FILL
    sheet.cell(indicator_row, 1).font = _WHITE_FONT
    sheet.merge_cells(
        start_row=indicator_row,
        start_column=1,
        end_row=indicator_row,
        end_column=3,
    )

    for row_number, (label, value) in enumerate(
        _migration_indicators(context),
        start=indicator_row + 1,
    ):
        sheet.cell(row_number, 1, label)
        sheet.cell(row_number, 2, value)

    nav_col = 5
    sheet.cell(3, nav_col, "Workbook navigation")
    sheet.cell(3, nav_col).fill = _HEADER_FILL
    sheet.cell(3, nav_col).font = _WHITE_FONT

    nav_row = 4
    for name in order:
        if name == "Summary":
            continue
        cell = sheet.cell(nav_row, nav_col, name)
        cell.hyperlink = f"#'{name}'!A1"
        cell.font = _LINK_FONT
        nav_row += 1

    sheet.column_dimensions["A"].width = 28
    sheet.column_dimensions["B"].width = 24
    sheet.column_dimensions["C"].width = 16
    sheet.column_dimensions["E"].width = 34


def _write_table_sheet(
    workbook: Workbook,
    sheet_name: str,
    headers: Sequence[str],
    rows: Iterable[Mapping[str, Any]],
    *,
    context: _ExcelContext,
) -> None:
    sheet = workbook.create_sheet(sheet_name)
    sheet.sheet_view.showGridLines = False
    sheet.sheet_view.zoomScale = 90

    max_col = max(len(headers), 1)
    derived_headers = set(DERIVED_COLUMNS_BY_SHEET.get(sheet_name, ()))
    hidden_headers = set(HIDDEN_COLUMNS_BY_DEFAULT.get(sheet_name, ()))
    sheet.merge_cells(start_row=1, start_column=1, end_row=1, end_column=max_col)
    sheet.cell(1, 1, sheet_name)
    sheet.cell(1, 1).fill = _TITLE_FILL
    sheet.cell(1, 1).font = _TITLE_FONT
    sheet.cell(1, 1).alignment = Alignment(vertical="center")
    sheet.row_dimensions[1].height = 24

    if max_col > 2:
        sheet.merge_cells(
            start_row=2,
            start_column=1,
            end_row=2,
            end_column=max_col - 1,
        )
    note = sheet.cell(2, 1)
    note.value = ""
    note.font = _MUTED_FONT
    note.alignment = Alignment(wrap_text=True, vertical="top")

    for column, header in enumerate(headers, start=1):
        cell = sheet.cell(3, column, header)
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
        cell.alignment = Alignment(wrap_text=True, vertical="center")
        cell.border = _BORDER


    row_count = 0
    for index, row in enumerate(rows, start=4):
        row_count += 1
        review_fill = (
            _ERROR_FILL
            if row.get("__error__")
            else _REVIEW_FILL
            if row.get("__review__")
            else None
        )
        alternate_fill = _ALT_FILL if index % 2 == 1 else None
        outline = row.get("__outline_level__")
        if isinstance(outline, int) and outline > 0:
            sheet.row_dimensions[index].outlineLevel = min(outline, 7)

        for column, header in enumerate(headers, start=1):
            value = _excel_safe(row.get(header))
            cell = sheet.cell(index, column, value)
            cell.alignment = _CELL_ALIGNMENT
            fill = (
                review_fill
                or (_DERIVED_FILL if header in derived_headers else None)
                or alternate_fill
            )
            if fill is not None:
                cell.fill = fill

    note.value = _sheet_note(sheet_name, row_count)

    if row_count:
        sheet.auto_filter.ref = f"A3:{get_column_letter(max_col)}{row_count + 3}"

    sheet.freeze_panes = _freeze_pane(sheet_name, headers)
    _apply_widths(sheet, headers)
    for column, header in enumerate(headers, start=1):
        if header in hidden_headers:
            sheet.column_dimensions[get_column_letter(column)].hidden = True
    _add_back_link(sheet)

    if sheet_name == "Review Required":
        _apply_review_colors(sheet, headers, row_count)


def _write_source_inventory_sheet(
    workbook: Workbook,
    context: _ExcelContext,
) -> None:
    sheet_name = "FortiGate Source Inventory"
    headers = SHEET_HEADERS[sheet_name]
    row_count = _source_inventory_row_count(context)
    sheet = workbook.create_sheet(sheet_name)
    sheet.sheet_view.showGridLines = False
    sheet.sheet_view.zoomScale = 90

    max_col = len(headers)
    sheet.merge_cells(start_row=1, start_column=1, end_row=1, end_column=max_col)
    sheet.cell(1, 1, sheet_name)
    sheet.cell(1, 1).fill = _TITLE_FILL
    sheet.cell(1, 1).font = _TITLE_FONT
    sheet.cell(1, 1).alignment = Alignment(vertical="center")
    sheet.row_dimensions[1].height = 24

    sheet.merge_cells(start_row=2, start_column=1, end_row=2, end_column=max_col - 1)
    note = sheet.cell(2, 1)
    note.value = _sheet_note(sheet_name, row_count)
    note.font = _MUTED_FONT
    note.alignment = Alignment(wrap_text=True, vertical="top")

    for column, header in enumerate(headers, start=1):
        cell = sheet.cell(3, column, header)
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
        cell.alignment = Alignment(wrap_text=True, vertical="center")
        cell.border = _BORDER

    for values in _iter_fortigate_source_inventory_rows(context):
        sheet.append(values)

    sheet.auto_filter.ref = f"A3:{get_column_letter(max_col)}{row_count + 3}"
    sheet.freeze_panes = "A4"
    for column, header in enumerate(headers, start=1):
        sheet.column_dimensions[get_column_letter(column)].width = _SOURCE_INVENTORY_WIDTHS[header]
    _add_back_link(sheet)


def _add_back_link(sheet) -> None:
    if sheet.max_column <= 1:
        return

    cell = sheet.cell(2, sheet.max_column)
    cell.value = "Back to Summary"
    cell.hyperlink = "#'Summary'!A1"
    cell.font = _LINK_FONT
    cell.alignment = Alignment(horizontal="right")


def _apply_review_colors(sheet, headers: Sequence[str], row_count: int) -> None:
    if "Severity" not in headers:
        return

    severity_col = headers.index("Severity") + 1

    for row in range(4, row_count + 4):
        severity = str(sheet.cell(row, severity_col).value or "").lower()
        fill = _ERROR_FILL if severity == "error" else _REVIEW_FILL

        for column in range(1, len(headers) + 1):
            sheet.cell(row, column).fill = fill


def _apply_widths(sheet, headers: Sequence[str]) -> None:
    for index, header in enumerate(headers, start=1):
        normalized = header.lower()

        if any(token in normalized for token in ("additional settings", "review reason", "raw capture", "notes")):
            width = 36
        elif any(token in normalized for token in ("description", "comment", "source path", "setting", "value")):
            width = 28
        elif any(token in normalized for token in ("members", "addresses", "interfaces", "services", "profiles", "references")):
            width = 26
        elif any(token in normalized for token in ("name", "object", "category", "status", "type")):
            width = 20
        elif "id" in normalized or "port" in normalized or "vlan" in normalized:
            width = 14
        else:
            width = 18

        sheet.column_dimensions[get_column_letter(index)].width = width


def _freeze_pane(sheet_name: str, headers: Sequence[str]) -> str:
    if sheet_name == "Interfaces":
        return "D4"
    if sheet_name == "Policies":
        return "D4"
    if len(headers) > 12:
        return "C4"
    return "A4"


def _sheet_note(
    sheet_name: str,
    row_count: int,
) -> str:
    if sheet_name == "FortiGate Source Inventory":
        return (
            "Explicit FortiGate source commands retained for traceability. "
            "Extraction Status identifies whether the source section has "
            "dedicated typed extraction support."
        )

    if row_count:
        return (
            f"{row_count} record(s). "
            "Values are explicit FortiGate source data unless the column is "
            "identified as derived or analysis output."
        )

    return "No matching explicit FortiGate source records were extracted."


def _inventory_counts(context: _ExcelContext) -> list[tuple[str, int, str]]:
    config = context.config
    source_only = context.source_only_counts
    counts = [
        ("Source Interfaces", len(config.interfaces), "Interfaces"),
        ("Zones", len(config.zones), "Zones"),
        ("Addresses", len(config.addresses), "Addresses"),
        ("Address Groups", len(config.address_groups), "Address Groups"),
        ("Services", len(context.derived.services.services), "Services"),
        ("Service Groups", len(context.derived.services.groups), "Service Groups"),
        ("Policies", len(config.policies), "Policies"),
        ("Security Policies", len(config.security_policies), "Security Policies"),
        ("NAT Rules", len(context.derived.nat), "NAT Rules"),
        ("IP Pools", len(config.ip_pools) + len(config.ip_pools6), "IP Pools"),
        ("Virtual IPs", len(config.vips) + len(config.vips6), "Virtual IPs"),
        ("Routes", len(config.static_routes), "Routes"),
        ("VPN Tunnels", len(config.ipsec_phase1), "VPN Tunnels"),
        ("Policy IPsec Phase 1", len(config.ipsec_policy_phase1), "Policy IPsec Phase 1"),
        ("Policy IPsec Phase 2", len(config.ipsec_policy_phase2), "Policy IPsec Phase 2"),
        ("VPN Phase 2", len(config.ipsec_phase2), "VPN Phase 2"),
        ("Local Users", len(config.local_users), "Local Users"),
        ("DHCP Servers", len(config.dhcp_servers), "DHCP Servers"),
        ("SD-WAN Members", sum(len(item.members) for item in config.sdwans), "SD-WAN Members"),
        ("SSL VPN Portals", len(config.ssl_vpn_portals), "SSL VPN Portals"),
        ("SSL VPN Realms", len(config.ssl_vpn_realms), "SSL VPN Realms"),
        ("SSL VPN Clients", len(config.ssl_vpn_clients), "SSL VPN Clients"),
        ("SSL VPN Bookmark Owners", len(config.ssl_vpn_user_bookmarks) + len(config.ssl_vpn_user_group_bookmarks), "SSL VPN Bookmark Owners"),
        ("SSL VPN Bookmarks", sum(len(owner.bookmarks) for owner in config.ssl_vpn_user_bookmarks + config.ssl_vpn_user_group_bookmarks), "SSL VPN Bookmarks"),
        ("Administrators", len(config.administrators), "Administrators"),
        ("IPS Sensors", len(config.ips_sensors), "IPS Sensors"),
        ("External Resources", len(config.external_resources), "External Resources"),
        ("Review Required", len(context.validation.issues), "Review Required"),
        ("Source-only Sections", len(source_only), "Unsupported"),
    ]
    return counts


def _hostname(context: _ExcelContext) -> str | None:
    for record in context.source_by_path.get("system global", ()):
        for key, value in record.values.items():
            if _normalize_key(key) == "hostname":
                return value
    return None


def _migration_indicators(context: _ExcelContext) -> list[tuple[str, Any]]:
    config = context.config
    topology_issues = sum(
        len(item.issues)
        for item in (
            *context.derived.topology.interfaces,
            *context.derived.topology.vpns,
        )
    )
    nat_review_items = sum(
        issue.domain == "nat"
        for issue in context.validation.issues
    )
    dynamic_wan = any(
        (interface.mode or "").lower() in {"dhcp", "pppoe"}
        for interface in config.interfaces
    )
    return [
        ("IPv6 Explicit Configuration Present", "Yes" if context.ipv6_explicit else "No"),
        ("Dynamic WAN Addressing Present", "Yes" if dynamic_wan else "No"),
        ("SD-WAN Present", "Yes" if config.sdwans else "No"),
        ("NAT Review Items", nat_review_items),
        ("Broken References", len(context.derived.broken_references)),
        ("Topology Issues", topology_issues),
    ]


def _vdoms(context: _ExcelContext) -> list[str]:
    values = set(context.vdoms)
    values.update(
        getattr(item, "vdom", "root")
        for collection_name in (
            "interfaces",
            "zones",
            "addresses",
            "policies",
            "static_routes",
            "ipsec_phase1",
        )
        for item in getattr(context.config, collection_name, ())
    )
    return sorted(values)


def _review_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for issue in context.validation.issues:
        row = {
            "Severity": issue.severity.value,
            "Category": issue.domain,
            "Object": issue.object_name,
            "VDOM": issue.vdom,
            "Field": issue.field,
            "Issue / Review Reason": issue.message,
            "Source Sheet": _sheet_for_domain(issue.domain),
        }
        rows.append(row)

    return rows


def _interface_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    topology = {(item.vdom, item.name): item for item in context.derived.topology.interfaces}
    interfaces = {(item.vdom, item.name): item for item in context.config.interfaces}
    aggregate_members: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    children: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
    owned: set[tuple[str, str]] = set()
    for interface in context.config.interfaces:
        key = (interface.vdom, interface.name)
        if interface.interface and (interface.vdom, interface.interface) in interfaces:
            children[(interface.vdom, interface.interface)].append(key)
        for member in interface.members:
            member_key = (interface.vdom, member)
            aggregate_members[key].append(member_key)
            owned.add(member_key)

    vpns_by_interface: dict[tuple[str, str], list[Any]] = defaultdict(list)
    vpns = {(item.vdom, item.name): item for item in context.config.ipsec_phase1}
    for vpn in context.derived.topology.vpns:
        if vpn.attached_interface:
            vpns_by_interface[(vpn.vdom, vpn.attached_interface)].append(vpn)

    def rank(key: tuple[str, str]) -> tuple[int, str]:
        return _interface_rank(topology.get(key), interfaces[key])

    roots = sorted(
        (key for key in interfaces if key not in owned and not interfaces[key].interface),
        key=rank,
    )
    zones_by_interface: dict[tuple[str, str], list[str]] = defaultdict(list)
    for zone in context.config.zones:
        for member in zone.members:
            zones_by_interface[(zone.vdom, member)].append(zone.name)
    rows: list[dict[str, Any]] = []
    visited: set[tuple[str, str]] = set()
    emitted_vpns: set[tuple[str, str]] = set()

    def emit_vpn(vpn_top: Any, prefix: str = "") -> None:
        vpn_key = (vpn_top.vdom, vpn_top.name)
        if vpn_key in emitted_vpns:
            return
        emitted_vpns.add(vpn_key)
        vpn = vpns.get(vpn_key)
        if vpn is None:
            return
        row = {
            "Name": f"{prefix}{_topology_symbol('vpn')} {vpn.name}",
            "Type": vpn.type,
            "Parent Interface": vpn_top.attached_interface,
            "Aggregate": vpn_top.aggregate,
            "Physical Interfaces": list(vpn_top.physical_interfaces),
            "Topology Path": list(vpn_top.path),
            "VDOM": vpn.vdom,
            "Topology Issues": list(vpn_top.issues),
            "Source Explicit Fields": sorted(vpn.explicit_fields),
            "Additional Settings": sanitize_source_attributes(vpn.raw_extra),
        }
        _add_analysis_status(
            row,
            context,
            vdom=vpn.vdom,
            names=(vpn.name,),
            domains=("ipsec_phase1", "vpn_topology"),
            extra_reasons=vpn_top.issues,
        )
        _overlay_raw(row, vpn.raw_extra, headers)
        rows.append(row)

    def emit_interface(key: tuple[str, str], prefix: str = "", child_indent: str = "") -> None:
        if key in visited:
            return
        visited.add(key)
        interface = interfaces[key]
        key = (interface.vdom, interface.name)
        top = topology.get(key)
        row = {
            "Name": f"{prefix}{_topology_symbol(top.kind if top else None)} {interface.name}",
            "Alias": interface.alias,
            "Zone": zones_by_interface.get(key, []),
            "IP / Prefix": interface.ip,
            "Type": interface.type,
            "Role": interface.role,
            "Addressing Mode": interface.mode,
            "Management Access": interface.allowaccess,
            "VLAN ID": interface.vlanid,
            "Parent Interface": interface.interface,
            "Aggregate": top.aggregate if top else None,
            "Physical Interfaces": list(top.physical_interfaces) if top else [],
            "Topology Path": list(top.path) if top else [interface.name],
            "Members": interface.members,
            "Status": _enabled_text(interface.status),
            "Description": interface.description,
            "VDOM": interface.vdom,
            "Topology Issues": list(top.issues) if top else [],
            "Source Explicit Fields": sorted(interface.explicit_fields),
            "Additional Settings": sanitize_source_attributes(interface.raw_extra),
        }

        _add_analysis_status(
            row,
            context,
            vdom=interface.vdom,
            names=(interface.name,),
            domains=("interface", "interface_topology"),
        )
        source_values = _interface_source_values(
            context,
            vdom=interface.vdom,
            name=interface.name,
        )

        row["Secondary IPv4 Addresses"] = [secondary.ip for secondary in interface.secondary_ips if secondary.ip]
        _overlay_raw(row, source_values, headers)
        _overlay_raw(row, interface.raw_extra, headers)
        row["Additional Settings"] = _additional_source_settings(
            source_values,
            row,
            headers,
        )
        rows.append(row)

        child_keys = tuple(aggregate_members.get(key, ())) + tuple(children.get(key, ()))
        child_keys = tuple(sorted((item for item in dict.fromkeys(child_keys) if item in interfaces), key=rank))
        vpn_children = tuple(vpns_by_interface.get(key, ()))
        children_count = len(child_keys) + len(vpn_children)
        child_number = 0
        for child_key in child_keys:
            child_number += 1
            last = child_number == children_count
            emit_interface(child_key, child_indent + ("└─ " if last else "├─ "), child_indent + ("   " if last else "│  "))
        for vpn_top in vpn_children:
            child_number += 1
            last = child_number == children_count
            emit_vpn(vpn_top, child_indent + ("└─ " if last else "├─ "))

    for key in roots:
        emit_interface(key)
    for key in sorted(interfaces, key=rank):
        emit_interface(key)
    for vpn_top in context.derived.topology.vpns:
        if (vpn_top.vdom, vpn_top.name) not in emitted_vpns:
            emit_vpn(vpn_top)

    return rows


def _interface_rank(topology: Any, interface: Any) -> tuple[int, str]:
    return (
        {"aggregate": 0, "physical": 1, "vlan": 2, "logical": 3, "tunnel": 4}.get(
            topology.kind if topology else None,
            5,
        ),
        interface.name,
    )


def _topology_symbol(kind: str | None) -> str:
    return {"aggregate": "◆", "physical": "●", "vlan": "▣", "logical": "◇", "tunnel": "◇", "vpn": "◈"}.get(kind, "◇")


def _interface_secondary_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for interface in context.config.interfaces:
        for item in interface.secondary_ips:
            row = {
                "Interface": interface.name,
                "ID": item.id,
                "IP / Prefix": item.ip,
                "Management Access": item.allowaccess,
                "HA Priority": item.ha_priority,
                "Additional Settings": _additional_settings(item),
            }
            _add_analysis_status(
                row,
                context,
                vdom=interface.vdom,
                names=(interface.name, item.id),
            )
            _overlay_raw(row, item.raw_extra, headers)
            rows.append(row)
    return rows


def _zone_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for item in context.config.zones:
        row = {
            "Name": item.name,
            "Members": item.members,
            "Description": item.description,
            "Intrazone": item.intrazone,
            "VDOM": item.vdom,
            "Additional Settings": _additional_settings(item),
        }
        _add_analysis_status(row, context, vdom=item.vdom, names=(item.name,), domains=('zone',))
        _overlay_raw(row, item.raw_extra, headers)
        rows.append(row)
    return rows


def _address_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    for item in context.config.addresses:
        value = item.subnet or item.ip6 or (
            f"{item.start_ip}-{item.end_ip}" if item.start_ip and item.end_ip else None
        ) or item.fqdn or item.wildcard or item.wildcard_fqdn
        row = {
            "Name": item.name,
            "Type": item.type,
            "Value": value,
            "Address Family": item.address_family,
            "Associated Interface": item.associated_interface,
            "Allow Routing": item.allow_routing,
            "Tags": [
                tag
                for entry in item.tagging
                for tag in entry.tags
            ],
            "Description": item.comment,
            "VDOM": item.vdom,
            "Additional Settings": sanitize_source_attributes(item.raw_extra),
        }
        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(item.name,),
            domains=("address6",) if item.address_family == "ipv6" else ("address",),
        )
        _overlay_raw(row, item.raw_extra, headers)
        yield row


def _wildcard_fqdn_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for item in context.config.wildcard_fqdns:
        row = {
            "Name": item.name,
            "Wildcard FQDN": item.wildcard_fqdn,
            "Description": item.comment,
            "VDOM": item.vdom,
            "Additional Settings": sanitize_source_attributes(item.raw_extra),
        }
        _add_analysis_status(row, context, vdom=item.vdom, names=(item.name,), domains=('wildcard_fqdn',))
        rows.append(row)
    return rows


def _address_group_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for item in context.config.address_groups:
        row = {
            "Name": item.name,
            "Members": item.members,
            "Address Family": item.address_family,
            "Exclusion Enabled": item.exclude,
            "Exclude Members": item.exclude_members,
            "Description": item.comment,
            "Allow Routing": item.allow_routing,
            "Group Type": item.type,
            "Tags": [tag for entry in item.tagging for tag in entry.tags],
            "VDOM": item.vdom,
            "Additional Settings": sanitize_source_attributes(item.raw_extra),
        }
        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(item.name,),
            domains=("address_group6",)
            if item.address_family == "ipv6"
            else ("address_group",),
        )
        _overlay_raw(row, item.raw_extra, headers)
        rows.append(row)
    return rows


def _address_group_tag_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for group in context.config.address_groups:
        for tag in group.tagging:
            rows.append(
                {
                    "Group Name": group.name,
                    "Address Family": group.address_family,
                    "Tag Entry": tag.name,
                    "Category": tag.category,
                    "Tags": tag.tags,
                    "Extraction Status": "EXTRACTED",
                    "Manual Review": "No",
                    "Additional Settings": sanitize_source_attributes(tag.raw_extra),
                }
            )
    return rows


def _service_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    source = {(item.vdom, item.name): item for item in context.config.services}
    for item in context.derived.services.services:
        source_item = source.get((item.vdom, item.source_name or item.name))
        row = {
            "Name": item.name,
            "Source Service": item.source_name,
            "Protocol": item.protocol,
            "Destination Port": item.port,
            "Source Port": item.source_port,
            "Protocol Number": item.protocol_number,
            "ICMP Type": item.icmp_type,
            "ICMP Code": item.icmp_code,
            "Generated": item.generated,
            "Description": item.comment,
            "VDOM": item.vdom,
        }
        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(item.source_name, item.name),
            domains=('service',),
        )
        if source_item is not None:
            _overlay_raw(row, source_item.raw_extra, headers)
        yield row


def _service_group_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    source = {(item.vdom, item.name): item for item in context.config.service_groups}
    rows = []
    for item in context.derived.services.groups:
        source_item = source.get((item.vdom, item.name))
        row = {
            "Name": item.name,
            "Members": list(item.members),
            "Generated": item.generated,
            "Description": item.comment,
            "VDOM": item.vdom,
        }
        _add_analysis_status(row, context, vdom=item.vdom, names=(item.name,), domains=('service_group', 'service'))
        if source_item is not None:
            _overlay_raw(row, source_item.raw_extra, headers)
        rows.append(row)
    return rows


def _policy_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    nat = {
        (item.vdom, item.policy_id): item
        for item in context.derived.nat
    }
    for item in context.config.policies:
        nat_item = nat.get((item.vdom, item.policy_id))
        row = {
            "Rule #": item.policy_id,
            "Policy Name": item.name,
            "Source Name": item.name,
            "Source Interface": item.srcintf,
            "Source Addresses": item.srcaddr,
            "Source IPv6 Addresses": item.srcaddr6,
            "Source IPv6 Address Negate": item.srcaddr6_negate,
            "Destination Interface": item.dstintf,
            "Destination Addresses": item.dstaddr,
            "Destination IPv6 Addresses": item.dstaddr6,
            "Destination IPv6 Address Negate": item.dstaddr6_negate,
            "Services": item.service,
            "Action": item.action,
            "Schedule": item.schedule,
            "NAT Enabled": _enabled_text(item.nat),
            "UTM Status": item.utm_status,
            "Source Address Negate": item.srcaddr_negate,
            "Destination Address Negate": item.dstaddr_negate,
            "User Groups": item.groups,
            "Users": item.users,
            "Service Negate": item.service_negate,
            "VPN Tunnel": item.vpntunnel,
            "Security Profile Group": item.profile_group,
            "Protocol Options": item.profile_protocol_options,
            "Per-IP Shaper": item.per_ip_shaper,
            "Antivirus": item.av_profile,
            "IPS Sensor": item.ips_sensor,
            "Web Filter": item.webfilter_profile,
            "Application List": item.application_list,
            "DNS Filter": item.dnsfilter_profile,
            "SSL/SSH Profile": item.ssl_ssh_profile,
            "Log Setting": item.logtraffic,
            "Comments": item.comments,
            "Status": _enabled_text(item.status),
            "SNAT Type": _nat_type(nat_item.translation_type) if nat_item else None,
            "SNAT Address": list(nat_item.translated_addresses) if nat_item else [],
            "IP Pool Name": list(nat_item.pool_names) if nat_item else [],
            "VDOM": item.vdom,
            "Source Explicit Fields": sorted(item.explicit_fields),
            "Additional Settings": _additional_settings(item),
        }
        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(item.name, item.policy_id),
            domains=('policy', 'nat'),
        )
        _overlay_raw(row, item.raw_extra, headers)
        yield row


def _security_policy_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    return _model_rows(
        context, context.config.security_policies, headers,
        {"Policy ID": "policy_id", "Action": "action", "Application Categories": "app_category", "VDOM": "vdom"},
        domains=("security_policy",),
    )


def _ip_pool_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        [*context.config.ip_pools, *context.config.ip_pools6],
        headers,
        {
            "Name": "name",
            "Address Family": "address_family",
            "Type": "type",
            "Start IP": "startip",
            "End IP": "endip",
            "Source Start IP": "source_startip",
            "Source End IP": "source_endip",
            "Start Port": "startport",
            "End Port": "endport",
            "Associated Interface": "associated_interface",
            "ARP Reply": "arp_reply",
            "ARP Interface": "arp_intf",
            "Permit Any Host": "permit_any_host",
            "Excluded IPs": "exclude_ip",
            "NAT64": "nat64",
            "Add NAT64 Route": "add_nat64_route",
            "NAT46": "nat46",
            "Add NAT46 Route": "add_nat46_route",
            "Description": "comments",
            "Comments": "comments",
            "Source Explicit Fields": "explicit_fields",
        },
        domains=('ip_pool', 'ip_pool6'),
    )
def _vip_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        [*context.config.vips, *context.config.vips6],
        headers,
        {
            "Name": "name",
            "Address Family": "address_family",
            "Type": "type",
            "Status": "status",
            "External IP": "extip",
            "External Address Objects": "extaddr",
            "External Interface": "extintf",
            "Mapped IPs": "mappedip",
            "Real Servers": lambda item: [
                ":".join(
                    str(value)
                    for value in (server.ip or server.address, server.port)
                    if value is not None
                )
                for server in getattr(item, "realservers", [])
            ],
            "Real Server Count": lambda item: len(getattr(item, "realservers", [])),
            "Port Forward": "portforward",
            "Protocol": "protocol",
            "External Port": "extport",
            "Mapped Port": "mappedport",
            "ARP Reply": "arp_reply",
            "NAT Source VIP": "nat_source_vip",
            "NAT64": "nat64",
            "NAT66": "nat66",
            "NDP Reply": "ndp_reply",
            "Services": "service",
            "Load Balance Method": "ldb_method",
            "Server Type": "server_type",
            "Monitors": "monitor",
            "Description": "comment",
            "VDOM": "vdom",
        },
        domains=('vip', 'vip6'),
    )
def _vip_real_server_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    rows = []

    for vip in context.config.vips:
        for item in vip.realservers:
            row = {
                "VIP Name": vip.name,
                "Server ID": item.id,
                "IP": item.ip,
                "Address": item.address,
                "Port": item.port,
                "Status": item.status,
                "Weight": item.weight,
                "Monitors": item.monitor,
                "VDOM": vip.vdom,
                "Additional Settings": _additional_settings(item),
            }
            _add_analysis_status(
                row,
                context,
                vdom=vip.vdom,
                names=(vip.name, item.id),
                domains=('vip',),
            )
            _overlay_raw(
                row,
                item.raw_extra,
                headers,
            )
            rows.append(row)

    return rows


def _vip_group_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        [*context.config.vip_groups, *context.config.vip_groups6],
        headers,
        {
            "Name": "name",
            "Address Family": "address_family",
            "Interface": "interface",
            "Members": "members",
            "Comments": "comments",
            "VDOM": "vdom",
        },
        domains=('vip_group', 'vip_group6'),
    )
def _nat_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterator[dict[str, Any]]:
    policies = {
        (policy.vdom, policy.policy_id): policy
        for policy in context.config.policies
    }

    for item in context.derived.nat:
        policy = policies.get(
            (item.vdom, item.policy_id)
        )

        row = {
            "Rule #": item.policy_id,
            "Policy Name": item.policy_name,
            "Source Interface": (
                policy.srcintf
                if policy is not None
                else []
            ),
            "Destination Interface": (
                policy.dstintf
                if policy is not None
                else list(item.egress_interfaces)
            ),
            "Source Addresses": (
                policy.srcaddr
                if policy is not None
                else []
            ),
            "Source IPv6 Addresses": (
                policy.srcaddr6
                if policy is not None
                else []
            ),
            "Destination Addresses": (
                policy.dstaddr
                if policy is not None
                else []
            ),
            "Destination IPv6 Addresses": (
                policy.dstaddr6
                if policy is not None
                else []
            ),
            "Services": (
                policy.service
                if policy is not None
                else []
            ),
            "NAT Enabled": _enabled_text(policy.nat) if policy is not None else None,
            "SNAT Type": _nat_type(item.translation_type),
            "SNAT Address": list(item.translated_addresses),
            "IP Pool Name": list(item.pool_names),
            "Egress Interfaces": list(
                item.egress_interfaces
            ),
            "VDOM": item.vdom,
        }

        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(
                item.policy_name,
                item.policy_id,
            ),
            extra_reasons=item.issues,
            domains=('nat',),
        )
        yield row


def _route_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterator[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.static_routes,
        headers,
        {
            "Route ID": "seq_num",
            "Destination": "dst",
            "Destination Address Object": "dstaddr",
            "Interface": "device",
            "Gateway": "gateway",
            "Distance": "distance",
            "Priority": "priority",
            "Status": "status",
            "SD-WAN Zone": "sdwan_zone",
            "Preferred Source": "preferred_source",
            "Source Prefix": "src",
            "Dynamic Gateway": "dynamic_gateway",
            "Blackhole": "blackhole",
            "Description": "comment",
            "Address Family": "address_family",
            "VDOM": "vdom",
        },
        domains=('static_route', 'static_route6'),
    )
def _vpn_phase1_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    topology = {
        (item.vdom, item.name): item
        for item in context.derived.topology.vpns
    }

    rows: list[dict[str, Any]] = []

    for item in context.config.ipsec_phase1:
        top = topology.get(
            (item.vdom, item.name)
        )

        row = {
            "Name": item.name,
            "Local Interface": item.interface,
            "Remote Gateway IPv4": item.remote_gw,
            "Remote Gateway DDNS": item.remotegw_ddns,
            "Type": item.type,
            "IKE Version": item.ike_version,
            "IKE Mode": item.mode,
            "Authentication Method": item.authmethod,
            "Remote Authentication Method": item.authmethod_remote,
            "PSK Configured": "Yes" if item.psk_configured else "No",
            "PPK Secret Configured": "Yes" if item.ppk_secret_configured else "No",
            "Auth Password Configured": "Yes" if item.auth_password_configured else "No",
            "Group Authentication Secret Configured": "Yes" if item.group_authentication_secret_configured else "No",
            "Phase 1 Proposal": item.proposal,
            "Phase 1 DH Groups": item.dhgrp,
            "Key Lifetime (Seconds)": item.keylife,
            "NAT Traversal": item.nattraversal,
            "DPD Mode": item.dpd,
            "DPD Retry Count": item.dpd_retrycount,
            "DPD Retry Interval": item.dpd_retryinterval,
            "Local Gateway": item.local_gw,
            "Local ID": item.localid,
            "Local ID Type": item.localid_type,
            "Peer ID": item.peerid,
            "Certificate": item.certificate,
            "Description": item.comments,
            "VDOM": item.vdom,
            "Aggregate": (
                top.aggregate
                if top
                else None
            ),
            "Attached Physical Interfaces": (
                list(top.physical_interfaces)
                if top
                else []
            ),
            "Topology Path": (
                list(top.path)
                if top
                else []
            ),
            "Topology Issues": (
                list(top.issues)
                if top
                else []
            ),
            "Source Explicit Fields": sorted(
                item.explicit_fields
            ),
            "Additional Settings": _additional_settings(item),
        }

        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(item.name,),
            domains=("ipsec_phase1", "vpn_topology"),
            extra_reasons=(
                top.issues
                if top
                else ()
            ),
        )

        _overlay_raw(
            row,
            item.raw_extra,
            headers,
        )

        rows.append(row)

    return rows


def _policy_vpn_phase1_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.ipsec_policy_phase1,
        headers,
        {
            "Name": "name",
            "Remote Gateway IPv4": "remote_gw",
            "Remote Gateway DDNS": "remotegw_ddns",
            "IKE Version": "ike_version",
            "IKE Mode": "mode",
            "Authentication Method": "authmethod",
            "Remote Authentication Method": "authmethod_remote",
            "PSK Configured": lambda item: "Yes" if item.psk_configured else "No",
            "PPK Secret Configured": lambda item: "Yes" if item.ppk_secret_configured else "No",
            "Auth Password Configured": lambda item: "Yes" if item.auth_password_configured else "No",
            "Group Authentication Secret Configured": lambda item: "Yes" if item.group_authentication_secret_configured else "No",
            "Phase 1 Proposal": "proposal",
            "Phase 1 DH Groups": "dhgrp",
            "Key Lifetime (Seconds)": "keylife",
            "NAT Traversal": "nattraversal",
            "DPD Mode": "dpd",
            "DPD Retry Count": "dpd_retrycount",
            "DPD Retry Interval": "dpd_retryinterval",
            "Local Gateway": "local_gw",
            "Local ID": "localid",
            "Peer ID": "peerid",
            "Certificate": "certificate",
            "Description": "comments",
            "VDOM": "vdom",
        },
        domains=("ipsec_policy_phase1",),
    )


def _vpn_phase2_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    normalized = {
        (item.vpn_type, item.vdom, item.name): item
        for item in context.derived.vpn.phase2
    }

    rows: list[dict[str, Any]] = []

    for item in context.config.ipsec_phase2:
        norm = normalized.get(
            ("route-based", item.vdom, item.name)
        )

        row = {
            "Name": item.name,
            "Phase 1": item.phase1name,
            "Proposal": item.proposal,
            "PFS": item.pfs,
            "DH Groups": item.dhgrp,
            "Key Lifetime Seconds": item.keylifeseconds,
            "Key Lifetime KB": item.keylifekbs,
            "Source Range": (
                norm.source_range
                if norm
                else None
            ),
            "Destination Range": (
                norm.destination_range
                if norm
                else None
            ),
            "Source Range IPv6": norm.source_range6 if norm else None,
            "Destination Range IPv6": norm.destination_range6 if norm else None,
            "Protocol": item.protocol,
            "Source Port": item.src_port,
            "Destination Port": item.dst_port,
            "Auto Negotiate": item.auto_negotiate,
            "VDOM": item.vdom,
            "Comments": item.comments,
            "Source Explicit Fields": sorted(
                item.explicit_fields
            ),
            "Additional Settings": _additional_settings(item),
        }

        _add_analysis_status(
            row,
            context,
            vdom=item.vdom,
            names=(item.name,),
            domains=("vpn_phase2",),
        )

        _overlay_raw(
            row,
            item.raw_extra,
            headers,
        )

        rows.append(row)

    return rows


def _policy_vpn_phase2_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    normalized = {(item.vpn_type, item.vdom, item.name): item for item in context.derived.vpn.phase2}
    rows = []
    for item in context.config.ipsec_policy_phase2:
        norm = normalized.get(("policy-based", item.vdom, item.name))
        row = {
            "Name": item.name, "Phase 1": item.phase1name, "Proposal": item.proposal,
            "PFS": item.pfs, "DH Groups": item.dhgrp, "Key Lifetime Seconds": item.keylifeseconds,
            "Key Lifetime KB": item.keylifekbs, "Source Range": norm.source_range if norm else None,
            "Destination Range": norm.destination_range if norm else None,
            "Source Range IPv6": norm.source_range6 if norm else None,
            "Destination Range IPv6": norm.destination_range6 if norm else None,
            "Protocol": item.protocol, "Source Port": item.src_port, "Destination Port": item.dst_port,
            "Auto Negotiate": item.auto_negotiate, "Comments": item.comments, "VDOM": item.vdom,
            "Source Explicit Fields": sorted(item.explicit_fields),
            "Additional Settings": _additional_settings(item),
        }
        _add_analysis_status(row, context, vdom=item.vdom, names=(item.name,), domains=("ipsec_policy_phase2",))
        _overlay_raw(row, item.raw_extra, headers)
        rows.append(row)
    return rows


def _dhcp_server_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.dhcp_servers,
        headers,
        {
            "Server ID": "id",
            "Interface": "interface",
            "Status": "status",
            "Server Type": "server_type",
            "IP Mode": "ip_mode",
            "Default Gateway": "default_gateway",
            "Netmask": "netmask",
            "Lease Time": "lease_time",
            "DNS Service": "dns_service",
            "DNS Server 1": "dns_server1",
            "DNS Server 2": "dns_server2",
            "DNS Server 3": "dns_server3",
            "DNS Server 4": "dns_server4",
            "Timezone Option": "timezone_option",
            "Timezone": "timezone",
            "Relay Agent": "relay_agent",
            "VDOM": "vdom",
        },
        domains=('dhcp_server',),
    )
def _dhcp_ip_range_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _dhcp_child_rows(context, headers, "ip_ranges")


def _dhcp_exclude_range_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _dhcp_child_rows(context, headers, "exclude_ranges")


def _dhcp_reservation_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for server in context.config.dhcp_servers:
        for item in server.reserved_addresses:
            row = {
                "Server ID": server.id,
                "Interface": server.interface,
                "Reservation ID": item.id,
                "IP Address": item.ip,
                "MAC Address": item.mac,
                "Description": item.description,
                "Action": item.action,
                "Type": item.type,
                "VDOM": server.vdom,
                "Extraction Status": "EXTRACTED",
                "Source Explicit Fields": sorted(item.explicit_fields),
                "Additional Settings": _additional_settings(item),
            }
            _overlay_raw(row, item.raw_extra, headers)
            _add_analysis_status(row, context, vdom=server.vdom, names=(server.id, item.id), domains=('dhcp_server',))
            rows.append(row)
    return rows


def _dhcp_child_rows(
    context: _ExcelContext,
    headers: Sequence[str],
    attribute: str,
) -> list[dict[str, Any]]:
    rows = []
    for server in context.config.dhcp_servers:
        for item in getattr(server, attribute):
            row = {
                "Server ID": server.id,
                "Interface": server.interface,
                "Range ID": item.id,
                "Source ID": item.id,
                "Start IP": item.start_ip,
                "End IP": item.end_ip,
                "Lease Time": item.lease_time,
                "VDOM": server.vdom,
                "Extraction Status": "EXTRACTED",
                "Manual Review": "No",
                "Source Explicit Fields": sorted(item.explicit_fields),
                "Additional Settings": _additional_settings(item),
            }
            _overlay_raw(row, item.raw_extra, headers)
            _add_analysis_status(row, context, vdom=server.vdom, names=(server.id, item.id), domains=('dhcp_server',))
            rows.append(row)
    return rows


def _sdwan_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for item in context.config.sdwans:
        row = {
            "Status": item.status,
            "Load Balance Mode": item.load_balance_mode,
            "Extraction Status": "EXTRACTED",
            "Manual Review": "No",
            "Additional Settings": _additional_settings(item),
            "VDOM": item.vdom,
        }
        _overlay_raw(row, item.raw_extra, headers)
        _add_analysis_status(row, context, vdom=item.vdom, names=(item.vdom,))
        rows.append(row)
    return rows


def _sdwan_zone_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for sdwan in context.config.sdwans:
        for item in sdwan.zones:
            row = {
                "Zone Name": item.name,
                "Additional Settings": _additional_settings(item),
                "VDOM": sdwan.vdom,
            }
            _overlay_raw(row, item.raw_extra, headers)
            _add_analysis_status(row, context, vdom=sdwan.vdom, names=(item.name,))
            rows.append(row)
    return rows


def _sdwan_member_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    topology = {(item.vdom, item.name): item for item in context.derived.topology.interfaces}
    rows = []
    for sdwan in context.config.sdwans:
        for item in sdwan.members:
            top = topology.get((sdwan.vdom, item.interface or ""))
            row = {
                "ID": item.seq_num,
                "Interface": item.interface,
                "Zone": item.zone,
                "Gateway": item.gateway,
                "Source": item.source,
                "Cost": item.cost,
                "Weight": item.weight,
                "Priority": item.priority,
                "Status": item.status,
                "Additional Settings": _additional_settings(item),
                "VDOM": sdwan.vdom,
                "Physical Interfaces": list(top.physical_interfaces) if top else [],
                "Aggregate": top.aggregate if top else None,
                "Source Explicit Fields": sorted(item.explicit_fields),
            }
            _overlay_raw(row, item.raw_extra, headers)
            _add_analysis_status(row, context, vdom=sdwan.vdom, names=(item.interface, item.seq_num), domains=('sdwan_member',))
            rows.append(row)
    return rows


def _sdwan_health_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for sdwan in context.config.sdwans:
        for item in sdwan.health_checks:
            row = {
                "Name": item.name,
                "Server": item.server,
                "Members": item.members,
                "Protocol": item.protocol,
                "Interval": item.interval,
                "Fail Time": item.failtime,
                "Recovery Time": item.recoverytime,
                "Additional Settings": _additional_settings(item),
                "VDOM": sdwan.vdom,
            }
            _overlay_raw(row, item.raw_extra, headers)
            _add_analysis_status(row, context, vdom=sdwan.vdom, names=(item.name,))
            rows.append(row)
    return rows


def _sdwan_rule_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for sdwan in context.config.sdwans:
        for item in sdwan.services:
            row = {
                "ID": item.id,
                "Name": item.name,
                "Status": item.status,
                "Mode": item.mode,
                "Source": item.src,
                "Destination": item.dst,
                "Priority Members": item.priority_members,
                "Health Checks": item.health_check,
                "Priority Zones": item.priority_zone,
                "Additional Settings": _additional_settings(item),
                "VDOM": sdwan.vdom,
            }
            _overlay_raw(row, item.raw_extra, headers)
            _add_analysis_status(row, context, vdom=sdwan.vdom, names=(item.id, item.name))
            rows.append(row)
    return rows


def _ssl_settings_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.ssl_vpn_settings,
        headers,
        {
            "Status": "status",
            "Minimum Protocol": "ssl_min_proto_ver",
            "Maximum Protocol": "ssl_max_proto_ver",
            "Authentication Timeout": "auth_timeout",
            "Idle Timeout": "idle_timeout",
            "Port": "port",
            "DNS Server 1": "dns_server1",
            "DNS Server 2": "dns_server2",
            "Server Certificate": "servercert",
            "Source Interfaces": "source_interface",
            "Source Addresses": "source_address",
            "Tunnel IP Pools": "tunnel_ip_pools",
            "Default Portal": "default_portal",
            "VDOM": "vdom",
        },
        domains=('ssl_settings',),
    )


def _ssl_realm_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    rows = list(_model_rows(context, context.config.ssl_vpn_realms, headers, {
        "URL Path": "url_path",
        "Login Page Configured": lambda item: bool(item.login_page),
        "Login Page Length": lambda item: len(item.login_page or ""),
        "Maximum Concurrent Users": "max_concurrent_user",
        "NAS IP": "nas_ip", "RADIUS Port": "radius_port", "RADIUS Server": "radius_server",
        "Virtual Host": "virtual_host", "Virtual Host Only": "virtual_host_only",
        "Virtual Host Server Certificate": "virtual_host_server_cert", "VDOM": "vdom",
    }, domains=("ssl_vpn_realm",)))
    for row in rows:
        settings = row.get("Additional Settings")
        if isinstance(settings, dict):
            settings.pop("login_page", None)
    return rows


def _ssl_client_rows(context: _ExcelContext, headers: Sequence[str]) -> Iterator[dict[str, Any]]:
    return _model_rows(context, context.config.ssl_vpn_clients, headers, {
        "Name": "name", "Certificate": "certificate", "Class ID": "class_id", "Comment": "comment",
        "Distance": "distance", "Interface": "interface", "IPv4 Subnets": "ipv4_subnets",
        "IPv6 Subnets": "ipv6_subnets", "Peer": "peer", "Port": "port", "Priority": "priority",
        "PSK Configured": lambda item: "Yes" if item.psk_configured else "No",
        "Realm": "realm", "Server": "server", "Source IP": "source_ip", "Status": "status",
        "User": "user", "VDOM": "vdom",
    }, domains=("ssl_vpn_client",))


def _ssl_bookmark_owner_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for owner_type, owners in (("User", context.config.ssl_vpn_user_bookmarks), ("Group", context.config.ssl_vpn_user_group_bookmarks)):
        for owner in owners:
            row = {"Owner Type": owner_type, "Owner Name": owner.owner_name,
                   "Custom Language": owner.custom_lang, "Bookmark Count": len(owner.bookmarks), "VDOM": owner.vdom,
                   "Additional Settings": _additional_settings(owner)}
            _add_analysis_status(row, context, vdom=owner.vdom, names=(owner.owner_name,))
            rows.append(row)
    return rows


def _ssl_bookmark_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for owner_type, owners in (("User", context.config.ssl_vpn_user_bookmarks), ("Group", context.config.ssl_vpn_user_group_bookmarks)):
        for owner in owners:
            for item in owner.bookmarks:
                row = {"Owner Type": owner_type, "Owner Name": owner.owner_name, "Bookmark": item.name,
                       "Application Type": item.apptype, "URL": item.url, "Host": item.host,
                       "Port": item.port, "Domain": item.domain, "Folder": item.folder,
                       "Description": item.description, "Logon User": item.logon_user,
                       "Logon Password Configured": "Yes" if item.logon_password_configured else "No",
                       "SSO Password Configured": "Yes" if item.sso_password_configured else "No",
                       "Form Data": [{"name": value.name, "value": value.value} for value in item.form_data],
                       "VDOM": owner.vdom, "Additional Settings": _additional_settings(item)}
                _overlay_raw(row, item.raw_extra, headers)
                _add_analysis_status(row, context, vdom=owner.vdom, names=(owner.owner_name, item.name))
                rows.append(row)
    return rows
def _ssl_portal_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.ssl_vpn_portals,
        headers,
        {
            "Name": "name",
            "Tunnel Mode": "tunnel_mode",
            "IPv6 Tunnel Mode": "ipv6_tunnel_mode",
            "IP Pools": "ip_pools",
            "IPv6 Pools": "ipv6_pools",
            "Split Tunneling": "split_tunneling",
            "Limit User Logins": "limit_user_logins",
            "FortiClient Download": "forticlient_download",
            "Split Tunneling Routing Addresses": "split_tunneling_routing_address",
            "VDOM": "vdom",
        },
        domains=('ssl_vpn_portal',),
    )
def _ssl_auth_rule_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for settings in context.config.ssl_vpn_settings:
        for item in settings.authentication_rules:
            row = {
                "ID": item.id,
                "Auth": item.auth,
                "Cipher": item.cipher,
                "Client Certificate": item.client_cert,
                "Realm": item.realm,
                "Source Interfaces": item.source_interface,
                "Source Addresses": item.source_address,
                "Source Address Negate": item.source_address_negate,
                "Users": item.users,
                "User Peer": item.user_peer,
                "Groups": item.groups,
                "Portal": item.portal,
                "Extraction Status": "EXTRACTED",
                "Manual Review": "No",
                "Additional Settings": _additional_settings(item),
            }
            _overlay_raw(row, item.raw_extra, headers)
            _add_analysis_status(row, context, vdom=settings.vdom, names=(item.id, item.portal))
            rows.append(row)
    return rows


def _local_user_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.local_users,
        headers,
        {
            "Name": "name",
            "ID": "id",
            "Status": "status",
            "Type": "type",
            "Password Configured": "password_configured",
            "Password Time": "passwd_time",
            "Two Factor": "two_factor",
            "Two Factor Authentication": "two_factor_authentication",
            "Two Factor Notification": "two_factor_notification",
            "FortiToken": "fortitoken",
            "Email": "email_to",
            "LDAP Server": "ldap_server",
            "RADIUS Server": "radius_server",
            "TACACS+ Server": "tacacs_server",
            "Auth Concurrent Override": "auth_concurrent_override",
            "Auth Concurrent Value": "auth_concurrent_value",
            "Authentication Timeout": "authtimeout",
            "Password Policy": "passwd_policy",
            "Workstation": "workstation",
            "Username Sensitivity": "username_sensitivity",
            "PPK Identity": "ppk_identity",
            "PPK Secret Configured": "ppk_secret_configured",
            "VDOM": "vdom",
        },
        domains=('local_user',),
    )
def _user_group_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.user_groups,
        headers,
        {
            "Name": "name",
            "ID": "id",
            "Type": "group_type",
            "Group Type": "group_type",
            "Members": "members",
            "Match Count": lambda item: len(item.matches),
            "Auth Concurrent Override": "auth_concurrent_override",
            "Auth Concurrent Value": "auth_concurrent_value",
            "Authentication Timeout": "authtimeout",
            "VDOM": "vdom",
        },
        domains=('user_group',),
    )
def _user_group_match_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for group in context.config.user_groups:
        for item in group.matches:
            row = {
                "User Group": group.name,
                "Match ID": item.id,
                "Server Name": item.server_name,
                "Group Name": item.group_name,
                "VDOM": group.vdom,
                "Additional Settings": _additional_settings(item),
            }
            _overlay_raw(row, item.raw_extra, headers)
            _add_analysis_status(row, context, vdom=group.vdom, names=(group.name, item.id))
            rows.append(row)
    return rows


def _administrator_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.administrators,
        headers,
        {
            "Name": "name",
            "Access Profile": "accprofile",
            "VDOMs": "vdoms",
            "IPv4 Trusted Hosts": "trusthosts",
            "Two Factor": "two_factor",
            "Two Factor Authentication": "two_factor_authentication",
            "Two Factor Notification": "two_factor_notification",
            "Remote Auth": "remote_auth",
            "Remote Group": "remote_group",
            "Credential Configured": lambda item: (
                bool(item.password_configured or item.ssh_key_configured)
            ),
            "FortiToken": "fortitoken",
            "Guest User Groups": "guest_usergroups",
            "Schedule": "schedule",
            "Peer Auth": "peer_auth",
            "Peer Group": "peer_group",
            "SSH Certificate": "ssh_certificate",
            "Additional Settings": "raw_extra",
        },
        domains=('administrator',), issue_vdom='root',
    )
def _admin_profile_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.admin_profiles,
        headers,
        {
            "Name": "name",
            "Additional Settings": "raw_extra",
        },
        domains=('admin_profile',), issue_vdom='root',
    )
def _admin_permission_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for profile in context.config.admin_profiles:
        for kind, permission in (
            ("Firewall", profile.firewall_permission),
            ("Log", profile.log_permission),
            ("Network", profile.network_permission),
            ("System", profile.system_permission),
            ("UTM", profile.utm_permission),
        ):
            if permission is None:
                continue
            values = permission.model_dump(mode="python", exclude={"raw_extra", "explicit_fields"})
            for setting, value in values.items():
                if value in (None, "", [], {}):
                    continue
                rows.append(
                    {
                        "Profile": profile.name,
                        "Permission Group": kind,
                        "Setting": setting,
                        "Value": value,
                        "Extraction Status": "EXTRACTED",
                        "Additional Settings": _additional_settings(permission),
                    }
                )
                _add_analysis_status(
                    rows[-1],
                    context,
                    vdom="root",
                    names=(profile.name, setting),
                    domains=('admin_profile',),
                )
    return rows


def _ips_sensor_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.ips_sensors,
        headers,
        {
            "Name": "name",
            "Description": "comment",
            "Block Malicious URL": "block_malicious_url",
            "Scan Botnet Connections": "scan_botnet_connections",
            "Extended Log": "extended_log",
            "Replacement Message Group": "replacemsg_group",
            "Entry Count": lambda item: len(item.entries),
            "VDOM": "vdom",
        },
        domains=('ips_sensor',),
    )
def _ips_entry_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for sensor in context.config.ips_sensors:
        for item in sensor.entries:
            row = {
                "Sensor": sensor.name,
                "Entry ID": item.id,
                "Signature IDs": item.rule,
                "CVEs": item.cve,
                "Applications": item.application,
                "OS": item.os,
                "Protocols": item.protocol,
                "Severities": item.severity,
                "Location": item.location,
                "Default Action Filter": item.default_action,
                "Default Status Filter": item.default_status,
                "Action": item.action,
                "Status": item.status,
                "Log": item.log,
                "Log Packet": item.log_packet,
                "Log Attack Context": item.log_attack_context,
                "Rate Count": item.rate_count,
                "Rate Duration": item.rate_duration,
                "Rate Mode": item.rate_mode,
                "Rate Track": item.rate_track,
                "Quarantine": item.quarantine,
                "Quarantine Expiry": item.quarantine_expiry,
                "Quarantine Log": item.quarantine_log,
                "Vulnerability Types": item.vuln_type,
                "Last Modified Filter": item.last_modified,
                "VDOM": sensor.vdom,
                "Additional Settings": _additional_settings(item),
            }

            _overlay_raw(
                row,
                item.raw_extra,
                headers,
            )
            _add_analysis_status(row, context, vdom=sensor.vdom, names=(sensor.name, item.id), domains=('ips_sensor',))

            rows.append(row)

    return rows


def _ips_exempt_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for sensor in context.config.ips_sensors:
        for entry in sensor.entries:
            for item in entry.exempt_ips:
                row = {
                        "Sensor": sensor.name,
                        "Entry ID": entry.id,
                        "Exempt IP ID": item.id,
                        "Source IP": item.src_ip,
                        "Destination IP": item.dst_ip,
                        "VDOM": sensor.vdom,
                        "Additional Settings": _additional_settings(item),
                    }
                _add_analysis_status(row, context, vdom=sensor.vdom, names=(sensor.name, entry.id, item.id), domains=('ips_sensor',))
                rows.append(row)
    return rows


def _security_profile_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.profile_groups,
        headers,
        {
            "Name": "name",
            "Antivirus": "av_profile",
            "IPS Sensor": "ips_sensor",
            "Application List": "application_list",
            "Web Filter": "webfilter_profile",
            "DNS Filter": "dnsfilter_profile",
            "File Filter": "file_filter_profile",
            "SSL/SSH Profile": "ssl_ssh_profile",
            "VDOM": "vdom",
        },
        domains=('profile_group',),
    )
def _external_resource_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    return _model_rows(
        context,
        context.config.external_resources,
        headers,
        {
            "Name": "name",
            "Resource": "resource",
            "Type": "type",
            "Refresh Rate": "refresh_rate",
            "Comments": "comments",
            "VDOM": "vdom",
        },
        domains=('external_resource',),
    )
def _policy_source_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    policy_names = {str(item.policy_id): item.name for item in context.config.policies if item.policy_id is not None}
    for record in context.source_by_path.get("firewall policy", ()):
        for command in record.commands:
            rows.append(
                {
                    "Source Policy ID": record.object_name,
                    "Policy Name": policy_names.get(str(record.object_name), ""),
                    "Operation": command.operation,
                    "Setting": command.key,
                    "Ordered Source Values": _safe_command_value(
                        command.key,
                        command.values,
                    ),
                }
            )
    return rows


def _interface_source_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for record in context.source_by_path.get("system interface", ()):
        for command in record.commands:
            rows.append(
                {
                    "Interface": record.object_name,
                    "Setting": command.key,
                    "Value": _safe_command_value(
                        command.key,
                        command.values,
                    ),
                    "Extraction Status": "EXTRACTED",
                }
            )
    return rows


def _interface_nested_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for records in context.nested_source_by_parent.values():
        for record in records:
            interface = record.parent_objects[0] if record.parent_objects else None
            for command in record.commands:
                rows.append(
                    {
                        "Interface": interface,
                        "Config Path": record.source_path,
                        "Node Type": "edit" if record.object_name is not None else "config",
                        "Object / Edit": record.object_name,
                        "Operation": command.operation,
                        "Setting": command.key,
                        "Value": _safe_command_value(command.key, command.values),
                        "Extraction Status": "EXTRACTED",
                        "Manual Review": "No",
                    }
                )
    return rows


def _unresolved_reference_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for item in context.derived.broken_references:
        rows.append(
            {
                "Source VDOM": item.source_vdom,
                "Source Type": item.source_kind,
                "Source Object": item.source_name,
                "Field": item.source_field,
                "Reference": item.reference,
                "Expected Type": [kind.value for kind in item.expected_kinds],
                "Reason": "Reference could not be resolved in the same VDOM.",
            }
        )
    return rows


def _warning_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    del headers

    return [
        {
            "ID": index,
            "Category": issue.domain,
            "Message": issue.message,
        }
        for index, issue in enumerate(
            context.validation.warnings,
            start=1,
        )
    ]


def _unsupported_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    del headers
    return [
        {
            "Section": path,
            "Source Records": count,
            "Primitive Registration": "REGISTERED" if path in context.registered_sections else "GENERIC",
            "Model Coverage": "SOURCE_ONLY",
            "Reason": (
                "Primitive source shapes are registered, but no dedicated FortiGate source model is defined."
                if path in context.registered_sections
                else "Explicit source is preserved generically, with no primitive registration or dedicated FortiGate model."
            ),
            "Raw Capture Location": "FortiGate Source Inventory",
        }
        for path, count in sorted(context.source_only_counts.items())
    ]


def _iter_fortigate_source_inventory_rows(
    context: _ExcelContext,
) -> Iterator[tuple[Any, ...]]:
    for record in context.extracted.source_objects:
        typed = find_typed_source_object(context.typed_source_inventory, record)
        raw_extra = getattr(typed.model, "raw_extra", {}) if typed else {}
        status = extraction_status(supports_path(record.source_path), typed)
        registration = "REGISTERED" if record.source_path in context.registered_sections else "GENERIC"
        base = (
            _excel_safe(_source_category(record.source_path)),
            _excel_safe(record.vdom),
            _excel_safe("Object" if record.object_name is not None else "Config"),
            _excel_safe(record.source_path),
            _excel_safe(record.object_name),
            _excel_safe("\n".join(record.parent_objects) or None),
        )

        if not record.commands:
            yield (*base, None, None, None, _excel_safe(registration), _excel_safe(status), len(raw_extra) if typed else None)
            continue

        for command in record.commands:
            yield (
                *base,
                _excel_safe(command.operation),
                _excel_safe(command.key),
                _excel_safe(_safe_command_value(command.key, command.values)),
                _excel_safe(registration),
                _excel_safe(status),
                len(raw_extra) if typed else None,
            )


def _source_inventory_row_count(context: _ExcelContext) -> int:
    return context.source_inventory_row_count


def _coverage_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    del headers

    rows: list[dict[str, Any]] = []

    paths = context.source_paths | frozenset(
        path for path, objects in context.typed_source_inventory.items() if objects
    )
    for path in sorted(paths):
        records = context.source_by_path.get(path, [])
        typed_objects = context.typed_source_inventory.get(path, ())
        typed_support = supports_path(path)
        matched = sum(
            find_typed_source_object(context.typed_source_inventory, record) is not None
            for record in records
        )
        source_only = 0 if typed_support else len(records)
        model_gaps = len(records) - matched if typed_support else 0
        raw_extra_objects = sum(bool(getattr(item.model, "raw_extra", {})) for item in typed_objects)
        raw_extra_entries = sum(len(getattr(item.model, "raw_extra", {})) for item in typed_objects)

        rows.append(
            {
                "Source Section": path,
                "Found": "Yes",
                "Source Records": len(records),
                "Primitive Registration": "REGISTERED" if path in context.registered_sections else "GENERIC",
                "Model Coverage": "TYPED" if typed_support else "SOURCE_ONLY",
                "Typed Objects": len(typed_objects),
                "Raw Extra Objects": raw_extra_objects,
                "Raw Extra Entries": raw_extra_entries,
                "Model Gaps": model_gaps,
                "Source-only Records": source_only,
                "Line Start": min(
                    (
                        record.start_line_number
                        for record in records
                        if record.start_line_number is not None
                    ),
                    default=None,
                ),
                "Line End": max(
                    (
                        record.end_line_number
                        for record in records
                        if record.end_line_number is not None
                    ),
                    default=None,
                ),
                "Notes": (
                    "Typed extraction is declared, but source records are missing matching model objects."
                    if model_gaps
                    else "Dedicated FortiGate model represents this source path; additional explicit state is preserved in raw_extra."
                    if typed_support and raw_extra_objects
                    else "Dedicated FortiGate source model represents this source path."
                    if typed_support
                    else "Explicit source is preserved in Source Inventory; no dedicated FortiGate model is defined."
                ),
            }
        )

    return rows


def _generic_source_rows(
    sheet_name: str,
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterator[dict[str, Any]]:
    del headers

    paths = _SOURCE_PATHS_BY_SHEET.get(
        sheet_name,
        (),
    )

    for path in paths:
        for record in context.source_by_path.get(
            path,
            (),
        ):
            values = sanitize_source_attributes(
                record.values
            )

            if not values:
                row = {
                    "VDOM": record.vdom,
                    "Source Path": record.source_path,
                    "Object": record.object_name,
                    "Parent / Subsection": list(
                        record.parent_objects
                    ),
                    "Setting": None,
                    "Value": None,
                }

                _add_analysis_status(
                    row,
                    context,
                    vdom=record.vdom,
                    names=(record.object_name,),
                )

                yield row
                continue

            for setting, value in values.items():
                row = {
                    "VDOM": record.vdom,
                    "Source Path": record.source_path,
                    "Object": record.object_name,
                    "Parent / Subsection": list(
                        record.parent_objects
                    ),
                    "Setting": setting,
                    "Value": value,
                }

                _add_analysis_status(
                    row,
                    context,
                    vdom=record.vdom,
                    names=(record.object_name,),
                )

                yield row


def _schedule_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for item, kind in (
        *((item, "one-time") for item in context.config.one_time_schedules),
        *((item, "recurring") for item in context.config.recurring_schedules),
    ):
        row = {
            "Name": item.name,
            "Type": kind,
            "Days": getattr(item, "days", []),
            "Start": item.start,
            "End": item.end,
            "Start UTC": getattr(item, "start_utc", None),
            "End UTC": getattr(item, "end_utc", None),
            "Expiration Days": getattr(item, "expiration_days", None),
            "VDOM": item.vdom,
            "Source Explicit Fields": sorted(item.explicit_fields),
            "Additional Settings": _additional_settings(item),
        }
        _add_analysis_status(context=context, row=row, vdom=item.vdom, names=(item.name,))
        _overlay_raw(row, item.raw_extra, headers)
        rows.append(row)
    return rows


def _schedule_group_rows(context: _ExcelContext, headers: Sequence[str]) -> list[dict[str, Any]]:
    rows = []
    for item in context.config.schedule_groups:
        row = {
            "Name": item.name,
            "Members": item.members,
            "VDOM": item.vdom,
            "Source Explicit Fields": sorted(item.explicit_fields),
            "Additional Settings": _additional_settings(item),
        }
        _add_analysis_status(context=context, row=row, vdom=item.vdom, names=(item.name,))
        _overlay_raw(row, item.raw_extra, headers)
        rows.append(row)
    return rows


def _ntp_setting_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> Iterable[Mapping[str, Any]]:
    del headers
    rows: list[dict[str, Any]] = []

    for record in context.source_by_path.get("system ntp", ()):
        values = sanitize_source_attributes(record.values)
        for setting, value in values.items():
            row = {
                "Setting": setting,
                "Value": value,
                "Source Path": record.source_path,
            }
            _add_analysis_status(
                row,
                context,
                vdom=record.vdom,
                names=(None,),
            )
            rows.append(row)

    return rows


def _ntp_server_rows(
    context: _ExcelContext,
    headers: Sequence[str],
) -> list[dict[str, Any]]:
    del headers
    rows: list[dict[str, Any]] = []

    for record in context.source_by_path.get("system ntp ntpserver", ()):
        values = sanitize_source_attributes(record.values)
        for setting, value in values.items():
            row = {
                "Server ID": record.object_name,
                "Setting": setting,
                "Value": value,
                "Source Path": record.source_path,
            }
            _add_analysis_status(
                row,
                context,
                vdom=record.vdom,
                names=(record.object_name,),
            )
            rows.append(row)

    return rows


def _model_rows(
    context: _ExcelContext,
    objects: Iterable[Any],
    headers: Sequence[str],
    mapping: Mapping[str, str | None | Any],
    *,
    domains: Iterable[str] | None = None,
    issue_vdom: str | None = None,
) -> Iterator[dict[str, Any]]:
    for item in objects:
        data = item.model_dump(
            mode="python"
        )

        row: dict[str, Any] = {}

        for header, attribute in mapping.items():
            if header not in headers:
                continue

            if callable(attribute):
                row[header] = attribute(item)
            elif attribute:
                row[header] = data.get(
                    attribute
                )

        raw_extra = _additional_settings_from_data(
            data,
            row.values(),
        )

        _overlay_raw(
            row,
            raw_extra,
            headers,
        )

        if "Source Explicit Fields" in headers:
            row["Source Explicit Fields"] = sorted(
                data.get(
                    "explicit_fields",
                    [],
                )
            )

        if "Additional Settings" in headers:
            row["Additional Settings"] = raw_extra

        vdom = issue_vdom if issue_vdom is not None else str(data.get("vdom") or "")

        name = (
            data.get("name")
            or data.get("policy_id")
            or data.get("seq_num")
            or data.get("id")
        )

        _add_analysis_status(
            row,
            context,
            vdom=vdom,
            names=(name,),
            domains=domains,
        )

        yield row


def _additional_settings(
    item: Any,
    visible_values: Iterable[Any] = (),
) -> dict[str, Any]:
    return _additional_settings_from_data(
        item.model_dump(mode="python"),
        visible_values,
    )


def _additional_settings_from_data(
    data: Mapping[str, Any],
    visible_values: Iterable[Any] = (),
) -> dict[str, Any]:
    visible = list(visible_values)
    settings = dict(data.get("raw_extra", {}))

    explicit_fields = set(data.get("explicit_fields", ()))
    for field, value in data.items():
        if field not in explicit_fields:
            continue
        if field in {"name", "vdom", "raw_extra", "explicit_fields"}:
            continue
        if value in (None, "", [], {}) or value in visible:
            continue
        settings[field] = value

    return sanitize_source_attributes(settings)


def _add_analysis_status(
    row: dict[str, Any],
    context: _ExcelContext,
    *,
    vdom: str,
    names: Iterable[Any],
    domains: Iterable[str] | None = None,
    extra_reasons: Iterable[str] = (),
) -> None:
    names = tuple(name for name in names if name not in (None, ""))
    issues = context.issues_for(vdom=vdom, names=names, domains=domains) if names else []
    reasons = [issue.message for issue in issues]
    reasons.extend(str(reason) for reason in extra_reasons if reason)
    reasons = list(dict.fromkeys(reasons))

    row["Analysis Status"] = "REVIEW_REQUIRED" if reasons else "EXTRACTED"
    row["Review Reasons"] = reasons
    row["__review__"] = bool(reasons)
    row["__error__"] = any(
        issue.severity.value == "error"
        for issue in issues
    )


def _overlay_raw(
    row: dict[str, Any],
    raw: Mapping[str, Any],
    headers: Sequence[str],
) -> None:
    safe = sanitize_source_attributes(raw)

    for header in headers:
        if row.get(header) not in (None, "", [], {}):
            continue

        value, _ = _lookup_source_header(header, safe)
        if value not in (None, "", [], {}):
            row[header] = value


def _lookup_source_header(
    header: str,
    values: Mapping[str, Any],
) -> tuple[Any, str | None]:
    normalized_values = {
        _normalize_key(key): (key, value)
        for key, value in values.items()
    }

    candidates = [
        *_SOURCE_HEADER_ALIASES.get(
            header,
            (),
        ),
        header,
    ]

    for candidate in candidates:
        normalized = _normalize_key(
            candidate
        )

        if normalized not in normalized_values:
            continue

        source_key, value = normalized_values[
            normalized
        ]

        return value, source_key

    return None, None


def _normalize_key(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _enabled_text(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"enable", "enabled", "up", "yes", "true", "1"}:
        return "Yes"
    if normalized in {"disable", "disabled", "down", "no", "false", "0"}:
        return "No"
    return str(value)


def _nat_type(value: str | None) -> str | None:
    return {
        "ip_pool": "IP Pool",
        "nat64_ip_pool": "NAT64 IP Pool",
        "interface_address": "Interface Address",
    }.get(value, value)


def _disabled_text(value: Any) -> str | None:
    enabled = _enabled_text(value)
    if enabled == "Yes":
        return "No"
    if enabled == "No":
        return "Yes"
    return None


def _interface_source_values(
    context: _ExcelContext,
    *,
    vdom: str,
    name: str,
) -> dict[str, Any]:
    """
    Return safe explicit source values for one interface, including nested
    interface configuration.

    Nested values are exposed both by their raw key when unambiguous and by a
    namespaced key such as ipv6.ip6-address. This is report presentation only;
    FGInterface remains the typed source model.
    """

    values: dict[str, Any] = {}
    records = [
        *context.source_by_identity.get((vdom, "system interface", name), ()),
        *context.nested_source_by_parent.get((vdom, "system interface", name), ()),
    ]

    for record in records:
        nested = record.source_path != "system interface"
        suffix = (
            record.source_path.removeprefix("system interface ").strip()
            if nested
            else ""
        )

        for key, value in record.values.items():
            if key not in values:
                values[key] = value

            if suffix:
                values[f"{suffix}.{key}"] = value

    return sanitize_source_attributes(values)


def _source_secret_configured(
    context: _ExcelContext,
    *,
    vdom: str,
    name: str,
    keys: Iterable[str],
) -> str | None:
    wanted = {
        _normalize_key(key)
        for key in keys
    }

    records = [
        *context.source_by_identity.get((vdom, "system interface", name), ()),
        *context.nested_source_by_parent.get((vdom, "system interface", name), ()),
    ]
    for record in records:
        present = {
            _normalize_key(key)
            for key in record.values
        }

        if present & wanted:
            return "Yes"

    return None


def _additional_source_settings(
    source_values: Mapping[str, Any],
    row: Mapping[str, Any],
    headers: Sequence[str],
) -> dict[str, Any]:
    consumed: set[str] = set()

    for header in headers:
        if row.get(header) in (None, "", [], {}):
            continue

        _, source_key = _lookup_source_header(
            header,
            source_values,
        )

        if source_key is not None:
            consumed.add(source_key)

    return {
        key: value
        for key, value in source_values.items()
        if key not in consumed
    }


def _source_category(path: str) -> str:
    parts = path.split()
    return " ".join(parts[:2]) if len(parts) >= 2 else path


def _sheet_for_domain(domain: str) -> str:
    return {
        "interface": "Interfaces",
        "interface_topology": "Interfaces",
        "zone": "Zones",
        "address": "Addresses",
        "address6": "Addresses",
        "address_group": "Address Groups",
        "address_group6": "Address Groups",
        "service": "Services",
        "service_group": "Service Groups",
        "policy": "Policies",
        "nat": "NAT Rules",
        "vip": "Virtual IPs",
        "vip_group": "VIP Groups",
        "ip_pool": "IP Pools",
        "ipsec_phase1": "VPN Tunnels",
        "vpn_topology": "VPN Tunnels",
        "vpn_phase2": "VPN Phase 2",
        "static_route": "Routes",
        "user_group": "User Groups",
        "ips_sensor": "IPS Sensors",
    }.get(domain, "FortiGate Source Inventory")


def _safe_command_value(
    key: str,
    values: Iterable[Any],
) -> Any:
    """
    Sanitize one raw CLI command before it reaches Excel.

    Source-command appendix sheets must never bypass the same secret-redaction
    rules used for raw_extra/source inventory.
    """

    raw_values = list(values)
    raw_value: Any

    if not raw_values:
        raw_value = True
    elif len(raw_values) == 1:
        raw_value = raw_values[0]
    else:
        raw_value = raw_values

    return sanitize_source_value(key, raw_value)


def _excel_safe(value: Any) -> Any:
    value = _plain_value(value)

    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value

    return value


def _plain_value(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, Enum):
        return value.value

    if is_dataclass(value):
        return _plain_value(asdict(value))

    if isinstance(value, Mapping):
        return "\n".join(
            f"{key} = {_plain_value(item)}"
            for key, item in value.items()
        )

    if isinstance(value, (list, tuple, set, frozenset)):
        return "\n".join(
            str(_plain_value(item))
            for item in value
            if item not in (None, "", [], {})
        )

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, (str, int, float)):
        return value

    return str(value)
