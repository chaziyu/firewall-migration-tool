from __future__ import annotations

from pathlib import Path
from typing import Any

from .excel_schema import SHEET_HEADERS, SHEET_ORDER


def _value(value: Any) -> Any:
    return str(value) if isinstance(value, (list, tuple, dict)) else value


def export_juniper_excel(result: Any, output: Any) -> Any:
    from openpyxl import Workbook

    workbook = Workbook()
    workbook.remove(workbook.active)
    views = result.derived
    rows = {"Interfaces": views.interface_topology, "Zones": views.zone_memberships,
            "Routing Instances": views.routing_instances, "Address Books": views.address_books,
            "Applications": views.applications, "Policies": views.policies, "NAT": views.nat_rule_sets,
            "VPN": views.vpn_relationships}
    for name in SHEET_ORDER:
        sheet = workbook.create_sheet(name)
        if name == "Summary":
            sheet.append(("Field", "Value"))
            sheet.append(("Vendor", "Juniper SRX"))
            sheet.append(("Hostname", result.config.hostname))
            sheet.append(("Validation Issues", len(result.validation.issues)))
            continue
        if name == "Source Inventory":
            sheet.append(("Domain", "Source Path", "Status", "Review Required"))
            for item in result.inventory_items:
                sheet.append((item.domain, item.source_path, item.status.value, item.requires_manual_review))
            continue
        if name == "Validation":
            sheet.append(SHEET_HEADERS[name])
            for issue in result.validation.issues:
                sheet.append((issue.severity, issue.category, issue.message, issue.context, issue.object_name))
            continue
        sheet.append(SHEET_HEADERS[name])
        for item in rows[name]:
            sheet.append(tuple(_value(item.get(header.lower().replace(" ", "_"))) for header in SHEET_HEADERS[name]))
    if hasattr(output, "write"):
        workbook.save(output)
        return output
    path = Path(output)
    workbook.save(path)
    return path


__all__ = ["export_juniper_excel"]
