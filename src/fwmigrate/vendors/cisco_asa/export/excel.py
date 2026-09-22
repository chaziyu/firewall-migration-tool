from __future__ import annotations

from pathlib import Path
from typing import Any

from .excel_schema import SHEET_HEADERS, SHEET_ORDER


def _value(value: Any) -> Any:
    if isinstance(value, (list, tuple, dict)):
        return str(value)
    return value


def _row(sheet: str, item: Any) -> tuple[Any, ...]:
    if sheet == "Interfaces":
        return item.name, item.nameif, item.source_context, item.ip, item.mask, item.security_level
    if sheet == "Network Objects":
        return item.name, item.type, item.value, item.source_context
    if sheet == "Network Groups":
        return item.name, ", ".join(item.members), item.source_context
    if sheet == "ACL Rules":
        return (item.acl_name, item.effective_source_order or item.source_order, item.action,
                item.protocol, getattr(item.source_endpoint, "value", None),
                getattr(item.destination_endpoint, "value", None), item.service,
                item.source_context, item.raw_line)
    if sheet == "NAT Rules":
        return (item.name, item.effective_source_order or item.source_order, item.section,
                item.source_interface, item.destination_interface, item.real_source,
                item.mapped_source, item.source_context, item.raw_line)
    if sheet == "Routes":
        return item.interface, item.destination, item.mask, item.gateway, item.source_context, item.raw_line
    if sheet == "VPN":
        return item["crypto_map"], item["sequence"], item["tunnel_group"], item["access_list"], item["source_context"]
    raise KeyError(sheet)


def export_asa_excel(result: Any, output: Any) -> Any:
    from openpyxl import Workbook

    workbook = Workbook()
    workbook.remove(workbook.active)
    config = result.config
    rows = {
        "Interfaces": config.interfaces,
        "Network Objects": config.network_objects,
        "Network Groups": config.network_groups,
        "ACL Rules": config.access_rules,
        "NAT Rules": config.nat_rules,
        "Routes": config.static_routes,
        "VPN": result.derived.vpn_relationships,
    }
    for name in SHEET_ORDER:
        sheet = workbook.create_sheet(name)
        if name == "Summary":
            sheet.append(("Field", "Value"))
            for key, value in {
                "Vendor": "Cisco ASA", "Hostname": config.hostname,
                "Interfaces": len(config.interfaces), "ACL Rules": len(config.access_rules),
                "NAT Rules": len(config.nat_rules), "Validation Issues": len(result.validation.issues),
            }.items():
                sheet.append((key, _value(value)))
            continue
        if name == "Source Inventory":
            sheet.append(("Domain", "Source Path", "Source ID", "Status", "Review Required"))
            for item in result.inventory_items:
                sheet.append((item.domain, item.source_path, item.source_id, item.status.value, item.requires_manual_review))
            continue
        if name == "Validation":
            sheet.append(SHEET_HEADERS[name])
            for issue in result.validation.issues:
                sheet.append((issue.severity, issue.category, issue.message, issue.source_context, issue.source_object))
            continue
        sheet.append(SHEET_HEADERS[name])
        for item in rows[name]:
            sheet.append(tuple(_value(value) for value in _row(name, item)))
    if hasattr(output, "write"):
        workbook.save(output)
        return output
    path = Path(output)
    workbook.save(path)
    return path


__all__ = ["export_asa_excel"]

