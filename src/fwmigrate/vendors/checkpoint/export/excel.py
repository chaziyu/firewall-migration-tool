from __future__ import annotations

from pathlib import Path
from typing import Any

from .excel_schema import SHEET_HEADERS, SHEET_ORDER


def _value(value: Any) -> Any:
    if isinstance(value, (list, tuple, dict)):
        return str(value)
    return value


def _row(item: Any, sheet: str) -> tuple[Any, ...]:
    if sheet == "Access Layers":
        return item.uid, item.name, item.package, item.parent_layer_uid, item.command
    if sheet == "Access Rules":
        return item.uid, item.name, item.order, item.package, item.layer, item.domain, item.command
    if sheet == "NAT Rules":
        return item.uid, item.name, item.order, item.package, item.domain, item.command
    if sheet == "Gaia":
        return item.name, item.object_type, item.gateway, item.command
    if sheet == "Groups":
        return item.uid, item.name, ", ".join(map(str, item.members)), item.domain, item.command
    if sheet == "Gateways":
        return item.uid, item.name, item.domain, item.gateway, item.command
    if sheet == "Domains":
        return item.uid, item.name, item.source_plane, item.command
    if sheet in {"Network Objects", "Services", "Applications", "Schedules"}:
        return item.uid, item.name, item.object_type or "", item.domain, item.command
    if sheet in {"Packages", "VPN Communities"}:
        return item.uid, item.name, item.domain, item.command
    raise KeyError(sheet)


def export_checkpoint_excel(result: Any, output: Any) -> Any:
    from openpyxl import Workbook

    workbook = Workbook()
    workbook.remove(workbook.active)
    config = result.config
    rows = {
        "Domains": config.domains,
        "Packages": config.packages,
        "Access Layers": config.access_layers,
        "Network Objects": config.network_objects,
        "Groups": config.groups,
        "Services": config.services,
        "Applications": config.applications,
        "Schedules": config.schedules,
        "Access Rules": config.access_rules,
        "NAT Rules": config.nat_rules,
        "VPN Communities": config.vpn_communities,
        "Gateways": config.gateways,
        "Gaia": config.gaia_interfaces + config.gaia_routes + config.pbr + config.dns_ntp + config.cluster_state + config.management_access,
    }
    for name in SHEET_ORDER:
        sheet = workbook.create_sheet(name)
        if name == "Summary":
            sheet.append(("Field", "Value"))
            sheet.append(("Vendor", "Check Point"))
            sheet.append(("Validation Issues", len(result.validation.issues)))
            for key, value in rows.items():
                sheet.append((key, len(value)))
        elif name == "Collection":
            sheet.append(("Command", "Plane", "Status", "Complete", "Error"))
            for item in config.collection:
                sheet.append((item.command, item.source_plane, item.status.value, item.complete, item.error))
        elif name == "Validation":
            sheet.append(SHEET_HEADERS[name])
            for issue in result.validation.issues:
                sheet.append((issue.severity, issue.category, issue.message, issue.command, issue.reference))
        else:
            sheet.append(SHEET_HEADERS[name])
            for item in rows.get(name, ()):
                sheet.append(tuple(_value(value) for value in _row(item, name)))
    if hasattr(output, "write"):
        workbook.save(output)
        return output
    path = Path(output)
    workbook.save(path)
    return path


__all__ = ["export_checkpoint_excel"]
