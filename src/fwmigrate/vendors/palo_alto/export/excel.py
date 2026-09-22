from __future__ import annotations

from pathlib import Path
from typing import Any, BinaryIO

from openpyxl import Workbook

from ..source_report import PaloAltoSourceResult


def _safe(value: Any) -> Any:
    if isinstance(value, (dict, list, tuple)):
        return "\n".join(f"{key}: {item}" for key, item in value.items()) if isinstance(value, dict) else "\n".join(map(str, value))
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def export_panos_excel(analysis: PaloAltoSourceResult, output: BinaryIO | str | Path) -> None:
    workbook = Workbook()
    workbook.remove(workbook.active)
    config = analysis.config

    summary = workbook.create_sheet("Summary")
    summary.append(["PAN-OS Source Report"])
    summary.append(["Hostname", config.hostname])
    summary.append(["Source Version", config.source_version])
    summary.append(["Scopes", len(config.scopes)])
    summary.append(["Source Records", len(config.source_inventory)])

    scopes = workbook.create_sheet("Scopes")
    scopes.append(["Kind", "Name", "Device", "Serial", "Device Group", "Template Stack"])
    for scope in config.scopes:
        scopes.append([scope.kind, scope.name, scope.device_name, scope.device_serial, scope.device_group, scope.template_stack])

    records = workbook.create_sheet("Source Inventory")
    records.append(["Order", "Kind", "Source Path", "Name", "Scope", "Values"])
    for record in config.source_inventory:
        records.append([record.source_order, record.kind, record.source_path, record.name, record.scope.name if record.scope else None, _safe(record.values)])

    domain_rows = {
        "Interfaces": [*config.interfaces, *config.interface_units],
        "Addresses": [*config.addresses, *config.address_groups],
        "Policies": [*config.security_rules, *config.default_security_rules],
        "NAT Rules": config.nat_rules,
        "Routes": [route for router in config.virtual_routers for route in (router.static_routes or [])],
    }
    for sheet_name, items in domain_rows.items():
        sheet = workbook.create_sheet(sheet_name)
        sheet.append(["Order", "Kind", "Source Path", "Name", "Scope", "Values"])
        for item in items:
            scope = getattr(item, "scope", None)
            sheet.append([getattr(item, "source_order", None), type(item).__name__, getattr(item, "source_path", None), getattr(item, "name", None), scope.name if scope else None, _safe(item.model_dump())])

    validation = workbook.create_sheet("Validation")
    validation.append(["Severity", "Domain", "Source Path", "Source Name", "Message"])
    for issue in analysis.validation.issues:
        validation.append([issue.severity, issue.domain, issue.source_path, issue.source_name, issue.message])

    if isinstance(output, (str, Path)):
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        workbook.save(output)
    else:
        workbook.save(output)
