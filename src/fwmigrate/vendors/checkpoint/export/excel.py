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
        members = getattr(item, "members", ())
        if hasattr(item, "include"):
            members = (item.include, item.except_)
        return item.uid, item.name, ", ".join(map(str, members)), item.domain, item.command
    if sheet == "Gateways":
        return item.uid, item.name, item.domain, item.gateway, item.command
    if sheet == "Domains":
        return item.uid, item.name, item.source_plane, item.command
    if sheet in {"Network Objects", "Services", "Applications", "Schedules"}:
        return item.uid, item.name, item.object_type or "", item.domain, item.command
    if sheet in {"Packages", "VPN Communities"}:
        return item.uid, item.name, item.domain, item.command
    raise KeyError(sheet)


def _nat_references(values: tuple[Any, ...] | None) -> str:
    if values is None:
        return "UNKNOWN"
    return ", ".join(
        f"{item.reference} (resolved: {item.resolved_uid or item.resolved_name})"
        if item.resolved_uid or item.resolved_name else item.reference
        for item in values
    )


def export_checkpoint_excel(result: Any, output: Any) -> Any:
    from openpyxl import Workbook

    workbook = Workbook()
    workbook.remove(workbook.active)
    config = result.config
    rows = {
        "Domains": config.domains,
        "Packages": config.policy_packages,
        "Access Layers": config.access_layers,
        "Network Objects": config.hosts + config.networks + config.address_ranges + config.dns_domains + config.wildcard_addresses + config.dynamic_addresses + config.updatable_objects + config.security_zones,
        "Groups": config.groups + config.groups_with_exclusion + config.service_groups + config.time_groups,
        "Services": config.services,
        "Applications": config.applications,
        "Schedules": config.times,
        "Access Rules": config.access_rules,
        "NAT Rules": config.nat_rules,
        "VPN Communities": config.vpn_communities,
        "Gateways": config.gateways,
        "Gaia": config.gaia_interfaces + config.gaia_static_routes + config.gaia_dhcp_servers + config.gaia_users + config.gaia_rba_roles + config.gaia_rba_user_assignments + config.vtis,
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
            for item in result.collection:
                sheet.append((item.command, item.source_plane, item.status.value, item.complete, item.error))
        elif name == "Validation":
            sheet.append(SHEET_HEADERS[name])
            for issue in result.validation.issues:
                sheet.append((issue.severity, issue.category, issue.message, issue.command, issue.reference))
        elif name == "NAT Migration View":
            sheet.append(SHEET_HEADERS[name])
            for item in result.derived.nat.views:
                sheet.append((
                    item.source_kind, item.source_uid, item.source_name, item.domain,
                    item.rule_order, item.enabled, _nat_references(item.original_source),
                    _nat_references(item.original_destination), _nat_references(item.original_service),
                    _nat_references(item.translated_source), _nat_references(item.translated_destination),
                    _nat_references(item.translated_service), item.translation_method,
                    item.owner_uid, item.owner_name, _nat_references(item.install_on),
                    "; ".join(issue.message for issue in item.issues),
                ))
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
