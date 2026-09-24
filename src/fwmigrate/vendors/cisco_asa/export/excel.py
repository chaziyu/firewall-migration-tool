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
        rule = item.source_rule
        return (rule.name, item.source_order, item.effective_order, item.ordering_status, item.section,
                item.translation_semantics, rule.source_interface, rule.destination_interface,
                rule.real_source, rule.mapped_source, item.source_context, rule.raw_line)
    if sheet == "Routes":
        route = item.source_route
        return (item.interface, item.configured_destination, item.configured_mask, item.normalized_destination,
                item.gateway, item.configured_administrative_distance, item.effective_administrative_distance,
                item.track_id, item.source_context, route.raw_line)
    if sheet == "VPN":
        source = item.source_identity
        return (item.topology_type, source.name, item.crypto_map, item.crypto_map_sequence,
                getattr(item.crypto_acl, "acl_name", item.crypto_acl), item.peers,
                tuple(getattr(value, "name", value) for value in item.tunnel_groups),
                getattr(item.interface, "name", None), tuple(getattr(value, "name", value) for value in item.transform_sets),
                tuple(getattr(value, "name", value) for value in item.ikev2_proposals), item.tunnel_interface,
                item.ipsec_profile, getattr(item.group_policy, "name", None),
                tuple(getattr(value, "name", value) for value in item.address_pools), item.source_context, item.issues)
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
        "NAT Rules": result.derived.nat.rules,
        "Routes": result.derived.routes.routes,
        "VPN": result.derived.vpn.topologies,
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

