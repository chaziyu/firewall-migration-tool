from __future__ import annotations

from pathlib import Path
import json
from typing import Any

from .excel_schema import SHEET_HEADERS, SHEET_ORDER


def _text(value: Any) -> Any:
    return str(value) if isinstance(value, (list, tuple, dict)) else value


def export_ftd_excel(result: Any, output: Any) -> Any:
    from openpyxl import Workbook

    workbook = Workbook()
    workbook.remove(workbook.active)
    config = result.config
    rows = {
        "Managed Objects": [(x.name, x.source_id, x.object_type, x.source_plane) for x in config.managed_objects],
        "Object Groups": [(x.name, x.members, x.source_plane) for x in config.object_groups],
        "Services": [(x.name, x.protocol, x.ports or x.members, x.source_plane) for x in config.services],
        "Zones": [(x.name, x.interfaces, x.source_plane) for x in config.security_zones],
        "Interfaces": [(x.name, x.interface_type, x.address, x.zone, x.source_plane) for x in config.source_interfaces],
        "Routes": [(x.name, x.interface, x.destination, x.gateway, x.source_plane) for x in config.routes],
        "ACP Rules": [(x.name, x.policy, x.action, x.source, x.destination, x.services, x.source_plane) for x in config.acp_rules],
        "NAT Rules": [(x.name, x.policy, x.source_interface, x.destination_interface, x.original, x.translated, x.source_plane) for x in config.nat_policies],
    }
    native_collections = ("time_ranges", "intrusion_policies", "intrusion_rule_overrides", "file_policies",
        "decryption_policies", "dns_policies", "fmc_user_roles", "fmc_users", "dhcp_servers", "realms",
        "realm_user_groups", "realm_users", "local_realm_users", "s2s_vpn_topologies", "s2s_vpn_endpoints",
        "ike_policies", "ipsec_proposals", "ra_vpn_policies", "ra_vpn_connection_profiles", "native_resources")
    for name in SHEET_ORDER:
        sheet = workbook.create_sheet(name)
        if name == "Summary":
            sheet.append(("Field", "Value"))
            for key, value in {"Vendor": "Cisco FTD", "Input Source": config.input_source_type,
                               "Source Plane": config.source_plane,
                               "Validation Issues": len(result.validation.issues)}.items():
                sheet.append((key, _text(value)))
        elif name == "Source Evidence":
            sheet.append(SHEET_HEADERS[name])
            for item in config.unsupported_evidence:
                sheet.append((item.get("source_path"), item.get("reason")))
        elif name == "Validation":
            sheet.append(SHEET_HEADERS[name])
            for item in result.validation.issues:
                sheet.append((item.severity, item.category, item.message, item.source_plane, item.source_object))
        elif name == "Native Sources":
            sheet.append(SHEET_HEADERS[name])
            for collection in native_collections:
                for item in getattr(config, collection):
                    sheet.append((collection, item.name, item.source_id, item.source_context,
                        json.dumps(item.source_attributes, default=str), json.dumps(item.raw, default=str)))
        else:
            sheet.append(SHEET_HEADERS[name])
            for row in rows[name]:
                sheet.append(tuple(_text(value) for value in row))
    if hasattr(output, "write"):
        workbook.save(output)
        return output
    path = Path(output)
    workbook.save(path)
    return path


__all__ = ["export_ftd_excel"]
