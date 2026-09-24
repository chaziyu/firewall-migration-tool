from __future__ import annotations

from pathlib import Path
import json
from typing import Any

from .excel_schema import SHEET_HEADERS, SHEET_ORDER


def _text(value: Any) -> Any:
    return str(value) if isinstance(value, (list, tuple, dict)) else value


def _refs(values: Any) -> Any:
    if values is None:
        return None
    if isinstance(values, dict):
        return values
    return [item.model_dump(exclude_none=True) if hasattr(item, "model_dump") else item for item in values]


def _nat_ref(value: Any) -> Any:
    if isinstance(value, dict):
        return value.get("name") or value.get("id") or str(value)
    if hasattr(value, "name"):
        return value.name or value.source_id
    return value


def export_ftd_excel(result: Any, output: Any) -> Any:
    from openpyxl import Workbook

    workbook = Workbook()
    workbook.remove(workbook.active)
    config = result.config
    rows = {
        "Managed Objects": [(x.name, x.source_id, x.address_type, x.value, x.description, x.address_family,
            x.fqdn_lookup_type, x.override_metadata, x.source_plane) for x in config.network_addresses],
        "Object Groups": [(x.name, _refs(x.members), _refs(x.literal_members), x.description,
            x.override_metadata, x.source_plane) for x in config.network_groups],
        "Services": ([(x.name, x.protocol, x.port if x.port is not None else x.ports, x.end_port, x.icmp_type, x.icmp_code,
            x.description, x.override_metadata, None, x.source_plane) for x in config.protocol_port_objects]
                     + [(x.name, None, None, None, None, None, x.description, x.override_metadata,
                         _refs(x.members), x.source_plane) for x in config.port_object_groups]),
        "Zones": [(x.name, x.interfaces, x.source_plane) for x in config.security_zones],
        "Interfaces": [(x.name, x.interface_type, x.address, x.zone.name if x.zone else None, x.source_plane) for x in config.device_interfaces]
                      + [(x.name, x.interface_type, x.address, x.zone, x.source_plane) for x in config.source_interfaces],
        "Routes": [(x.name, *(ref.name or ref.source_id if ref else None for ref in (x.interface, x.destination, x.gateway)), x.source_plane) for x in config.routes],
        "ACP Rules": [(rule.policy_name, rule.name, rule.source_id, rule.enabled, rule.position,
            rule.section, rule.category, rule.action, _refs(rule.source_zones), _refs(rule.destination_zones),
            _refs(rule.source_networks), _refs(rule.destination_networks), _refs(rule.source_ports),
            _refs(rule.destination_ports), _refs(rule.realm_users), _refs(rule.users), _refs(rule.user_groups),
            _refs(rule.applications), _refs(rule.application_filters), _refs(rule.inline_application_filters),
            _text(rule.urls), _refs(rule.url_categories), _refs([rule.time_range] if rule.time_range else None),
            _refs([rule.intrusion_policy] if rule.intrusion_policy else None),
            _refs([rule.variable_set] if rule.variable_set else None), _refs([rule.file_policy] if rule.file_policy else None),
            rule.log_begin, rule.log_end, rule.comments, rule.source_plane, rule.source_context)
            for policy in config.access_control_policies for rule in (policy.rules or [])],
        "NAT Rules": [(policy.name, rule.name, rule.source_id, kind, rule.enabled,
            getattr(rule, "section", None) or section, getattr(rule, "position", getattr(rule, "order", None)),
            _nat_ref(getattr(rule, "source_interface", None)), _nat_ref(getattr(rule, "destination_interface", None)),
            _nat_ref(getattr(rule, "original_source", None)), _nat_ref(getattr(rule, "translated_source", None)),
            _nat_ref(getattr(rule, "original_destination", None)), _nat_ref(getattr(rule, "translated_destination", None)),
            _nat_ref(getattr(rule, "original_source_service", None) or getattr(rule, "original_source_port", None)),
            _nat_ref(getattr(rule, "translated_source_service", None) or getattr(rule, "translated_source_port", None)),
            _nat_ref(getattr(rule, "original_destination_service", None) or getattr(rule, "original_destination_port", None)),
            _nat_ref(getattr(rule, "translated_destination_service", None) or getattr(rule, "translated_destination_port", None)),
            getattr(rule, "nat_type", None), getattr(rule, "interface_pat", None), getattr(rule, "dns", None),
            getattr(rule, "route_lookup", None), getattr(rule, "proxy_arp", None), rule.source_plane, rule.source_context,
            rule.raw_extra)
            for policy in config.nat_policies
            for section, kind, rules in (("BEFORE_AUTO", "manual", policy.manual_rules_before_auto),
                ("AUTO", "auto", policy.auto_rules), ("AFTER_AUTO", "manual", policy.manual_rules_after_auto),
                (None, "manual", policy.unclassified_manual_rules), (None, "manual", policy.rules))
            for rule in (rules or [])],
    }
    native_collections = ("applications", "variable_sets", "url_categories", "vlan_objects", "time_ranges",
        "intrusion_policies", "intrusion_rule_overrides", "file_policies",
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
                        json.dumps(item.source_attributes, default=str), json.dumps(item.raw_extra, default=str)))
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
