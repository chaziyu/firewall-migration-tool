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


def _ra_ref(value: Any) -> Any:
    return value.model_dump(exclude_none=True) if value is not None else None


def _nat_ref(value: Any) -> Any:
    if isinstance(value, dict):
        return value.get("name") or value.get("id") or str(value)
    if hasattr(value, "name"):
        return value.name or value.source_id
    return value


def _nat_row(policy: Any, rule: Any, section: str | None, kind: str) -> tuple[Any, ...]:
    fdm = kind == "fdm" or hasattr(rule, "rule_type")
    synthetic = policy.source_attributes.get("synthetic_container")
    return (None if synthetic else policy.name, rule.name, rule.source_id,
        getattr(rule, "rule_type", None) if fdm else kind, rule.enabled,
        None if fdm else getattr(rule, "section", None) or section,
        getattr(rule, "sequence", None) if fdm else getattr(rule, "position", getattr(rule, "order", None)),
        _nat_ref(getattr(rule, "source_interface", None)), _nat_ref(getattr(rule, "destination_interface", None)),
        _nat_ref(getattr(rule, "original_source", None)), _nat_ref(getattr(rule, "translated_source", None)),
        _nat_ref(getattr(rule, "original_destination", None)), _nat_ref(getattr(rule, "translated_destination", None)),
        _nat_ref(getattr(rule, "original_source_service", None) or getattr(rule, "original_source_port", None)),
        _nat_ref(getattr(rule, "translated_source_service", None) or getattr(rule, "translated_source_port", None)),
        _nat_ref(getattr(rule, "original_destination_service", None) or getattr(rule, "original_destination_port", None)),
        _nat_ref(getattr(rule, "translated_destination_service", None) or getattr(rule, "translated_destination_port", None)),
        getattr(rule, "nat_type", None), getattr(rule, "interface_pat", None), getattr(rule, "dns", None),
        getattr(rule, "route_lookup", None), getattr(rule, "proxy_arp", None), rule.source_plane, rule.source_context,
        rule.raw_extra, _nat_ref(getattr(rule, "service", None)),
        getattr(rule, "source_translation_mode", None), getattr(rule, "destination_translation_mode", None))


def _inspection_rows(config: Any) -> list[tuple[Any, ...]]:
    rows = []
    groups = (("File", config.file_policies, ()),
              ("Decryption", config.decryption_policies, ("default_action", "undecryptable_action", "advanced_settings")),
              ("DNS", config.dns_policies, ("default_action", "umbrella_settings")))
    for kind, policies, behavior_fields in groups:
        for policy in policies:
            rules = policy.rules
            for rule in rules or [None]:
                fields = {} if rule is None else rule.model_dump(exclude_none=True, exclude={
                    "name", "source_id", "source_plane", "source_context", "domain_id", "device_id",
                    "explicit_fields", "source_attributes", "raw_extra", "parent_policy_id", "parent_policy_name",
                    "position", "collection_order", "enabled", "action"})
                behavior = {field: getattr(policy, field) for field in behavior_fields
                            if getattr(policy, field) is not None}
                rows.append((kind, policy.name, policy.source_id, rule.name if rule else None,
                    rule.source_id if rule else None, "UNKNOWN" if rules is None else "PRESENT" if rules else "KNOWN EMPTY",
                    rule.position if rule else None, rule.collection_order if rule else None,
                    rule.enabled if rule else None, rule.action if rule else None,
                    json.dumps(fields, default=str), json.dumps(behavior, default=str),
                    json.dumps({"policy": policy.raw_extra, "rule": rule.raw_extra if rule else {}}, default=str),
                    policy.source_plane, policy.source_context))
    return rows


def export_ftd_excel(result: Any, output: Any) -> Any:
    from openpyxl import Workbook

    workbook = Workbook()
    workbook.remove(workbook.active)
    config = result.config
    derived = getattr(result, "derived", None)
    topologies = {item.name: item for item in getattr(getattr(derived, "interface_topology", None), "interfaces", ())}
    normalized_routes = {item.source_name: item.normalized_destination
                         for item in getattr(derived, "normalized_routes", ())}
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
        "Interfaces": [(x.name, x.interface_type, x.address, x.zone.name if x.zone else None, x.source_plane, None, None, None) for x in config.device_interfaces]
                      + [(x.name, x.interface_type, x.address, x.zone, x.source_plane, None, None, None) for x in config.source_interfaces]
                      + [(item.name, None, item.ip, None, config.source_plane, topology.kind, topology.parent, item.vlan_id)
                         for item in config.interfaces
                         for topology in (topologies[item.name],) if item.name in topologies],
        "Routes": [(x.name, *(ref.name or ref.source_id if ref else None for ref in
            (x.interface, x.destination, x.gateway, x.sla_monitor)), x.source_plane, x.address_family, None, None) for x in config.routes]
            + [(route.name, route.interface, route.destination, route.gateway, None, config.source_plane,
                route.address_family, route.mask, normalized_routes.get(route.name)) for route in config.static_routes],
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
        "NAT Rules": [_nat_row(policy, rule, section, kind)
            for policy in config.nat_policies
            for section, kind, rules in (("BEFORE_AUTO", "manual", policy.manual_rules_before_auto),
                ("AUTO", "auto", policy.auto_rules), ("AFTER_AUTO", "manual", policy.manual_rules_after_auto),
                (None, "manual", policy.unclassified_manual_rules), (None, "manual", policy.rules))
            for rule in (rules or [])],
        "Inspection Policies": _inspection_rows(config),
        "RA VPN Policies": [(x.name, x.source_id, _refs(x.target_devices), _refs(x.access_interfaces),
            _refs(x.certificates), _refs(x.certificate_maps), x.certificate_map_settings, _refs(x.connection_profiles),
            _refs(x.group_policies), _refs(x.address_pools), _refs(x.realms), x.ssl_tls_settings,
            x.dtls_settings, x.session_settings, x.raw_extra) for x in config.ra_vpn_policies],
        "RA Connection Profiles": [(x.parent_policy_name, x.name, x.source_id, x.alias, x.group_url,
            x.enabled, x.authentication_method, _ra_ref(x.realm), _ra_ref(x.authentication_server),
            _ra_ref(x.authorization), _ra_ref(x.accounting_server), _ra_ref(x.default_group_policy),
            _refs(x.address_pools), x.address_assignment, _refs(x.certificates), _refs(x.certificate_maps),
            x.connection_settings, x.raw_extra) for x in config.ra_vpn_connection_profiles],
        "RA Group Policies": [(x.name, x.source_id, x.vpn_access, x.protocols, x.connection_settings,
            x.dns_servers, x.wins_servers, x.domain_name, _ra_ref(x.realm), _ra_ref(x.aaa_server_group),
            _refs(x.address_pools), x.split_tunnel_policy, _refs(x.split_tunnel_networks), _ra_ref(x.split_tunnel_acl), x.split_dns,
            _refs(x.secure_client), x.session_settings, x.simultaneous_logins, x.raw_extra)
            for x in config.group_policies],
        "RA Address Pools": [(x.name, x.source_id, x.address_family, x.start_address, x.end_address,
            x.source_representation, x.address_reuse_delay, x.override_metadata, x.raw_extra)
            for x in config.address_pools],
        "RA Certificates": [(x.name, x.source_id, x.certificate_type, x.issuer, x.subject,
            x.validity, x.certificate_metadata, x.private_key_present, x.raw_extra) for x in config.certificates],
        "RA Certificate Maps": [(x.name, x.source_id, x.conditions, _ra_ref(x.connection_profile),
            _ra_ref(x.group_policy), x.raw_extra) for x in config.certificate_maps],
        "RA Secure Client": [(x.name, x.source_id, _refs(x.packages), _refs(x.profiles), x.raw_extra)
            for x in config.secure_client_settings],
        "RA IPsec Settings": [(x.source_attributes.get("parent_policy_id"),
            x.source_attributes.get("parent_policy_name"), x.name, x.ikev2_settings, x.ipsec_settings,
            x.nat_keepalive, x.raw_extra) for x in config.ra_vpn_ipsec_settings],
        "RA Address Assignment": [(x.source_attributes.get("parent_policy_id"),
            x.source_attributes.get("parent_policy_name"), x.name, _refs(x.address_pools),
            x.assignment_method, x.reuse_delay, x.use_dhcp, x.use_authorization_server_for_ipv4,
            x.use_authorization_server_for_ipv6, x.use_internal_address_pool_for_ipv4,
            x.use_internal_address_pool_for_ipv6, x.raw_extra)
            for x in config.ra_vpn_address_assignment_settings],
    }
    native_collections = ("applications", "variable_sets", "url_categories", "vlan_objects", "time_ranges",
        "intrusion_policies", "intrusion_rule_groups", "intrusion_rule_behaviors", "intrusion_rule_overrides",
        "fmc_user_roles", "fmc_users", "dhcp_servers", "realms",
        "realm_user_groups", "realm_users", "local_realm_users", "s2s_vpn_topologies", "s2s_vpn_endpoints",
        "ike_policies", "ipsec_proposals", "ra_vpn_policies", "ra_vpn_connection_profiles",
        "virtual_routers", "sla_monitors", "ecmp_zones", "policy_based_routes", "certificates",
        "certificate_maps", "certificate_enrollments", "address_pools", "group_policies",
        "s2s_ike_settings", "s2s_ipsec_settings", "s2s_advanced_settings", "ra_vpn_ipsec_settings",
        "ldap_attribute_maps", "ra_vpn_load_balance_settings", "ra_vpn_address_assignment_settings",
        "secure_client_settings", "ra_vpn_ipsec_crypto_maps", "prefilter_policies", "prefilter_rules",
        "prefilter_default_actions", "network_analysis_policies", "inspector_configs",
        "inspector_override_configs", "native_resources")
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
