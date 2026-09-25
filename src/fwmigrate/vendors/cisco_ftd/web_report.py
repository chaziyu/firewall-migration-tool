from __future__ import annotations

from typing import Any

from .source_report import FTDSourceResult
from .reporting_counts import count_acp_rules, count_nat_rules


def build_ftd_preview(result: FTDSourceResult) -> dict[str, Any]:
    config = result.config
    def value(item):
        if item is None:
            return None
        if hasattr(item, "model_dump"):
            return item.model_dump(mode="python", exclude_none=True)
        if isinstance(item, dict):
            return item
        return item

    def ref(item):
        if item is None:
            return None
        if isinstance(item, str):
            return item
        if isinstance(item, dict):
            return item.get("name") or item.get("value") or item.get("source_id") or item.get("id") or item
        return getattr(item, "name", None) or getattr(item, "value", None) or getattr(item, "source_id", None)

    def scope(item):
        return getattr(item, "source_context", None) or getattr(item, "domain_id", None) or getattr(item, "device_id", None)

    interfaces = [{"name": item.name, "display_name": item.nameif or item.name,
                   "kind": item.interface_type, "ip": [item.ip] if item.ip else [],
                   "zone": [], "parent": item.parent_interface, "aggregate": item.etherchannel_id,
                   "physical_interfaces": [], "status": "SHUTDOWN" if item.shutdown else "EXTRACTED",
                   "scope": None, "source_plane": config.source_plane}
                  for item in config.interfaces]
    interfaces.extend({"name": item.name, "display_name": item.name, "kind": item.interface_type,
                       "ip": [item.address] if item.address else [], "zone": [ref(item.zone)] if item.zone else [],
                       "status": "EXTRACTED", "scope": scope(item), "source_plane": item.source_plane}
                      for item in (*config.device_interfaces, *config.source_interfaces))
    addresses = [{"name": item.name, "value": value(item.value), "type": item.address_type,
                  "address_family": item.address_family, "scope": scope(item), "source_plane": item.source_plane}
                 for item in config.network_addresses]
    address_groups = [{"name": item.name, "members": [ref(value) for value in (item.members or item.literal_members or ())],
                       "scope": scope(item), "source_plane": item.source_plane} for item in config.network_groups]
    services = [{"name": item.name, "protocol": item.protocol,
                 "port": item.ports or item.port or item.end_port,
                 "scope": scope(item), "source_plane": item.source_plane} for item in config.protocol_port_objects]
    service_groups = [{"name": item.name, "members": [ref(member) for member in item.members or ()],
                       "scope": scope(item), "source_plane": item.source_plane} for item in config.port_object_groups]
    schedules = [{"name": item.name, "value": value(item), "scope": scope(item), "source_plane": item.source_plane}
                 for item in config.time_ranges]
    policies = []
    for policy in config.access_control_policies:
        for index, rule in enumerate(policy.rules or (), 1):
            policies.append({"policy_id": rule.position or rule.collection_order or index,
                             "name": rule.name, "source_addresses": [ref(x) for x in rule.source_networks or ()],
                             "destination_addresses": [ref(x) for x in rule.destination_networks or ()],
                             "source_interfaces": [ref(x) for x in rule.source_zones or ()],
                             "destination_interfaces": [ref(x) for x in rule.destination_zones or ()],
                             "services": [ref(x) for x in rule.destination_ports or ()],
                             "schedule": ref(rule.time_range), "action": rule.action,
                             "section": rule.section, "category": rule.category,
                             "source_plane": rule.source_plane, "scope": scope(rule)})
    nat_rows = []
    for policy in config.nat_policies:
        for collection, rules in (("manual-before-auto", policy.manual_rules_before_auto),
                                  ("auto", policy.auto_rules), ("manual-after-auto", policy.manual_rules_after_auto),
                                  ("unclassified-manual", policy.unclassified_manual_rules), ("fdm", policy.rules)):
            for rule in rules or ():
                translated = [ref(getattr(rule, field, None)) for field in
                              ("translated_source", "translated_destination", "translated_network")]
                nat_rows.append({"policy_id": getattr(rule, "position", None) or getattr(rule, "sequence", None),
                                 "policy_name": rule.name, "translation_type": getattr(rule, "nat_type", None) or getattr(rule, "rule_type", None),
                                 "translated_addresses": [item for item in translated if item],
                                 "egress_interfaces": [ref(rule.destination_interface)] if getattr(rule, "destination_interface", None) else [],
                                 "source_kind": collection, "source_plane": rule.source_plane,
                                 "source_order": getattr(rule, "observed_collection_order", None), "scope": scope(rule)})
    routes = [{"route_id": item.source_name, "destination": item.normalized_destination or item.configured_destination,
               "configured_destination": item.configured_destination, "gateway": item.gateway,
               "device": item.device_id or item.virtual_router, "distance": None,
               "status": "EXTRACTED" if item.normalized_destination else "REVIEW",
               "review": [item.issue] if item.issue else [], "scope": item.device_id or item.virtual_router}
              for item in result.derived.normalized_routes]
    vpn_tunnels = [{"kind": "Site-to-site", "name": item.name, "peer": value(item),
                    "source_plane": item.source_plane, "scope": scope(item)} for item in config.s2s_vpn_topologies]
    vpn_tunnels.extend({"kind": "Site-to-site endpoint", "name": item.name, "peer": value(item),
                        "source_plane": item.source_plane, "scope": scope(item)} for item in config.s2s_vpn_endpoints)
    validation = [{"severity": item.severity, "domain": item.category, "object_name": item.source_object,
                   "field": None, "message": item.message,
                   "scope": getattr(item, "source_context", None)} for item in result.validation.issues]
    unresolved = [{"source_kind": item.source_plane, "source_name": item.owner,
                   "source_field": item.field, "reference": item.reference,
                   "expected_kinds": list(item.expected_kinds), "status": item.status,
                   "scope": item.domain_id or item.scope}
                  for item in result.derived.unresolved_references]
    scopes = sorted({row["scope"] for rows in (interfaces, addresses, address_groups, services, service_groups, policies, nat_rows, routes, vpn_tunnels)
                     for row in rows if row.get("scope")})
    sections = {"interfaces": interfaces, "interface_topology": interfaces, "addresses": addresses,
                "address_groups": address_groups, "services": services, "service_groups": service_groups,
                "schedules": schedules, "policies": policies, "nat": nat_rows, "routes": routes,
                "vpn_tunnels": vpn_tunnels, "vpn_phase2": [], "validation": validation,
                "unresolved_references": unresolved}
    return {
        "vendor": "cisco_ftd",
        "input_source_type": config.input_source_type,
        "source_plane": config.source_plane,
        "summary": {
            "network_addresses": len(config.network_addresses),
            "network_address_overrides": len(config.network_address_overrides),
            "network_groups": len(config.network_groups),
            "protocol_port_objects": len(config.protocol_port_objects),
            "port_object_groups": len(config.port_object_groups),
            "applications": len(config.applications),
            "security_zones": len(config.security_zones),
            "interfaces": len(config.device_interfaces) + len(config.source_interfaces) + len(config.interfaces),
            "routes": len(config.routes) + len(config.static_routes),
            "access_control_policies": len(config.access_control_policies),
            "access_control_default_actions": len(config.access_control_default_actions),
            "access_control_logging_settings": len(config.access_control_logging_settings),
            "security_intelligence_policies": len(config.security_intelligence_policies),
            "access_policy_inheritance_settings": len(config.access_policy_inheritance_settings),
            "policy_assignments": len(config.policy_assignments),
            "acp_rules": count_acp_rules(config),
            "nat_policies": len(config.nat_policies),
            "nat_rules": count_nat_rules(config),
            "time_ranges": len(config.time_ranges), "intrusion_policies": len(config.intrusion_policies),
            "intrusion_rule_groups": len(config.intrusion_rule_groups),
            "intrusion_rule_behaviors": len(config.intrusion_rule_behaviors),
            "intrusion_rule_overrides": len(config.intrusion_rule_overrides),
            "file_policies": len(config.file_policies),
            "file_rules": sum(len(item.rules or []) for item in config.file_policies),
            "decryption_policies": len(config.decryption_policies),
            "decryption_rules": sum(len(item.rules or []) for item in config.decryption_policies),
            "dns_policies": len(config.dns_policies),
            "dns_rules": sum(len(item.rules or []) for item in config.dns_policies), "fmc_users": len(config.fmc_users),
            "fmc_user_roles": len(config.fmc_user_roles), "realms": len(config.realms),
            "realm_user_groups": len(config.realm_user_groups), "realm_users": len(config.realm_users),
            "local_realm_users": len(config.local_realm_users),
            "s2s_vpn_topologies": len(config.s2s_vpn_topologies),
            "s2s_vpn_endpoints": len(config.s2s_vpn_endpoints),
            "ikev1_policies": sum(item.ike_version == "IKEv1" for item in config.ike_policies),
            "ikev2_policies": sum(item.ike_version == "IKEv2" for item in config.ike_policies),
            "ikev1_ipsec_proposals": sum(item.ike_version == "IKEv1" for item in config.ipsec_proposals),
            "ikev2_ipsec_proposals": sum(item.ike_version == "IKEv2" for item in config.ipsec_proposals),
            "ra_vpn_policies": len(config.ra_vpn_policies),
            "ra_vpn_connection_profiles": len(config.ra_vpn_connection_profiles),
            "virtual_routers": len(config.virtual_routers), "policy_based_routes": len(config.policy_based_routes),
            "ecmp_zones": len(config.ecmp_zones), "sla_monitors": len(config.sla_monitors),
            "certificates": len(config.certificates), "certificate_maps": len(config.certificate_maps),
            "certificate_enrollments": len(config.certificate_enrollments), "address_pools": len(config.address_pools),
            "group_policies": len(config.group_policies), "s2s_ike_settings": len(config.s2s_ike_settings),
            "s2s_ipsec_settings": len(config.s2s_ipsec_settings), "s2s_advanced_settings": len(config.s2s_advanced_settings),
            "ra_vpn_children": sum(map(len, (config.ra_vpn_ipsec_settings, config.ldap_attribute_maps,
                config.ra_vpn_load_balance_settings, config.ra_vpn_address_assignment_settings,
                config.secure_client_settings, config.ra_vpn_ipsec_crypto_maps))),
            "prefilter_policies": len(config.prefilter_policies), "prefilter_rules": len(config.prefilter_rules),
            "network_analysis_policies": len(config.network_analysis_policies),
            "identity_policies": len(config.identity_policies),
            "inspector_configs": len(config.inspector_configs),
            "dhcp_servers": len(config.dhcp_servers), "native_resources": len(config.native_resources),
            "dhcp_relay_settings": len(config.dhcp_relay_settings),
            "objects": {"interfaces": len(interfaces), "addresses": len(addresses),
                        "address_groups": len(address_groups), "services": len(services),
                        "service_groups": len(service_groups), "policies": len(policies),
                        "nat": len(nat_rows), "routes": len(routes)},
            "validation": {"issue_count": len(validation),
                           "severity_counts": {"error": sum(item["severity"] == "error" for item in validation),
                                               "warning": sum(item["severity"] == "warning" for item in validation)}},
            "scopes": scopes,
        },
        "source_metadata": config.source_metadata,
        "capability_coverage": config.source_metadata.get("coverage", {}),
        "source_plane_completeness": result.derived.source_plane_completeness,
        "interface_topology": [{"name": item.name, "device_id": item.device_id, "kind": item.kind, "parent": item.parent,
            "aggregate": item.aggregate, "physical_interfaces": item.physical_interfaces}
            for item in result.derived.interface_topology.interfaces],
        "normalized_routes": [item.__dict__ for item in result.derived.normalized_routes],
        "unresolved_references": [item.__dict__ for item in result.derived.unresolved_references],
        "identity_relationships": result.derived.identity_relationships,
        "vpn_relationships": result.derived.vpn_relationships,
        "ra_vpn_relationships": result.derived.ra_vpn_relationships,
        "ra_vpn": {name: [item.model_dump(exclude_none=True) for item in getattr(config, name)]
            for name in ("ra_vpn_policies", "ra_vpn_connection_profiles", "group_policies",
                         "address_pools", "certificates", "certificate_maps", "secure_client_settings",
                         "ra_vpn_address_assignment_settings", "ra_vpn_ipsec_settings")},
        "inspection_relationships": result.derived.inspection_relationships,
        "policy_relationships": result.derived.policy_relationships,
        "unsupported": config.unsupported_evidence,
        "validation": [issue.__dict__ for issue in result.validation.issues],
        "sections": sections,
    }


__all__ = ["build_ftd_preview"]
