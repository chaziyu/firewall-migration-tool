"""Cisco ASA source preview serialization."""

from __future__ import annotations

from typing import Any
from .source_report import ASASourceResult
from .presentation_schema import SOURCE_SECTIONS
from .presentation import safe_value
from .presentation import has_source_evidence


def _source_record(item: Any, allowed: str) -> dict[str, Any]:
    return {field: safe_value(getattr(item, field, None)) for field in allowed.split()}


def _name(value: Any) -> Any:
    return getattr(value, "name", value)


def _webvpn_attribute_names(value: Any) -> tuple[str, ...]:
    if hasattr(value, "explicit_fields"):
        return tuple(sorted(value.explicit_fields))
    if isinstance(value, dict):
        sensitive = ("password", "secret", "key", "token", "credential", "psk", "private")
        return tuple(sorted(key for key in value if not any(word in key.casefold() for word in sensitive)))
    return ()


def build_asa_preview(result: ASASourceResult) -> dict[str, Any]:
    config, derived = result.config, result.derived
    source = {}
    for section, spec in SOURCE_SECTIONS.items():
        records = getattr(config, spec[0], ()) or ()
        singleton = bool(getattr(type(records), "model_fields", None))
        if singleton:
            records = (records,)
        if section in {"DNS Settings", "System Settings", "HTTP Server"} and not has_source_evidence(records[0] if singleton else records):
            records = ()
        if len(spec) == 3:
            records = (child for parent in records for child in (getattr(parent, spec[1], ()) or ()))
            fields = spec[2]
        else:
            fields = spec[1]
        if section == "Policy Routing":
            records = (item for item in records if any(getattr(item, key, None)
                       for key in ("policy_route_maps", "policy_route_cost", "policy_route_path_monitors")))
        source[section.lower().replace(" ", "_")] = [_source_record(item, fields) for item in records]
    source["management_settings"] = {"dns": safe_value(config.dns_settings) if has_source_evidence(config.dns_settings) else None,
                                     "system": safe_value(config.system_settings) if has_source_evidence(config.system_settings) else None,
                                     "http_server": safe_value(config.http_server) if has_source_evidence(config.http_server) else None,
                                     "connection_controls": safe_value(config.connection_controls),
                                     "management_settings": safe_value(config.management_settings)}
    source["failover_config"] = safe_value(config.failover_config) if has_source_evidence(config.failover_config) else None
    source["multi_context_system"] = safe_value(config.multi_context_system) if has_source_evidence(config.multi_context_system) else None
    source = {
        "interfaces": source.pop("interfaces"), "zones": source.pop("zones"),
        "addresses": source.pop("network_objects"), "address_groups": source.pop("network_groups"),
        "services": source.pop("service_objects"), "service_groups": source.pop("service_groups"),
        "schedules": source.pop("time_ranges"), "acl_rules": source.pop("acl_rules"),
        "nat_rules": source.pop("nat_rules"),
        "mpf": {key: source.pop(key) for key in ("class_maps", "policy_maps", "service_policies")},
        "dhcp": {key: source.pop(key) for key in ("dhcp_global_settings", "dhcp_servers", "dhcp_reservations", "dhcp_relays")},
        "routing": {key: source.pop(key, []) for key in ("routes", "route_maps", "policy_routing", "sla_monitors", "tracks")},
        "identity": {key: source.pop(key) for key in ("local_users", "user_groups", "aaa_server_groups", "aaa_server_hosts", "aaa_authentication", "aaa_authorization", "aaa_accounting", "command_privileges")},
        "vpn": {key: source.pop(key) for key in ("ike_policies", "ikev2_proposals", "ipsec_transform_sets", "ipsec_profiles", "crypto_maps", "tunnel_groups", "group_policies", "vpn_address_pools", "vpn_address_assignment", "webvpn")},
        "management": {**source.pop("management_settings"),
                        **{key: source.pop(key) for key in ("dns", "ntp", "management_access", "snmp", "logging")}},
        "failover": {"config": source.pop("failover_config"), "settings": source.pop("failover")},
        "contexts": source.pop("contexts"),
        "other_source": source,
    }
    source["routing"]["static_routes"] = [_source_record(item, "source_context interface destination mask gateway administrative_distance address_family routing_context track_id tunneled raw_options raw_line") for item in config.static_routes]
    bindings = derived.acl_relationships.bindings
    interfaces_by_key = {(item.source_context, item.name): item for item in config.interfaces}
    interfaces = []
    for item in derived.interface_topology.interfaces:
        original = interfaces_by_key.get((item.source_context, item.name))
        interfaces.append({
            "name": item.name, "display_name": item.nameif or item.name, "kind": item.kind,
            "ip": ([original.ip] if original and original.ip else []) +
                  [address.address for address in (original.ipv6_addresses if original else ())],
            "zone": [_name(zone) for zone in item.zones],
            "parent": _name(item.parent), "aggregate": _name(item.aggregate),
            "physical_interfaces": [_name(value) for value in item.physical_interfaces],
            "status": original.extraction_status if original else "DERIVED",
            "review": list(item.issues), "scope": item.source_context,
        })
    policies = []
    for rule in config.access_rules:
        matching = [binding for binding in bindings
                    if binding.source_context == rule.source_context and binding.acl_name == rule.acl_name]
        for binding in matching or (None,):
            policies.append({
                "policy_id": rule.source_order, "name": rule.acl_name, "acl_name": rule.acl_name,
                "source_order": rule.source_order, "source_sequence": rule.source_sequence,
                "acl_type": rule.acl_type, "action": rule.action, "protocol": rule.protocol,
                "source_addresses": [rule.source_endpoint.value] if rule.source_endpoint and rule.source_endpoint.value else [],
                "destination_addresses": [rule.destination_endpoint.value] if rule.destination_endpoint and rule.destination_endpoint.value else [],
                "services": [value for value in (rule.service, rule.protocol_object) if value],
                "schedule": rule.time_range, "binding": (f"{binding.scope}:{binding.interface}" if binding and binding.interface else binding.scope if binding else "unbound"),
                "direction": binding.direction if binding else None,
                "interface": binding.interface if binding else None,
                "scope": rule.source_context, "inactive": rule.inactive,
                "review": list(rule.review_reasons),
            })
    nat_rows = [{
        "policy_id": item.source_order, "policy_name": item.source_rule.name or item.source_rule.raw_line,
        "translation_type": item.translation_semantics, "translated_addresses": [value for value in
            (item.source_rule.mapped_source, item.source_rule.mapped_destination, item.source_rule.pat_pool) if value],
        "egress_interfaces": [item.source_rule.destination_interface] if item.source_rule.destination_interface else [],
        "source_order": item.source_order, "effective_order": item.effective_order,
        "ordering_status": item.ordering_status, "section": item.section,
        "source_context": item.source_context, "scope": item.source_context, "review": list(item.issues),
    } for item in derived.nat.rules]
    route_rows = [{
        "route_id": getattr(item.source_route, "name", None) or index,
        "destination": item.normalized_destination or item.configured_destination,
        "configured_destination": item.configured_destination, "mask": item.configured_mask,
        "gateway": item.gateway, "device": item.interface,
        "distance": item.configured_administrative_distance,
        "effective_distance": item.effective_administrative_distance,
        "track_id": item.track_id, "address_family": item.address_family,
        "status": "EXTRACTED" if item.normalized_destination else "REVIEW",
        "review": list(item.issues), "scope": item.source_context,
    } for index, item in enumerate(derived.routes.routes, 1)]
    vpn_rows = [{
        "kind": item.topology_type, "name": _name(item.source_identity),
        "attachment": _name(item.interface) or item.tunnel_interface,
        "peer": list(item.peers),
        "crypto": {"crypto_map": item.crypto_map, "transform_sets": [_name(value) for value in item.transform_sets],
                   "ikev2_proposals": [_name(value) for value in item.ikev2_proposals], "ipsec_profile": item.ipsec_profile},
        "topology": {"sequence": item.crypto_map_sequence, "crypto_acl": _name(item.crypto_acl),
                     "selector_acl": _name(item.selector_acl), "tunnel_source": item.tunnel_source,
                     "tunnel_destination": item.tunnel_destination, "resolution_status": item.resolution_status},
        "review": list(item.issues), "scope": item.source_context,
    } for item in derived.vpn.ipsec_topologies]
    validation_rows = [{
        "severity": issue.severity, "domain": issue.category, "object_name": issue.source_object,
        "field": None, "message": issue.message, "scope": issue.source_context,
    } for issue in result.validation.issues]
    unresolved_rows = [{
        "source_kind": issue.reference_kind.value, "source_name": issue.source_object,
        "source_field": issue.reference_context, "reference": issue.reference_name,
        "status": issue.status.value, "scope": issue.source_context,
        "expected_kinds": [issue.reference_kind.value],
    } for issue in derived.relationship_issues]
    scopes = sorted({item.source_context for item in (*config.interfaces, *config.access_rules, *config.nat_rules, *config.static_routes) if item.source_context}) or ["root"]
    sections = {
        "interfaces": interfaces,
        "interface_topology": interfaces,
        "addresses": [{"name": item.name, "value": item.value, "type": item.type,
                       "address_family": item.address_family, "review": [], "scope": item.source_context}
                      for item in config.network_objects],
        "address_groups": [{"name": item.name, "members": item.members,
                             "address_family": item.address_family, "review": item.review_reasons,
                             "scope": item.source_context} for item in config.network_groups],
        "services": [{"name": item.name, "protocol": port.protocol if port else None,
                       "port": port.destination.values if port and port.destination else [],
                       "source_port": port.source.values if port and port.source else None,
                       "review": item.review_reasons, "scope": item.source_context}
                      for item in config.service_objects for port in (item.ports or (None,))],
        "service_groups": [{"name": item.name, "members": item.members,
                            "protocol": item.protocol, "review": item.review_reasons,
                            "scope": item.source_context} for item in config.service_groups],
        "schedules": [{"name": item.name, "clauses": safe_value(item.clauses),
                       "review": item.review_reasons, "scope": item.source_context} for item in config.time_ranges],
        "policies": policies, "nat": nat_rows, "routes": route_rows,
        "vpn_tunnels": vpn_rows, "vpn_phase2": [], "validation": validation_rows,
        "unresolved_references": unresolved_rows,
    }
    return {
        "vendor": "cisco_asa", "hostname": config.hostname,
        "summary": {"objects": {"interfaces": len(config.interfaces), "addresses": len(config.network_objects),
                    "address_groups": len(config.network_groups), "services": len(config.service_objects),
                    "service_groups": len(config.service_groups), "policies": len(config.access_rules),
                    "nat": len(nat_rows), "routes": len(route_rows)},
                    "validation": {"issue_count": len(validation_rows),
                                   "severity_counts": {"error": sum(row["severity"] == "error" for row in validation_rows),
                                                       "warning": sum(row["severity"] == "warning" for row in validation_rows)}},
                    "scopes": scopes,
                    "interfaces": len(config.interfaces), "network_objects": len(config.network_objects),
                    "network_groups": len(config.network_groups), "access_rules": len(config.access_rules),
                    "nat_rules": len(config.nat_rules), "routes": len(config.static_routes), "contexts": len(config.contexts)},
        "sections": sections,
        "source": source,
        "source_sections": [safe_value(item) for item in result.source_sections],
        "inventory": [{"domain": item.domain, "source_path": item.source_path, "source_id": item.source_id,
                       "status": item.status.value, "requires_manual_review": item.requires_manual_review,
                       "notes": safe_value(item.notes)} for item in result.inventory_items],
        "unsupported": [{"source_path": item.source_path, "source_name": item.source_name,
                         "reason": item.reason, "raw_capture": safe_value(item.raw_capture or "")}
                        for item in result.unsupported_items],
        "validation": [issue.__dict__ for issue in result.validation.issues],
        "relationships": {
            "object_groups": derived.object_group_memberships,
            "acl": safe_value(derived.acl_relationships),
            "acl_bindings": [
                {"acl_name": item.acl_name, "scope": item.scope, "direction": item.direction,
                 "interface": item.interface, "rules": [rule.source_order for rule in item.rules],
                 "issues": [issue.reason for issue in item.issues]}
                for item in derived.acl_relationships.bindings
            ],
            "mpf": safe_value(derived.mpf_relationships),
            "routing": safe_value(derived.routing_relationships),
            "identity": safe_value(derived.identity_relationships),
            "vpn_relationships": safe_value(derived.vpn_relationships),
            "interface_topology": [
                {"name": item.name, "nameif": item.nameif, "kind": item.kind,
                 "parent": _name(item.parent), "aggregate": _name(item.aggregate),
                 "physical_interfaces": [_name(value) for value in item.physical_interfaces],
                 "issues": item.issues}
                for item in derived.interface_topology.interfaces
            ],
            "nat": [{"source_context": row.source_context, "source_rule": row.rule.name,
                     "owning_object": _name(row.owning_object), "source_interface": _name(row.source_interface),
                     "destination_interface": _name(row.destination_interface), "issues": safe_value(row.issues)}
                    for row in derived.nat_relationships.rules],
            "vpn": [{"source_context": row.source.source_context, "source": row.source.name,
                     "targets": {key: _name(value) for key, value in row.targets},
                     "source_only": row.source_only, "issues": [issue.reason for issue in row.issues]}
                    for row in derived.vpn_relationships.relationships],
        },
        "coverage": [{"path": item.path, "status": item.status.value, "notes": safe_value(item.notes),
                       "line_start": item.line_start, "line_end": item.line_end}
                      for item in result.source_sections],
        "review_required": [{"source_path": item.source_path, "source_id": item.source_id,
                             "status": item.status.value, "notes": safe_value(item.notes)}
                            for item in result.inventory_items if item.requires_manual_review],
        "derived": {
            "nat": {
                "rules": [{"source_context": row.source_context, "source_rule": row.source_rule.name,
                     "source_order": row.source_order, "effective_order": row.effective_order,
                     "ordering_status": row.ordering_status, "section": row.section,
                     "translation_semantics": row.translation_semantics, "issues": safe_value(row.issues)}
                    for row in derived.nat.rules],
                "source_nat_pools": [{"source_context": row.source_context, "source_rule": row.source_rule.name,
                    "pool_type": row.pool_type, "mapped_source": row.mapped_source,
                    "mapped_object": _name(row.mapped_object),
                    "mapped_interface": _name(row.mapped_interface), "address_family": row.address_family,
                    "source_interface": _name(row.source_interface), "destination_interface": _name(row.destination_interface),
                    "translation_semantics": row.translation_semantics, "issues": row.issues}
                    for row in derived.nat.source_nat_pools],
                "vips": [{"source_context": row.source_context, "source_rule": row.source_rule.name,
                    "source_nat_order": row.source_nat_order, "source_nat_interface": _name(row.source_nat_interface),
                    "destination_nat_interface": _name(row.destination_nat_interface), "mapped_address": row.mapped_address,
                    "real_address": row.real_address, "mapped_service": row.mapped_service,
                    "real_service": row.real_service, "protocol": row.protocol,
                    "translation_type": row.translation_type, "inactive": row.inactive, "issues": safe_value(row.issues)}
                    for row in derived.nat.vips],
            },
            "vpn": {
                "ipsec": [{"source_context": row.source_context, "type": row.topology_type,
                     "source": row.source_identity.name, "crypto_map": row.crypto_map,
                     "sequence": row.crypto_map_sequence, "crypto_acl": _name(row.crypto_acl),
                     "selector_acl": _name(row.selector_acl),
                     "peers": row.peers, "tunnel_groups": [_name(v) for v in row.tunnel_groups],
                     "interface": _name(row.interface), "transform_sets": [_name(v) for v in row.transform_sets],
                     "ikev2_proposals": [_name(v) for v in row.ikev2_proposals],
                     "tunnel_interface": row.tunnel_interface, "tunnel_source": row.tunnel_source,
                     "tunnel_destination": row.tunnel_destination, "ipsec_profile": row.ipsec_profile,
                     "resolution_status": row.resolution_status, "group_policy": _name(row.group_policy),
                     "address_pools": [_name(v) for v in row.address_pools], "trustpoint": _name(row.trustpoint),
                     "issues": safe_value(row.issues)} for row in derived.vpn.ipsec_topologies],
                "remote_access": [{
                    "source_context": row.source_context, "connection_profile": row.tunnel_group.name,
                    "connection_profile_type": row.connection_profile_type,
                    "group_policy": _name(row.group_policy), "inherited_group_policy": _name(row.inherited_group_policy),
                    "authentication_server_group": _name(row.authentication_server_group),
                    "local_authentication_available": row.local_authentication_available,
                    "address_pools": [_name(value) for value in row.address_pools],
                    "dhcp_servers": [_name(value) for value in row.dhcp_servers],
                    "address_assignment_methods": row.address_assignment_methods,
                    "vpn_protocols": row.vpn_protocols, "vpn_access_hours": _name(row.vpn_access_hours),
                    "vpn_filter_acl": _name(row.vpn_filter_acl), "split_tunnel_policy": row.split_tunnel_policy,
                    "split_tunnel_acl": _name(row.split_tunnel_acl), "dns_servers": row.dns_servers,
                    "wins_servers": row.wins_servers, "default_domain": row.default_domain,
                    "enabled_interfaces": [_name(value) for value in row.enabled_interfaces],
                    "webvpn_attributes": {layer: _webvpn_attribute_names(value)
                                          for layer, value in row.webvpn_attributes},
                    "trustpoints": [_name(value) for value in row.trustpoints],
                    "resolution_status": row.resolution_status, "issues": safe_value(row.issues),
                } for row in derived.vpn.remote_access],
            },
            "routes": [{"source_context": row.source_context, "destination": row.configured_destination,
                        "mask": row.configured_mask, "normalized_destination": row.normalized_destination,
                        "interface": row.interface, "gateway": row.gateway,
                        "configured_administrative_distance": row.configured_administrative_distance,
                        "effective_administrative_distance": row.effective_administrative_distance,
                        "track_id": row.track_id, "issues": safe_value(row.issues)} for row in derived.routes.routes],
        },
    }


__all__ = ["build_asa_preview"]
