from __future__ import annotations

from .identity import source_identity

from dataclasses import asdict, is_dataclass
from collections import defaultdict
from typing import Any

from .source_model import PANScope, pan_scope_identity
from .source_report import PaloAltoSourceResult


_PREVIEW_RECORD_LIMIT = 200


def _scope_id(scope: PANScope | None) -> str:
    return pan_scope_identity(scope) if scope else "<unscoped>"


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def build_panos_preview(analysis: PaloAltoSourceResult) -> dict[str, Any]:
    config = analysis.config
    records = config.source_inventory
    identity_reviews = defaultdict(list)
    reviews: dict[tuple[str, str | None, str | None], list[str]] = defaultdict(list)
    review_fallbacks: dict[tuple[str, str | None], list[str]] = defaultdict(list)
    for issue in analysis.validation.issues:
        scope_id = _scope_id(issue.source_scope)
        if issue.source_identity:
            identity_reviews[issue.source_identity].append(issue.message)
        else:
            reviews[(scope_id, issue.source_path, issue.source_name)].append(issue.message)
        if issue.source_path is None:
            review_fallbacks[(scope_id, issue.source_name)].append(issue.message)

    def scope_fields(item: Any) -> dict[str, Any]:
        scope = item if isinstance(item, PANScope) else getattr(item, "scope", None)
        return {
            "scope": _scope_id(scope),
            "scope_type": scope.kind if scope else None,
            "scope_name": scope.name if scope else None,
            "device_name": scope.device_name if scope else None,
            "device_serial": scope.device_serial if scope else None,
            "device_group": scope.device_group if scope else None,
            "parent_device_group": scope.parent_device_group if scope else None,
            "vsys": scope.vsys if scope else None,
            "template": scope.template_provenance.get("template") if scope else None,
            "template_stack": scope.template_stack if scope else None,
            "rulebase_position": getattr(item, "rulebase_position", None),
        }

    def review(item: Any) -> list[str]:
        scope_id = _scope_id(getattr(item, "scope", None))
        name = getattr(item, "name", None)
        path = getattr(item, "source_path", None)
        return [*identity_reviews.get(source_identity(item), []),
                *(reviews.get((scope_id, path, name), []) or
                  (review_fallbacks.get((scope_id, name), []) if path is None else []))]

    def source_row(item: Any) -> dict[str, Any]:
        fields = item.model_dump(mode="json", exclude={"scope", "raw_extra", "explicit_fields"})
        # Child metadata uses the same report key as parent metadata; keep the API alias.
        for name in ("client_authentication", "client_configs"):
            for child in fields.get(name) or ():
                child["additional_settings"] = child["raw_extra"]
        return {**fields,
                "additional_settings": item.raw_extra, "explicit_fields": sorted(item.explicit_fields),
                "review": review(item), **scope_fields(item)}

    def rule_rows(items):
        positions = defaultdict(int)
        for item in items:
            key = (_scope_id(item.scope), item.rulebase_position)
            positions[key] += 1
            # Keep the old API alias; the UI uses source_order and rule_uuid instead.
            yield {**source_row(item), "policy_id": item.source_order, "rule_order": positions[key],
                   "rule_uuid": item.raw_extra.get("@attributes", {}).get("uuid")}

    addresses = [
        {
            **source_row(item),
            "name": item.name,
            "value": item.ip_netmask or item.ip_range or item.ip_wildcard or item.fqdn,
            "type": next((field for field in ("ip_netmask", "ip_range", "ip_wildcard", "fqdn") if getattr(item, field)), None),
            "address_family": "IPv6" if ":" in (item.ip_netmask or item.ip_range or item.ip_wildcard or "") else "IPv4" if item.ip_netmask or item.ip_range or item.ip_wildcard else None,
            "associated_interface": None,
            "review": review(item),
            **scope_fields(item),
        }
        for item in config.addresses
    ]
    address_groups = [{**source_row(item), "members": item.static_members, "address_family": None, "exclude_members": []} for item in config.address_groups]
    services = []
    for item in config.services:
        protocol = item.tcp or item.udp
        services.append({**source_row(item), "protocol": "tcp" if item.tcp else "udp" if item.udp else None,
                         "port": protocol.port if protocol else None, "source_port": protocol.source_port if protocol else None,
                         "generated": False, "review": review(item), **scope_fields(item)})
    service_groups = [{**source_row(item), "generated": False} for item in config.service_groups]
    policies = [{**row, "source_interfaces": row["from_zones"], "destination_interfaces": row["to_zones"],
                 "source_addresses": row["source"], "destination_addresses": row["destination"],
                 "services": row["service"]} for row in rule_rows(config.security_rules)]
    nat_rows = []
    for item, row in zip(config.nat_rules, rule_rows(config.nat_rules)):
        source_translation = item.source_translation
        translated_addresses = []
        if source_translation is not None:
            translated_addresses.extend(getattr(source_translation, "translated_addresses", None) or ())
            translated_address = getattr(source_translation, "translated_address", None)
            if translated_address:
                translated_addresses.append(translated_address)
        if item.destination_translation and item.destination_translation.translated_address:
            translated_addresses.append(item.destination_translation.translated_address)
        if item.dynamic_destination_translation:
            translated_addresses.extend(item.dynamic_destination_translation.translated_addresses or ())
        translation_type = (
            getattr(source_translation, "translation_type", None)
            or ("dynamic-destination-translation" if item.dynamic_destination_translation else None)
            or ("destination-translation" if item.destination_translation else None)
            or item.nat_type
        )
        nat_rows.append({
            **row,
            "policy_name": item.name,
            "source_addresses": item.source,
            "destination_addresses": item.destination,
            "translation_type": translation_type,
            "nat_type": item.nat_type,
            "translated_addresses": translated_addresses,
            "source_translation_interface": getattr(source_translation, "interface", None),
            "source_translation_ip": getattr(source_translation, "ip", None),
            "egress_interfaces": [item.to_interface] if item.to_interface else item.to_zones,
            "review": review(item),
            **scope_fields(item),
        })
    interface_by_key = {
        (_scope_id(item.scope), item.name): item
        for item in [*config.interfaces, *config.interface_units]
        if item.name
    }
    interface_rows = []
    for item in analysis.derived.interface_topology:
        source = interface_by_key.get((item.scope, item.interface))
        interface_rows.append({**(source_row(source) if source else {}),
                               "name": item.interface, "display_name": item.interface, "kind": item.kind,
                               "ip": getattr(source, "ipv4_addresses", None), "zone": item.zones, "parent": item.parent,
                               "virtual_routers": item.virtual_routers, "imported_vsys": item.imported_vsys,
                               "aggregate": item.aggregate, "physical_interfaces": item.physical_interfaces,
                               "status": "EXTRACTED", "review": item.issues,
                               **(scope_fields(source) if source else {"scope": item.scope}), "_scope": item.scope,
                               "_attached_tunnels": item.attached_tunnels})
    topology_rows = {(row["_scope"], row["name"]): row for row in interface_rows}
    children = defaultdict(list)
    for key, row in topology_rows.items():
        parent = row["parent"]
        if parent and (key[0], parent) in topology_rows:
            children[(key[0], parent)].append(key)
    ranks = {"aggregate": 0, "physical": 1, "vlan": 2, "logical": 3, "tunnel": 4}
    rendered: list[dict[str, Any]] = []
    visited: set[tuple[str, str]] = set()

    def emit(key: tuple[str, str], prefix: str = "") -> None:
        if key in visited:
            return
        visited.add(key)
        row = topology_rows[key]
        symbol = {"aggregate": "◆", "physical": "●", "vlan": "▣", "tunnel": "◇", "logical": "◇"}.get(row["kind"], "◇")
        row = {**row, "display_name": f"{prefix}{symbol} {row['name']}"}
        row.pop("_scope", None)
        tunnels = row.pop("_attached_tunnels", ())
        rendered.append(row)
        child_keys = sorted(children.get(key, ()), key=lambda child: (ranks.get(topology_rows[child]["kind"], 9), child[1]))
        total = len(child_keys) + len(tunnels)
        for index, child in enumerate(child_keys, 1):
            last = index == total
            emit(child, prefix + ("└─ " if last else "├─ "))
        for index, tunnel in enumerate(tunnels, len(child_keys) + 1):
            rendered.append({"display_name": f"{prefix}{'└─ ' if index == total else '├─ '}◈ {tunnel}", "name": tunnel,
                             "kind": "vpn", "parent": key[1], "zone": None, "status": "EXTRACTED", "review": [], "scope": row.get("scope")})

    for key in sorted(topology_rows, key=lambda value: (ranks.get(topology_rows[value]["kind"], 9), value[1])):
        if not topology_rows[key]["parent"] or (key[0], topology_rows[key]["parent"]) not in topology_rows:
            emit(key)
    for key in topology_rows:
        emit(key)
    interface_rows = rendered
    topology_by_key = {
        (item.scope, item.interface): item
        for item in analysis.derived.interface_topology
    }
    vpn_tunnels = []
    for item in config.ipsec_tunnels:
        topology = topology_by_key.get((_scope_id(item.scope), item.tunnel_interface))
        vpn_tunnels.append({
            **source_row(item),
            "name": item.name,
            "interface": item.tunnel_interface,
            "ike_gateways": item.ike_gateways,
            "ipsec_crypto_profile": item.ipsec_crypto_profile,
            "topology_path": topology.path if topology else (),
            "review": review(item),
            **scope_fields(item),
        })
    routes = []
    for router in config.virtual_routers:
        for item in router.static_routes or ():
            routes.append({**source_row(item), "route_id": item.name, "destination": item.destination, "gateway": item.nexthop_ip_address or item.nexthop,
                           "device": item.interface, "distance": item.admin_distance, "status": "EXTRACTED",
                           "review": review(item), **scope_fields(router), "router_type": "virtual-router",
                           "router": router.name, "vrf": None})
    for router in config.logical_routers:
        for vrf in router.vrfs or ():
            for item in vrf.static_routes or ():
                routes.append({**source_row(item), "route_id": item.name, "destination": item.destination, "gateway": item.nexthop_ip_address or item.nexthop,
                               "device": item.interface, "distance": item.admin_distance, "status": "EXTRACTED",
                               "review": review(item), **scope_fields(router), "router_type": "logical-router",
                               "router": router.name, "vrf": vrf.name})
    validation_rows = [{"severity": item.severity, "domain": item.domain, "object_name": item.source_name,
                        "field": item.field, "message": item.message, **scope_fields(item.source_scope)}
                       for item in analysis.validation.issues]
    object_counts = {"interfaces": sum(row.get("kind") != "vpn" for row in interface_rows), "addresses": len(addresses), "address_groups": len(address_groups),
                     "services": len(services), "service_groups": len(service_groups), "policies": len(policies),
                     "nat": len(nat_rows), "routes": len(routes), "vulnerability_profiles": len(config.vulnerability_profiles),
                     "dhcp_servers": len(config.dhcp_servers), "sdwan_rules": len(config.sdwan_rules),
                     "administrators": len(config.administrators), "ike_gateways": len(config.ike_gateways),
                     "admin_roles": len(config.admin_roles), "ike_crypto_profiles": len(config.ike_crypto_profiles),
                     "ipsec_crypto_profiles": len(config.ipsec_crypto_profiles),
                     "ipsec_tunnels": len(config.ipsec_tunnels), "globalprotect_portals": len(config.globalprotect_portals),
                     "globalprotect_gateways": len(config.globalprotect_gateways),
                     "local_users": len(config.local_users), "local_user_groups": len(config.local_user_groups),
                     "group_mappings": len(config.group_mappings),
                     "sdwan_interface_profiles": len(config.sdwan_interface_profiles),
                     "sdwan_path_quality_profiles": len(config.sdwan_path_quality_profiles),
                     "sdwan_traffic_distribution_profiles": len(config.sdwan_traffic_distribution_profiles),
                     "sdwan_saas_quality_profiles": len(config.sdwan_saas_quality_profiles),
                     "sdwan_error_correction_profiles": len(config.sdwan_error_correction_profiles)}
    vdoms = sorted({scope.vsys for scope in config.scopes if scope.vsys})
    inventory_rows = [{"extraction_status": analysis.accounting.inventory_status(record),
                       "kind": record.kind, "source_path": record.source_path, "name": record.name,
                       "source_order": record.source_order, "values": record.values, **scope_fields(record)}
                      for record in records]
    coverage = [_jsonable(item) for item in analysis.accounting.coverage]
    source_only_count = sum(status == "SOURCE_ONLY" for status in analysis.accounting.record_statuses.values())
    unsupported_count = sum(status == "UNSUPPORTED" for status in analysis.accounting.record_statuses.values())
    return {
        "vendor": "palo_alto",
        "hostname": config.hostname,
        "source_version": config.source_version,
        "summary": {
            "objects": object_counts,
            "vdoms": vdoms,
            "scopes": vdoms,
            "scope_identities": list(analysis.derived.scope_identities),
            "scope_count": len(config.scopes),
            "records": len(records),
            "source_only_count": source_only_count,
            "unsupported_count": source_only_count + unsupported_count,
            "partial_count": sum(status == "PARTIAL" for status in analysis.accounting.record_statuses.values()),
            "interfaces": len(config.interfaces),
            "addresses": len(config.addresses) + len(config.address_groups),
            "services": len(config.services) + len(config.service_groups),
            "schedules": len(config.schedules),
            "policies": len(config.security_rules),
            "default_security_rules": len(config.default_security_rules),
            "nat_rules": len(config.nat_rules),
            "routes": len(analysis.derived.static_routes),
            "virtual_routers": len(config.virtual_routers),
            "logical_routers": len(config.logical_routers),
            "vulnerability_profiles": len(config.vulnerability_profiles),
            "dhcp_servers": len(config.dhcp_servers),
            "sdwan_rules": len(config.sdwan_rules),
            "administrators": len(config.administrators),
            "admin_roles": len(config.admin_roles),
            "ike_gateways": len(config.ike_gateways),
            "ike_crypto_profiles": len(config.ike_crypto_profiles),
            "ipsec_crypto_profiles": len(config.ipsec_crypto_profiles),
            "ipsec_tunnels": len(config.ipsec_tunnels),
            "globalprotect_portals": len(config.globalprotect_portals),
            "globalprotect_gateways": len(config.globalprotect_gateways),
            "local_users": len(config.local_users),
            "local_user_groups": len(config.local_user_groups),
            "group_mappings": len(config.group_mappings),
            "sdwan_interface_profiles": len(config.sdwan_interface_profiles),
            "sdwan_path_quality_profiles": len(config.sdwan_path_quality_profiles),
            "sdwan_traffic_distribution_profiles": len(config.sdwan_traffic_distribution_profiles),
            "sdwan_saas_quality_profiles": len(config.sdwan_saas_quality_profiles),
            "sdwan_error_correction_profiles": len(config.sdwan_error_correction_profiles),
            "unresolved_references": len(analysis.derived.unresolved_references),
            "relationship_issues": len(analysis.derived.relationship_issues),
            "validation_errors": len(analysis.validation.errors),
            "validation_warnings": len(analysis.validation.warnings),
            "validation": {
                "issue_count": len(analysis.validation.issues),
                "severity_counts": {
                    "error": len(analysis.validation.errors),
                    "warning": len(analysis.validation.warnings),
                },
            },
        },
        "scopes": [scope.model_dump() for scope in config.scopes],
        "scope_hierarchy": {
            "parents": list(analysis.derived.scope_hierarchy.parents),
            "ancestors": list(analysis.derived.scope_hierarchy.ancestors),
        },
        "extraction_coverage": coverage,
        "records_total": len(records),
        "records_returned": min(len(records), _PREVIEW_RECORD_LIMIT),
        "records_truncated": len(records) > _PREVIEW_RECORD_LIMIT,
        "records": [
            {
                "extraction_status": analysis.accounting.inventory_status(record),
                "kind": record.kind,
                "source_path": record.source_path,
                "name": record.name,
                "scope": record.scope.model_dump() if record.scope else None,
                "source_order": record.source_order,
                "values": record.values,
            }
            for record in records[:_PREVIEW_RECORD_LIMIT]
        ],
        "unresolved_references": [_jsonable(item) for item in analysis.derived.reference_resolutions if item.status != "RESOLVED"],
        "validation": [_jsonable(issue) for issue in analysis.validation.issues],
        "sections": {
            **{name: [source_row(item) for item in getattr(config, name)] for name in (
                "tags", "schedules", "zones", "security_profile_groups", "admin_roles",
                "dhcp_servers", "sdwan_rules", "administrators", "local_users", "local_user_groups",
                "group_mappings", "ike_gateways", "ike_crypto_profiles", "ipsec_crypto_profiles",
                "ipsec_tunnels", "globalprotect_portals", "globalprotect_gateways",
                "sdwan_interface_profiles", "sdwan_path_quality_profiles", "sdwan_traffic_distribution_profiles",
                "sdwan_saas_quality_profiles", "sdwan_error_correction_profiles",
            )},
            "default_security_rules": list(rule_rows(config.default_security_rules)),
            "extraction_coverage": coverage,
            "source_inventory": inventory_rows,
            "interfaces": interface_rows,
            "interface_topology": interface_rows,
            "addresses": addresses,
            "address_groups": address_groups,
            "services": services,
            "service_groups": service_groups,
            "policies": policies,
            "nat": nat_rows,
            "routes": routes,
            "vpn_tunnels": vpn_tunnels,
            "vpn_phase2": [{**proxy.model_dump(mode="json", exclude={"raw_extra", "explicit_fields"}),
                            "tunnel": tunnel.name, "additional_settings": proxy.raw_extra, **scope_fields(tunnel)}
                           for tunnel in config.ipsec_tunnels for proxy in tunnel.proxy_ids or ()],
            "validation": validation_rows,
            "unresolved_references": [_jsonable(item) for item in analysis.derived.unresolved_references],
            "vulnerability_profiles": [{**source_row(item), "rules": len(item.rules or ()),
                                         "exceptions": len(item.exceptions or ()),
                                         "rule_details": [rule.model_dump(mode="json") for rule in item.rules or ()],
                                         "exception_details": [rule.model_dump(mode="json") for rule in item.exceptions or ()]}
                                        for item in config.vulnerability_profiles],
        },
    }
