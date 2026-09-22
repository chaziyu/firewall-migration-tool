from __future__ import annotations

from dataclasses import asdict, is_dataclass
from collections import defaultdict
from typing import Any

from .source_model import PANScope, pan_scope_identity
from .source_report import PaloAltoSourceResult


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
    reviews: dict[str | None, list[str]] = defaultdict(list)
    for issue in analysis.validation.issues:
        reviews[issue.source_name].append(issue.message)

    def vdom(item: Any) -> str | None:
        scope = getattr(item, "scope", None)
        return scope.vsys if scope else None

    def review(item: Any) -> list[str]:
        return reviews.get(getattr(item, "name", None), [])

    addresses = [
        {
            "name": item.name,
            "value": item.ip_netmask or item.ip_range or item.ip_wildcard or item.fqdn,
            "type": next((field for field in ("ip_netmask", "ip_range", "ip_wildcard", "fqdn") if getattr(item, field)), None),
            "address_family": "IPv6" if ":" in (item.ip_netmask or item.ip_range or item.ip_wildcard or "") else "IPv4" if item.ip_netmask or item.ip_range or item.ip_wildcard else None,
            "associated_interface": None,
            "review": review(item),
            "vdom": vdom(item),
        }
        for item in config.addresses
    ]
    address_groups = [{"name": item.name, "members": item.static_members, "address_family": None, "exclude_members": [], "review": review(item), "vdom": vdom(item)} for item in config.address_groups]
    services = []
    for item in config.services:
        protocol = item.tcp or item.udp
        services.append({"name": item.name, "protocol": "tcp" if item.tcp else "udp" if item.udp else None,
                         "port": protocol.port if protocol else None, "source_port": protocol.source_port if protocol else None,
                         "generated": False, "review": review(item), "vdom": vdom(item)})
    service_groups = [{"name": item.name, "members": item.members, "generated": False, "review": review(item), "vdom": vdom(item)} for item in config.service_groups]
    policies = [{"policy_id": item.source_order, "name": item.name, "source_interfaces": item.from_zones,
                 "destination_interfaces": item.to_zones, "services": item.service, "action": item.action,
                 "nat": False, "review": review(item), "vdom": vdom(item)} for item in config.security_rules]
    nat_rows = [{"policy_id": item.source_order, "policy_name": item.name, "translation_type": item.nat_type,
                 "translated_addresses": getattr(item.source_translation, "translated_addresses", None) or [getattr(item.source_translation, "translated_address", None)] if item.source_translation else [],
                 "egress_interfaces": [item.to_interface] if item.to_interface else item.to_zones,
                 "review": review(item), "vdom": vdom(item)} for item in config.nat_rules]
    interface_by_key = {
        (_scope_id(item.scope), item.name): item
        for item in [*config.interfaces, *config.interface_units]
        if item.name
    }
    interface_rows = []
    for item in analysis.derived.interface_topology:
        source = interface_by_key.get((item.scope, item.interface))
        interface_rows.append({"name": item.interface, "display_name": item.interface, "kind": item.kind,
                               "ip": getattr(source, "ipv4_addresses", None), "role": item.zones, "parent": item.parent,
                               "aggregate": item.aggregate, "physical_interfaces": item.physical_interfaces,
                               "status": "EXTRACTED", "review": item.issues,
                               "vdom": item.imported_vsys[0] if item.imported_vsys else vdom(source), "_scope": item.scope,
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
                             "kind": "vpn", "parent": key[1], "role": None, "status": "EXTRACTED", "review": [], "vdom": row.get("vdom")})

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
            "name": item.name,
            "interface": item.tunnel_interface,
            "ike_gateways": item.ike_gateways,
            "ipsec_crypto_profile": item.ipsec_crypto_profile,
            "topology_path": topology.path if topology else (),
            "review": review(item),
            "vdom": vdom(item),
        })
    routes = []
    for router in config.virtual_routers:
        for item in router.static_routes or ():
            routes.append({"route_id": item.name, "destination": item.destination, "gateway": item.nexthop_ip_address or item.nexthop,
                           "device": item.interface, "distance": item.admin_distance, "status": "EXTRACTED",
                           "review": review(item), "vdom": vdom(router)})
    validation_rows = [{"severity": item.severity, "domain": item.domain, "object_name": item.source_name,
                        "field": item.field, "message": item.message, "vdom": item.source_scope.vsys if item.source_scope else None}
                       for item in analysis.validation.issues]
    object_counts = {"interfaces": sum(row.get("kind") != "vpn" for row in interface_rows), "addresses": len(addresses), "address_groups": len(address_groups),
                     "services": len(services), "service_groups": len(service_groups), "policies": len(policies),
                     "nat": len(nat_rows), "routes": len(routes)}
    vdoms = sorted({scope.vsys for scope in config.scopes if scope.vsys})
    return {
        "vendor": "palo_alto",
        "hostname": config.hostname,
        "source_version": config.source_version,
        "summary": {
            "objects": object_counts,
            "vdoms": vdoms,
            "scopes": len(config.scopes),
            "records": len(records),
            "interfaces": len(config.interfaces),
            "addresses": len(config.addresses) + len(config.address_groups),
            "services": len(config.services) + len(config.service_groups),
            "schedules": len(config.schedules),
            "policies": len(config.security_rules),
            "default_security_rules": len(config.default_security_rules),
            "nat_rules": len(config.nat_rules),
            "routes": len(config.static_routes),
            "virtual_routers": len(config.virtual_routers),
            "logical_routers": len(config.logical_routers),
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
        "records": [
            {
                "kind": record.kind,
                "source_path": record.source_path,
                "name": record.name,
                "scope": record.scope.model_dump() if record.scope else None,
                "source_order": record.source_order,
                "values": record.values,
            }
            for record in records[:200]
        ],
        "unresolved_references": [_jsonable(item) for item in analysis.derived.reference_resolutions if item.status != "RESOLVED"],
        "validation": [_jsonable(issue) for issue in analysis.validation.issues],
        "sections": {
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
            "vpn_phase2": [],
            "validation": validation_rows,
            "unresolved_references": [_jsonable(item) for item in analysis.derived.unresolved_references],
        },
    }
