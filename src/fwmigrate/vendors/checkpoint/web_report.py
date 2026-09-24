"""Explicit, secret-safe Check Point presentation projection."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any

from fwmigrate.extraction.sanitize import sanitize_source_attributes
from .export.excel_schema import SOURCE_SHEETS
from .source_report import CheckPointSourceResult


def _project(value: Any) -> Any:
    if isinstance(value, Enum): return value.value
    if hasattr(value, "model_dump"): value = value.model_dump(mode="python", by_alias=False)
    elif is_dataclass(value): value = asdict(value)
    if isinstance(value, dict): return sanitize_source_attributes({str(k): _project(v) for k, v in value.items()})
    if isinstance(value, (list, tuple, set)): return [_project(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None: return value
    return str(value)


def _refs(values):
    return [_project(v) for v in values or ()]


def build_checkpoint_preview(result: CheckPointSourceResult) -> dict[str, Any]:
    config, derived = result.config, result.derived
    source = {field: [_project(item) for item in getattr(config, field)] for field in SOURCE_SHEETS.values()}
    def ref_names(values):
        return [label for value in values or () if (label :=
                (value if isinstance(value, str) else getattr(value, "name", None) or getattr(value, "uid", None)))]

    nat = [{"source_kind": v.source_kind, "source_owner": v.owner_name or v.source_name,
            "translation_classification": v.translation_method, "original_source": _refs(v.original_source),
            "original_destination": _refs(v.original_destination), "translated_source": _refs(v.translated_source),
            "translated_destination": _refs(v.translated_destination), "issues": [_project(i) for i in v.issues]}
           for v in derived.nat.views]
    traversal = [{"package": e.package_name, "layer": e.layer_name, "section": e.section_name,
                  "rule": e.rule_name, "source_rule_order": e.rule_order,
                  "derived_traversal_position": e.traversal_position, "parent_rule": e.parent_rule_uid,
                  "inline_depth": e.inline_depth, "issues": [_project(i) for i in e.issues]}
                 for e in derived.policy_traversal.entries]
    interfaces = [{"device": v.device_name, "device_kind": v.device_kind, "interface": v.interface_name,
                  "resolved_zone": v.resolved_zone_name, "zone_assignment_source": v.zone_assignment_source,
                  "management_source_present": v.management_source_present, "gaia_source_present": v.gaia_source_present,
                  "issues": [_project(i) for i in v.issues]} for v in derived.interface_views.views]
    vpn = [{"community": v.community_name, "community_type": v.community_type,
            "gateways": _refs(v.member_gateways), "clusters": _refs(v.member_clusters),
            "interoperable_devices": _refs(v.member_interoperable_devices), "centers": _refs(v.center_members),
            "satellites": _refs(v.satellite_members), "vpn_domains": _refs(v.vpn_domains),
            "vtis": _refs(v.vtis), "route_based": v.route_based, "issues": [_project(i) for i in v.issues]}
           for v in derived.vpn_views.views]
    interfaces = [{"name": v.interface_name, "display_name": v.interface_name,
                   "kind": v.device_kind, "ip": [value for value in (v.explicit_ipv4, v.explicit_ipv6) if value],
                   "zone": [v.resolved_zone_name] if v.resolved_zone_name else [], "status": "EXTRACTED",
                   "scope": getattr(v.management_source or v.gaia_source, "domain", None), "device": v.device_name,
                   "zone_assignment_source": v.zone_assignment_source,
                   "management_source_present": v.management_source_present,
                   "gaia_source_present": v.gaia_source_present, "review": [_project(i) for i in v.issues]}
                  for v in derived.interface_views.views]
    addresses = []
    for field in ("hosts", "networks", "address_ranges", "dns_domains", "wildcard_addresses", "dynamic_addresses", "updatable_objects"):
        for item in getattr(config, field):
            address_family = ("IPv6" if getattr(item, "ipv6_address", None) or getattr(item, "subnet6", None)
                              else "IPv4" if any(getattr(item, key, None) for key in
                                  ("ip_address", "ipv4_address", "network", "subnet4", "ipv4_address_first"))
                              else None)
            addresses.append({"name": item.name, "value": next((getattr(item, key, None) for key in
                ("ip_address", "ipv4_address", "ipv6_address", "network", "subnet4", "subnet6", "fqdn", "domain_name", "wildcard")
                if getattr(item, key, None) is not None), None), "type": field,
                "address_family": address_family,
                "scope": item.domain, "review": []})
    address_groups = [{"name": item.name, "members": ref_names(item.members), "exclude_members": [],
                       "scope": item.domain} for item in config.groups]
    address_groups.extend({"name": item.name, "members": ref_names((item.include,)),
                           "exclude_members": ref_names((item.except_,)), "scope": item.domain}
                          for item in config.groups_with_exclusion)
    services = [{"name": item.name, "protocol": item.protocol or item.ip_protocol,
                 "port": item.port, "source_port": item.source_port, "scope": item.domain}
                for item in config.services]
    service_groups = [{"name": item.name, "members": ref_names(item.members), "scope": item.domain}
                      for item in config.service_groups]
    schedules = [{"name": item.name, "value": _project(item), "scope": item.domain}
                 for item in (*config.times, *config.time_groups)]
    policies = []
    for entry in derived.policy_traversal.entries:
        rule = entry.source_rule
        policies.append({"policy_id": entry.rule_order, "name": entry.rule_name,
                         "source_addresses": ref_names(rule.source), "destination_addresses": ref_names(rule.destination),
                         "services": ref_names((*rule.service, *rule.services_and_applications)),
                         "action": ref_names((rule.action,))[0] if rule.action is not None else None,
                         "source_order": entry.rule_order, "package": entry.package_name,
                         "layer": entry.layer_name, "section": entry.section_name,
                         "inline_layer": ref_names((rule.inline_layer,))[0] if rule.inline_layer is not None else None,
                         "inline_depth": entry.inline_depth, "traversal_position": entry.traversal_position,
                         "domain": entry.domain, "scope": entry.domain,
                         "review": [_project(i) for i in entry.issues]})
    routes = []
    for route in config.gaia_static_routes:
        for hop in route.next_hops or (None,):
            routes.append({"route_id": route.name, "destination": route.ipv4_destination or route.ipv6_destination,
                           "gateway": hop.gateway if hop else None, "device": hop.interface if hop else None,
                           "distance": hop.priority if hop else None, "status": "EXTRACTED" if route.enabled is not False else "DISABLED",
                           "address_family": route.address_family, "scope": route.domain,
                           "source_plane": route.source_plane})
    validation = [_project(item) for item in result.validation.issues]
    unresolved = [{"source_kind": getattr(item.source, "object_type", None),
                   "source_name": getattr(item.source, "name", None), "source_field": item.source_field,
                   "reference": item.reference, "status": item.status,
                   "expected_kinds": [kind.value for kind in item.expected_kinds], "scope": item.scope}
                  for item in derived.broken_references]
    scopes = sorted({item.domain for field in SOURCE_SHEETS.values() for item in getattr(config, field)
                     if getattr(item, "domain", None)} |
                    ({result.scope.selected_domain} if result.scope.selected_domain else set()))
    sections = {"interfaces": interfaces, "interface_topology": interfaces,
                "addresses": addresses, "address_groups": address_groups,
                "services": services, "service_groups": service_groups,
                "schedules": schedules, "policies": policies, "nat": nat,
                "routes": routes, "vpn_tunnels": vpn, "vpn_phase2": [],
                "validation": [{"severity": row.get("severity"), "domain": row.get("category"),
                                "object_name": row.get("object_name"), "field": row.get("field"),
                                "message": row.get("message"), "scope": row.get("scope")}
                               for row in validation],
                "unresolved_references": unresolved}
    return _project({
        "vendor": "checkpoint",
        "summary": {"source_objects": sum(len(getattr(config, field)) for field in SOURCE_SHEETS.values()),
                    "derived_views": len(nat) + len(traversal) + len(interfaces) + len(vpn),
                    "validation_findings": len(result.validation.issues),
                    "incomplete_collections": len(derived.collection_incomplete),
                    "unsupported_source_inventory": len(result.source_inventory),
                    "scope_ambiguous": bool(getattr(result.scope, "ambiguous", False)),
                    "capabilities": {"SD-WAN": "No direct R81.00 equivalent"},
                    "objects": {"interfaces": len(interfaces), "addresses": len(addresses),
                                "address_groups": len(address_groups), "services": len(services),
                                "service_groups": len(service_groups), "policies": len(policies),
                                "nat": len(nat), "routes": len(routes)},
                    "validation": {"issue_count": len(validation),
                                   "severity_counts": {"error": sum(item.severity == "error" for item in result.validation.issues),
                                                       "warning": sum(item.severity == "warning" for item in result.validation.issues)}},
                    "scopes": scopes},
        "collection": [_project(item) for item in result.collection],
        "scope": _project(result.scope), "source": source,
        "derived": {"nat": nat, "policy_traversal": traversal, "interfaces": interfaces, "vpn": vpn,
                    "unresolved_references": [_project(i) for i in derived.broken_references]},
        "validation": [_project(i) for i in result.validation.issues],
        "source_inventory": [_project(i) for i in result.source_inventory],
        "unsupported": {"inventory": [_project(i) for i in result.source_inventory],
                        "collections": [_project(i) for i in result.collection if not i.complete]},
        "source_metadata": _project(result.source_metadata),
        "sections": sections,
    })


__all__ = ["build_checkpoint_preview"]
