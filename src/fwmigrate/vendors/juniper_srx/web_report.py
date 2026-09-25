"""Junos source preview serialization."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any

from fwmigrate.extraction.sanitize import sanitize_source_attributes
from .validation import JuniperValidationIssueIndex


def _project(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="python")
    elif is_dataclass(value):
        value = asdict(value)
    if isinstance(value, dict):
        return sanitize_source_attributes({str(key): _project(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return [_project(item) for item in value]
    return value


def build_juniper_preview(result: Any) -> dict[str, Any]:
    config = result.config
    issue_index = JuniperValidationIssueIndex(result.validation.issues)
    scopes = [context.name if context.context_type == "root" else f"{context.context_type} {context.name}"
              for context in config.iter_contexts()]
    interfaces, addresses, address_groups, services, service_groups = [], [], [], [], []
    schedules, policies, nat, routes, vpn_tunnels = [], [], [], [], []
    for context in config.iter_contexts():
        scope = context.name if context.context_type == "root" else f"{context.context_type} {context.name}"
        zone_by_interface = {name: zone.name for zone in context.zones.values() for name in zone.interfaces}
        for interface in context.interfaces.values():
            unit_rows = [None, *interface.units.values()]
            for unit in unit_rows:
                name = interface.name if unit is None else f"{interface.name}.{unit.unit}"
                addresses_for_unit = list(getattr(unit, "addresses", ())) if unit else []
                interfaces.append({"name": name, "display_name": name, "kind": "logical" if unit else "physical",
                                   "ip": [item.address for item in addresses_for_unit],
                                   "zone": [zone_by_interface[name]] if name in zone_by_interface else [],
                                   "parent": interface.name if unit else interface.redundant_parent,
                                   "aggregate": interface.aggregate_parent, "physical_interfaces": [],
                                   "status": "EXTRACTED", "scope": scope,
                                   "provenance": _project(getattr(unit, "field_provenance", None) or interface.field_provenance)})
        for book in context.address_books.values():
            for item in book.addresses.values():
                addresses.append({"name": item.name, "value": item.prefix or item.fqdn or item.range_start,
                                  "type": item.type, "address_family": "IPv6" if ":" in (item.prefix or "") else "IPv4" if item.prefix else None,
                                  "associated_interface": item.zone, "scope": scope, "address_book": book.name,
                                  "provenance": _project(getattr(item, "provenance", None))})
            for item in book.address_sets.values():
                address_groups.append({"name": item.name, "members": [member.name for member in item.members],
                                       "address_family": None, "exclude_members": [], "scope": scope,
                                       "address_book": book.name, "zone": item.zone,
                                       "provenance": _project(getattr(item, "provenance", None))})
        for item in context.applications.values():
            for term in item.terms or (None,):
                services.append({"name": item.name, "protocol": term.protocol if term else None,
                                 "port": term.destination_ports if term else [], "source_port": term.source_ports if term else None,
                                 "scope": scope, "term": term.name if term else None,
                                 "provenance": _project(getattr(item, "provenance", None))})
        for item in context.application_sets.values():
            service_groups.append({"name": item.name, "members": item.applications, "scope": scope,
                                   "provenance": _project(getattr(item, "provenance", None))})
        schedules.extend({"name": item.name, "start_date": item.start_date, "stop_date": item.stop_date,
                          "daily": item.daily, "weekdays": item.weekdays, "exclusions": item.exclusions,
                          "scope": scope, "provenance": _project(getattr(item, "provenance", None))}
                         for item in context.schedulers.values())
        for index, item in enumerate((*context.policies, *context.global_policies), 1):
            policies.append({"policy_id": item.sequence or index, "name": item.name,
                             "source_interfaces": item.from_zones, "destination_interfaces": item.to_zones,
                             "source_addresses": item.source_addresses, "destination_addresses": item.destination_addresses,
                             "services": [*item.applications, *item.dynamic_applications], "schedule": item.scheduler_name,
                             "action": item.action, "nat": False, "policy_scope": item.policy_scope,
                             "scope": scope, "provenance": _project(getattr(item, "provenance", None))})
        for sets in (context.nat.source_rule_sets, context.nat.destination_rule_sets, context.nat.static_rule_sets):
            for rule_set in sets.values():
                for item in rule_set.rules:
                    nat.append({"policy_name": item.name, "translation_type": item.nat_type,
                                "translated_addresses": list(item.action.values()),
                                "source_addresses": item.match.source_addresses,
                                "destination_addresses": item.match.destination_addresses,
                                "egress_interfaces": list(rule_set.from_context.interfaces),
                                "scope": scope, "rule_set": rule_set.name,
                                "routing_instance": ", ".join(rule_set.from_context.routing_instances),
                                "provenance": _project(getattr(item, "provenance", None))})
        for item in context.routes:
            for hop in item.next_hops or (None,):
                routes.append({"route_id": item.destination, "destination": item.destination,
                               "gateway": hop.value if hop else item.next_table,
                               "device": None, "distance": item.preference, "status": "INACTIVE" if item.disabled else "EXTRACTED",
                               "routing_instance": item.routing_instance, "scope": scope,
                               "provenance": _project(getattr(item, "provenance", None))})
        for item in context.vpn.ipsec_vpns.values():
            vpn_tunnels.append({"kind": "IPsec VPN", "name": item.name,
                                "attachment": item.bind_interface, "peer": item.ike_gateway,
                                "crypto": item.ipsec_policy,
                                "topology": {"traffic_selectors": _project(item.traffic_selectors),
                                             "establish_tunnels": item.establish_tunnels},
                                "scope": scope, "provenance": _project(getattr(item, "provenance", None))})
    validation_rows = [{"severity": issue.severity, "domain": issue.category,
                        "object_name": issue.object_name, "field": issue.field,
                        "message": issue.message, "scope": issue.context,
                        "reference": issue.reference, "expected_type": issue.expected_type,
                        "status": issue.code}
                       for issue in result.validation.issues]
    sections = {"interfaces": interfaces, "interface_topology": interfaces,
                "addresses": addresses, "address_groups": address_groups,
                "services": services, "service_groups": service_groups,
                "schedules": schedules, "policies": policies, "nat": nat,
                "routes": routes, "vpn_tunnels": vpn_tunnels, "vpn_phase2": [],
                "validation": validation_rows,
                "unresolved_references": [row for row in validation_rows if row.get("reference")]}
    return {
        "vendor": "juniper_srx",
        "hostname": config.hostname,
        "source_format": result.source_format,
        "summary": {"contexts": len(config.contexts), "groups": len(config.configuration_groups),
                     "unsupported": len(config.unsupported_commands),
                     "source_sections": len(result.source_sections),
                     "extracted_sections": sum(item.status.value == "EXTRACTED" for item in result.source_sections),
                     "partial_sections": sum(item.status.value == "PARTIAL" for item in result.source_sections),
                     "source_only_sections": sum(item.status.value == "SOURCE_ONLY" for item in result.source_sections),
                     "unsupported_sections": sum(item.status.value == "UNSUPPORTED" for item in result.source_sections),
                     "parse_error_sections": sum(item.status.value == "PARSE_ERROR" for item in result.source_sections),
                     "validation_errors": len(result.validation.errors),
                     "validation_warnings": len(result.validation.warnings),
                     "interfaces": len(result.derived.interface_topology),
                     "policies": len(result.derived.policies), "nat_rule_sets": len(result.derived.nat_rule_sets),
                     "dhcp_objects": len(result.derived.dhcp), "apbr_objects": len(result.derived.apbr),
                     "remote_access_objects": len(result.derived.remote_access),
                     "objects": {"interfaces": len(interfaces), "addresses": len(addresses),
                                 "address_groups": len(address_groups), "services": len(services),
                                 "service_groups": len(service_groups), "policies": len(policies),
                                 "nat": len(nat), "routes": len(routes)},
                     "validation": {"issue_count": len(validation_rows),
                                    "severity_counts": {"error": sum(row["severity"] == "error" for row in validation_rows),
                                                        "warning": sum(row["severity"] == "warning" for row in validation_rows)}},
                     "scopes": scopes},
        "contexts": [{"name": item.name, "type": item.context_type} for item in config.iter_contexts()],
        "source": {"hostname": config.hostname, "version": config.version, "time_zone": config.time_zone},
        "source_sections": _project(result.source_sections),
        "inventory": _project(result.inventory_items),
        "unsupported": _project(result.unsupported_items),
        "review_required": _project(result.review_required),
        "extraction_coverage": _project(result.source_sections),
        "relationships": _project({"interfaces": result.derived.interface_topology,
                           "zones": result.derived.zone_memberships,
                           "routing_instances": result.derived.routing_instances,
                           "policies": result.derived.policies,
                           "nat": result.derived.nat_rule_sets,
                           "vpn": result.derived.vpn_relationships,
                           "dhcp": result.derived.dhcp,
                           "access_profiles": result.derived.access_profiles,
                           "firewall_users": result.derived.firewall_users,
                           "apbr": result.derived.apbr,
                           "remote_access": result.derived.remote_access,
                           "interface_topology": result.derived.interface_topology,
                           "policy_relationships": result.derived.policy_relationships,
                           "nat_usage": result.derived.nat_usage,
                           "nat_pool_usage": result.derived.nat_pool_usage,
                           "vpn_graph": result.derived.vpn_graph,
                           "secure_connect_graph": result.derived.secure_connect_graph,
                           "apbr_graph": result.derived.apbr_graph,
                           "inheritance": result.derived.inheritance,
                           "inheritance_view": result.derived.inheritance_view,
                           "activation_directives": result.derived.activation_directives}),
        "validation": _project(result.validation.issues),
        "semantic_validation": _project(tuple(issue for issue in result.validation.issues
                                               if issue.category != "extraction-coverage")),
        "extraction_review": _project(tuple(issue for issue in result.validation.issues
                                             if issue.category == "extraction-coverage")),
        "validation_summary": {"errors": len(result.validation.errors),
                               "warnings": len(result.validation.warnings)},
        "validation_by_context": {context: _project(issues)
                                  for context, issues in sorted(issue_index.by_context.items())},
        "sections": sections,
    }


__all__ = ["build_juniper_preview"]
