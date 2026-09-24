"""Cisco ASA source validation."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Any

from .derived import ASADerivedViews
from .relationships.references import ASAReferenceKind


@dataclass(frozen=True)
class ASAValidationIssue:
    severity: str
    category: str
    message: str
    source_context: str | None = None
    source_object: str | None = None


@dataclass(frozen=True)
class ASAValidationResult:
    issues: tuple[ASAValidationIssue, ...] = ()

    @property
    def errors(self) -> tuple[ASAValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "error")

    @property
    def warnings(self) -> tuple[ASAValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "warning")


def validate_asa_config(config: Any, derived: ASADerivedViews) -> ASAValidationResult:
    issues = [ASAValidationIssue(
        severity="error" if not item.resolved else "warning",
        category=item.reference_type,
        message=item.reason,
        source_context=item.source_context,
        source_object=item.source_object,
    ) for item in derived.relationship_issues if not item.resolved]
    issues.extend(ASAValidationIssue(
        severity="error",
        category="parse",
        message=item.reason,
        source_object=item.object_name,
    ) for item in config.diagnostics)
    issues.extend(ASAValidationIssue(
        severity="warning",
        category="unsupported",
        message=item["reason"],
        source_object=f"line {item.get('line_number', '')}".strip(),
    ) for item in config.unsupported_commands)
    issues.extend(ASAValidationIssue("warning", item.category, item.message,
                                     item.source_context, item.source_object)
                  for item in derived.transform_issues)
    for server in getattr(config, "dhcp_servers", ()):
        if (server.pool or server.enabled) and not server.interface:
            issues.append(ASAValidationIssue("warning", "dhcp", "DHCP server configuration has no explicit interface", server.source_context, server.name))
    pool_owners = {}
    for server in getattr(config, "dhcp_servers", ()):
        if server.pool and server.interface:
            key = (server.source_context, server.pool)
            pool_owners.setdefault(key, set()).add(server.interface)
    for (context, pool), interfaces in pool_owners.items():
        if len(interfaces) > 1:
            issues.append(ASAValidationIssue("warning", "dhcp", f"DHCP pool {pool} is assigned to multiple interfaces", context, pool))
    for interface in getattr(config, "interfaces", ()):
        for monitor in getattr(interface, "policy_route_path_monitors", ()):
            if monitor.mode == "peer":
                try:
                    ipaddress.ip_address(monitor.peer or "")
                except ValueError:
                    issues.append(ASAValidationIssue("warning", "policy-routing", "Path-monitor peer is not a valid IP address", interface.source_context, interface.name))
    for privilege in getattr(config, "command_privileges", ()):
        if not 0 <= privilege.privilege_level <= 15:
            issues.append(ASAValidationIssue("warning", "authorization", "Command privilege level must be between 0 and 15", privilege.source_context, privilege.name))
    for user in getattr(config, "local_users", ()):
        if user.privilege is not None and not 0 <= user.privilege <= 15:
            issues.append(ASAValidationIssue("warning", "authorization", "Username privilege level must be between 0 and 15", user.source_context, user.name))
    for binding in derived.acl_relationships.bindings:
        if binding.resolved_acl is not None and not binding.rules:
            issues.append(ASAValidationIssue("warning", "acl", "Bound ACL has no functional ACEs", binding.source_context, binding.acl_name))

    for context in derived.references.contexts:
        families = derived.references.group_address_families(context)
        for rule in getattr(config, "nat_rules", ()):
            if rule.source_context != context:
                continue
            for field in ("real_source", "mapped_source", "real_destination", "mapped_destination", "pat_pool"):
                name = getattr(rule, field, None)
                if name and families.get(name) == "mixed":
                    issues.append(ASAValidationIssue("error", "nat", f"Mixed IPv4/IPv6 network group {name} is used for NAT", context, rule.name))
            if rule.syntax_family == "object" and not rule.owning_object:
                issues.append(ASAValidationIssue("error", "nat", "Object NAT has no owning network object", context, rule.name))

    for rule in getattr(config, "nat_rules", ()):
        if not rule.service_operand_1 or not rule.service_operand_2:
            continue
        relationship = next((item for item in derived.nat_relationships.rules if item.rule is rule), None)
        first = getattr(relationship, "service_operand_1", None)
        second = getattr(relationship, "service_operand_2", None)
        protocols = []
        for service in (first, second):
            if service is None:
                continue
            values = {str(getattr(port, "protocol", "")).lower() for port in getattr(service, "ports", ()) if getattr(port, "protocol", None)}
            if not values and getattr(service, "protocol", None):
                values.add(str(service.protocol).lower())
            if len(values) == 1:
                protocols.append(next(iter(values)))
        if len(protocols) == 2 and protocols[0] != protocols[1]:
            issues.append(ASAValidationIssue("warning", "nat", "Twice NAT service operands use different protocols", rule.source_context, rule.name))

    zone_members: dict[tuple[str | None, str], set[str]] = {}
    for zone in getattr(config, "traffic_zones", ()):
        if len(zone.members) > 8:
            issues.append(ASAValidationIssue("error", "zone", "Traffic zone exceeds the eight-interface limit", zone.source_context, zone.name))
        levels = set()
        for member in zone.members:
            reference = derived.references.resolve(zone.source_context, ASAReferenceKind.INTERFACE, member)
            interface = reference.target
            if interface is not None:
                zone_members.setdefault((zone.source_context, interface.name.casefold()), set()).add(zone.name)
                if interface.security_level is not None:
                    levels.add(interface.security_level)
                if interface.management_only or interface.channel_group is not None:
                    issues.append(ASAValidationIssue("error", "zone", "Traffic zone contains an unsupported interface member", zone.source_context, zone.name))
        if len(levels) > 1:
            issues.append(ASAValidationIssue("error", "zone", "Traffic zone members have different security levels", zone.source_context, zone.name))
    for interface in getattr(config, "interfaces", ()):
        for zone_name in interface.traffic_zone_members:
            zone_members.setdefault((interface.source_context, interface.name.casefold()), set()).add(zone_name)
    for (context, interface), zones in zone_members.items():
        if len(zones) > 1:
            issues.append(ASAValidationIssue("error", "zone", "Interface belongs to more than one traffic zone", context, interface))

    for interface in getattr(config, "interfaces", ()):
        if interface.interface_type == "tunnel" and not interface.ipsec_profile:
            issues.append(ASAValidationIssue("warning", "vpn", "VTI has no explicitly configured IPsec profile", interface.source_context, interface.name))
    for profile in getattr(config, "ipsec_profiles", ()):
        if not profile.ikev1_transform_sets and not profile.ikev2_ipsec_proposals:
            issues.append(ASAValidationIssue("warning", "vpn", "IPsec profile has no transform set or proposal", profile.source_context, profile.name))
    for crypto in getattr(config, "crypto_maps", ()):
        if crypto.sequence is None:
            continue
        if not crypto.acl_name:
            issues.append(ASAValidationIssue("warning", "vpn", "Crypto map entry has no ACL reference", crypto.source_context, crypto.name))
        if not crypto.transform_sets and not crypto.ikev2_proposals:
            issues.append(ASAValidationIssue("warning", "vpn", "Crypto map entry has no transform set or proposal", crypto.source_context, crypto.name))

    for policy in getattr(config, "group_policies", ()):
        seen = {policy.name}
        parent = policy.parent
        while parent:
            if parent in seen:
                issues.append(ASAValidationIssue("error", "vpn", "Group-policy inheritance cycle", policy.source_context, policy.name))
                break
            seen.add(parent)
            parent_policy = next((item for item in config.group_policies
                                  if item.source_context == policy.source_context and item.name == parent), None)
            if parent_policy is None:
                break
            parent = parent_policy.parent
    return ASAValidationResult(tuple(issues))


__all__ = ["ASAValidationIssue", "ASAValidationResult", "validate_asa_config"]

