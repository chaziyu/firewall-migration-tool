from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import Any

from ..model.source import PANOSConfig
from ..source_model import PANOSDerivedViews, pan_scope_identity
from .models import PANOSValidationIssue, PANOSValidationResult

_PORT = re.compile(r"^(\d+)(?:\s*-\s*(\d+))?$")


def _issue(issues, severity, domain, message, item=None, field=None, *, scope=None, object_type=None, source_name=None):
    scope = scope or getattr(item, "scope", None)
    issues.append(PANOSValidationIssue(severity, domain, message,
        getattr(item, "source_path", None), source_name if source_name is not None else getattr(item, "name", None), field,
        scope, pan_scope_identity(scope) if scope else None, object_type or domain))


def _scope_key(item: Any) -> str:
    scope = getattr(item, "scope", None)
    return scope.model_dump_json() if scope else "<unscoped>"


def _validate_ip(value: str, *, ranges: bool = True) -> bool:
    if ranges and "-" in value:
        parts = [part.strip() for part in value.split("-")]
        if len(parts) != 2:
            return False
        try:
            start, end = (ipaddress.ip_address(part) for part in parts)
        except ValueError:
            return False
        return start.version == end.version and start <= end
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


def _validate_ports(value: str) -> bool:
    parts = [part.strip() for part in value.split(",")]
    if not parts or any(not part for part in parts):
        return False
    for part in parts:
        match = _PORT.fullmatch(part)
        if not match:
            return False
        start, end = int(match.group(1)), int(match.group(2) or match.group(1))
        if not 1 <= start <= 65535 or not 1 <= end <= 65535 or start > end:
            return False
    return True


def validate_panos_config(config: PANOSConfig, derived: PANOSDerivedViews) -> PANOSValidationResult:
    issues: list[PANOSValidationIssue] = []
    if not config.source_inventory:
        _issue(issues, "warning", "source", "PAN-OS XML contains no entry records.")
    if not config.scopes:
        _issue(issues, "warning", "scope", "PAN-OS XML contains no explicit device, VSYS, or device-group scope.")

    families = {
        "address": config.addresses, "address-group": config.address_groups,
        "service": config.services, "service-group": config.service_groups,
        "schedule": config.schedules, "zone": config.zones,
        "vulnerability-profile": config.vulnerability_profiles, "security-profile-group": config.security_profile_groups,
        "dhcp-server": config.dhcp_servers, "sdwan-interface-profile": config.sdwan_interface_profiles,
        "sdwan-path-quality-profile": config.sdwan_path_quality_profiles,
        "sdwan-traffic-distribution-profile": config.sdwan_traffic_distribution_profiles,
        "sdwan-saas-quality-profile": config.sdwan_saas_quality_profiles,
        "sdwan-error-correction-profile": config.sdwan_error_correction_profiles,
        "sdwan-rule": config.sdwan_rules, "administrator": config.administrators, "admin-role": config.admin_roles,
        "ike-gateway": config.ike_gateways, "ike-crypto-profile": config.ike_crypto_profiles,
        "ipsec-crypto-profile": config.ipsec_crypto_profiles, "ipsec-tunnel": config.ipsec_tunnels,
        "globalprotect-portal": config.globalprotect_portals, "globalprotect-gateway": config.globalprotect_gateways,
    }
    for family, items in families.items():
        seen: dict[tuple[str, str | None], Any] = {}
        for item in items:
            key = (_scope_key(item), getattr(item, "name", None))
            if key[1] and key in seen:
                _issue(issues, "error", "identity", f"duplicate {family} name {key[1]!r} in the same scope", item, "name", object_type=family)
            elif key[1]:
                seen[key] = item

    for name, rules in _by_name(config.security_rules).items():
        scopes = {_scope_key(rule) for rule in rules}
        if len(rules) > len(scopes):
            _issue(issues, "error", "identity", f"duplicate security rule name {name!r} in the same scope", rules[-1], "name", object_type="policy")

    for message in getattr(derived.scope_hierarchy, "issues", ()):
        _issue(issues, "error", "scope", message)
    for item in derived.reference_resolutions:
        if item.status in {"UNRESOLVED", "AMBIGUOUS"}:
            _issue(issues, "error" if item.status == "UNRESOLVED" else "warning", "reference",
                   f"{item.status.lower()} PAN-OS reference {item.reference_name!r} in {item.owner_name or '<unnamed>'}.{item.owner_field}",
                   field=item.owner_field, scope=item.source_scope, source_name=item.owner_name, object_type=item.owner_family or "reference")
    for item in derived.relationship_issues:
        _issue(issues, "warning", "relationship", item.message, field=item.field,
               scope=item.source_scope, source_name=item.source_name, object_type=item.category)

    for address in config.addresses:
        for field in ("ip_netmask", "ip_range", "ip_wildcard"):
            value = getattr(address, field)
            if value is not None and field in address.explicit_fields and not _validate_ip(value):
                _issue(issues, "error", "address", f"malformed {field}: {value!r}", address, field)
    for item in (*config.interfaces, *config.interface_units):
        for value in getattr(item, "ipv4_addresses", ()) or ():
            if not _validate_ip(value.split("/")[0], ranges=False):
                _issue(issues, "error", "interface", f"malformed IPv4 address: {value!r}", item, "ipv4_addresses")
        for value in getattr(item, "ipv6_addresses", ()) or ():
            text = value if isinstance(value, str) else getattr(value, "address", None)
            if text and not _validate_ip(text.split("/")[0], ranges=False):
                _issue(issues, "error", "interface", f"malformed IPv6 address: {text!r}", item, "ipv6_addresses")
    for route in config.static_routes:
        if route.destination and not _validate_ip(route.destination):
            _issue(issues, "error", "route", f"malformed route destination: {route.destination!r}", route, "destination")
        if route.nexthop_ip_address and not _validate_ip(route.nexthop_ip_address, ranges=False):
            _issue(issues, "error", "route", f"malformed next-hop IP: {route.nexthop_ip_address!r}", route, "nexthop_ip_address")

    for service in config.services:
        for protocol in (service.tcp, service.udp):
            if protocol and protocol.port and not _validate_ports(protocol.port):
                _issue(issues, "error", "service", f"malformed port expression: {protocol.port!r}", service, "port")
            if protocol and protocol.source_port and not _validate_ports(protocol.source_port):
                _issue(issues, "error", "service", f"malformed source port expression: {protocol.source_port!r}", service, "source_port")

    for rule in config.security_rules:
        explicit = rule.explicit_fields
        for field in ("action", "source", "destination", "from_zones", "to_zones"):
            if field not in explicit:
                _issue(issues, "error", "policy", f"security rule is missing explicitly configured field {field!r}", rule, field)
    for rule in config.nat_rules:
        for translation in (rule.destination_translation, rule.dynamic_destination_translation):
            port = getattr(translation, "translated_port", None) if translation else None
            if port and not _validate_ports(port):
                _issue(issues, "error", "nat", f"malformed translated port: {port!r}", rule, "translated_port")
        if rule.disabled in {"yes", "true"} and not rule.source_translation and not rule.destination_translation:
            continue
        if rule.source_translation is None and rule.destination_translation is None and rule.dynamic_destination_translation is None:
            _issue(issues, "warning", "nat", "NAT rule has no explicit translation branch", rule, "translation")
    return PANOSValidationResult(tuple(issues))


def _by_name(items):
    grouped = defaultdict(list)
    for item in items:
        if getattr(item, "name", None):
            grouped[item.name].append(item)
    return grouped
