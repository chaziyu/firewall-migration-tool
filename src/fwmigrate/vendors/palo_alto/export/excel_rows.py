from __future__ import annotations

from typing import Any, Iterable

from ..source_report import PaloAltoSourceResult


def _text(value: Any) -> Any:
    if isinstance(value, (list, tuple, set)):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return "; ".join(f"{key}: {value[key]}" for key in value)
    return value


def _scope(item: Any) -> tuple[Any, Any]:
    scope = getattr(item, "scope", None)
    return getattr(scope, "kind", None), getattr(scope, "name", None)


def _field(item: Any, header: str) -> Any:
    aliases = {
        "Name": "name", "Description": "description", "Tags": "tags", "Members": "members",
        "Static Members": "static_members", "Dynamic Filter": "dynamic_filter", "Value": "ip_netmask",
        "Destination Port": "tcp.port", "Source Port": "tcp.source_port", "From Zones": "from_zones",
        "To Zones": "to_zones", "Source Addresses": "source", "Destination Addresses": "destination",
        "Source Users": "source_user", "Applications": "application", "Services": "service",
        "Categories": "category", "Schedule": "schedule", "Action": "action", "Disabled": "disabled",
        "Rule Type": "rule_type", "Rule Order": "source_order", "Source Negate": "negate_source",
        "Destination Negate": "negate_destination", "Source HIP": "source_hip", "Destination HIP": "destination_hip",
        "ICMP Unreachable": "icmp_unreachable", "Disable Inspect": "disable_inspect", "Group Tag": "group_tag",
        "Log Setting": "log_setting", "Log Start": "log_start", "Log End": "log_end", "NAT Type": "nat_type",
        "To Interface": "to_interface", "Interface Type": "interface_family", "Parent Interface": "parent",
        "Unit / Subinterface": "name", "SD-WAN Enabled": "sdwan_enabled", "IPv6 SD-WAN Enabled": "ipv6_sdwan_enabled",
        "SD-WAN Interface Profile": "sdwan_interface_profile", "Upstream NAT": "upstream_nat", "Network Type": "network_type",
        "Address Family": "address_family", "Destination": "destination", "Next Hop Type": "nexthop_type",
        "Next Hop": "nexthop", "Admin Distance": "admin_distance", "Metric": "metric", "Route Table": "route_table",
        "BFD Profile": "bfd_profile",
    }
    path = aliases.get(header)
    if path is None:
        return None
    value = item
    for part in path.split("."):
        value = getattr(value, part, None) if value is not None else None
    return _text(value)


def _row(item: Any, headers: Iterable[str], result: PaloAltoSourceResult) -> list[Any]:
    reasons = [issue.message for issue in result.validation.issues if issue.source_name == getattr(item, "name", None)]
    scope_type, scope_name = _scope(item)
    row = []
    for header in headers:
        if header == "Scope Type": value = scope_type
        elif header == "Scope Name": value = scope_name
        elif header == "Analysis Status": value = "REVIEW_REQUIRED" if reasons else "EXTRACTED"
        elif header == "Review Reasons": value = reasons
        elif header == "Source Explicit Fields": value = sorted(getattr(item, "explicit_fields", ()))
        elif header == "Additional Settings": value = _text(getattr(item, "raw_extra", {}))
        else: value = _field(item, header)
        row.append(value)
    return row


def rows_for(items: Iterable[Any], headers: tuple[str, ...], result: PaloAltoSourceResult) -> list[list[Any]]:
    return [_row(item, headers, result) for item in items]


def domain_items(result: PaloAltoSourceResult) -> dict[str, list[Any]]:
    config = result.config
    return {
        "Tags": config.tags, "Addresses": config.addresses, "Address Groups": config.address_groups,
        "Services": config.services, "Service Groups": config.service_groups, "Schedules": config.schedules,
        "Security Policies": [*config.security_rules, *config.default_security_rules], "NAT Rules": config.nat_rules,
        "Interfaces": [*config.interfaces, *config.interface_units], "Zones": config.zones,
        "Virtual Router Routes": [route for router in config.virtual_routers for route in (router.static_routes or [])],
        "Logical Router Routes": [route for router in config.logical_routers for vrf in (router.vrfs or []) for route in (vrf.static_routes or [])],
        "Vulnerability Profiles": config.vulnerability_profiles, "Security Profile Groups": config.security_profile_groups,
        "DHCP Servers": config.dhcp_servers, "SD-WAN Interface Profiles": config.sdwan_interface_profiles,
        "SD-WAN Path Quality": config.sdwan_path_quality_profiles, "SD-WAN Traffic Distribution": config.sdwan_traffic_distribution_profiles,
        "SD-WAN SaaS Quality": config.sdwan_saas_quality_profiles, "SD-WAN Error Correction": config.sdwan_error_correction_profiles,
        "SD-WAN Rules": config.sdwan_rules, "Local Users": config.local_users, "Local User Groups": config.local_user_groups,
        "Group Mappings": config.group_mappings, "Administrators": config.administrators, "Admin Roles": config.admin_roles,
        "IKE Gateways": config.ike_gateways, "IKE Crypto Profiles": config.ike_crypto_profiles,
        "IPsec Crypto Profiles": config.ipsec_crypto_profiles, "IPsec Tunnels": config.ipsec_tunnels,
        "GlobalProtect Portals": config.globalprotect_portals, "GlobalProtect Gateways": config.globalprotect_gateways,
    }
