from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..schema_registry import registered_paths
from ..source_model import PANScope, pan_scope_identity
from ..source_report import PaloAltoSourceResult


def _scope_id(scope: PANScope | None) -> str:
    return pan_scope_identity(scope) if scope else "<unscoped>"


def _scope(scope: PANScope | None) -> tuple[str | None, str | None]:
    return (scope.kind, scope.name) if scope else (None, None)


def _text(value: Any) -> Any:
    if isinstance(value, dict):
        return "; ".join(f"{key}: {_text(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple, set)) or (hasattr(value, "__iter__") and not isinstance(value, (str, bytes))):
        return ", ".join(str(item) for item in value)
    return value


@dataclass(slots=True)
class _PANExcelContext:
    analysis: PaloAltoSourceResult
    source_name: str | None = None
    validation_by_object: dict[tuple[str, str, str | None], tuple[Any, ...]] = field(init=False)
    validation_by_scope: dict[str, tuple[Any, ...]] = field(init=False)

    def __post_init__(self) -> None:
        objects: dict[tuple[str, str, str | None], list[Any]] = defaultdict(list)
        scopes: dict[str, list[Any]] = defaultdict(list)
        for issue in self.analysis.validation.issues:
            scope = getattr(issue, "scope_identity", None) or "<unscoped>"
            objects[(scope, getattr(issue, "object_type", None) or issue.domain, issue.source_name)].append(issue)
            scopes[scope].append(issue)
        self.validation_by_object = {key: tuple(value) for key, value in objects.items()}
        self.validation_by_scope = {key: tuple(value) for key, value in scopes.items()}

    @property
    def config(self): return self.analysis.config

    @property
    def derived(self): return self.analysis.derived

    @property
    def validation(self): return self.analysis.validation

    def issues_for(self, item: Any, object_type: str) -> tuple[Any, ...]:
        return self.validation_by_object.get((_scope_id(getattr(item, "scope", None)), object_type, getattr(item, "name", None)), ())


def _base(context: _PANExcelContext, item: Any, object_type: str) -> dict[str, Any]:
    issues = context.issues_for(item, object_type)
    scope_type, scope_name = _scope(getattr(item, "scope", None))
    return {"Name": getattr(item, "name", None), "Scope Type": scope_type, "Scope Name": scope_name,
            "Analysis Status": "REVIEW_REQUIRED" if issues else "EXTRACTED",
            "Review Reasons": _text(issue.message for issue in issues),
            "Source Explicit Fields": _text(sorted(getattr(item, "explicit_fields", ()))),
            "Additional Settings": _text(getattr(item, "raw_extra", {})),
            "__review__": bool(issues), "__error__": any(issue.severity == "error" for issue in issues)}


def _simple_rows(context: _PANExcelContext, items: Iterable[Any], object_type: str, fields: dict[str, str]) -> list[dict[str, Any]]:
    rows = []
    for item in items:
        row = _base(context, item, object_type)
        row.update({header: _text(getattr(item, attribute, None)) for header, attribute in fields.items()})
        rows.append(row)
    return rows


def _object_rows(context: _PANExcelContext, items: Iterable[Any], object_type: str, fields: dict[str, str]) -> list[dict[str, Any]]:
    rows = []
    for item in items:
        row = _base(context, item, object_type)
        for header, attribute in fields.items():
            row[header] = _text(getattr(item, attribute, None))
        rows.append(row)
    return rows


def _child_rows(context: _PANExcelContext, parents: Iterable[Any], child_attr: str, object_type: str, fields: dict[str, str], parent_header: str = "Profile") -> list[dict[str, Any]]:
    rows = []
    for parent in parents:
        for child in getattr(parent, child_attr, None) or ():
            row = _base(context, parent, object_type)
            row[parent_header] = parent.name
            for header, attribute in fields.items():
                row[header] = _text(getattr(child, attribute, None))
            rows.append(row)
    return rows


def _vulnerability_profile_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for item in context.config.vulnerability_profiles:
        row = _base(context, item, "vulnerability-profile")
        row.update({"Rule Count": len(item.rules or ()), "Exception Count": len(item.exceptions or ())})
        rows.append(row)
    return rows


def _address_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for item in context.config.addresses:
        variants = [(name, getattr(item, name)) for name in ("ip_netmask", "ip_range", "ip_wildcard", "fqdn") if getattr(item, name) is not None]
        row = _base(context, item, "address")
        row.update({"Type": _text(name.replace("_", "-") for name, _ in variants), "Value": _text(value for _, value in variants), "Tags": _text(item.tags), "Description": item.description})
        rows.append(row)
    return rows


def _address_group_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for item in context.config.address_groups:
        row = _base(context, item, "address-group")
        row.update({"Group Type": "static" if item.static_members is not None else "dynamic" if item.dynamic_filter is not None else None,
                    "Static Members": _text(item.static_members), "Dynamic Filter": item.dynamic_filter, "Tags": _text(item.tags), "Description": item.description})
        rows.append(row)
    return rows


def _service_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for item in context.config.services:
        protocols = [(name, value) for name, value in (("tcp", item.tcp), ("udp", item.udp)) if value is not None] or [(None, None)]
        for protocol, value in protocols:
            override = value.override if value else None
            row = _base(context, item, "service")
            row.update({"Protocol": protocol, "Destination Port": value.port if value else None, "Source Port": value.source_port if value else None,
                        "Override Enabled": "yes" if override else None, "Timeout": override.timeout if override else None,
                        "Half-Close Timeout": override.halfclose_timeout if override else None, "Time-Wait Timeout": override.timewait_timeout if override else None,
                        "Tags": _text(item.tags), "Description": item.description})
            rows.append(row)
    return rows


def _schedule_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for item in context.config.schedules:
        recurring = item.recurring
        row = _base(context, item, "schedule")
        row.update({"Schedule Type": "recurring" if recurring is not None else "non-recurring" if item.non_recurring is not None else None,
                    "Daily Entries": _text(recurring.daily if recurring else None), "Weekly Entries": _text(recurring.weekly if recurring else None),
                    "Non-Recurring Entries": _text(item.non_recurring)})
        rows.append(row)
    return rows


def _reference_text(context: _PANExcelContext, item: Any, fields: set[str]) -> str:
    values = []
    for result in context.derived.reference_resolutions:
        if result.owner_name == item.name and _scope_id(result.source_scope) == _scope_id(item.scope) and result.owner_field in fields:
            values.append(f"{result.reference_name} -> {_scope_id(result.resolved_target_scope) if result.resolved_target_scope else result.status}")
    return _text(values)


def _effective_order(context: _PANExcelContext, item: Any) -> str:
    return _text(f"{entry.target_scope}: {entry.effective_order}" for entry in context.derived.policy_order
                 if entry.rule_name == item.name and _scope_id(entry.source_scope) == _scope_id(item.scope) and entry.source_order == item.source_order)


def _security_policy_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for item in (*context.config.security_rules, *context.config.default_security_rules):
        profile = item.profile_setting
        row = _base(context, item, "policy")
        row.update({"Source Order": item.source_order, "Rulebase Position": item.rulebase_position, "Effective Order": _effective_order(context, item),
                    "Rule Type": getattr(item, "rule_type", None), "From Zones": _text(getattr(item, "from_zones", None)), "To Zones": _text(getattr(item, "to_zones", None)),
                    "Source Addresses": _text(getattr(item, "source", None)), "Source Negate": getattr(item, "negate_source", None), "Source Users": _text(getattr(item, "source_user", None)),
                    "Destination Addresses": _text(getattr(item, "destination", None)), "Destination Negate": getattr(item, "negate_destination", None),
                    "Applications": _text(getattr(item, "application", None)), "Services": _text(getattr(item, "service", None)), "Categories": _text(getattr(item, "category", None)),
                    "Schedule": getattr(item, "schedule", None), "Tags": _text(item.tags), "Action": item.action, "Disabled": item.disabled,
                    "Profile Group": _text(profile.groups if profile else None), "Log Setting": item.log_setting, "Log Start": item.log_start, "Log End": item.log_end,
                    "Description": item.description, "Resolved Source References": _reference_text(context, item, {"source"}),
                    "Resolved Destination References": _reference_text(context, item, {"destination"})})
        rows.append(row)
    return rows


def _nat_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    derived_by_identity = {(item.source_path, item.name, item.source_order): item for item in context.derived.nat}
    rows = []
    for item in context.config.nat_rules:
        source, destination, dynamic = item.source_translation, item.destination_translation, item.dynamic_destination_translation
        derived = derived_by_identity.get((item.source_path, item.name, item.source_order))
        row = _base(context, item, "nat")
        row.update({"Source Order": item.source_order, "Rulebase Position": item.rulebase_position, "Effective Order": None,
                    "From Zones": _text(item.from_zones), "To Zones": _text(item.to_zones), "Source Addresses": _text(item.source), "Destination Addresses": _text(item.destination),
                    "Service": item.service, "NAT Type": item.nat_type, "To Interface": item.to_interface, "Source Translation Type": getattr(source, "translation_type", None),
                    "Source Translated Addresses": _text(getattr(source, "translated_addresses", None) or getattr(source, "translated_address", None)),
                    "Source Interface": getattr(source, "interface", None), "Source IP": getattr(source, "ip", None), "Source Bi-Directional": getattr(source, "bi_directional", None),
                    "Destination Translated Address": getattr(destination, "translated_address", None), "Destination Translated Port": getattr(destination, "translated_port", None),
                    "Dynamic Destination Address": _text(getattr(dynamic, "translated_addresses", None)), "Dynamic Destination Port": getattr(dynamic, "translated_port", None),
                    "Dynamic Destination Distribution": getattr(dynamic, "distribution", None), "Derived Source Translation Mode": derived.source_translation_mode if derived else None,
                    "Derived Destination Translation Mode": derived.destination_translation_mode if derived else None,
                    "Resolved Translation References": _text(derived.translated_references if derived else ()), "Disabled": item.disabled, "Tags": _text(item.tags), "Description": item.description})
        rows.append(row)
    return rows


def _interface_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    topology = {(item.scope, item.interface): item for item in context.derived.interface_topology}
    rows = []
    for item in context.config.interfaces:
        view = topology.get((_scope_id(item.scope), item.name or ""))
        row = _base(context, item, "interface")
        row.update({"Kind": view.kind if view else item.interface_family, "Aggregate Interface": view.aggregate if view else item.aggregate_group,
                    "Topology Path": _text(view.path if view else (item.name,)), "Physical Interfaces": _text(view.physical_interfaces if view else ()),
                    "Attached Tunnels": _text(view.attached_tunnels if view else ()),
                    "Layer": _text(item.mode), "IPv4 Addresses": _text(item.ipv4_addresses),
                    "IPv6 Addresses": _text(address.address for address in item.ipv6_addresses or ()), "Imported VSYS": _text(view.imported_vsys if view else ()),
                    "Zone": _text(view.zones if view else ()), "Virtual Router": _text(view.virtual_routers if view else ()),
                    "Topology Issues": _text(view.issues if view else ()), "Description": item.comment})
        rows.append(row)
        for unit in context.config.interface_units:
            if unit.parent == item.name:
                unit_view = topology.get((_scope_id(unit.scope), unit.name or ""))
                unit_row = _base(context, unit, "interface")
                unit_row.update({"Kind": unit_view.kind if unit_view else unit.interface_family or item.interface_family, "Parent Interface": unit.parent,
                                 "Aggregate Interface": unit_view.aggregate if unit_view else None, "Topology Path": _text(unit_view.path if unit_view else (unit.name,)),
                                 "Physical Interfaces": _text(unit_view.physical_interfaces if unit_view else ()), "Attached Tunnels": _text(unit_view.attached_tunnels if unit_view else ()), "Layer": _text(item.mode),
                                 "IPv4 Addresses": _text(unit.ipv4_addresses), "IPv6 Addresses": _text(address.address for address in unit.ipv6_addresses or ()),
                                 "Imported VSYS": _text(unit_view.imported_vsys if unit_view else ()), "Zone": _text(unit_view.zones if unit_view else ()),
                                 "Virtual Router": _text(unit_view.virtual_routers if unit_view else ()), "Topology Issues": _text(unit_view.issues if unit_view else ())})
                rows.append(unit_row)
    for unit in context.config.interface_units:
        if unit.parent and any(item.name == unit.parent for item in context.config.interfaces):
            continue
        unit_view = topology.get((_scope_id(unit.scope), unit.name or ""))
        row = _base(context, unit, "interface")
        row.update({"Kind": unit_view.kind if unit_view else unit.interface_family, "Parent Interface": unit.parent,
                    "Aggregate Interface": unit_view.aggregate if unit_view else None, "Topology Path": _text(unit_view.path if unit_view else (unit.name,)),
                    "Physical Interfaces": _text(unit_view.physical_interfaces if unit_view else ()), "Attached Tunnels": _text(unit_view.attached_tunnels if unit_view else ()), "IPv4 Addresses": _text(unit.ipv4_addresses),
                    "IPv6 Addresses": _text(address.address for address in unit.ipv6_addresses or ()),
                    "Imported VSYS": _text(unit_view.imported_vsys if unit_view else ()), "Zone": _text(unit_view.zones if unit_view else ()),
                    "Virtual Router": _text(unit_view.virtual_routers if unit_view else ()), "Topology Issues": _text(unit_view.issues if unit_view else ())})
        rows.append(row)
    return rows


def _route_rows(context: _PANExcelContext, logical: bool) -> list[dict[str, Any]]:
    rows = []
    for router in context.config.logical_routers if logical else context.config.virtual_routers:
        groups = ((vrf.name, vrf.static_routes or ()) for vrf in router.vrfs or ()) if logical else ((None, router.static_routes or ()),)
        for vrf, routes in groups:
            for item in routes:
                row = _base(context, item, "route")
                row.update({"Logical Router" if logical else "Virtual Router": router.name, "VRF": vrf, "Route Name": item.name,
                            "Source Order": item.source_order, "Address Family": item.address_family, "Destination": item.destination,
                            "Next Hop Type": item.nexthop_type, "Next Hop": item.nexthop_ip_address or item.nexthop, "Interface": item.interface,
                            "Admin Distance": item.admin_distance, "Metric": item.metric, "Route Table": item.route_table, "BFD Profile": item.bfd_profile})
                rows.append(row)
    return rows


def _unresolved_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for item in context.derived.reference_resolutions:
        if item.status not in {"UNRESOLVED", "AMBIGUOUS"}: continue
        source_type, source_name = _scope(item.source_scope)
        resolved_type, resolved_name = _scope(item.resolved_target_scope)
        rows.append({"Source Scope Type": source_type, "Source Scope Name": source_name, "Source Object Type": item.owner_family,
                     "Source Object": item.owner_name, "Field": item.owner_field, "Reference": item.reference_name, "Expected Type": item.expected_family,
                     "Status": item.status, "Resolved Scope": _text(value for value in (resolved_type, resolved_name) if value),
                     "Resolved Object": item.target_source_path, "Reason": item.resolution_reason, "__review__": True, "__error__": item.status == "UNRESOLVED"})
    return rows


_SOURCE_SHEET = {"address": "Addresses", "address-group": "Address Groups", "service": "Services", "service-group": "Service Groups",
                 "schedule": "Schedules", "policy": "Security Policies", "nat": "NAT Rules", "interface": "Interfaces", "route": "Virtual Router Routes", "reference": "Unresolved References"}


def _validation_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for issue in context.validation.issues:
        scope_type, scope_name = _scope(getattr(issue, "source_scope", None))
        rows.append({"Severity": issue.severity, "Domain": issue.domain, "Category": issue.domain, "Object": issue.source_name,
                     "Scope Type": scope_type, "Scope Name": scope_name, "Field": issue.field, "Issue / Review Reason": issue.message,
                     "Source Sheet": _SOURCE_SHEET.get(getattr(issue, "object_type", None) or issue.domain), "__review__": True, "__error__": issue.severity == "error"})
    return rows


def _inventory_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for item in context.config.source_inventory:
        scope = item.scope
        rows.append({"Scope Type": scope.kind if scope else None, "Scope Name": scope.name if scope else None, "Device": scope.device_name if scope else None,
                     "Serial": scope.device_serial if scope else None, "Device Group": scope.device_group if scope else None, "Source Path": item.source_path,
                     "Kind": item.kind, "Object": item.name, "Rulebase Position": item.rulebase_position, "Source Order": item.source_order,
                     "Values": _text(item.values), "Extraction Status": "UNSUPPORTED" if item.unsupported else "EXTRACTED"})
    return rows


def _typed_counts(context: _PANExcelContext) -> dict[str, int]:
    config = context.config
    counts = {"address": len(config.addresses), "address_group": len(config.address_groups), "service": len(config.services),
              "service_group": len(config.service_groups), "schedule": len(config.schedules), "security_rule": len(config.security_rules),
              "default_security_rule": len(config.default_security_rules), "nat_rule": len(config.nat_rules), "zone": len(config.zones),
              "interface_unit": len(config.interface_units), "virtual_router": len(config.virtual_routers), "logical_router": len(config.logical_routers)}
    counts.update({f"interface_{family}": sum(item.interface_family == family for item in config.interfaces)
                   for family in ("ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan")})
    return counts


def _coverage_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    source = Counter(item.kind.replace("-", "_") for item in context.config.source_inventory)
    typed = _typed_counts(context)
    domains = sorted(set(registered_paths()) | set(source) | set(typed))
    return [{"Source Domain": domain, "Found": "yes" if source[domain] else "no", "Source Records": source[domain], "Typed Objects": typed.get(domain, 0),
             "Status": "EXTRACTED" if domain in registered_paths() else "SOURCE_ONLY",
             "Unknown Paths": _text(path for path in context.config.unknown_paths if domain.replace("_", "-") in path), "Notes": None} for domain in domains]


ROW_BUILDERS: dict[str, Callable[[_PANExcelContext], list[dict[str, Any]]]] = {
    "Review Required": _validation_rows, "Validation": _validation_rows,
    "Tags": lambda c: _simple_rows(c, c.config.tags, "tag", {"Color": "color", "Comments": "comments"}),
    "Addresses": _address_rows, "Address Groups": _address_group_rows, "Services": _service_rows,
    "Service Groups": lambda c: _simple_rows(c, c.config.service_groups, "service-group", {"Members": "members", "Tags": "tags", "Description": "description"}),
    "Schedules": _schedule_rows, "Security Policies": _security_policy_rows, "NAT Rules": _nat_rows, "Interfaces": _interface_rows,
    "Security Profile Groups": lambda c: _simple_rows(c, c.config.security_profile_groups, "security-profile-group", {
        "Antivirus": "antivirus", "Anti-Spyware": "anti_spyware", "Vulnerability": "vulnerability",
        "URL Filtering": "url_filtering", "File Blocking": "file_blocking", "WildFire Analysis": "wildfire_analysis",
        "Data Filtering": "data_filtering", "GTP": "gtp", "SCTP": "sctp", "AI Security": "ai_security",
        "Disable Override": "disable_override",
    }),
    "Zones": lambda c: _simple_rows(c, c.config.zones, "zone", {"Network Type": "network_type", "Members": "members", "Zone Protection Profile": "zone_protection_profile", "Log Setting": "log_setting", "User Identification": "user_identification", "Device Identification": "device_identification"}),
    "Virtual Router Routes": lambda c: _route_rows(c, False), "Logical Router Routes": lambda c: _route_rows(c, True),
    "Unresolved References": _unresolved_rows,
    "Unsupported": lambda c: [{"Source Path": path, "Status": "UNSUPPORTED", "Reason": "typed extraction failed or is not registered"} for path in c.config.unknown_paths],
    "PAN-OS Source Inventory": _inventory_rows, "Extraction Coverage": _coverage_rows,
    "Vulnerability Profiles": _vulnerability_profile_rows,
    "Vulnerability Rules": lambda c: _child_rows(c, c.config.vulnerability_profiles, "rules", "vulnerability-rule", {"Rule Name": "name", "Threat Name": "threat_name", "Host": "host", "Vendor IDs": "vendor_ids", "Severities": "severities", "Category": "category", "Action": "action", "Packet Capture": "packet_capture"}),
    "Vulnerability Exceptions": lambda c: _child_rows(c, c.config.vulnerability_profiles, "exceptions", "vulnerability-exception", {"Exception Name": "name", "Action": "action", "Packet Capture": "packet_capture", "Time Interval": "time_interval", "Time Threshold": "time_threshold", "Time Track By": "time_track_by", "Exempt IP Configuration": "exempt_ips"}),
    "DHCP Servers": lambda c: _object_rows(c, c.config.dhcp_servers, "dhcp-server", {header: field for header, field in (("Interface", "interface"), ("Mode", "mode"), ("Probe IP", "probe_ip"), ("Lease Type", "lease_type"), ("Lease Timeout", "lease_timeout"), ("Inheritance Source", "inheritance_source"), ("Gateway", "gateway"), ("Subnet Mask", "subnet_mask"), ("DNS Primary", "dns_primary"), ("DNS Secondary", "dns_secondary"), ("WINS", "wins"), ("NTP", "ntp"), ("POP3 Server", "pop3_server"), ("SMTP Server", "smtp_server"), ("DNS Suffix", "dns_suffix"))}),
    "SD-WAN Interface Profiles": lambda c: _object_rows(c, c.config.sdwan_interface_profiles, "sdwan-interface-profile", {"Link Tag": "link_tag", "Link Type": "link_type", "VPN Data Tunnel Support": "vpn_data_tunnel_support", "Maximum Download": "maximum_download", "Maximum Upload": "maximum_upload", "Error Correction": "error_correction", "Path Monitoring": "path_monitoring", "VPN Failover Metric": "vpn_failover_metric", "Probe Frequency": "probe_frequency", "Probe Idle Time": "probe_idle_time", "Failback Hold Time": "failback_hold_time", "Comment": "comment"}),
    "SD-WAN Path Quality": lambda c: _object_rows(c, c.config.sdwan_path_quality_profiles, "sdwan-path-quality-profile", {"Latency Threshold": "latency_threshold", "Latency Sensitivity": "latency_sensitivity", "Packet Loss Threshold": "packet_loss_threshold", "Packet Loss Sensitivity": "packet_loss_sensitivity", "Jitter Threshold": "jitter_threshold", "Jitter Sensitivity": "jitter_sensitivity"}),
    "SD-WAN Traffic Distribution": lambda c: _object_rows(c, c.config.sdwan_traffic_distribution_profiles, "sdwan-traffic-distribution-profile", {"Distribution Mode": "distribution_mode"}),
    "SD-WAN Traffic Distribution Links": lambda c: _child_rows(c, c.config.sdwan_traffic_distribution_profiles, "links", "sdwan-traffic-distribution-link", {"Link Tag": "link_tag", "Weight": "weight"}),
    "SD-WAN SaaS Quality": lambda c: _object_rows(c, c.config.sdwan_saas_quality_profiles, "sdwan-saas-quality-profile", {"Monitor Mode": "monitor_mode", "Probe Configuration": "probe_configuration", "Targets": "targets"}),
    "SD-WAN Error Correction": lambda c: _object_rows(c, c.config.sdwan_error_correction_profiles, "sdwan-error-correction-profile", {"Activation Threshold": "activation_threshold", "Mode": "mode"}),
    "SD-WAN Rules": lambda c: _object_rows(c, c.config.sdwan_rules, "sdwan-rule", {"Rule Order": "source_order", "From Zones": "from_zones", "To Zones": "to_zones", "Source Addresses": "source", "Source Users": "source_user", "Destination Addresses": "destination", "Applications": "application", "Services": "service", "Tags": "tags", "Source Negate": "negate_source", "Destination Negate": "negate_destination", "Disabled": "disabled", "Path Quality Profile": "path_quality_profile", "SaaS Quality Profile": "saas_quality_profile", "Error Correction Profile": "error_correction_profile", "Traffic Distribution Profile": "traffic_distribution_profile", "NAT Session Failover Action": "nat_session_failover_action", "Group Tag": "group_tag", "Description": "description"}),
    "Administrators": lambda c: _object_rows(c, c.config.administrators, "administrator", {"Role Type": "role_type", "Built-In Role": "built_in_role", "Custom Admin Role": "custom_admin_role", "Authentication Profile": "authentication_profile", "Password Configured": "password_configured"}),
    "Admin Roles": lambda c: _object_rows(c, c.config.admin_roles, "admin-role", {"Role Scope": "role_scope"}),
    "Admin Role Permissions": lambda c: _child_rows(c, c.config.admin_roles, "permissions", "admin-role-permission", {"Role Scope": "role_scope", "Channel": "channel", "Permission Path": "permission_path", "Setting": "setting", "Value": "value"}, "Role"),
    "IKE Gateways": lambda c: _object_rows(c, c.config.ike_gateways, "ike-gateway", {"Local Interface": "local_interface", "Local IP": "local_ip", "Peer Address Type": "peer_address_type", "Peer Address": "peer_address", "IKE Version": "ike_version", "IKEv1 Exchange Mode": "ikev1_exchange_mode", "IKEv1 Crypto Profile": "ikev1_crypto_profile", "IKEv2 Crypto Profile": "ikev2_crypto_profile", "Authentication Method": "authentication_method", "Pre-Shared Key Configured": "pre_shared_key_configured", "Local ID": "local_id", "Peer ID": "peer_id", "IKEv1 DPD Enabled": "ikev1_dpd_enabled", "IKEv1 DPD Interval": "ikev1_dpd_interval", "IKEv1 DPD Retry": "ikev1_dpd_retry", "IKEv2 DPD Enabled": "ikev2_dpd_enabled", "IKEv2 DPD Interval": "ikev2_dpd_interval", "NAT Traversal": "nat_traversal", "NAT Traversal Keepalive": "nat_traversal_keepalive", "Passive Mode": "passive_mode", "Fragmentation": "fragmentation"}),
    "IKE Crypto Profiles": lambda c: _object_rows(c, c.config.ike_crypto_profiles, "ike-crypto-profile", {"Encryption Algorithms": "encryption_algorithms", "Authentication Algorithms": "authentication_algorithms", "DH / AKE Groups": "dh_groups", "Lifetime Value": "lifetime_value", "Lifetime Unit": "lifetime_unit", "Authentication Multiple": "authentication_multiple"}),
    "IPsec Crypto Profiles": lambda c: _object_rows(c, c.config.ipsec_crypto_profiles, "ipsec-crypto-profile", {"Protocol": "protocol", "ESP Encryption": "esp_encryption", "ESP Authentication": "esp_authentication", "AH Authentication": "ah_authentication", "DH Group": "dh_group", "Lifetime Value": "lifetime_value", "Lifetime Unit": "lifetime_unit"}),
    "IPsec Tunnels": lambda c: _object_rows(c, c.config.ipsec_tunnels, "ipsec-tunnel", {"Tunnel Interface": "tunnel_interface", "Key Type": "key_type", "IKE Gateways": "ike_gateways", "IPsec Crypto Profile": "ipsec_crypto_profile", "Tunnel Monitor": "tunnel_monitor", "GlobalProtect Satellite": "globalprotect_satellite", "Manual Key Configured": "manual_key_configured"}),
    "IPsec Proxy IDs": lambda c: _child_rows(c, c.config.ipsec_tunnels, "proxy_ids", "ipsec-proxy-id", {"Name": "name", "Address Family": "address_family", "Local": "local", "Remote": "remote", "Protocol": "protocol", "Protocol Number": "protocol_number", "Local Port": "local_port", "Remote Port": "remote_port"}, "Tunnel"),
    "GlobalProtect Portals": lambda c: _object_rows(c, c.config.globalprotect_portals, "globalprotect-portal", {"SSL/TLS Service Profile": "ssl_tls_service_profile", "Certificate Profile": "certificate_profile", "Clientless VPN Enabled": "clientless_vpn_enabled"}),
    "GlobalProtect Gateways": lambda c: _object_rows(c, c.config.globalprotect_gateways, "globalprotect-gateway", {"Tunnel Mode": "tunnel_mode", "Local Interface": "local_interface", "Local Address": "local_address", "IP Address Family": "ip_address_family", "SSL/TLS Service Profile": "ssl_tls_service_profile", "Certificate Profile": "certificate_profile"}),
    "Local Users": lambda c: _simple_rows(c, c.config.local_users, "local-user", {"Disabled": "disabled", "Password Configured": "password_configured"}),
    "Local User Groups": lambda c: _simple_rows(c, c.config.local_user_groups, "local-user-group", {"Members": "members"}),
    "Group Mappings": lambda c: _simple_rows(c, c.config.group_mappings, "group-mapping", {"Server Profile": "server_profile", "Disabled": "disabled"}),
    "Route Path Monitors": lambda c: [], "DHCP IP Pools": lambda c: [], "DHCP Reservations": lambda c: [], "DHCP Options": lambda c: [],
    "SD-WAN Interface Bindings": lambda c: [], "GP Portal Client Configs": lambda c: [], "GP Portal Gateway Entries": lambda c: [],
    "GP Clientless VPN": lambda c: [], "GP Gateway Client Auth": lambda c: [], "GP Remote User Tunnels": lambda c: [],
}
