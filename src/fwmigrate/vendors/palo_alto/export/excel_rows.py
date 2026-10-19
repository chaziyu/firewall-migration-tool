from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator
import xml.etree.ElementTree as ET

from ....extraction.sanitize import sanitize_source_attributes

from ..source_model import PANScope, pan_scope_identity
from ..source_report import PaloAltoSourceResult
from ..source_accounting import _TYPED_COUNT_FIELDS
from ..identity import source_identity, source_identity_text

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


def _additional_settings(*settings: dict[str, Any]) -> str:
    return "; ".join(_text(sanitize_source_attributes(value)) for value in settings if value)


@dataclass(slots=True)
class _PANExcelContext:
    analysis: PaloAltoSourceResult
    source_name: str | None = None
    collection_status: str | None = None
    validation_by_object: dict[tuple, tuple[Any, ...]] = field(init=False)
    validation_legacy: dict[tuple, tuple[Any, ...]] = field(init=False)
    legacy_owner_counts: Counter = field(init=False)
    legacy_name_counts: Counter = field(init=False)
    references_by_owner: dict[tuple, tuple[Any, ...]] = field(init=False)
    validation_by_scope: dict[str, tuple[Any, ...]] = field(init=False)
    typed_paths: set[str] = field(init=False)
    source_domains: Counter = field(init=False)
    extracted_domains: Counter = field(init=False)
    domain_statuses: dict[str, tuple[str, ...]] = field(init=False)

    def __post_init__(self) -> None:
        objects, legacy, scopes = defaultdict(list), defaultdict(list), defaultdict(list)
        for issue in self.analysis.validation.issues:
            object_type = issue.object_type or issue.domain
            if issue.source_identity:
                objects[(object_type, issue.source_identity)].append(issue)
            elif issue.source_name is not None:
                legacy[(object_type, _scope_key(issue.source_scope), issue.source_name, issue.source_path)].append(issue)
            scopes[_scope_key(issue.source_scope)].append(issue)
        self.validation_by_object = {key: tuple(value) for key, value in objects.items()}
        self.validation_legacy = {key: tuple(value) for key, value in legacy.items()}
        self.validation_by_scope = {key: tuple(value) for key, value in scopes.items()}
        typed = [item for name in set(_TYPED_COUNT_FIELDS.values()) for item in getattr(self.config, name)]
        typed.extend(self.derived.static_routes)
        self.legacy_owner_counts = Counter(
            (_scope_key(item.scope), getattr(item, "name", None), item.source_path) for item in typed)
        self.legacy_name_counts = Counter((_scope_key(item.scope), getattr(item, "name", None)) for item in typed)
        references = defaultdict(list)
        for resolution in self.derived.reference_resolutions:
            references[(resolution.owner_family, resolution.owner_identity)].append(resolution)
        self.references_by_owner = {key: tuple(value) for key, value in references.items()}
        accounting = self.analysis.accounting
        self.typed_paths = set(accounting.typed_paths)
        self.source_domains = accounting.source_domains
        self.extracted_domains = accounting.extracted_domains
        self.domain_statuses = accounting.domain_statuses

    @property
    def config(self): return self.analysis.config

    @property
    def derived(self): return self.analysis.derived

    @property
    def validation(self): return self.analysis.validation

    def issues_for(self, item: Any, object_type: str) -> tuple[Any, ...]:
        exact = self.validation_by_object.get((object_type, source_identity(item)), ())
        scope, name, path = _scope_key(getattr(item, "scope", None)), getattr(item, "name", None), item.source_path
        legacy = self.validation_legacy.get((object_type, scope, name, path), ()) if self.legacy_owner_counts[(scope, name, path)] == 1 else ()
        fallback = self.validation_legacy.get((object_type, scope, name, None), ()) if self.legacy_name_counts[(scope, name)] == 1 else ()
        return (*exact, *legacy, *fallback)


def _scope_key(scope: PANScope | None) -> str:
    return scope.model_dump_json() if scope else "<unscoped>"


def _base(context: _PANExcelContext, item: Any, object_type: str) -> dict[str, Any]:
    issues = context.issues_for(item, object_type)
    scope_type, scope_name = _scope(getattr(item, "scope", None))
    row = {**_owner_columns(item), "Name": getattr(item, "name", None), "Scope Type": scope_type, "Scope Name": scope_name,
            "Analysis Status": "REVIEW_REQUIRED" if issues else "NO_VALIDATION_ISSUES",
            "Review Reasons": _text(issue.message for issue in issues),
            "Source Explicit Fields": _text(sorted(getattr(item, "explicit_fields", ()))),
            "Additional Settings": _text(getattr(item, "raw_extra", {})),
            "__review__": bool(issues), "__error__": any(issue.severity == "error" for issue in issues)}
    if object_type == "interface":
        row.update({"Unit / Subinterface": item.name if getattr(item, "parent", None) is not None else None,
                    "VLAN Tag": getattr(item, "tag", None),
                    "MTU": getattr(item, "mtu", None), "Management Profile": item.management_profile,
                    "Link State": getattr(item, "link_state", None), "Speed": getattr(item, "speed", None),
                    "Duplex": getattr(item, "duplex", None)})
        row["Additional Settings"] = _additional_settings(item.raw_extra, {
            "ipv6_addresses": [address.model_dump(exclude_none=True, exclude_defaults=True,
                                                   exclude={"explicit_fields"})
                               for address in item.ipv6_addresses]
        } if item.ipv6_addresses else {})
    return row


def _owner_columns(item: Any, *, scope=None) -> dict[str, Any]:
    scope = scope or getattr(item, "scope", None)
    return {"Scope Identity": _scope_id(scope), "Source Record": source_identity_text(item),
            "Device": scope.device_name if scope else None,
            "Device Serial": scope.device_serial if scope else None,
            "VSYS": scope.vsys if scope else None, "Device Group": scope.device_group if scope else None,
            "Template": scope.template_provenance.get("template") if scope else None,
            "Template Stack": scope.template_stack if scope else None}


def _simple_rows(context: _PANExcelContext, items: Iterable[Any], object_type: str, fields: dict[str, str]) -> Iterator[dict[str, Any]]:
    for item in items:
        row = _base(context, item, object_type)
        row.update({header: _text(getattr(item, attribute, None)) for header, attribute in fields.items()})
        yield row


def _object_rows(context: _PANExcelContext, items: Iterable[Any], object_type: str, fields: dict[str, str]) -> Iterator[dict[str, Any]]:
    for item in items:
        row = _base(context, item, object_type)
        for header, attribute in fields.items():
            row[header] = _text(getattr(item, attribute, None))
        yield row


def _child_rows(context: _PANExcelContext, parents: Iterable[Any], child_attr: str, object_type: str, fields: dict[str, str], parent_header: str = "Profile", parent_attribute: str = "name") -> list[dict[str, Any]]:
    rows = []
    for parent in parents:
        for child in getattr(parent, child_attr, None) or ():
            row = _base(context, parent, object_type)
            row[parent_header] = getattr(parent, parent_attribute)
            for header, attribute in fields.items():
                row[header] = _text(getattr(child, attribute, None))
            if hasattr(child, "raw_extra"):
                row["Additional Settings"] = _text(child.raw_extra)
            rows.append(row)
    return rows


def _portal_gateway_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for portal in context.config.globalprotect_portals:
        for client_config in portal.client_configs or ():
            for gateway in client_config.gateways or ():
                row = _base(context, portal, "globalprotect-portal-gateway")
                row.update({"Portal": portal.name, "Client Config": client_config.name, "Gateway Type": gateway.gateway_type,
                            "Gateway": gateway.gateway, "Priority": gateway.priority, "Additional Settings": _text(gateway.raw_extra)})
                rows.append(row)
    return rows


def _clientless_vpn_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for portal in context.config.globalprotect_portals:
        vpn = portal.clientless_vpn
        if vpn is None:
            continue
        row = _base(context, portal, "globalprotect-clientless-vpn")
        row.update({"Portal": portal.name, "Hostname": vpn.hostname, "Security Zone": vpn.security_zone, "Login Lifetime": vpn.login_lifetime,
                    "Inactivity Logout": vpn.inactivity_logout, "Maximum Users": vpn.maximum_users, "DNS Proxy": vpn.dns_proxy,
                    "Additional Settings": _text(vpn.raw_extra)})
        rows.append(row)
    return rows


def _sdwan_interface_binding_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    fields = ("sdwan_enabled", "ipv6_sdwan_enabled", "sdwan_interface_profile", "upstream_nat")
    for item in (*context.config.interfaces, *context.config.interface_units):
        if not any(getattr(item, field) is not None for field in fields):
            continue
        row = _base(context, item, "sdwan-interface-binding")
        row.update({"Interface": item.name, "Parent Interface": getattr(item, "parent", None), "SD-WAN Enabled": item.sdwan_enabled,
                    "IPv6 Enabled": item.ipv6_sdwan_enabled, "Interface Profile": item.sdwan_interface_profile, "Upstream NAT": item.upstream_nat})
        rows.append(row)
    return rows


def _vulnerability_profile_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for item in context.config.vulnerability_profiles:
        row = _base(context, item, "vulnerability-profile")
        row.update({"Rule Count": len(item.rules or ()), "Exception Count": len(item.exceptions or ())})
        rows.append(row)
    return rows


def _vulnerability_child_rows(context: _PANExcelContext, child_attr: str) -> list[dict[str, Any]]:
    rows = []
    is_exception = child_attr == "exceptions"
    for profile in context.config.vulnerability_profiles:
        for child in getattr(profile, child_attr, None) or ():
            row = _base(context, profile, "vulnerability-exception" if is_exception else "vulnerability-rule")
            block_ip = child.block_ip
            row.update({"Profile": profile.name,
                        "Rule Name" if not is_exception else "Exception Name": child.name,
                        "Threat Name": getattr(child, "threat_name", None), "Host": getattr(child, "host", None),
                        "Vendor IDs": _text(getattr(child, "vendor_ids", None)), "Severities": _text(getattr(child, "severities", None)),
                        "Category": getattr(child, "category", None), "Action": child.action,
                        "Block IP Track By": block_ip.track_by if block_ip else None,
                        "Block IP Duration": block_ip.duration if block_ip else None,
                        "Packet Capture": child.packet_capture,
                        "Time Interval": getattr(child, "time_interval", None), "Time Threshold": getattr(child, "time_threshold", None),
                        "Time Track By": getattr(child, "time_track_by", None),
                        "Exempt IP Configuration": _text(getattr(child, "exempt_ips", None)),
                        "Additional Settings": _text(child.raw_extra)})
            rows.append(row)
    return rows


def _address_rows(context: _PANExcelContext) -> Iterator[dict[str, Any]]:
    for item in context.config.addresses:
        variants = [(name, getattr(item, name)) for name in ("ip_netmask", "ip_range", "ip_wildcard", "fqdn") if getattr(item, name) is not None]
        row = _base(context, item, "address")
        row.update({"Type": _text(name.replace("_", "-") for name, _ in variants), "Value": _text(value for _, value in variants), "Tags": _text(item.tags), "Description": item.description})
        yield row


def _address_group_rows(context: _PANExcelContext) -> Iterator[dict[str, Any]]:
    for item in context.config.address_groups:
        row = _base(context, item, "address-group")
        row.update({"Group Type": "static" if item.static_members is not None else "dynamic" if item.dynamic_filter is not None else None,
                    "Static Members": _text(item.static_members), "Dynamic Filter": item.dynamic_filter, "Tags": _text(item.tags), "Description": item.description})
        yield row


def _service_rows(context: _PANExcelContext) -> Iterator[dict[str, Any]]:
    for item in context.config.services:
        protocols = [(name, value) for name, value in (("tcp", item.tcp), ("udp", item.udp)) if value is not None] or [(None, None)]
        for protocol, value in protocols:
            override = value.override if value else None
            row = _base(context, item, "service")
            row.update({"Protocol": protocol, "Destination Port": value.port if value else None, "Source Port": value.source_port if value else None,
                        "Override Enabled": override.enabled if override else None, "Timeout": override.timeout if override else None,
                        "Half-Close Timeout": override.halfclose_timeout if override else None, "Time-Wait Timeout": override.timewait_timeout if override else None,
                        "Tags": _text(item.tags), "Description": item.description})
            row["Additional Settings"] = _additional_settings(
                item.raw_extra,
                {protocol: value.raw_extra} if value and value.raw_extra else {},
                {"override": override.raw_extra} if override and override.raw_extra else {},
            )
            yield row


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
    for result in context.references_by_owner.get(("policy", source_identity(item)), ()):
        if result.owner_field in fields:
            values.append(f"{result.reference_name} -> {_scope_id(result.resolved_target_scope) if result.resolved_target_scope else result.status}")
    return _text(values)


def _effective_order(context: _PANExcelContext, item: Any) -> str:
    return _text(f"{entry.target_scope}: {entry.effective_order}{'' if entry.complete else ' (incomplete; source-only; source order retained)'}" for entry in context.derived.policy_order
                 if entry.rule_name == item.name and _scope_id(entry.source_scope) == _scope_id(item.scope) and entry.source_order == item.source_order)


def _security_policy_rows(context: _PANExcelContext) -> Iterator[dict[str, Any]]:
    for item in (*context.config.security_rules, *context.config.default_security_rules):
        profile = item.profile_setting
        row = _base(context, item, "default-security-rule" if item in context.config.default_security_rules else "policy")
        row.update({"Source Order": item.source_order, "Rulebase Position": item.rulebase_position, "Effective Order": _effective_order(context, item),
                    "Rule Type": getattr(item, "rule_type", None), "From Zones": _text(getattr(item, "from_zones", None)), "To Zones": _text(getattr(item, "to_zones", None)),
                    "Source Addresses": _text(getattr(item, "source", None)), "Source Negate": getattr(item, "negate_source", None), "Source Users": _text(getattr(item, "source_user", None)),
                    "Destination Addresses": _text(getattr(item, "destination", None)), "Destination Negate": getattr(item, "negate_destination", None),
                    "Source HIP": _text(getattr(item, "source_hip", None)), "Destination HIP": _text(getattr(item, "destination_hip", None)),
                    "Applications": _text(getattr(item, "application", None)), "Services": _text(getattr(item, "service", None)), "Categories": _text(getattr(item, "category", None)),
                    "Schedule": getattr(item, "schedule", None), "Tags": _text(item.tags), "Action": item.action, "Disabled": item.disabled,
                    "ICMP Unreachable": getattr(item, "icmp_unreachable", None), "Disable Inspect": getattr(item, "disable_inspect", None),
                    "Group Tag": getattr(item, "group_tag", None),
                    "URL Filtering": _text((profile.profiles or {}).get("url-filtering") if profile else None),
                    "Data Filtering": _text((profile.profiles or {}).get("data-filtering") if profile else None),
                    "File Blocking": _text((profile.profiles or {}).get("file-blocking") if profile else None),
                    "WildFire Analysis": _text((profile.profiles or {}).get("wildfire-analysis") if profile else None),
                    "Antivirus": _text((profile.profiles or {}).get("virus") if profile else None),
                    "Anti-Spyware": _text((profile.profiles or {}).get("spyware") if profile else None),
                    "Vulnerability Profile": _text((profile.profiles or {}).get("vulnerability") if profile else None),
                    "Profile Group": _text(profile.groups if profile else None), "Log Setting": item.log_setting, "Log Start": item.log_start, "Log End": item.log_end,
                    "Description": item.description, "Resolved Source References": _reference_text(context, item, {"source"}),
                    "Resolved Destination References": _reference_text(context, item, {"destination"})})
        yield row


def _nat_rows(context: _PANExcelContext) -> Iterator[dict[str, Any]]:
    derived_by_identity = {(item.source_path, item.name, item.source_order): item for item in context.derived.nat}
    for item in context.config.nat_rules:
        source, destination, dynamic = item.source_translation, item.destination_translation, item.dynamic_destination_translation
        derived = derived_by_identity.get((item.source_path, item.name, item.source_order))
        row = _base(context, item, "nat")
        nested = {}
        for name, translation in (("source_translation", source), ("destination_translation", destination),
                                  ("dynamic_destination_translation", dynamic)):
            if translation is None:
                continue
            settings = dict(translation.raw_extra)
            fallback = getattr(translation, "fallback", None)
            if fallback is not None:
                settings["fallback"] = fallback
            rewrite = getattr(translation, "dns_rewrite", None)
            if rewrite is not None and rewrite.raw_extra:
                settings["dns_rewrite"] = rewrite.raw_extra
            if settings:
                nested[name] = settings
        row["Additional Settings"] = _additional_settings(item.raw_extra, nested)
        row.update({"Source Order": item.source_order, "Rulebase Position": item.rulebase_position, "Effective Order": None,
                    "From Zones": _text(item.from_zones), "To Zones": _text(item.to_zones), "Source Addresses": _text(item.source), "Destination Addresses": _text(item.destination),
                    "Service": item.service, "NAT Type": item.nat_type, "To Interface": item.to_interface, "Source Translation Type": getattr(source, "translation_type", None),
                    "Source Translated Addresses": _text(getattr(source, "translated_addresses", None) or getattr(source, "translated_address", None)),
                    "Source Interface": getattr(source, "interface", None), "Source IP": getattr(source, "ip", None), "Source Bi-Directional": getattr(source, "bi_directional", None),
                    "Destination Translated Address": getattr(destination, "translated_address", None), "Destination Translated Port": getattr(destination, "translated_port", None),
                    "Destination Translation Type": "destination-translation" if destination else "dynamic-destination-translation" if dynamic else None,
                    "Destination DNS Rewrite": ("yes" if destination.dns_rewrite else None) if destination else getattr(getattr(dynamic, "dns_rewrite", None), "enabled", None),
                    "DNS Rewrite Direction": getattr(getattr(destination, "dns_rewrite", None), "direction", None) or getattr(getattr(dynamic, "dns_rewrite", None), "direction", None),
                    "Dynamic Destination Address": _text(getattr(dynamic, "translated_addresses", None)), "Dynamic Destination Port": getattr(dynamic, "translated_port", None),
                    "Dynamic Destination Distribution": getattr(dynamic, "distribution", None), "Derived Source Translation Mode": derived.source_translation_mode if derived else None,
                    "Derived Destination Translation Mode": derived.destination_translation_mode if derived else None,
                    "Resolved Translation References": _text(f"{resolution.reference_name} -> {resolution.status}" for resolution in context.references_by_owner.get(("nat", source_identity(item)), ()) if resolution.owner_field.startswith(("source_translation.", "destination_translation.", "dynamic_destination_translation."))), "Disabled": item.disabled, "Tags": _text(item.tags), "Description": item.description})
        yield row


def _interface_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    topology = {(item.scope, item.interface): item for item in context.derived.interface_topology}
    rows = []
    for item in context.config.interfaces:
        view = topology.get((_scope_id(item.scope), item.name or ""))
        row = _base(context, item, "interface")
        row.update({"Device": item.scope.device_name if item.scope else None,
                    "Device Serial": item.scope.device_serial if item.scope else None,
                    "Device Group": item.scope.device_group if item.scope else None,
                    "Template Stack": item.scope.template_stack if item.scope else None})
        row.update({"Kind": view.kind if view else item.interface_family, "Aggregate Interface": view.aggregate if view else item.aggregate_group,
                    "Topology Path": _text(view.path if view else (item.name,)), "Physical Interfaces": _text(view.physical_interfaces if view else ()),
                    "Attached Tunnels": _text(view.attached_tunnels if view else ()),
                    "Layer": _text(item.mode), "IPv4 Addresses": _text(item.ipv4_addresses),
                    "IPv6 Addresses": _text(address.address for address in item.ipv6_addresses or ()), "Imported VSYS": _text(view.imported_vsys if view else ()),
                    "Zone": _text(view.zones if view else ()), "Virtual Router": _text(view.virtual_routers if view else ()),
                    "Topology Issues": _text(view.issues if view else ()), "Description": item.comment,
                    "SD-WAN Enabled": item.sdwan_enabled, "IPv6 SD-WAN Enabled": item.ipv6_sdwan_enabled,
                    "SD-WAN Interface Profile": item.sdwan_interface_profile, "Upstream NAT": item.upstream_nat})
        rows.append(row)
        for unit in context.config.interface_units:
            if unit.parent == item.name and _scope_key(unit.scope) == _scope_key(item.scope):
                unit_view = topology.get((_scope_id(unit.scope), unit.name or ""))
                unit_row = _base(context, unit, "interface")
                unit_row.update({"Device": unit.scope.device_name if unit.scope else None,
                                 "Device Serial": unit.scope.device_serial if unit.scope else None,
                                 "Device Group": unit.scope.device_group if unit.scope else None,
                                 "Template Stack": unit.scope.template_stack if unit.scope else None})
                unit_row.update({"Kind": unit_view.kind if unit_view else unit.interface_family or item.interface_family, "Parent Interface": unit.parent,
                                 "Aggregate Interface": unit_view.aggregate if unit_view else None, "Topology Path": _text(unit_view.path if unit_view else (unit.name,)),
                                 "Physical Interfaces": _text(unit_view.physical_interfaces if unit_view else ()), "Attached Tunnels": _text(unit_view.attached_tunnels if unit_view else ()), "Layer": _text(item.mode),
                                 "IPv4 Addresses": _text(unit.ipv4_addresses), "IPv6 Addresses": _text(address.address for address in unit.ipv6_addresses or ()),
                                 "Imported VSYS": _text(unit_view.imported_vsys if unit_view else ()), "Zone": _text(unit_view.zones if unit_view else ()),
                                 "Virtual Router": _text(unit_view.virtual_routers if unit_view else ()), "Topology Issues": _text(unit_view.issues if unit_view else ())})
                unit_row.update({"SD-WAN Enabled": unit.sdwan_enabled, "IPv6 SD-WAN Enabled": unit.ipv6_sdwan_enabled,
                                 "SD-WAN Interface Profile": unit.sdwan_interface_profile, "Upstream NAT": unit.upstream_nat})
                rows.append(unit_row)
    for unit in context.config.interface_units:
        if unit.parent and any(item.name == unit.parent and _scope_key(item.scope) == _scope_key(unit.scope) for item in context.config.interfaces):
            continue
        unit_view = topology.get((_scope_id(unit.scope), unit.name or ""))
        row = _base(context, unit, "interface")
        row.update({"Device": unit.scope.device_name if unit.scope else None,
                    "Device Serial": unit.scope.device_serial if unit.scope else None,
                    "Device Group": unit.scope.device_group if unit.scope else None,
                    "Template Stack": unit.scope.template_stack if unit.scope else None})
        row.update({"Kind": unit_view.kind if unit_view else unit.interface_family, "Parent Interface": unit.parent,
                    "Aggregate Interface": unit_view.aggregate if unit_view else None, "Topology Path": _text(unit_view.path if unit_view else (unit.name,)),
                    "Physical Interfaces": _text(unit_view.physical_interfaces if unit_view else ()), "Attached Tunnels": _text(unit_view.attached_tunnels if unit_view else ()), "IPv4 Addresses": _text(unit.ipv4_addresses),
                    "IPv6 Addresses": _text(address.address for address in unit.ipv6_addresses or ()),
                    "Imported VSYS": _text(unit_view.imported_vsys if unit_view else ()), "Zone": _text(unit_view.zones if unit_view else ()),
                    "Virtual Router": _text(unit_view.virtual_routers if unit_view else ()), "Topology Issues": _text(unit_view.issues if unit_view else ())})
        row.update({"SD-WAN Enabled": unit.sdwan_enabled, "IPv6 SD-WAN Enabled": unit.ipv6_sdwan_enabled,
                    "SD-WAN Interface Profile": unit.sdwan_interface_profile, "Upstream NAT": unit.upstream_nat})
        rows.append(row)
    return rows


def _route_rows(context: _PANExcelContext, logical: bool) -> Iterator[dict[str, Any]]:
    for router in context.config.logical_routers if logical else context.config.virtual_routers:
        groups = ((vrf.name, vrf.static_routes or ()) for vrf in router.vrfs or ()) if logical else ((None, router.static_routes or ()),)
        for vrf, routes in groups:
            for item in routes:
                row = _base(context, item, "route")
                row.update({"Logical Router" if logical else "Virtual Router": router.name, "VRF": vrf, "Route Name": item.name,
                            "Source Order": item.source_order, "Address Family": item.address_family, "Destination": item.destination,
                            "Next Hop Type": item.nexthop_type, "Next Hop": item.nexthop_ip_address or item.nexthop, "Interface": item.interface,
                            "Admin Distance": item.admin_distance, "Metric": item.metric, "Route Table": item.route_table, "BFD Profile": item.bfd_profile,
                            "Path Monitor Enabled": item.path_monitor.enabled if item.path_monitor else None,
                            "Path Monitor Failure Condition": item.path_monitor.failure_condition if item.path_monitor else None,
                            "Path Monitor Hold Time": item.path_monitor.hold_time if item.path_monitor else None})
                yield row


def _route_path_monitor_rows(context: _PANExcelContext) -> Iterator[dict[str, Any]]:
    for logical, routers in ((False, context.config.virtual_routers), (True, context.config.logical_routers)):
        for router in routers:
            groups = ((vrf.name, vrf.static_routes or ()) for vrf in router.vrfs or ()) if logical else ((None, router.static_routes or ()),)
            for vrf, routes in groups:
                for route in routes:
                    for target in route.path_monitor.targets or () if route.path_monitor else ():
                        row = _base(context, route, "route")
                        row.update({"Router Type": "logical-router" if logical else "virtual-router", "Router": router.name,
                                    "VRF": vrf, "Route Name": route.name, "Monitor Name": target.name,
                                    "Enabled": target.enabled, "Source": target.source, "Destination": target.destination,
                                    "Destination FQDN": target.destination_fqdn, "Interval": target.interval, "Count": target.count,
                                    "Scope Type": route.scope.kind if route.scope else None, "Scope Name": route.scope.name if route.scope else None,
                                    "Additional Settings": _text(target.raw_extra)})
                        yield row


def _unresolved_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for item in context.derived.reference_resolutions:
        if item.status not in {"UNRESOLVED", "AMBIGUOUS"}: continue
        source_type, source_name = _scope(item.source_scope)
        resolved_type, resolved_name = _scope(item.resolved_target_scope)
        rows.append({**_owner_columns(item, scope=item.source_scope), "Source Scope Type": source_type, "Source Scope Name": source_name, "Source Object Type": item.owner_family,
                     "Source Object": item.owner_name, "Field": item.owner_field, "Reference": item.reference_name, "Expected Type": item.expected_family,
                     "Status": item.status, "Resolved Scope": _text(value for value in (resolved_type, resolved_name) if value),
                     "Resolved Object": item.target_source_path, "Reason": item.resolution_reason, "__review__": True, "__error__": item.status == "UNRESOLVED"})
    return rows


_SOURCE_SHEET = {"address": "Addresses", "address-group": "Address Groups", "service": "Services", "service-group": "Service Groups",
                 "schedule": "Schedules", "policy": "Security Policies", "nat": "NAT Rules", "interface": "Interfaces", "route": "Virtual Router Routes", "reference": "Unresolved References", "security-profile-group": "Security Profile Groups", "ike-gateway": "IKE Gateways"}


def _validation_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    rows = []
    for issue in context.validation.issues:
        scope_type, scope_name = _scope(getattr(issue, "source_scope", None))
        rows.append({**_owner_columns(issue, scope=issue.source_scope), "Severity": issue.severity, "Domain": issue.domain, "Category": issue.domain, "Object": issue.source_name,
                     "Scope Type": scope_type, "Scope Name": scope_name, "Field": issue.field, "Issue / Review Reason": issue.message,
                     "Source Sheet": _SOURCE_SHEET.get(getattr(issue, "object_type", None) or issue.domain), "__review__": True, "__error__": issue.severity == "error"})
    return rows


def _inventory_rows(context: _PANExcelContext) -> Iterator[dict[str, Any]]:
    for item in context.config.source_inventory:
        scope = item.scope
        yield {**_owner_columns(item), "Scope Type": scope.kind if scope else None, "Scope Name": scope.name if scope else None, "Device": scope.device_name if scope else None,
                     "Serial": scope.device_serial if scope else None, "Device Group": scope.device_group if scope else None, "Source Path": item.source_path,
                     "Kind": item.kind, "Object": item.name, "Rulebase Position": item.rulebase_position, "Source Order": item.source_order,
                     "Values": _text(item.values), "Extraction Status": _inventory_status(context, item)}


def _inventory_status(context: _PANExcelContext, record: Any) -> str:
    return context.analysis.accounting.inventory_status(record)


def _unsupported_rows(context: _PANExcelContext) -> Iterator[dict[str, Any]]:
    for item in context.config.source_inventory:
        status = _inventory_status(context, item)
        path_parts = item.source_path.split("/")
        under_typed_path = any("/".join(path_parts[:index]) in context.typed_paths for index in range(1, len(path_parts)))
        if status == "EXTRACTED" or (status == "SOURCE_ONLY" and (item.source_path.endswith(("devices/entry", "device-group/entry", "vsys/entry")) or under_typed_path)):
            continue
        issue = next((issue for issue in context.config.extraction_issues if (issue.source_path, issue.source_name, _scope_key(issue.scope), issue.source_order) == (item.source_path, item.name, _scope_key(item.scope), item.source_order)), None)
        reason = f"{issue.exception_type}: {issue.message}" if issue else "typed object retains unstructured source evidence" if status == "PARTIAL" else "no standalone typed source object"
        yield {**_owner_columns(item), "Source Path": item.source_path, "Status": status, "Reason": reason}


def _typed_counts(context: _PANExcelContext) -> dict[str, int]:
    return context.analysis.accounting.typed_counts


def _coverage_rows(context: _PANExcelContext) -> list[dict[str, Any]]:
    return [{"Source Domain": item.domain, "Found": "yes" if item.source_records else "no",
             "Source Records": item.source_records, "Typed Objects": item.typed_objects,
             "Status": item.status, "Unknown Paths": _text(item.unknown_paths), "Notes": None}
            for item in context.analysis.accounting.coverage]


def _source_appendix_rows(context: _PANExcelContext) -> Iterator[dict[str, Any]]:
    standalone_paths = {record.source_path for record in context.config.source_inventory
                        if not record.source_path.endswith("/entry")}
    for record in context.config.source_inventory:
        if not record.raw_xml:
            continue
        try:
            root = ET.fromstring(record.raw_xml)
        except ET.ParseError:
            continue
        scope = record.scope
        evidence_order = 0

        def emit(path: str, kind: str, value: str):
            nonlocal evidence_order
            evidence_order += 1
            return {**_owner_columns(record), "Scope Type": scope.kind if scope else None, "Scope Name": scope.name if scope else None,
                "Source Path": record.source_path, "Kind": record.kind, "Object": record.name,
                "Source Order": record.source_order, "Evidence Order": evidence_order, "Evidence Path": path,
                "Evidence Type": kind, "Evidence Value": value}

        def visit(node: ET.Element, path: str, source_path: str):
            for name, value in node.attrib.items():
                yield emit(f"{path}/@{name}", "attribute", value)
            text = (node.text or "").strip()
            if text:
                yield emit(path, "text", text)
            if not len(node) and not text:
                yield emit(path, "presence", "yes")
            for child in node:
                # Every <entry> has its own inventory record and appendix traversal.
                # Stop here so nested records are not repeated under their parent.
                if child.tag == "entry" or f"{source_path}/{child.tag}" in standalone_paths:
                    continue
                yield from visit(child, f"{path}/{child.tag}", f"{source_path}/{child.tag}")

        yield from visit(root, root.tag, record.source_path)


ROW_BUILDERS: dict[str, Callable[[_PANExcelContext], Iterable[dict[str, Any]]]] = {
    "Review Required": _validation_rows,
    "Tags": lambda c: _simple_rows(c, c.config.tags, "tag", {"Color": "color", "Comments": "comments"}),
    "Addresses": _address_rows, "Address Groups": _address_group_rows, "Services": _service_rows,
    "Service Groups": lambda c: _simple_rows(c, c.config.service_groups, "service-group", {"Members": "members", "Tags": "tags", "Description": "description", "Disable Override": "disable_override"}),
    "Schedules": _schedule_rows, "Security Policies": _security_policy_rows, "NAT Rules": _nat_rows, "Interfaces": _interface_rows,
    "Security Profile Groups": lambda c: _simple_rows(c, c.config.security_profile_groups, "security-profile-group", {
        "Antivirus": "antivirus", "Anti-Spyware": "anti_spyware", "Vulnerability": "vulnerability",
        "URL Filtering": "url_filtering", "File Blocking": "file_blocking", "WildFire Analysis": "wildfire_analysis",
        "Data Filtering": "data_filtering", "GTP": "gtp", "SCTP": "sctp", "AI Security": "ai_security",
        "Disable Override": "disable_override",
    }),
    "Zones": lambda c: _simple_rows(c, c.config.zones, "zone", {"Network Type": "network_type", "Members": "members", "Zone Protection Profile": "zone_protection_profile", "Packet Buffer Protection": "packet_buffer_protection", "Network Inspection": "network_inspection", "Pre-NAT User Identification": "pre_nat_user_identification", "Pre-NAT Device Identification": "pre_nat_device_identification", "Pre-NAT Source Policy Lookup": "pre_nat_source_policy_lookup", "Pre-NAT Source IP Downstream": "pre_nat_source_ip_downstream", "Log Setting": "log_setting", "User Identification": "user_identification", "Device Identification": "device_identification", "User ACL Include": "user_acl_include", "User ACL Exclude": "user_acl_exclude", "Device ACL Include": "device_acl_include", "Device ACL Exclude": "device_acl_exclude"}),
    "Virtual Router Routes": lambda c: _route_rows(c, False), "Logical Router Routes": lambda c: _route_rows(c, True),
    "Unresolved References": _unresolved_rows,
    "Unsupported": _unsupported_rows,
    "PAN-OS Source Inventory": _inventory_rows, "PAN-OS Source Appendix": _source_appendix_rows, "Extraction Coverage": _coverage_rows,
    "Vulnerability Profiles": _vulnerability_profile_rows,
    "Vulnerability Rules": lambda c: _vulnerability_child_rows(c, "rules"),
    "Vulnerability Exceptions": lambda c: _vulnerability_child_rows(c, "exceptions"),
    "Route Path Monitors": _route_path_monitor_rows,
    "DHCP Servers": lambda c: _object_rows(c, c.config.dhcp_servers, "dhcp-server", {header: field for header, field in (("Interface", "interface"), ("Mode", "mode"), ("Probe IP", "probe_ip"), ("Lease Type", "lease_type"), ("Lease Timeout", "lease_timeout"), ("Inheritance Source", "inheritance_source"), ("Gateway", "gateway"), ("Subnet Mask", "subnet_mask"), ("DNS Primary", "dns_primary"), ("DNS Secondary", "dns_secondary"), ("WINS", "wins"), ("NTP", "ntp"), ("POP3 Server", "pop3_server"), ("SMTP Server", "smtp_server"), ("DNS Suffix", "dns_suffix"))}),
    "SD-WAN Interface Profiles": lambda c: _object_rows(c, c.config.sdwan_interface_profiles, "sdwan-interface-profile", {"Link Tag": "link_tag", "Link Type": "link_type", "VPN Data Tunnel Support": "vpn_data_tunnel_support", "Maximum Download": "maximum_download", "Maximum Upload": "maximum_upload", "Error Correction": "error_correction", "Path Monitoring": "path_monitoring", "VPN Failover Metric": "vpn_failover_metric", "Probe Frequency": "probe_frequency", "Probe Idle Time": "probe_idle_time", "Failback Hold Time": "failback_hold_time", "Comment": "comment"}),
    "SD-WAN Path Quality": lambda c: _object_rows(c, c.config.sdwan_path_quality_profiles, "sdwan-path-quality-profile", {"Latency Threshold": "latency_threshold", "Latency Sensitivity": "latency_sensitivity", "Packet Loss Threshold": "packet_loss_threshold", "Packet Loss Sensitivity": "packet_loss_sensitivity", "Jitter Threshold": "jitter_threshold", "Jitter Sensitivity": "jitter_sensitivity"}),
    "SD-WAN Traffic Distribution": lambda c: _object_rows(c, c.config.sdwan_traffic_distribution_profiles, "sdwan-traffic-distribution-profile", {"Distribution Mode": "distribution_mode"}),
    "SD-WAN Distribution Links": lambda c: _child_rows(c, c.config.sdwan_traffic_distribution_profiles, "links", "sdwan-traffic-distribution-link", {"Link Tag": "link_tag", "Weight": "weight"}),
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
    "Group Mappings": lambda c: _simple_rows(c, c.config.group_mappings, "group-mapping", {"Server Profile": "server_profile", "Disabled": "disabled", "LDAP Serial Number Check": "ldap_serial_number_check", "Use Modify Timestamp": "use_modify_timestamp", "Limited Group Search": "limited_group_search", "Nested Group Level": "nested_group_level", "Group Object Attributes": "group_object_attributes", "Group Member Attributes": "group_member_attributes", "Group Name Attributes": "group_name_attributes", "User Object Attributes": "user_object_attributes", "User Name Attributes": "user_name_attributes", "User Email Attributes": "user_email_attributes", "Group Email Attributes": "group_email_attributes", "Alternate Username 1": "alternate_username_1", "Alternate Username 2": "alternate_username_2", "Alternate Username 3": "alternate_username_3", "Container Object Attributes": "container_object_attributes", "Last Modify Attribute": "last_modify_attribute", "Group Include List": "group_include_list"}),
    "DHCP IP Pools": lambda c: _child_rows(c, c.config.dhcp_servers, "ip_pools", "dhcp-ip-pool", {"Pool Entry": "name", "Start IP": "start_ip", "End IP": "end_ip"}, "Interface", "interface"),
    "DHCP Reservations": lambda c: _child_rows(c, c.config.dhcp_servers, "reservations", "dhcp-reservation", {"Reservation Name": "name", "IP Address": "ip_address", "MAC Address": "mac_address", "Description": "description"}, "Interface", "interface"),
    "DHCP Options": lambda c: _child_rows(c, c.config.dhcp_servers, "options", "dhcp-option", {"Option Name": "name", "Code": "code", "Vendor Class Identifier": "vendor_class_identifier", "Inherited": "inherited", "Value Type": "value_type", "IP Values": "ip_values", "ASCII Values": "ascii_values", "Hex Values": "hex_values"}, "Interface", "interface"),
    "SD-WAN Interface Bindings": _sdwan_interface_binding_rows,
    "GP Portal Client Configs": lambda c: _child_rows(c, c.config.globalprotect_portals, "client_configs", "globalprotect-portal-client-config", {"Config Name": "name", "Internal Host Detection IP": "internal_host_detection_ip", "Internal Host Detection Hostname": "internal_host_detection_hostname", "Authentication Override": "authentication_override", "Agent UI Settings": "agent_ui_settings", "HIP Collection Settings": "hip_collection_settings", "Agent Configuration": "agent_configuration", "GP App Configuration": "app_configuration"}, "Portal"),
    "GP Portal Gateway Entries": _portal_gateway_rows,
    "GP Clientless VPN": _clientless_vpn_rows,
    "GP Gateway Client Auth": lambda c: _child_rows(c, c.config.globalprotect_gateways, "client_authentication", "globalprotect-gateway-client-auth", {"Auth Name": "name", "OS": "operating_system", "Authentication Profile": "authentication_profile", "Auto Retrieve Passcode": "auto_retrieve_passcode"}, "Gateway"),
    "GP Remote User Tunnels": lambda c: _child_rows(c, c.config.globalprotect_gateways, "remote_user_tunnels", "globalprotect-remote-user-tunnel", {"Config Name": "name", "IP Pools": "ip_pools", "Authentication Server IP Pools": "authentication_server_ip_pools", "Split Tunneling": "split_tunneling", "No Direct Access To Local Network": "no_direct_access_to_local_network", "Retrieve Framed IP": "retrieve_framed_ip"}, "Gateway"),
}
