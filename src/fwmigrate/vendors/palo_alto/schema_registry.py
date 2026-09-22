"""Declarative PAN-OS XML path and primitive source-field metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True, slots=True)
class PANPathSpec:
    name: str
    path_suffix: tuple[str, ...]
    scalar_fields: frozenset[str] = field(default_factory=frozenset)
    member_list_fields: frozenset[str] = field(default_factory=frozenset)
    entry_list_fields: frozenset[str] = field(default_factory=frozenset)
    nested_fields: frozenset[str] = field(default_factory=frozenset)
    field_map: Mapping[str, str] = field(default_factory=dict)
    allowed_scope_kinds: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.name or not self.path_suffix or any(not item for item in self.path_suffix):
            raise ValueError("PAN-OS path specs require a non-empty name and path suffix.")
        categories = (self.scalar_fields, self.member_list_fields, self.entry_list_fields, self.nested_fields)
        for left, right in ((categories[i], categories[j]) for i in range(4) for j in range(i + 1, 4)):
            overlap = left & right
            if overlap:
                raise ValueError(f"{self.name!r}: fields {sorted(overlap)!r} have incompatible categories")
        known = set().union(*categories)
        if set(self.field_map) - known:
            raise ValueError(f"{self.name!r}: field mappings must refer to registered fields")
        if any(not source or not target for source, target in self.field_map.items()):
            raise ValueError(f"{self.name!r}: field mappings cannot contain empty names")
        if len(set(self.field_map.values())) != len(self.field_map):
            raise ValueError(f"{self.name!r}: field mappings must have unique model targets")
        object.__setattr__(self, "field_map", MappingProxyType(dict(self.field_map)))


_REGISTRY: dict[str, PANPathSpec] = {}


def register_path(spec: PANPathSpec) -> None:
    if spec.name in _REGISTRY:
        raise ValueError(f"PAN-OS path already registered: {spec.name!r}")
    if any(item.path_suffix == spec.path_suffix for item in _REGISTRY.values()):
        raise ValueError(f"PAN-OS path suffix already registered: {spec.path_suffix!r}")
    _REGISTRY[spec.name] = spec


def get_path_spec(name: str) -> PANPathSpec | None:
    return _REGISTRY.get(name)


def match_path_spec(path: tuple[str, ...]) -> PANPathSpec | None:
    matches = [spec for spec in _REGISTRY.values() if path[-len(spec.path_suffix):] == spec.path_suffix]
    match = max(matches, key=lambda spec: len(spec.path_suffix), default=None)
    if match is None:
        return None
    ancestors = [
        spec
        for end in range(1, len(path))
        for spec in _REGISTRY.values()
        if path[:end][-len(spec.path_suffix):] == spec.path_suffix
    ]
    if ancestors and not (
        match.name == "interface_unit"
        and any(spec.name.startswith("interface_") for spec in ancestors)
    ):
        return None
    return match


def registered_paths() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def _spec(name: str, suffix: tuple[str, ...], *, scalar=(), members=(), entries=(), nested=(), field_map=None) -> None:
    register_path(PANPathSpec(name, suffix, frozenset(scalar), frozenset(members), frozenset(entries), frozenset(nested), field_map or {}))


_spec("address", ("address", "entry"), scalar=("ip-netmask", "ip-range", "ip-wildcard", "fqdn", "description"), members=("tag",), field_map={"ip-netmask": "ip_netmask", "ip-range": "ip_range", "ip-wildcard": "ip_wildcard", "tag": "tags"})
_spec("address_group", ("address-group", "entry"), scalar=("description",), nested=("static", "dynamic"), members=("tag",), field_map={"static": "static_members", "dynamic": "dynamic_filter", "tag": "tags"})
_spec("service", ("service", "entry"), scalar=("description",), members=("tag",), nested=("protocol", "protocol/tcp", "protocol/udp", "protocol/*/port", "protocol/*/source-port", "protocol/*/override"), field_map={"tag": "tags"})
_spec("service_group", ("service-group", "entry"), scalar=("description",), members=("members", "tag"), field_map={"tag": "tags"})
_spec("schedule", ("schedule", "entry"), nested=("schedule-type", "schedule-type/recurring", "schedule-type/recurring/daily", "schedule-type/recurring/weekly", "schedule-type/non-recurring"), field_map={"schedule-type": "recurring"})
_spec("security_rule", ("security", "rules", "entry"), members=("from", "to", "source", "destination", "source-user", "application", "service", "category", "source-hip", "destination-hip", "tag", "saas-user-list", "saas-tenant-list"), scalar=("negate-source", "negate-destination", "schedule", "action", "rule-type", "description", "group-tag", "log-start", "log-end", "log-setting", "disabled", "disable-inspect", "disable-server-response-inspection"), nested=("profile-setting",), field_map={"from": "from_zones", "to": "to_zones", "source-user": "source_user", "source-hip": "source_hip", "destination-hip": "destination_hip", "tag": "tags", "group-tag": "group_tag", "negate-source": "negate_source", "negate-destination": "negate_destination", "log-start": "log_start", "log-end": "log_end", "log-setting": "log_setting", "rule-type": "rule_type", "disable-inspect": "disable_inspect", "disable-server-response-inspection": "disable_server_response_inspection", "saas-user-list": "saas_user_list", "saas-tenant-list": "saas_tenant_list", "profile-setting": "profile_setting"})
_spec("default_security_rule", ("default-security-rules", "rules", "entry"), members=("tag",), scalar=("action", "disabled", "log-start", "log-end", "log-setting", "description", "group-tag", "disable-server-response-inspection", "icmp-unreachable"), nested=("option", "profile-setting"), field_map={"tag": "tags", "group-tag": "group_tag", "log-start": "log_start", "log-end": "log_end", "log-setting": "log_setting", "disable-server-response-inspection": "disable_server_response_inspection", "profile-setting": "profile_setting", "icmp-unreachable": "icmp_unreachable"})
_spec("nat_rule", ("nat", "rules", "entry"), members=("from", "to", "source", "destination"), scalar=("service", "disabled", "active-active-device-binding"), nested=("source-translation", "source-translation/dynamic-ip-and-port", "source-translation/static-ip", "destination-translation", "dynamic-destination-translation", "dynamic-destination-translation/distribution", "dynamic-destination-translation/dns-rewrite"), field_map={"from": "from_zones", "to": "to_zones", "active-active-device-binding": "active_active_device_binding", "source-translation": "source_translation", "destination-translation": "destination_translation", "dynamic-destination-translation": "dynamic_destination_translation"})
_spec("interface_import", ("import", "network", "interface"), members=("member",), field_map={"member": "interfaces"})
_spec("interface_unit", ("units", "entry"), scalar=("tag", "interface-management-profile"), nested=("ip", "ipv6"), field_map={"interface-management-profile": "management_profile", "ip": "ipv4_addresses", "ipv6": "ipv6_addresses"})
for _family in ("ethernet", "aggregate-ethernet", "loopback", "tunnel", "vlan"):
    _spec(f"interface_{_family}", (_family, "entry"), scalar=("comment", "link-state", "speed", "duplex", "vlan", "lldp"), nested=("layer3", "layer2", "virtual-wire", "tap", "ha", "decrypt-mirror"), field_map={"link-state": "link_state", "lldp": "lldp_enable"})
_spec("virtual_router", ("virtual-router", "entry"), members=("interface",), nested=("static-routes", "protocol", "bgp", "ospf", "ospfv3", "rip", "redistribution-profile"), field_map={"interface": "interfaces", "static-routes": "static_routes", "bgp": "bgp", "ospf": "ospf", "ospfv3": "ospfv3", "rip": "rip", "redistribution-profile": "redistribution_profiles"})
_spec("logical_router", ("logical-router", "entry"), nested=("vrf",), field_map={"vrf": "vrfs"})
