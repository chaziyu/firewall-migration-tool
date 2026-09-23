"""Typed, read-only Check Point reference resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from ..model.common import CheckPointObjectReference, CheckPointSourceObject
from ..model.source import CheckPointConfig


class CPReferenceKind(str, Enum):
    HOST = "host"; NETWORK = "network"; ADDRESS_RANGE = "address_range"; ADDRESS = "address"
    GROUP = "group"; GROUP_WITH_EXCLUSION = "group_with_exclusion"; SERVICE = "service"; SERVICE_GROUP = "service_group"
    TIME = "time"; TIME_GROUP = "time_group"; SECURITY_ZONE = "security_zone"; USER = "user"; USER_GROUP = "user_group"
    ACCESS_ROLE = "access_role"; PERMISSION_PROFILE = "permission_profile"; ADMINISTRATOR = "administrator"; GATEWAY = "gateway"; CLUSTER = "cluster"
    INTEROPERABLE_DEVICE = "interoperable_device"; VPN_COMMUNITY = "vpn_community"; VPN_DOMAIN = "vpn_domain"
    POLICY_PACKAGE = "policy_package"; ACCESS_LAYER = "access_layer"; ACCESS_SECTION = "access_section"; ACCESS_RULE = "access_rule"
    THREAT_PROFILE = "threat_profile"; THREAT_LAYER = "threat_layer"; THREAT_RULE = "threat_rule"; HTTPS_INSPECTION_RULE = "https_inspection_rule"


@dataclass(frozen=True, slots=True)
class CPResolvedReference:
    reference: str; target: CheckPointSourceObject | None; kind: CPReferenceKind | None; scope: str | None
    status: str = "resolved"; source_field: str | None = None


@dataclass(frozen=True, slots=True)
class CPBrokenReference:
    source: Any | None; source_field: str; reference: str; expected_kinds: tuple[CPReferenceKind, ...] = ()
    status: str = "missing"; scope: str | None = None; message: str | None = None


@dataclass(frozen=True, slots=True)
class CPDuplicateObject:
    key: str; kind: CPReferenceKind | None; scope: str | None; objects: tuple[CheckPointSourceObject, ...]


@dataclass(frozen=True, slots=True)
class CPMembership:
    owner: CheckPointSourceObject; source_field: str; member_reference: str
    resolved_target: CheckPointSourceObject | None; resolved_kind: CPReferenceKind | None; scope: str | None
    status: str = "resolved"; issue: CPBrokenReference | None = None


@dataclass(frozen=True, slots=True)
class CPReferenceResolution:
    resolved: tuple[CPResolvedReference, ...] = (); broken: tuple[CPBrokenReference, ...] = ()


CPRelationshipIssue = CPBrokenReference


def _scope(item: CheckPointSourceObject) -> str | None:
    return item.domain_uid or item.domain or "global"


def _key(value: Any) -> str | None:
    if isinstance(value, dict): return value.get("uid") or value.get("name")
    if isinstance(value, CheckPointObjectReference): return value.uid or value.name
    value = getattr(value, "uid", None) or getattr(value, "name", None) or value
    return str(value) if value not in (None, "") else None


_FIELDS = {
    "hosts": CPReferenceKind.HOST, "networks": CPReferenceKind.NETWORK, "address_ranges": CPReferenceKind.ADDRESS_RANGE,
    "dns_domains": CPReferenceKind.ADDRESS, "wildcard_addresses": CPReferenceKind.ADDRESS, "dynamic_addresses": CPReferenceKind.ADDRESS,
    "updatable_objects": CPReferenceKind.ADDRESS, "groups": CPReferenceKind.GROUP, "groups_with_exclusion": CPReferenceKind.GROUP_WITH_EXCLUSION,
    "services": CPReferenceKind.SERVICE, "service_groups": CPReferenceKind.SERVICE_GROUP, "times": CPReferenceKind.TIME,
    "time_groups": CPReferenceKind.TIME_GROUP, "security_zones": CPReferenceKind.SECURITY_ZONE, "users": CPReferenceKind.USER,
    "user_groups": CPReferenceKind.USER_GROUP, "access_roles": CPReferenceKind.ACCESS_ROLE, "permission_profiles": CPReferenceKind.PERMISSION_PROFILE,
    "administrators": CPReferenceKind.ADMINISTRATOR, "gateways": CPReferenceKind.GATEWAY, "clusters": CPReferenceKind.CLUSTER,
    "interoperable_devices": CPReferenceKind.INTEROPERABLE_DEVICE, "vpn_communities": CPReferenceKind.VPN_COMMUNITY,
    "vpn_domains": CPReferenceKind.VPN_DOMAIN, "policy_packages": CPReferenceKind.POLICY_PACKAGE, "access_layers": CPReferenceKind.ACCESS_LAYER,
    "access_sections": CPReferenceKind.ACCESS_SECTION, "access_rules": CPReferenceKind.ACCESS_RULE, "threat_profiles": CPReferenceKind.THREAT_PROFILE,
    "threat_layers": CPReferenceKind.THREAT_LAYER, "threat_rules": CPReferenceKind.THREAT_RULE, "https_inspection_rules": CPReferenceKind.HTTPS_INSPECTION_RULE,
}


@dataclass(slots=True)
class CPReferenceIndex:
    objects: dict[CPReferenceKind, tuple[CheckPointSourceObject, ...]] = field(default_factory=dict)
    by_uid: dict[str, CheckPointSourceObject] = field(default_factory=dict)
    by_name: dict[tuple[str | None, str], tuple[CheckPointSourceObject, ...]] = field(default_factory=dict)
    kinds_by_object: dict[int, CPReferenceKind] = field(default_factory=dict)
    duplicates: list[CPDuplicateObject] = field(default_factory=list)
    memberships: tuple[CPMembership, ...] = ()

    def kind_of(self, target: Any) -> CPReferenceKind | None: return self.kinds_by_object.get(id(target))

    def resolve(self, value: Any, *, owner: Any | None = None, expected_kinds: Iterable[CPReferenceKind] = (), source_field: str | None = None):
        key = _key(value); expected = tuple(expected_kinds); scope = _scope(owner) if isinstance(owner, CheckPointSourceObject) else None
        if not key or key.casefold() in {"any", "original"}:
            return CPResolvedReference(key or "", None, None, scope, "source_only", source_field)
        exact = self.by_uid.get(key)
        if exact is not None and (not expected or self.kind_of(exact) in expected): candidates = [exact]
        elif exact is not None: return CPBrokenReference(owner, source_field or "", key, expected, "wrong_type", scope)
        else: candidates = [item for item in self.by_name.get((scope, key), ()) if not expected or self.kind_of(item) in expected]
        if len(candidates) == 1:
            target = candidates[0]; return CPResolvedReference(key, target, self.kind_of(target), scope, "resolved", source_field)
        status = "ambiguous" if candidates else "cross_scope" if any(name == key for _, name in self.by_name) else "missing"
        return CPBrokenReference(owner, source_field or "", key, expected, status, scope)


def _records(config: CheckPointConfig):
    for field_name, kind in _FIELDS.items():
        for item in getattr(config, field_name, ()):
            if isinstance(item, CheckPointSourceObject): yield kind, item


def build_reference_index(config: CheckPointConfig) -> CPReferenceIndex:
    index = CPReferenceIndex(); by_name: dict[tuple[str | None, str], list[CheckPointSourceObject]] = {}; by_uid: dict[str, list[CheckPointSourceObject]] = {}; by_kind = {}
    for kind, item in _records(config):
        by_kind.setdefault(kind, []).append(item); index.kinds_by_object[id(item)] = kind
        if item.uid: by_uid.setdefault(item.uid, []).append(item)
        if item.name: by_name.setdefault((_scope(item), item.name), []).append(item)
    index.objects = {kind: tuple(items) for kind, items in by_kind.items()}
    index.by_uid = {uid: items[0] for uid, items in by_uid.items() if len(items) == 1}
    index.by_name = {key: tuple(items) for key, items in by_name.items()}
    index.duplicates = [CPDuplicateObject(uid, index.kind_of(items[0]), _scope(items[0]), tuple(items)) for uid, items in by_uid.items() if len(items) > 1]
    index.duplicates += [CPDuplicateObject(name, index.kind_of(items[0]), scope, tuple(items)) for (scope, name), items in by_name.items() if len(items) > 1]
    return index


def _membership(owner, field: str, values, index: CPReferenceIndex, kinds) -> tuple[CPMembership, ...]:
    result = []
    for value in values or ():
        if value in (None, ""): continue
        resolution = index.resolve(value, owner=owner, expected_kinds=kinds, source_field=field)
        if isinstance(resolution, CPResolvedReference): result.append(CPMembership(owner, field, resolution.reference, resolution.target, resolution.kind, resolution.scope, resolution.status))
        else: result.append(CPMembership(owner, field, resolution.reference, None, None, resolution.scope, resolution.status, resolution))
    return tuple(result)


def build_memberships(config: CheckPointConfig, index: CPReferenceIndex) -> tuple[CPMembership, ...]:
    result = []
    specs = [
        *((item, "members", item.members, (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS, CPReferenceKind.GROUP)) for item in config.groups),
        *((item, "include", (item.include,), (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS, CPReferenceKind.GROUP)) for item in config.groups_with_exclusion),
        *((item, "except_", (item.except_,), (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS, CPReferenceKind.GROUP)) for item in config.groups_with_exclusion),
        *((item, "members", item.members, (CPReferenceKind.SERVICE, CPReferenceKind.SERVICE_GROUP)) for item in config.service_groups),
        *((item, "members", item.members, (CPReferenceKind.TIME, CPReferenceKind.TIME_GROUP)) for item in config.time_groups),
        *((item, "members", item.members, (CPReferenceKind.USER, CPReferenceKind.USER_GROUP)) for item in config.user_groups),
        *((item, "users", item.users, (CPReferenceKind.USER,)) for item in config.user_groups),
        *((item, "members", item.members, (CPReferenceKind.GATEWAY, CPReferenceKind.CLUSTER, CPReferenceKind.INTEROPERABLE_DEVICE)) for item in config.vpn_domains),
    ]
    for owner, field, values, kinds in specs: result.extend(_membership(owner, field, values, index, kinds))
    return tuple(result)


def collect_broken_references(config: CheckPointConfig, index: CPReferenceIndex | None = None) -> tuple[CPBrokenReference, ...]:
    index = index or build_reference_index(config); broken = []
    rule_fields = {
        "source": (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS, CPReferenceKind.GROUP),
        "destination": (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS, CPReferenceKind.GROUP),
        "service": (CPReferenceKind.SERVICE, CPReferenceKind.SERVICE_GROUP), "services_and_applications": (CPReferenceKind.SERVICE, CPReferenceKind.SERVICE_GROUP),
        "install_on": (CPReferenceKind.GATEWAY, CPReferenceKind.CLUSTER, CPReferenceKind.INTEROPERABLE_DEVICE), "time": (CPReferenceKind.TIME, CPReferenceKind.TIME_GROUP),
        "original_source": (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS, CPReferenceKind.GROUP),
        "original_destination": (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS, CPReferenceKind.GROUP),
        "original_service": (CPReferenceKind.SERVICE, CPReferenceKind.SERVICE_GROUP), "translated_source": (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS, CPReferenceKind.GROUP),
        "translated_destination": (CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE, CPReferenceKind.ADDRESS, CPReferenceKind.GROUP), "translated_service": (CPReferenceKind.SERVICE, CPReferenceKind.SERVICE_GROUP),
    }
    for owner in (*config.access_rules, *config.nat_rules, *config.threat_rules, *config.https_inspection_rules):
        for field, expected in rule_fields.items():
            for value in getattr(owner, field, ()) or ():
                item = index.resolve(value, owner=owner, expected_kinds=expected, source_field=field)
                if isinstance(item, CPBrokenReference): broken.append(item)
    specs = [
        *((item, "access_layers", item.access_layers, (CPReferenceKind.ACCESS_LAYER,)) for item in config.policy_packages),
        *((item, "permission_profiles", item.permission_profiles, (CPReferenceKind.PERMISSION_PROFILE,)) for item in config.administrators),
        *((item, "groups", item.groups, (CPReferenceKind.USER_GROUP,)) for item in config.users),
        *((item, "networks", item.networks, (CPReferenceKind.ADDRESS, CPReferenceKind.HOST, CPReferenceKind.NETWORK, CPReferenceKind.ADDRESS_RANGE)) for item in config.access_roles),
        *((item, "users", item.users, (CPReferenceKind.USER,)) for item in config.access_roles),
        *((item, "groups", item.groups, (CPReferenceKind.USER_GROUP,)) for item in config.access_roles),
    ]
    for owner, field, values, kinds in specs:
        for value in values or ():
            item = index.resolve(value, owner=owner, expected_kinds=kinds, source_field=field)
            if isinstance(item, CPBrokenReference): broken.append(item)
    broken.extend(edge.issue for edge in build_memberships(config, index) if edge.issue)
    return tuple(broken)


def build_reference_views(config: CheckPointConfig):
    index = build_reference_index(config); memberships = {}
    for edge in build_memberships(config, index):
        key = edge.owner.uid or f"{_scope(edge.owner)}:{edge.owner.name}"; memberships.setdefault(key, []).append(edge.member_reference)
    return index.by_uid, index.by_name, {key: tuple(value) for key, value in memberships.items()}, tuple({"command": getattr(item.source, "command", None), "uid": getattr(item.source, "uid", None), "reference": item.reference} for item in collect_broken_references(config, index))


__all__ = ["CPBrokenReference", "CPDuplicateObject", "CPMembership", "CPReferenceIndex", "CPReferenceKind", "CPReferenceResolution", "CPRelationshipIssue", "CPResolvedReference", "build_memberships", "build_reference_index", "build_reference_views", "collect_broken_references"]
