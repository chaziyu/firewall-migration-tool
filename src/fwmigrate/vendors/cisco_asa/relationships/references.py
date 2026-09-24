"""Context-scoped, read-only Cisco ASA named-reference lookup."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable


class ASAReferenceKind(str, Enum):
    INTERFACE = "interface"
    TRAFFIC_ZONE = "traffic_zone"
    NETWORK_OBJECT = "network_object"
    NETWORK_GROUP = "network_group"
    SERVICE_OBJECT = "service_object"
    SERVICE_GROUP = "service_group"
    PROTOCOL_GROUP = "protocol_group"
    ICMP_GROUP = "icmp_group"
    ACL = "acl"
    TIME_RANGE = "time_range"
    ROUTE_MAP = "route_map"
    TRACK = "route_tracking"
    SLA_MONITOR = "sla_monitor"
    CLASS_MAP = "class_map"
    POLICY_MAP = "policy_map"
    INSPECTION_POLICY_MAP = "inspection_policy_map"
    TCP_MAP = "tcp_map"
    LOCAL_USER = "local_user"
    USER_GROUP = "user_group"
    SECURITY_GROUP = "security_group"
    AAA_SERVER_GROUP = "aaa_server_group"
    VPN_ADDRESS_POOL = "vpn_address_pool"
    GROUP_POLICY = "group_policy"
    TUNNEL_GROUP = "tunnel_group"
    CRYPTO_MAP = "crypto_map"
    IPSEC_TRANSFORM_SET = "ipsec_transform_set"
    IKEV2_PROPOSAL = "ikev2_proposal"
    TRUSTPOINT = "trustpoint"
    IKE_POLICY = "ike_policy"
    DNS_SERVER_GROUP = "dns_server_group"


class ASAReferenceStatus(str, Enum):
    RESOLVED = "RESOLVED"
    UNRESOLVED = "UNRESOLVED"
    AMBIGUOUS = "AMBIGUOUS"
    SOURCE_SELECTOR = "SOURCE_SELECTOR"


@dataclass(frozen=True, slots=True)
class ASAResolvedReference:
    source_context: str | None
    reference_kind: ASAReferenceKind
    source_name: str
    status: ASAReferenceStatus
    target: Any = None
    candidates: tuple[Any, ...] = ()


@dataclass(frozen=True, slots=True)
class ASAReferenceIssue:
    source_context: str | None
    reference_kind: ASAReferenceKind
    source_object: str
    reference_name: str
    status: ASAReferenceStatus
    reason: str
    reference_context: str | None = None

    @property
    def resolved(self) -> bool:
        return self.status is ASAReferenceStatus.RESOLVED

    @property
    def reference_type(self) -> str:
        return self.reference_kind.value


@dataclass(frozen=True, slots=True)
class ASADuplicateReference:
    source_context: str | None
    reference_kind: ASAReferenceKind
    source_name: str
    candidates: tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class ASAGroupMemberRelationship:
    group: Any
    member: Any
    reference_kind: ASAReferenceKind | None
    reference_name: str | None
    status: ASAReferenceStatus
    target: Any = None


@dataclass(frozen=True, slots=True)
class ASAGroupRelationships:
    members: tuple[ASAGroupMemberRelationship, ...] = ()
    issues: tuple[ASAReferenceIssue, ...] = ()


def source_context_of(item: Any) -> str | None:
    if hasattr(item, "source_context"):
        return getattr(item, "source_context")
    return getattr(item, "source_attributes", {}).get("source_context")


def build_group_relationships(config: Any, references: ASAReferenceIndex) -> ASAGroupRelationships:
    issues = []
    relationships = []
    collections = (
        ("network_groups", {"network_object": ASAReferenceKind.NETWORK_OBJECT,
                            "network_group": ASAReferenceKind.NETWORK_GROUP,
                            "nested_group": ASAReferenceKind.NETWORK_GROUP}),
        ("protocol_groups", {"protocol_group": ASAReferenceKind.PROTOCOL_GROUP}),
        ("icmp_type_groups", {"icmp_group": ASAReferenceKind.ICMP_GROUP}),
        ("user_groups", {"user_group": ASAReferenceKind.USER_GROUP}),
        ("security_groups", {"security_group": ASAReferenceKind.SECURITY_GROUP}),
        ("service_groups", {"service_group": ASAReferenceKind.SERVICE_GROUP,
                            "service_object": ASAReferenceKind.SERVICE_OBJECT}),
    )
    for collection, member_kinds in collections:
        for group in getattr(config, collection, ()):
            context = source_context_of(group)
            for member in getattr(group, "member_entries", ()):
                get = member.get if isinstance(member, dict) else lambda key, default=None: getattr(member, key, default)
                kind = member_kinds.get(get("type"))
                name = get("value")
                if kind is None or not name:
                    relationships.append(ASAGroupMemberRelationship(
                        group, member, kind, name, ASAReferenceStatus.SOURCE_SELECTOR,
                    ))
                    continue
                result = references.resolve(context, kind, str(name))
                relationships.append(ASAGroupMemberRelationship(
                    group, member, kind, str(name), result.status, result.target,
                ))
                if result.status is not ASAReferenceStatus.RESOLVED:
                    issues.append(ASAReferenceIssue(
                        context, kind, group.name, str(name), result.status,
                        f"Unresolved {kind.value.replace('_', ' ')} reference", "group-member",
                    ))
    return ASAGroupRelationships(tuple(relationships), tuple(issues))


class ASAReferenceIndex:
    """Indexes explicit source objects by context, family, and source name."""

    def __init__(self) -> None:
        self._items: dict[tuple[str | None, ASAReferenceKind, str], list[Any]] = {}
        self._interfaces_casefold: dict[tuple[str | None, str], list[Any]] = {}
        self._interface_names: dict[tuple[str | None, str], list[str]] = {}

    def __eq__(self, other: object) -> bool:
        return (isinstance(other, ASAReferenceIndex)
                and self._items == other._items
                and self._interfaces_casefold == other._interfaces_casefold)

    def register(self, context: str | None, kind: ASAReferenceKind, name: str, target: Any) -> None:
        if not name:
            return
        key = (context, kind, name)
        self._items.setdefault(key, []).append(target)
        if kind is ASAReferenceKind.INTERFACE:
            key = (context, name.casefold())
            self._interfaces_casefold.setdefault(key, []).append(target)
            self._interface_names.setdefault(key, []).append(name)

    def register_interface_alias(self, context: str | None, name: str, target: Any) -> None:
        self.register(context, ASAReferenceKind.INTERFACE, name, target)

    def resolve(self, context: str | None, kind: ASAReferenceKind, name: str) -> ASAResolvedReference:
        candidates = (self._interfaces_casefold.get((context, name.casefold()), ())
                     if kind is ASAReferenceKind.INTERFACE else self._items.get((context, kind, name), ()))
        candidates = tuple(candidates)
        status = (ASAReferenceStatus.UNRESOLVED if not candidates else
                  ASAReferenceStatus.RESOLVED if len(candidates) == 1 else ASAReferenceStatus.AMBIGUOUS)
        return ASAResolvedReference(context, kind, name, status, candidates[0] if len(candidates) == 1 else None, candidates)

    @property
    def duplicates(self) -> tuple[ASADuplicateReference, ...]:
        duplicates = [ASADuplicateReference(context, kind, name, tuple(items))
                      for (context, kind, name), items in self._items.items() if len(items) > 1]
        exact = {(item.source_context, item.reference_kind, item.source_name) for item in duplicates}
        for (context, folded), items in self._interfaces_casefold.items():
            name = self._interface_names[(context, folded)][0]
            if len(items) > 1 and (context, ASAReferenceKind.INTERFACE, name) not in exact:
                duplicates.append(ASADuplicateReference(context, ASAReferenceKind.INTERFACE, name, tuple(items)))
        return tuple(duplicates)

    @property
    def contexts(self) -> frozenset[str | None]:
        return frozenset(context for context, _, _ in self._items)

    def items(self, context: str | None, kind: ASAReferenceKind) -> tuple[Any, ...]:
        return tuple(target for (item_context, item_kind, _), targets in self._items.items()
                     if item_context == context and item_kind is kind for target in targets)

    def group_address_families(self, context: str | None) -> dict[str, str | None]:
        objects = {item.name: item for item in self.items(context, ASAReferenceKind.NETWORK_OBJECT)}
        groups = {item.name: item for item in self.items(context, ASAReferenceKind.NETWORK_GROUP)}
        resolved: dict[str, str | None] = {}
        visiting: set[str] = set()

        def visit(name: str) -> str | None:
            if name in resolved: return resolved[name]
            if name in visiting: return None
            group = groups[name]; visiting.add(name); families: set[str] = set(); uncertain = False
            for entry in getattr(group, "member_entries", ()):
                get = entry.get if isinstance(entry, dict) else lambda key, default=None: getattr(entry, key, default)
                kind = get("type"); value = get("value", "")
                if kind in {"host", "inline_network"}:
                    family = get("address_family")
                elif kind == "network_object":
                    target = objects.get(value); family = getattr(target, "address_family", None)
                    uncertain |= target is None or family is None
                elif kind == "network_group":
                    family = visit(value) if value in groups else None
                    uncertain |= value not in groups or family is None
                else: continue
                if family == "mixed": families.update(("ipv4", "ipv6"))
                elif family in {"ipv4", "ipv6"}: families.add(family)
                else: uncertain = True
            visiting.remove(name)
            result = None if uncertain else next(iter(families)) if len(families) == 1 else "mixed" if families else None
            resolved[name] = result
            return result

        for name in groups: visit(name)
        return resolved

    def scoped(self, context: str | None) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for (item_context, kind, name), items in self._items.items():
            if item_context == context:
                result.setdefault(kind.value, {})[name] = items[0]
        return result


def build_asa_reference_index(config: Any) -> ASAReferenceIndex:
    index = ASAReferenceIndex()

    def register(items: Iterable[Any], kind: ASAReferenceKind, *, attr: str = "name") -> None:
        for item in items:
            name = getattr(item, attr, None)
            if name:
                index.register(source_context_of(item), kind, str(name), item)

    collections = (
        ("interfaces", ASAReferenceKind.INTERFACE), ("traffic_zones", ASAReferenceKind.TRAFFIC_ZONE),
        ("network_objects", ASAReferenceKind.NETWORK_OBJECT), ("network_groups", ASAReferenceKind.NETWORK_GROUP),
        ("service_objects", ASAReferenceKind.SERVICE_OBJECT), ("service_groups", ASAReferenceKind.SERVICE_GROUP),
        ("protocol_groups", ASAReferenceKind.PROTOCOL_GROUP), ("icmp_type_groups", ASAReferenceKind.ICMP_GROUP),
        ("security_groups", ASAReferenceKind.SECURITY_GROUP),
        ("time_ranges", ASAReferenceKind.TIME_RANGE), ("route_maps", ASAReferenceKind.ROUTE_MAP),
        ("ike_policies", ASAReferenceKind.IKE_POLICY), ("ikev2_proposals", ASAReferenceKind.IKEV2_PROPOSAL),
        ("ipsec_transform_sets", ASAReferenceKind.IPSEC_TRANSFORM_SET), ("vpn_address_pools", ASAReferenceKind.VPN_ADDRESS_POOL),
        ("crypto_maps", ASAReferenceKind.CRYPTO_MAP), ("tunnel_groups", ASAReferenceKind.TUNNEL_GROUP),
        ("group_policies", ASAReferenceKind.GROUP_POLICY), ("class_maps", ASAReferenceKind.CLASS_MAP),
        ("tcp_maps", ASAReferenceKind.TCP_MAP), ("dns_server_groups", ASAReferenceKind.DNS_SERVER_GROUP),
        ("aaa_server_groups", ASAReferenceKind.AAA_SERVER_GROUP), ("local_users", ASAReferenceKind.LOCAL_USER),
        ("user_groups", ASAReferenceKind.USER_GROUP),
    )
    for attr, kind in collections:
        register(getattr(config, attr, ()), kind)
    for item in getattr(config, "local_users", ()):
        username = getattr(item, "username", None)
        if username and username != getattr(item, "name", None):
            index.register(source_context_of(item), ASAReferenceKind.LOCAL_USER, username, item)
    for item in getattr(config, "interfaces", ()):
        if getattr(item, "nameif", None) and item.nameif.casefold() != item.name.casefold():
            index.register_interface_alias(source_context_of(item), item.nameif, item)
    acl_names = {(source_context_of(item), item.acl_name) for item in getattr(config, "access_rules", ())}
    for context, name in acl_names:
        index.register(context, ASAReferenceKind.ACL, name, name)
    for kind, items, attr in ((ASAReferenceKind.TRACK, getattr(config, "tracks", ()), "track_id"),
                              (ASAReferenceKind.SLA_MONITOR, getattr(config, "sla_monitors", ()), "sla_id")):
        for item in items:
            index.register(source_context_of(item), kind, str(getattr(item, attr)), item)
    for record in getattr(config, "trustpoint_records", ()):
        index.register(source_context_of(record), ASAReferenceKind.TRUSTPOINT, record.name, record)
    if not getattr(config, "trustpoint_records", ()):
        # Legacy names have no context provenance; permit them only in system scope.
        for name in getattr(config, "trustpoints", ()):
            index.register(None, ASAReferenceKind.TRUSTPOINT, name, name)
    for item in getattr(config, "policy_maps", ()):
        kind = ASAReferenceKind.INSPECTION_POLICY_MAP if getattr(item, "policy_map_type", None) == "inspect" else ASAReferenceKind.POLICY_MAP
        index.register(source_context_of(item), kind, item.name, item)
    for item in getattr(config, "aaa_records", ()):
        raw = getattr(item, "source_attributes", {}).get("raw_command", "")
        if raw.lower().startswith("aaa-server "):
            parts = raw.split()
            if len(parts) > 1 and not index.resolve(source_context_of(item), ASAReferenceKind.AAA_SERVER_GROUP, parts[1]).candidates:
                index.register(source_context_of(item), ASAReferenceKind.AAA_SERVER_GROUP, parts[1], item)
    return index
