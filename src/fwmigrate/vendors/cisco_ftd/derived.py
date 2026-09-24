"""FTD relationships and read-only views over vendor source state."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .model import CiscoFTDConfig


class FTDReferenceKind(str, Enum):
    NETWORK_ADDRESS = "NETWORK_ADDRESS"
    NETWORK_GROUP = "NETWORK_GROUP"
    SERVICE_OBJECT = "SERVICE_OBJECT"
    SERVICE_GROUP = "SERVICE_GROUP"
    SECURITY_ZONE = "SECURITY_ZONE"
    INTERFACE = "INTERFACE"
    TIME_RANGE = "TIME_RANGE"
    REALM = "REALM"
    REALM_USER = "REALM_USER"
    REALM_USER_GROUP = "REALM_USER_GROUP"
    INTRUSION_POLICY = "INTRUSION_POLICY"
    FILE_POLICY = "FILE_POLICY"
    VARIABLE_SET = "VARIABLE_SET"
    SLA_MONITOR = "SLA_MONITOR"
    VPN_ENDPOINT = "VPN_ENDPOINT"
    IKE_POLICY = "IKE_POLICY"
    IPSEC_PROPOSAL = "IPSEC_PROPOSAL"
    APPLICATION = "APPLICATION"
    URL_CATEGORY = "URL_CATEGORY"
    VLAN_OBJECT = "VLAN_OBJECT"


@dataclass(frozen=True)
class FTDReferenceIssue:
    owner: str
    field: str
    reference: str
    source_plane: str
    source_context: str | None = None
    domain_id: str | None = None
    status: str = "UNRESOLVED"
    reference_id: str | None = None
    reference_name: str | None = None
    expected_kinds: tuple[str, ...] = ()
    found_kinds: tuple[str, ...] = ()
    scope: str | None = None
    reason: str = "unresolved"


@dataclass(frozen=True)
class FTDDerivedViews:
    resolved_references: tuple[dict[str, str | None], ...] = ()
    zone_interfaces: dict[str, tuple[str, ...]] = field(default_factory=dict)
    acp_relationships: tuple[dict[str, Any], ...] = ()
    nat_relationships: tuple[dict[str, Any], ...] = ()
    unresolved_references: tuple[FTDReferenceIssue, ...] = ()
    source_plane_completeness: dict[str, str] = field(default_factory=dict)
    identity_relationships: tuple[dict[str, Any], ...] = ()
    vpn_relationships: tuple[dict[str, Any], ...] = ()


def build_ftd_derived_views(config: CiscoFTDConfig) -> FTDDerivedViews:
    by_id: dict[tuple[str | None, FTDReferenceKind, str], list[Any]] = {}
    by_name: dict[tuple[str | None, FTDReferenceKind, str], list[Any]] = {}

    def key_scope(record: Any) -> str:
        return record.domain_id or f"{record.source_plane}:{record.source_context or ''}"

    def register(kind: FTDReferenceKind, records: Any) -> None:
        for item in records:
            domain = key_scope(item)
            if item.source_id:
                by_id.setdefault((domain, kind, str(item.source_id)), []).append(item)
            by_name.setdefault((domain, kind, item.name), []).append(item)

    for kind, records in (
        (FTDReferenceKind.NETWORK_ADDRESS, config.network_addresses),
        (FTDReferenceKind.NETWORK_GROUP, config.network_groups),
        (FTDReferenceKind.SERVICE_OBJECT, config.protocol_port_objects),
        (FTDReferenceKind.SERVICE_GROUP, config.port_object_groups),
        (FTDReferenceKind.SECURITY_ZONE, config.security_zones),
        (FTDReferenceKind.INTERFACE, (*config.source_interfaces, *config.device_interfaces)),
        (FTDReferenceKind.TIME_RANGE, config.time_ranges), (FTDReferenceKind.REALM, config.realms),
        (FTDReferenceKind.REALM_USER, (*config.realm_users, *config.local_realm_users)),
        (FTDReferenceKind.REALM_USER_GROUP, config.realm_user_groups),
        (FTDReferenceKind.INTRUSION_POLICY, config.intrusion_policies),
        (FTDReferenceKind.FILE_POLICY, config.file_policies),
        (FTDReferenceKind.VARIABLE_SET, config.variable_sets),
        (FTDReferenceKind.VPN_ENDPOINT, config.s2s_vpn_endpoints),
        (FTDReferenceKind.IKE_POLICY, config.ike_policies),
        (FTDReferenceKind.IPSEC_PROPOSAL, config.ipsec_proposals),
        (FTDReferenceKind.APPLICATION, config.applications),
        (FTDReferenceKind.URL_CATEGORY, config.url_categories),
        (FTDReferenceKind.VLAN_OBJECT, config.vlan_objects),
    ):
        register(kind, records)

    issues: list[FTDReferenceIssue] = []
    resolved: list[dict[str, str | None]] = []

    def identity(value: Any) -> tuple[str | None, str | None]:
        if isinstance(value, dict):
            return (str(value["id"]) if value.get("id") is not None else None,
                    str(value["name"]) if value.get("name") is not None else None)
        if hasattr(value, "source_id"):
            return (str(value.source_id) if value.source_id else None, str(value.name) if value.name else None)
        return (None, str(value)) if value is not None else (None, None)

    def resolve(owner: Any, field_name: str, value: Any, kinds: tuple[FTDReferenceKind, ...], *,
                special: frozenset[str] = frozenset(), scope: str | None = None) -> None:
        ref_id, ref_name = identity(value)
        if ref_id is None and ref_name is None:
            return
        if ref_id is None and ref_name and ref_name.casefold() in special:
            return
        domain = key_scope(owner)
        source_type = getattr(value, "source_type", None)
        if source_type and source_type.casefold() in {"securityzone", "security-zone"}:
            kinds = tuple(dict.fromkeys((*kinds, FTDReferenceKind.SECURITY_ZONE)))
        found = ([item for kind in kinds for item in by_id.get((domain, kind, ref_id), ())] if ref_id else
                 [item for kind in kinds for item in by_name.get((domain, kind, ref_name), ())])
        if scope:
            found = [item for item in found if item.device_id == scope]
        if len(found) == 1:
            match = found[0]
            actual_kind = next(kind for kind in kinds if match in by_id.get((domain, kind, str(match.source_id)), ())
                               or match in by_name.get((domain, kind, match.name), ()))
            resolved.append({"owner": owner.name, "field": field_name, "reference_id": ref_id,
                "reference_name": ref_name, "kind": actual_kind.value, "target_id": match.source_id,
                "target_name": match.name})
            return
        reason, status = "unresolved", "UNRESOLVED"
        if len(found) > 1:
            reason, status = "ambiguous", "AMBIGUOUS"
        else:
            other = [item for kind in FTDReferenceKind if kind not in kinds
                     for item in (by_id.get((domain, kind, ref_id), ()) if ref_id else
                                  by_name.get((domain, kind, ref_name), ()))]
            if other:
                reason, status = "wrong-kind", "WRONG_KIND"
        found_kinds = tuple(kind.value for kind in FTDReferenceKind if
            bool(by_id.get((domain, kind, ref_id), ())) or bool(by_name.get((domain, kind, ref_name), ())))
        issues.append(FTDReferenceIssue(owner.name, field_name, ref_id or ref_name or "", owner.source_plane,
            owner.source_context, owner.domain_id, status, ref_id, ref_name,
            tuple(kind.value for kind in kinds), found_kinds, scope or owner.source_context or owner.source_plane, reason))

    network = (FTDReferenceKind.NETWORK_ADDRESS, FTDReferenceKind.NETWORK_GROUP)
    service = (FTDReferenceKind.SERVICE_OBJECT, FTDReferenceKind.SERVICE_GROUP)
    interface_or_zone = (FTDReferenceKind.INTERFACE, FTDReferenceKind.SECURITY_ZONE)
    any_network = frozenset({"any", "any-ip", "any4", "any6"})
    for group in config.network_groups:
        for member in group.members:
            resolve(group, "members", member, network)
    for group in config.port_object_groups:
        for member in group.members:
            resolve(group, "members", member, service)

    acp_rules = [rule for policy in config.access_control_policies for rule in (policy.rules or [])]
    nat_rules = []
    for policy in config.nat_policies:
        nat_rules.extend((policy, rule, "manual") for rule in (policy.manual_rules_before_auto or []))
        nat_rules.extend((policy, rule, "auto") for rule in (policy.auto_rules or []))
        nat_rules.extend((policy, rule, "manual") for rule in (policy.manual_rules_after_auto or []))
        nat_rules.extend((policy, rule, "manual") for rule in (policy.unclassified_manual_rules or []))
        nat_rules.extend((policy, rule, "fdm") for rule in (policy.rules or []))

    acp_kinds = {
        "source_zones": (FTDReferenceKind.SECURITY_ZONE,), "destination_zones": (FTDReferenceKind.SECURITY_ZONE,),
        "source_networks": network, "destination_networks": network,
        "source_ports": service, "destination_ports": service,
        "source_dynamic_objects": network, "destination_dynamic_objects": network,
        "realm_users": (FTDReferenceKind.REALM_USER,), "users": (FTDReferenceKind.REALM_USER,),
        "user_groups": (FTDReferenceKind.REALM_USER_GROUP,), "applications": (FTDReferenceKind.APPLICATION,),
        "url_categories": (FTDReferenceKind.URL_CATEGORY,), "vlan_tags": (FTDReferenceKind.VLAN_OBJECT,),
    }
    acp_reference_fields = (*acp_kinds, "source_security_group_tags", "destination_security_group_tags",
                            "application_filters", "inline_application_filters")
    for rule in acp_rules:
        for field_name, kinds in acp_kinds.items():
            for value in getattr(rule, field_name) or []:
                resolve(rule, field_name, value, kinds,
                    special=any_network if field_name in {"source_networks", "destination_networks"} else frozenset())
        for field_name, kind in (("realm", FTDReferenceKind.REALM), ("time_range", FTDReferenceKind.TIME_RANGE),
            ("intrusion_policy", FTDReferenceKind.INTRUSION_POLICY), ("variable_set", FTDReferenceKind.VARIABLE_SET),
            ("file_policy", FTDReferenceKind.FILE_POLICY)):
            value = getattr(rule, field_name)
            if value is not None:
                resolve(rule, field_name, value, (kind,))

    for policy, rule, kind in nat_rules:
        for field_name in ("source_interface", "destination_interface"):
            value = getattr(rule, field_name, None)
            if value is not None:
                resolve(rule, field_name, value, interface_or_zone)
        if kind == "fdm":
            pass
        else:
            for field_name in ("original_source", "translated_source", "original_destination", "translated_destination",
                               "original_network", "translated_network", "owning_network"):
                value = getattr(rule, field_name, None)
                if value is not None:
                    resolve(rule, field_name, value, network, special=any_network)
            for field_name in ("original_source_port", "translated_source_port", "original_destination_port",
                "translated_destination_port", "original_source_service", "translated_source_service",
                "original_destination_service", "translated_destination_service"):
                value = getattr(rule, field_name, None)
                if value is not None:
                    resolve(rule, field_name, value, service)

    for route in config.routes:
        for field_name, kinds in (("interface", (FTDReferenceKind.INTERFACE,)), ("destination", network),
            ("gateway", network), ("sla_monitor", (FTDReferenceKind.SLA_MONITOR,))):
            value = getattr(route, field_name, None)
            if value is not None:
                resolve(route, field_name, value, kinds, scope=route.device_id if field_name == "interface" else None)

    zone_interfaces = {zone.name: tuple(ref.name or ref.source_id for ref in (zone.interfaces or []) if ref.name or ref.source_id)
                       for zone in config.security_zones}
    incomplete_interfaces = any(part.name.endswith("/ftd_interfaces") and not part.complete
                                for part in config.collection_metadata.parts)
    interface_records = (*config.source_interfaces, *config.device_interfaces)
    for zone in config.security_zones:
        for ref in zone.interfaces or []:
            device_id = ref.source_attributes.get("device_id") or ref.source_attributes.get("deviceId")
            candidates = [item for item in interface_records if item.name == ref.name]
            if incomplete_interfaces and candidates and not device_id and not ref.source_id:
                issues.append(FTDReferenceIssue(zone.name, "interfaces", ref.name or "", zone.source_plane,
                    zone.source_context, zone.domain_id, "AMBIGUOUS", None, ref.name,
                    (FTDReferenceKind.INTERFACE.value,), (FTDReferenceKind.INTERFACE.value,), None,
                    "incomplete-device-interface-collection"))
                continue
            before = len(issues)
            resolve(zone, "interfaces", ref, (FTDReferenceKind.INTERFACE,), scope=str(device_id) if device_id else None)
            if len(issues) > before and incomplete_interfaces and issues[-1].status == "UNRESOLVED":
                issues.pop()

    expected = {
        "network_objects": "present" if config.network_addresses or config.network_groups else "not_available",
        "security_zones": "present" if config.security_zones else "not_available",
        "interfaces": "present" if config.source_interfaces or config.device_interfaces or config.interfaces else "not_available",
        "acp": "present" if acp_rules else "not_available_from_source_plane",
        "nat": "present" if nat_rules else "not_available_from_source_plane",
        **{key: "present" if getattr(config, field_name) else "not_available_from_source_plane" for field_name, key in (
            ("time_ranges", "time_ranges"), ("intrusion_policies", "intrusion"), ("file_policies", "file_policy"),
            ("decryption_policies", "decryption"), ("dns_policies", "dns"), ("fmc_users", "administration"),
            ("realms", "identity"), ("routes", "routing"), ("dhcp_servers", "dhcp"),
            ("s2s_vpn_topologies", "s2s_vpn"), ("ra_vpn_policies", "ra_vpn"),
            ("native_resources", "sdwan_related_native_resources"))},
    }
    if config.source_plane == "fmc-rest-bundle" and not config.collection_metadata.provided:
        expected["network_objects"] = "unknown"
    if config.source_plane == "fmc-rest-bundle" and not config.collection_metadata.provided:
        expected.update({family: "unknown" for family in ("hosts", "networks", "ranges", "network_objects")})
    if config.collection_metadata.provided:
        state = {"SUCCESS": "present", "EMPTY": "known-empty", "PARTIAL": "partial", "FAILED": "failed"}
        for part in config.collection_metadata.parts:
            expected[f"collection:{part.name}"] = state.get(part.status, "unknown")
        families = {
            "hosts": ("hosts",), "networks": ("networks",), "ranges": ("ranges",),
            "network_objects": ("networkaddresses", "hosts", "networks", "ranges", "networkgroups"),
            "security_zones": ("securityzones",), "interfaces": ("/ftd_interfaces",),
            "acp": ("access_policies", "access_rules/"), "nat": ("nat_policies", "manual_rules/", "auto_rules/"),
            "time_ranges": ("timeranges",), "intrusion": ("intrusionpolicies",),
            "file_policy": ("filepolicies",), "decryption": ("decryptionpolicies",), "dns": ("dnspolicies",),
            "administration": ("fmc_users", "fmc_roles"), "identity": ("realms", "realmusergroups", "realmusers", "localrealmusers"),
            "routing": ("/static_routes",), "dhcp": ("/dhcp_servers",), "s2s_vpn": ("s2svpns",), "ra_vpn": ("ravpns",),
            "sdwan_related_native_resources": ("/pbr_policies", "/ecmp_zones", "/sla_monitors"),
        }
        parts = config.collection_metadata.parts
        for family, names in families.items():
            matching = [part for part in parts if any(part.name == name or part.name.startswith(name) or
                (name.startswith("/") and part.name.endswith(name[1:])) for name in names)]
            if not matching:
                expected[family] = "unknown"
            elif any(part.status == "PARTIAL" for part in matching) or (any(part.status == "FAILED" for part in matching)
                    and any(part.status in {"SUCCESS", "EMPTY"} for part in matching)):
                expected[family] = "partial"
            elif all(part.status == "FAILED" for part in matching):
                expected[family] = "failed"
            elif all(part.status == "EMPTY" for part in matching):
                expected[family] = "known-empty"
            elif any(part.status == "FAILED" for part in matching):
                expected[family] = "partial"
            else:
                expected[family] = "present"

    return FTDDerivedViews(
        resolved_references=tuple(resolved), zone_interfaces=zone_interfaces,
        acp_relationships=tuple({"policy_id": rule.policy_id, "policy_name": rule.policy_name,
            "rule_id": rule.source_id, "rule_name": rule.name,
            **{key: getattr(rule, key) for key in acp_reference_fields},
            "source_zone_refs": rule.source_zones, "destination_zone_refs": rule.destination_zones,
            "source_network_refs": rule.source_networks, "destination_network_refs": rule.destination_networks,
            "source_port_refs": rule.source_ports, "destination_port_refs": rule.destination_ports,
            **{key: getattr(rule, key) for key in ("realm", "time_range", "intrusion_policy", "variable_set", "file_policy")}}
            for rule in acp_rules),
        nat_relationships=tuple({"policy_id": policy.source_id, "policy": policy.name,
            "rule_id": rule.source_id, "rule": rule.name, "rule_kind": kind,
            "section": getattr(rule, "section", None), "position": getattr(rule, "position", getattr(rule, "order", None)),
            "original": getattr(rule, "original", None), "translated": getattr(rule, "translated", None)}
            for policy, rule, kind in nat_rules),
        unresolved_references=tuple(issues), source_plane_completeness=expected,
        identity_relationships=tuple({"user": user.name, "role": user.raw_extra.get("role") or user.raw_extra.get("roles")} for user in config.fmc_users),
        vpn_relationships=tuple({"topology": vpn.name, "endpoints": [endpoint.name for endpoint in config.s2s_vpn_endpoints
            if endpoint.source_attributes.get("parent_topology_id") == vpn.source_id]} for vpn in config.s2s_vpn_topologies),
    )


__all__ = ["FTDDerivedViews", "FTDReferenceIssue", "FTDReferenceKind", "build_ftd_derived_views"]
