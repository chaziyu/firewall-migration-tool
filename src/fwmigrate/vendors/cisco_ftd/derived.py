"""FTD relationships and read-only views over vendor source state."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .model import CiscoFTDConfig
from .relationships.interface_topology import FTDInterfaceTopology, build_ftd_interface_topology
from .transform.routes import NormalizedFTDRoute, normalize_ftd_routes


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
    LOCAL_REALM_USER = "LOCAL_REALM_USER"
    FMC_USER_ROLE = "FMC_USER_ROLE"
    INTRUSION_POLICY = "INTRUSION_POLICY"
    FILE_POLICY = "FILE_POLICY"
    DECRYPTION_POLICY = "DECRYPTION_POLICY"
    DNS_POLICY = "DNS_POLICY"
    SECURITY_INTELLIGENCE_SOURCE = "SECURITY_INTELLIGENCE_SOURCE"
    VARIABLE_SET = "VARIABLE_SET"
    SLA_MONITOR = "SLA_MONITOR"
    VPN_ENDPOINT = "VPN_ENDPOINT"
    IKE_POLICY = "IKE_POLICY"
    IPSEC_PROPOSAL = "IPSEC_PROPOSAL"
    APPLICATION = "APPLICATION"
    URL_CATEGORY = "URL_CATEGORY"
    VLAN_OBJECT = "VLAN_OBJECT"
    VIRTUAL_ROUTER = "VIRTUAL_ROUTER"
    ADDRESS_POOL = "ADDRESS_POOL"
    CERTIFICATE = "CERTIFICATE"
    CERTIFICATE_MAP = "CERTIFICATE_MAP"
    GROUP_POLICY = "GROUP_POLICY"
    PREFILTER_POLICY = "PREFILTER_POLICY"
    NETWORK_ANALYSIS_POLICY = "NETWORK_ANALYSIS_POLICY"
    RAVPN_CONNECTION_PROFILE = "RAVPN_CONNECTION_PROFILE"
    INTRUSION_RULE_GROUP = "INTRUSION_RULE_GROUP"
    INTRUSION_RULE_BEHAVIOR = "INTRUSION_RULE_BEHAVIOR"


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
    ra_vpn_relationships: tuple[dict[str, Any], ...] = ()
    intrusion_relationships: tuple[dict[str, Any], ...] = ()
    inspection_relationships: tuple[dict[str, Any], ...] = ()
    interface_topology: FTDInterfaceTopology = field(default_factory=FTDInterfaceTopology)
    normalized_routes: tuple[NormalizedFTDRoute, ...] = ()


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
        (FTDReferenceKind.REALM_USER, config.realm_users),
        (FTDReferenceKind.LOCAL_REALM_USER, config.local_realm_users),
        (FTDReferenceKind.REALM_USER_GROUP, config.realm_user_groups),
        (FTDReferenceKind.FMC_USER_ROLE, config.fmc_user_roles),
        (FTDReferenceKind.INTRUSION_POLICY, config.intrusion_policies),
        (FTDReferenceKind.INTRUSION_RULE_GROUP, config.intrusion_rule_groups),
        (FTDReferenceKind.INTRUSION_RULE_BEHAVIOR, config.intrusion_rule_behaviors),
        (FTDReferenceKind.FILE_POLICY, config.file_policies),
        (FTDReferenceKind.DECRYPTION_POLICY, config.decryption_policies),
        (FTDReferenceKind.DNS_POLICY, config.dns_policies),
        (FTDReferenceKind.VARIABLE_SET, config.variable_sets),
        (FTDReferenceKind.SLA_MONITOR, config.sla_monitors),
        (FTDReferenceKind.VPN_ENDPOINT, config.s2s_vpn_endpoints),
        (FTDReferenceKind.IKE_POLICY, config.ike_policies),
        (FTDReferenceKind.IPSEC_PROPOSAL, config.ipsec_proposals),
        (FTDReferenceKind.APPLICATION, config.applications),
        (FTDReferenceKind.URL_CATEGORY, config.url_categories),
        (FTDReferenceKind.VLAN_OBJECT, config.vlan_objects),
        (FTDReferenceKind.VIRTUAL_ROUTER, config.virtual_routers),
        (FTDReferenceKind.ADDRESS_POOL, config.address_pools),
        (FTDReferenceKind.CERTIFICATE, config.certificates),
        (FTDReferenceKind.CERTIFICATE_MAP, config.certificate_maps),
        (FTDReferenceKind.GROUP_POLICY, config.group_policies),
        (FTDReferenceKind.PREFILTER_POLICY, config.prefilter_policies),
        (FTDReferenceKind.NETWORK_ANALYSIS_POLICY, config.network_analysis_policies),
        (FTDReferenceKind.RAVPN_CONNECTION_PROFILE, config.ra_vpn_connection_profiles),
    ):
        register(kind, records)
    si_families = {"customsiurllists", "customsiiplists", "siurllists", "siurlfeeds", "siiplists", "siipfeeds"}
    register(FTDReferenceKind.SECURITY_INTELLIGENCE_SOURCE,
             [item for item in config.native_resources if item.source_attributes.get("resource_type") in si_families])

    issues: list[FTDReferenceIssue] = []
    resolved: list[dict[str, str | None]] = []
    identity_relationships: list[dict[str, Any]] = []

    def identity(value: Any) -> tuple[str | None, str | None]:
        if isinstance(value, dict):
            return (str(value["id"]) if value.get("id") is not None else None,
                    str(value["name"]) if value.get("name") is not None else None)
        if hasattr(value, "source_id"):
            return (str(value.source_id) if value.source_id else None, str(value.name) if value.name else None)
        return (None, str(value)) if value is not None else (None, None)

    def resolve(owner: Any, field_name: str, value: Any, kinds: tuple[FTDReferenceKind, ...], *,
                special: frozenset[str] = frozenset(), scope: str | None = None,
                relationship_type: str | None = None) -> None:
        ref_id, ref_name = identity(value)
        if ref_id is None and ref_name is None:
            return
        if ref_id is None and ref_name and ref_name.casefold() in special:
            return
        domain = key_scope(owner)
        source_type = getattr(value, "source_type", None)
        if source_type and source_type.casefold() in {"securityzone", "security-zone"}:
            kinds = tuple(dict.fromkeys((*kinds, FTDReferenceKind.SECURITY_ZONE)))
        elif source_type and source_type.casefold().replace("_", "").replace("-", "") in {"localrealmuser", "localuser"}:
            kinds = (FTDReferenceKind.LOCAL_REALM_USER,)
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
            if relationship_type:
                identity_relationships.append({"relationship_type": relationship_type,
                    "owner_id": owner.source_id, "owner_name": owner.name,
                    "target_id": match.source_id, "target_name": match.name,
                    "source_plane": owner.source_plane})
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

    for collection, relationship_type in ((config.realm_users, "realm-user-to-realm"),
        (config.realm_user_groups, "realm-group-to-realm"),
        (config.local_realm_users, "local-realm-user-to-realm")):
        for item in collection:
            if item.realm is not None:
                resolve(item, "realm", item.realm, (FTDReferenceKind.REALM,), relationship_type=relationship_type)
    for item in config.realm_users:
        for group in item.groups or []:
            resolve(item, "groups", group, (FTDReferenceKind.REALM_USER_GROUP,),
                    relationship_type="realm-user-to-group")
    for item in config.fmc_users:
        for role in item.roles or []:
            resolve(item, "roles", role, (FTDReferenceKind.FMC_USER_ROLE,),
                    relationship_type="fmc-user-to-role")

    network = (FTDReferenceKind.NETWORK_ADDRESS, FTDReferenceKind.NETWORK_GROUP)
    service = (FTDReferenceKind.SERVICE_OBJECT, FTDReferenceKind.SERVICE_GROUP)
    interface_or_zone = (FTDReferenceKind.INTERFACE, FTDReferenceKind.SECURITY_ZONE)
    any_network = frozenset({"any", "any-ip", "any4", "any6"})
    for group in config.network_groups:
        for member in group.members or []:
            resolve(group, "members", member, network)
    for group in config.port_object_groups:
        for member in group.members or []:
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

    for policy in config.access_control_policies:
        for field_name, kind in (("decryption_policy", FTDReferenceKind.DECRYPTION_POLICY),
                                 ("dns_policy", FTDReferenceKind.DNS_POLICY)):
            value = getattr(policy, field_name)
            if value is not None:
                resolve(policy, field_name, value, (kind,))
    for rule in acp_rules:
        for field_name, kind in (("realm", FTDReferenceKind.REALM), ("time_range", FTDReferenceKind.TIME_RANGE),
            ("intrusion_policy", FTDReferenceKind.INTRUSION_POLICY), ("variable_set", FTDReferenceKind.VARIABLE_SET),
            ("file_policy", FTDReferenceKind.FILE_POLICY)):
            value = getattr(rule, field_name)
            if value is not None:
                resolve(rule, field_name, value, (kind,))

    inspection_relationships: list[dict[str, Any]] = []
    for policy in config.access_control_policies:
        for field_name in ("decryption_policy", "dns_policy"):
            ref = getattr(policy, field_name)
            if ref is not None:
                inspection_relationships.append({"relationship_type": "acp-policy-reference",
                    "policy_type": field_name.removesuffix("_policy"), "policy_id": policy.source_id,
                    "policy_name": policy.name, "reference_id": ref.source_id,
                    "reference_name": ref.name, "field": field_name, "source_plane": policy.source_plane})
    for rule in acp_rules:
        if rule.file_policy is not None:
            inspection_relationships.append({"relationship_type": "acp-rule-reference", "policy_type": "file",
                "policy_id": rule.policy_id, "policy_name": rule.policy_name, "rule_id": rule.source_id,
                "rule_name": rule.name, "reference_id": rule.file_policy.source_id,
                "reference_name": rule.file_policy.name, "field": "file_policy", "source_plane": rule.source_plane})
    for policy, rules, family in (
        *((item, item.rules, "file") for item in config.file_policies),
        *((item, item.rules, "decryption") for item in config.decryption_policies),
        *((item, item.rules, "dns") for item in config.dns_policies),
    ):
        inspection_relationships.append({"relationship_type": "policy", "policy_type": family,
            "policy_id": policy.source_id, "policy_name": policy.name, "rule_id": None,
            "rule_name": None, "collection_order": None, "source_plane": policy.source_plane})
        for rule in rules or []:
            inspection_relationships.append({"relationship_type": "policy-rule", "policy_type": family,
                "policy_id": policy.source_id, "policy_name": policy.name, "rule_id": rule.source_id,
                "rule_name": rule.name, "collection_order": rule.collection_order,
                "source_plane": rule.source_plane})
            fields = {
                "file": (),
                "decryption": (("source_networks", network), ("destination_networks", network),
                    ("source_ports", service), ("destination_ports", service),
                    ("certificates", (FTDReferenceKind.CERTIFICATE,))),
                "dns": (("source_zones", (FTDReferenceKind.SECURITY_ZONE,)),
                    ("destination_zones", (FTDReferenceKind.SECURITY_ZONE,)),
                    ("source_networks", network), ("destination_networks", network), ("networks", network),
                    ("vlan_tags", (FTDReferenceKind.VLAN_OBJECT,)),
                    ("lists_feeds", (FTDReferenceKind.SECURITY_INTELLIGENCE_SOURCE,))),
            }[family]
            for field_name, kinds in fields:
                for ref in getattr(rule, field_name) or []:
                    resolve(rule, field_name, ref, kinds)
                    inspection_relationships.append({"relationship_type": "rule-reference", "policy_type": family,
                        "policy_id": policy.source_id, "policy_name": policy.name, "rule_id": rule.source_id,
                        "rule_name": rule.name, "field": field_name, "reference_id": ref.source_id,
                        "reference_name": ref.name, "source_plane": rule.source_plane})

    for policy in config.intrusion_policies:
        if policy.variable_set is not None:
            resolve(policy, "variable_set", policy.variable_set, (FTDReferenceKind.VARIABLE_SET,))

    for policy, rule, kind in nat_rules:
        for field_name in ("source_interface", "destination_interface"):
            value = getattr(rule, field_name, None)
            if value is not None:
                resolve(rule, field_name, value, interface_or_zone)
        if kind == "fdm":
            for field_name in ("original_source", "translated_source", "original_destination", "translated_destination"):
                value = getattr(rule, field_name, None)
                if value is not None:
                    resolve(rule, field_name, value, network)
            if rule.service is not None:
                resolve(rule, "service", rule.service, service)
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
        virtual_router = route.virtual_router_ref or route.virtual_router
        if virtual_router:
            resolve(route, "virtual_router", virtual_router, (FTDReferenceKind.VIRTUAL_ROUTER,),
                    special=frozenset({"global"}), scope=route.device_id)
        for field_name, kinds in (("interface", (FTDReferenceKind.INTERFACE,)), ("destination", network),
            ("gateway", network), ("sla_monitor", (FTDReferenceKind.SLA_MONITOR,))):
            value = getattr(route, field_name, None)
            if value is not None:
                resolve(route, field_name, value, kinds, scope=route.device_id if field_name == "interface" else None)

    for owner, field_name, values in (
        *((vr, "interfaces", vr.interfaces or []) for vr in config.virtual_routers),
        *((zone, "interfaces", zone.interfaces or []) for zone in config.ecmp_zones),
        *((route, field, [getattr(route, field)]) for route in config.policy_based_routes
          for field in ("virtual_router", "ingress_interface", "egress_interface", "path_interface", "sla_monitor") if getattr(route, field)),
        *((route, "networks", route.networks or []) for route in config.policy_based_routes),
    ):
        kinds = ((FTDReferenceKind.SLA_MONITOR,) if field_name == "sla_monitor" else
                 (FTDReferenceKind.VIRTUAL_ROUTER,) if field_name == "virtual_router" else
                 network if field_name == "networks" else (FTDReferenceKind.INTERFACE,))
        for value in values:
            resolve(owner, field_name, value, kinds, scope=owner.device_id if field_name != "networks" else None)

    for owner, fields in (
        *((item, (("ike_policies", FTDReferenceKind.IKE_POLICY), ("certificates", FTDReferenceKind.CERTIFICATE)))
          for item in config.s2s_ike_settings),
        *((item, (("ipsec_proposals", FTDReferenceKind.IPSEC_PROPOSAL),)) for item in config.s2s_ipsec_settings),
        *((item, (("address_pools", FTDReferenceKind.ADDRESS_POOL),)) for item in config.ra_vpn_address_assignment_settings),
        *((item, (("realm", FTDReferenceKind.REALM),
                  ("address_pools", FTDReferenceKind.ADDRESS_POOL), ("split_tunnel_networks", network)))
          for item in config.group_policies),
        *((item, (("realm", FTDReferenceKind.REALM),
                  ("address_pools", FTDReferenceKind.ADDRESS_POOL), ("default_group_policy", FTDReferenceKind.GROUP_POLICY),
                  ("certificates", FTDReferenceKind.CERTIFICATE), ("certificate_maps", FTDReferenceKind.CERTIFICATE_MAP)))
          for item in config.ra_vpn_connection_profiles),
        *((item, (("certificates", FTDReferenceKind.CERTIFICATE),
                  ("certificate_maps", FTDReferenceKind.CERTIFICATE_MAP),
                  ("connection_profiles", FTDReferenceKind.RAVPN_CONNECTION_PROFILE),
                  ("group_policies", FTDReferenceKind.GROUP_POLICY), ("address_pools", FTDReferenceKind.ADDRESS_POOL),
                  ("realms", FTDReferenceKind.REALM))) for item in config.ra_vpn_policies),
        *((item, (("connection_profile", FTDReferenceKind.RAVPN_CONNECTION_PROFILE),
                  ("group_policy", FTDReferenceKind.GROUP_POLICY))) for item in config.certificate_maps),
        *((item, (("prefilter_policy", FTDReferenceKind.PREFILTER_POLICY),
                  ("network_analysis_policy", FTDReferenceKind.NETWORK_ANALYSIS_POLICY)))
          for item in config.access_control_policies),
        *((item, (("interface", FTDReferenceKind.INTERFACE),
                  ("vti", FTDReferenceKind.INTERFACE), ("protected_networks", network)))
          for item in config.s2s_vpn_endpoints),
        *((item, (("interface", FTDReferenceKind.INTERFACE),)) for item in config.dhcp_servers),
    ):
        for field_name, kind in fields:
            values = getattr(owner, field_name, None)
            if values is None:
                continue
            for value in values if isinstance(values, list) else [values]:
                kinds = kind if isinstance(kind, tuple) else (kind,)
                resolve(owner, field_name, value, kinds,
                        scope=owner.device_id if FTDReferenceKind.INTERFACE in kinds else None)

    for policy in config.ra_vpn_policies:
        targets = policy.target_devices or []
        for ref in policy.access_interfaces or []:
            device_id = ref.source_attributes.get("deviceId") or ref.source_attributes.get("device_id")
            scope = str(device_id) if device_id else targets[0].source_id if len(targets) == 1 else None
            resolve(policy, "access_interfaces", ref, (FTDReferenceKind.INTERFACE,), scope=scope)
    for profile in config.ra_vpn_connection_profiles:
        for field_name in ("authentication_server", "authorization", "accounting_server"):
            server = getattr(profile, field_name)
            if server is not None and (server.source_type or "").casefold() == "identityrealm":
                resolve(profile, field_name, server, (FTDReferenceKind.REALM,))
    for policy in config.ra_vpn_policies:
        for settings in policy.certificate_map_settings or []:
            for mapping in settings.get("certificateToConnectionProfileMap", []):
                if not isinstance(mapping, dict):
                    continue
                for field_name, kind in (("certificateMap", FTDReferenceKind.CERTIFICATE_MAP),
                                         ("connectionProfile", FTDReferenceKind.RAVPN_CONNECTION_PROFILE)):
                    if isinstance(mapping.get(field_name), dict):
                        resolve(policy, f"certificate_map_settings.{field_name}", mapping[field_name], (kind,))

    def ra_refs(item: Any, fields: tuple[str, ...]) -> dict[str, Any]:
        return {field: getattr(item, field) for field in fields if getattr(item, field) is not None}

    ra_vpn_relationships = [
        {"kind": "policy", "id": item.source_id, "name": item.name,
            "source_only": ("target_devices",) if item.target_devices is not None else (), **ra_refs(item,
            ("target_devices", "access_interfaces", "certificates", "certificate_maps",
             "connection_profiles", "group_policies", "address_pools", "realms"))}
        for item in config.ra_vpn_policies]
    ra_vpn_relationships.extend({"kind": "connection-profile", "id": item.source_id,
        "name": item.name, "parent_policy_id": item.parent_policy_id,
        "source_only": tuple(field for field in ("authentication_server", "authorization", "accounting_server")
                             if getattr(item, field) is not None and
                             (getattr(item, field).source_type or "").casefold() != "identityrealm"),
        **ra_refs(item,
            ("realm", "authentication_server", "authorization", "accounting_server",
             "address_pools", "default_group_policy", "certificates", "certificate_maps"))}
        for item in config.ra_vpn_connection_profiles)
    ra_vpn_relationships.extend({"kind": "group-policy", "id": item.source_id,
        "name": item.name, "source_only": tuple(field for field in
            ("aaa_server_group", "split_tunnel_acl", "secure_client") if getattr(item, field) is not None),
        **ra_refs(item, ("realm", "aaa_server_group", "address_pools",
            "split_tunnel_networks", "split_tunnel_acl", "secure_client"))} for item in config.group_policies)
    ra_vpn_relationships.extend({"kind": "address-assignment", "id": item.source_id,
        "name": item.name, "parent_policy_id": item.source_attributes.get("parent_policy_id"),
        "source_only": ("external_assignment",) if item.external_assignment is not None else (),
        **ra_refs(item, ("address_pools", "external_assignment"))}
        for item in config.ra_vpn_address_assignment_settings)
    ra_vpn_relationships.extend({"kind": "certificate-map-selection", "policy_id": policy.source_id,
        "certificate_map": mapping.get("certificateMap"), "connection_profile": mapping.get("connectionProfile"),
        "enabled": settings.get("enableCertificateToConnectionProfileMapping"),
        "use_group_url": settings.get("useGroupURL")}
        for policy in config.ra_vpn_policies for settings in policy.certificate_map_settings or []
        for mapping in settings.get("certificateToConnectionProfileMap", []) if isinstance(mapping, dict))

    intrusion_relationships: list[dict[str, Any]] = []
    linked_behaviors: set[tuple[str | None, str | None]] = set()
    for policy in config.intrusion_policies:
        policy_groups = [group for group in config.intrusion_rule_groups if group.parent_policy_id == policy.source_id]
        policy_behaviors = [item for item in config.intrusion_rule_behaviors
                            if item.parent_policy_id == policy.source_id]
        policy_overrides = [item for item in config.intrusion_rule_overrides
                            if item.parent_policy_id == policy.source_id]
        has_relationship = False
        for group in policy_groups:
            memberships = [{"rule_id": str(child.get("ruleId") or child.get("id")),
                            "payload": child}
                           for child in group.raw_extra.get("rules", []) if isinstance(child, dict)
                           and (child.get("ruleId") is not None or child.get("id") is not None)]
            if not memberships:
                intrusion_relationships.append({"policy_id": policy.source_id, "policy_name": policy.name,
                    "rule_group_id": group.source_id, "rule_group_name": group.name,
                    "rule_id": None, "rule_behavior_id": None, "override_id": None})
                has_relationship = True
            for evidence in memberships:
                rule_id = evidence.get("rule_id")
                behavior = next((item for item in policy_behaviors
                                 if (item.rule_id or item.source_id) == rule_id or item.source_id == rule_id), None)
                intrusion_relationships.append({"policy_id": policy.source_id, "policy_name": policy.name,
                    "rule_group_id": group.source_id, "rule_group_name": group.name, "rule_id": rule_id,
                    "rule_behavior_id": behavior.source_id if behavior else None,
                    "override_id": next((override.source_id for override in policy_overrides
                        if override.rule_id == rule_id or override.source_id == rule_id), None)})
                if behavior:
                    linked_behaviors.add((policy.source_id, behavior.source_id))
                has_relationship = True
        for behavior in policy_behaviors:
            if (policy.source_id, behavior.source_id) in linked_behaviors:
                continue
            evidence = behavior.source_attributes.get("group_membership_evidence", [])
            rule_id = behavior.rule_id or behavior.source_id
            intrusion_relationships.append({"policy_id": policy.source_id, "policy_name": policy.name,
                "rule_group_id": evidence[0].get("rule_group_id") if evidence else None,
                "rule_group_name": evidence[0].get("rule_group_name") if evidence else None,
                "rule_id": rule_id, "rule_behavior_id": behavior.source_id,
                "override_id": next((override.source_id for override in policy_overrides
                    if override.rule_id == rule_id or override.source_id == behavior.source_id), None)})
            has_relationship = True
        if not has_relationship:
            intrusion_relationships.append({"policy_id": policy.source_id, "policy_name": policy.name,
                "rule_group_id": None, "rule_group_name": None, "rule_id": None,
                "rule_behavior_id": None, "override_id": None})

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
        "acp": ("partial" if acp_rules and any(policy.rules is None for policy in config.access_control_policies)
                else "present" if acp_rules else "not_available_from_source_plane"),
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
        expected["acp"] = "partial" if acp_rules and any(
            policy.rules is None for policy in config.access_control_policies) else "unknown"
        expected["nat"] = "unknown"
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

        def child_collection_state(matching: list[Any]) -> str:
            if not matching:
                return "unknown"
            if any(part.status == "PARTIAL" for part in matching) or (
                    any(part.status == "FAILED" for part in matching) and
                    any(part.status in {"SUCCESS", "EMPTY"} for part in matching)):
                return "partial"
            if all(part.status == "FAILED" for part in matching):
                return "failed"
            if all(part.status == "EMPTY" for part in matching):
                return "known-empty"
            return "present"

        expected["intrusion_policies"] = child_collection_state(
            [part for part in parts if part.name == "intrusionpolicies"])
        expected["intrusion_rule_groups"] = child_collection_state(
            [part for part in parts if part.name.startswith("intrusionpolicies/") and part.name.endswith("/rule_groups")])
        expected["intrusion_rule_behaviors"] = child_collection_state(
            [part for part in parts if part.name.startswith("intrusionpolicies/") and part.name.endswith("/rules")])
        for family, prefixes in (("file", ("filepolicies/", "filepolicyrules/")),
                                 ("decryption", ("decryptionpolicies/", "decryptionpolicyrules/")),
                                 ("dns", ("dnspolicies/", "block_rules/"))):
            matching = [part for part in parts if part.name.startswith(prefixes) and
                        part.name.rsplit("/", 1)[-1] in {"rules", "filepolicyrules", "decryptionpolicyrules", "block_rules"}]
            expected[f"{family}_rules"] = child_collection_state(matching)
    else:
        expected.update({"intrusion_policies": "unknown", "intrusion_rule_groups": "unknown",
                         "intrusion_rule_behaviors": "unknown", "file_rules": "unknown",
                         "decryption_rules": "unknown", "dns_rules": "unknown"})

    return FTDDerivedViews(
        interface_topology=build_ftd_interface_topology(config.interfaces),
        normalized_routes=normalize_ftd_routes(config.static_routes),
        resolved_references=tuple(resolved), zone_interfaces=zone_interfaces,
        acp_relationships=tuple({"policy_id": rule.policy_id, "policy_name": rule.policy_name,
            "rule_id": rule.source_id, "rule_name": rule.name,
            **{key: getattr(rule, key) for key in acp_reference_fields},
            "source_zone_refs": rule.source_zones, "destination_zone_refs": rule.destination_zones,
            "source_network_refs": rule.source_networks, "destination_network_refs": rule.destination_networks,
            "source_port_refs": rule.source_ports, "destination_port_refs": rule.destination_ports,
            **{key: getattr(rule, key) for key in ("realm", "time_range", "intrusion_policy", "variable_set", "file_policy")}}
            for rule in acp_rules),
        nat_relationships=tuple({"policy_id": None if policy.source_attributes.get("synthetic_container") else policy.source_id,
            "policy": None if policy.source_attributes.get("synthetic_container") else policy.name,
            "rule_id": rule.source_id, "rule": rule.name, "rule_kind": kind,
            "rule_type": getattr(rule, "rule_type", None),
            "section": None if kind == "fdm" else getattr(rule, "section", None),
            "position": getattr(rule, "sequence", None) if kind == "fdm" else getattr(rule, "position", getattr(rule, "order", None)),
            "sequence": getattr(rule, "sequence", None) if kind == "fdm" else None,
            "original_source": getattr(rule, "original_source", None),
            "translated_source": getattr(rule, "translated_source", None),
            "original_destination": getattr(rule, "original_destination", None),
            "translated_destination": getattr(rule, "translated_destination", None),
            "service": getattr(rule, "service", None),
            "source_translation_mode": getattr(rule, "source_translation_mode", None),
            "destination_translation_mode": getattr(rule, "destination_translation_mode", None),
            "original": getattr(rule, "original", None), "translated": getattr(rule, "translated", None)}
            for policy, rule, kind in nat_rules),
        unresolved_references=tuple(issues), source_plane_completeness=expected,
        identity_relationships=tuple(identity_relationships),
        vpn_relationships=tuple({
            "topology": vpn.name,
            "endpoints": [item.name for item in config.s2s_vpn_endpoints
                if item.source_attributes.get("parent_topology_id") == vpn.source_id],
            "ike_settings": [item.name for item in config.s2s_ike_settings
                if item.source_attributes.get("parent_topology_id") == vpn.source_id],
            "ipsec_settings": [item.name for item in config.s2s_ipsec_settings
                if item.source_attributes.get("parent_topology_id") == vpn.source_id],
            "advanced_settings": [item.name for item in config.s2s_advanced_settings
                if item.source_attributes.get("parent_topology_id") == vpn.source_id],
        } for vpn in config.s2s_vpn_topologies),
        ra_vpn_relationships=tuple(ra_vpn_relationships),
        intrusion_relationships=tuple(intrusion_relationships),
        inspection_relationships=tuple(inspection_relationships),
    )


__all__ = ["FTDDerivedViews", "FTDReferenceIssue", "FTDReferenceKind", "build_ftd_derived_views"]
