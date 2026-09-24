"""ASA-native VPN topology composed from resolved relationships."""

from dataclasses import dataclass
from typing import Any


def _resolved_values(names: Any, relationship: Any, field: str) -> tuple[Any, ...]:
    values = tuple(value for key, value in (relationship.targets if relationship else ()) if key == field)
    names = tuple(names or ())
    return tuple(next((value for value in values if getattr(value, "name", None) == name), name)
                 for name in names) or values


def _unique(values: Any) -> tuple[Any, ...]:
    result = []
    seen = set()
    for value in values:
        key = value if isinstance(value, str) else id(value)
        if key not in seen:
            seen.add(key)
            result.append(value)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class ASAVPNTopologyEntry:
    source_context: str | None
    topology_type: str
    source_identity: Any
    crypto_map: str | None = None
    crypto_map_sequence: int | None = None
    crypto_acl: Any = None
    peers: tuple[Any, ...] = ()
    tunnel_groups: tuple[Any, ...] = ()
    transform_sets: tuple[Any, ...] = ()
    ikev2_proposals: tuple[Any, ...] = ()
    interface: Any = None
    physical_interfaces: tuple[Any, ...] = ()
    tunnel_interface: Any = None
    tunnel_source: str | None = None
    tunnel_destination: str | None = None
    ipsec_profile: str | None = None
    resolution_status: str | None = None
    group_policy: Any = None
    address_pools: tuple[Any, ...] = ()
    trustpoint: Any = None
    issues: tuple[str, ...] = ()
    selector_acl: Any = None


@dataclass(frozen=True, slots=True)
class ASADerivedRemoteAccessVPN:
    source_context: str | None
    tunnel_group: Any
    connection_profile_type: str | None
    group_policy: Any = None
    inherited_group_policy: Any = None
    authentication_server_group: Any = None
    local_authentication_available: bool | None = None
    address_pools: tuple[Any, ...] = ()
    dhcp_servers: tuple[Any, ...] = ()
    address_assignment_methods: tuple[str, ...] | None = None
    vpn_protocols: tuple[str, ...] = ()
    vpn_access_hours: Any = None
    vpn_filter_acl: Any = None
    split_tunnel_policy: str | None = None
    split_tunnel_acl: Any = None
    dns_servers: tuple[str, ...] = ()
    wins_servers: tuple[str, ...] = ()
    default_domain: str | None = None
    enabled_interfaces: tuple[Any, ...] = ()
    webvpn_attributes: tuple[tuple[str, Any], ...] = ()
    trustpoints: tuple[Any, ...] = ()
    resolution_status: str = "SOURCE_ONLY"
    source_references: tuple[tuple[str, Any], ...] = ()
    issues: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ASAVPNTransformResult:
    topologies: tuple[ASAVPNTopologyEntry, ...] = ()
    issues: tuple[str, ...] = ()
    remote_access: tuple[ASADerivedRemoteAccessVPN, ...] = ()

    @property
    def ipsec_topologies(self) -> tuple[ASAVPNTopologyEntry, ...]:
        return tuple(row for row in self.topologies if row.topology_type != "remote-access")


def build_vpn_topology(config: Any, relationships: Any, interface_topology: Any) -> ASAVPNTransformResult:
    by_source = {id(row.source): row for row in relationships.relationships}
    interfaces = {(row.source_context, row.name): row for row in interface_topology.interfaces}
    entries, issues = [], []
    for source in config.crypto_maps:
        rel = by_source.get(id(source)); targets = {}
        if rel:
            for key, value in rel.targets: targets.setdefault(key, []).append(value)
        interface = (targets.get("interface") or [None])[0]
        topology = interfaces.get((source.source_context, getattr(interface, "name", None)))
        local = tuple(issue.reason for issue in (rel.issues if rel else ()))
        entries.append(ASAVPNTopologyEntry(source.source_context, "policy-based", source,
            source.map_name or source.name, source.sequence, (targets.get("crypto-acl") or [None])[0],
            tuple(source.peers or ([source.peer] if source.peer else ())), tuple(targets.get("peer", ())),
            tuple(targets.get("transform-set", ())), tuple(targets.get("ikev2-proposal", ())), interface,
            tuple(topology.physical_interfaces) if topology else (), issues=local))
        issues.extend(local)
    for source in config.interfaces:
        if source.interface_type != "tunnel" and not (source.tunnel_source or source.ipsec_profile): continue
        relationship = by_source.get(id(source))
        resolved_profile = next((value for key, value in (relationship.targets if relationship else ()) if key == "ipsec-profile"), None)
        profile_relationship = by_source.get(id(resolved_profile)) if resolved_profile is not None else None
        profile_targets = {}
        if profile_relationship:
            for key, value in profile_relationship.targets:
                profile_targets.setdefault(key, []).append(value)
        selector_acl = next((value for key, value in (relationship.targets if relationship else ())
                             if key == "ipsec-policy-acl"), None)
        dependency_issues = (*(relationship.issues if relationship else ()),
                             *(profile_relationship.issues if profile_relationship else ()))
        local_issues = tuple(dict.fromkeys(issue.reason for issue in dependency_issues))
        has_explicit_dependency = bool(source.ipsec_profile or source.ipsec_policy_acl)
        resolution_status = ("PARTIAL" if local_issues else
                             "RESOLVED" if has_explicit_dependency and (resolved_profile or selector_acl) else
                             "SOURCE_ONLY")
        entries.append(ASAVPNTopologyEntry(source.source_context, "vti", source, interface=source,
            tunnel_interface=source.name, tunnel_source=source.tunnel_source, tunnel_destination=source.tunnel_destination,
            transform_sets=tuple(profile_targets.get("ikev1-transform-set", ())),
            ikev2_proposals=tuple(profile_targets.get("ikev2-ipsec-proposal", ())),
            ipsec_profile=source.ipsec_profile, resolution_status=resolution_status,
            trustpoint=(profile_targets.get("trustpoint") or [None])[0],
            issues=local_issues, selector_acl=selector_acl))
        issues.extend(local_issues)
    remote_access = []
    webvpn_configs = tuple(getattr(config, "webvpn_configs", ()))
    assignments = tuple(getattr(config, "vpn_address_assignments", ()))
    for source in config.tunnel_groups:
        rel = by_source.get(id(source)); targets = {}
        if rel:
            for key, value in rel.targets: targets.setdefault(key, []).append(value)
        if any(targets.get(key) for key in ("group-policy", "address-pool", "trustpoint")):
            local = tuple(issue.reason for issue in rel.issues) if rel else ()
            entries.append(ASAVPNTopologyEntry(source.source_context, "remote-access", source,
                tunnel_groups=(source,), group_policy=(targets.get("group-policy") or [None])[0],
                address_pools=tuple(targets.get("address-pool", ())), trustpoint=(targets.get("trustpoint") or [None])[0], issues=local))
            issues.extend(local)
        if (getattr(source, "group_type", None) or "").casefold() not in {"remote-access", "webvpn"}:
            continue
        context = getattr(source, "source_context", None)
        global_webvpn = next((item for item in webvpn_configs if getattr(item, "source_context", None) == context), None)
        if global_webvpn is None and not webvpn_configs:
            global_webvpn = getattr(config, "webvpn", None)
        assignment = next((item for item in assignments if getattr(item, "source_context", None) == context), None)
        if assignment is None and not assignments:
            assignment = getattr(config, "vpn_address_assignment", None)
        global_relation = by_source.get(id(global_webvpn)) if global_webvpn is not None else None
        assignment_relation = by_source.get(id(assignment)) if assignment is not None else None
        policy = (targets.get("group-policy") or [None])[0]
        policy_rel = by_source.get(id(policy)) if policy is not None else None
        policy_targets: dict[str, list[Any]] = {}
        for key, value in (policy_rel.targets if policy_rel else ()):
            policy_targets.setdefault(key, []).append(value)
        parent = next(iter(policy_targets.get("parent", ())), None) or getattr(policy, "parent", None)
        inherited = parent
        tunnel_pools = _resolved_values(getattr(source, "address_pools", ()), rel, "address-pool")
        policy_pools = _resolved_values(getattr(policy, "address_pools", ()), policy_rel, "address-pool")
        assignment_pools = tuple(value for key, value in (assignment_relation.targets if assignment_relation else ())
                                 if key == "local-pool")
        pools = _unique((*tunnel_pools, *policy_pools, *assignment_pools))
        dhcp_servers = tuple(value for key, value in (assignment_relation.targets if assignment_relation else ())
                             if key == "dhcp")
        assignment_methods = None
        assignment_fields = {"aaa_enabled", "dhcp_enabled", "local_enabled"}
        if assignment is not None and assignment_fields.intersection(getattr(assignment, "explicit_fields", ())):
            assignment_methods = tuple(name for name in ("aaa", "dhcp", "local")
                                       if getattr(assignment, f"{name}_enabled", None) is True)
        policy_value = lambda key, default=None: getattr(policy, key, default) if policy is not None else default
        webvpn_attrs = tuple((label, value) for label, value in (
            ("global", global_webvpn),
            ("tunnel_group", getattr(source, "webvpn_attributes", None)),
            ("group_policy", getattr(policy, "webvpn_attributes", None) if policy is not None else None),
        ) if value is not None)
        enabled = tuple(getattr(global_webvpn, "enabled_interfaces", ()))
        trustpoints = (
            *_resolved_values((source.trustpoint,) if source.trustpoint else (), rel, "trustpoint"),
            *_resolved_values(getattr(global_webvpn, "trustpoint_references", ()), global_relation, "trustpoint"),
        )
        local_users = tuple(user for user in getattr(config, "local_users", ())
                            if getattr(user, "source_context", None) == context)
        local_auth = True if ((getattr(source, "authentication_method", None) or "").casefold() == "local"
                              and local_users) else None
        local_issues = list(issue.reason for issue in (rel.issues if rel else ()))
        local_issues.extend(issue.reason for issue in (policy_rel.issues if policy_rel else ()))
        local_issues.extend(issue.reason for issue in (global_relation.issues if global_relation else ()))
        local_issues.extend(issue.reason for issue in (assignment_relation.issues if assignment_relation else ()))
        if policy is None:
            local_issues.append("Explicit group-policy reference is absent")
        if global_webvpn is None:
            local_issues.append("WebVPN source is absent in this context")
        if not targets.get("aaa-server-group") and local_auth is None:
            local_issues.append("Authentication source is not explicitly configured")
        if "local" in (assignment_methods or ()) and not pools:
            local_issues.append("Explicit address-pool reference is absent")
        if "dhcp" in (assignment_methods or ()) and not dhcp_servers:
            local_issues.append("DHCP address-assignment source is unresolved")
        if assignment is not None and assignment_methods == ():
            local_issues.append("No address-assignment method is explicitly enabled")
        if policy is not None and policy_value("vpn_filter_acl") and not policy_targets.get("vpn-filter-acl"):
            local_issues.append("VPN filter ACL reference is unresolved")
        if policy is not None and policy_value("split_tunnel_acl") and not policy_targets.get("split-tunnel-acl"):
            local_issues.append("Split-tunnel ACL reference is unresolved")
        if policy is not None and (policy_value("split_tunnel_policy") or "").casefold() == "tunnelspecified" \
                and not policy_value("split_tunnel_acl"):
            local_issues.append("Split-tunnel ACL is not explicitly configured")
        if policy is not None and policy_value("vpn_access_hours") and not policy_targets.get("vpn-access-hours"):
            local_issues.append("VPN access-hours reference is unresolved")
        sources = [("tunnel_group", source)]
        if policy is not None: sources.append(("group_policy", policy))
        if inherited is not None: sources.append(("inherited_group_policy", inherited))
        if global_webvpn is not None: sources.append(("webvpn", global_webvpn))
        if assignment is not None: sources.append(("vpn_address_assignment", assignment))
        sources.extend(("address_pool", value) for value in pools)
        sources.extend(("dhcp_server", value) for value in dhcp_servers)
        status = "PARTIAL" if local_issues else "RESOLVED"
        remote_access.append(ASADerivedRemoteAccessVPN(
            source.source_context, source, source.group_type, policy, parent,
            (targets.get("aaa-server-group") or [None])[0]
            or (getattr(source, "general_attributes", {}) or {}).get("authentication_server_group"),
            local_auth, tuple(pools), dhcp_servers,
            assignment_methods, tuple(policy_value("vpn_protocols", ())),
            next(iter(policy_targets.get("vpn-access-hours", ())), policy_value("vpn_access_hours")),
            next(iter(policy_targets.get("vpn-filter-acl", ())), policy_value("vpn_filter_acl")),
            policy_value("split_tunnel_policy"),
            next(iter(policy_targets.get("split-tunnel-acl", ())), policy_value("split_tunnel_acl")),
            tuple(policy_value("dns_servers", ())), tuple(policy_value("wins_servers", ())),
            policy_value("default_domain"), enabled, webvpn_attrs, trustpoints,
            status, tuple(sources), tuple(dict.fromkeys(local_issues)),
        ))
        issues.extend(local_issues)
    return ASAVPNTransformResult(tuple(entries), tuple(issues), tuple(remote_access))
