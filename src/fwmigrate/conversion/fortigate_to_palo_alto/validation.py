"""Dependency and field validation for FortiGate to PAN-OS plans."""

from dataclasses import dataclass
from graphlib import CycleError, TopologicalSorter
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, ip_network
import re

from .models import MigrationIssue, MigrationSourceRef, PANMigrationPlan, PANMigrationStatus
from .plan_dependencies import item_key, policy_order_predecessors, target_identity
from .planning.services import PAN_BUILTIN_SERVICES
from .target.name_validation import zone_name_issue
from .planning.vpn import crypto_lifetime
from ...vendors.palo_alto.validation.validator import _validate_ip_wildcard, _validate_ports


ItemKey = tuple[str | None, str | None, str | None]


def validate_source_interfaces(source):
    """Report explicit malformed addresses without repairing vendor source state."""
    result = []
    for interface in source.interfaces:
        if not interface.ip:
            continue
        try:
            parts = interface.ip.split()
            if len(parts) not in {1, 2} or len(parts) == 1 and '/' not in parts[0]:
                raise ValueError('An explicit prefix or mask is required')
            IPv4Interface('/'.join(parts))
        except ValueError:
            result.append({'code': 'SOURCE_INTERFACE_IPV4_INVALID',
                'source_vdom': interface.vdom or 'root', 'source_kind': 'interface',
                'source_name': interface.name,
                'message': f'Correct the malformed primary IPv4 address for {interface.name} in the source configuration. Secondary addresses are not substitutes.'})
    return result


@dataclass(frozen=True, slots=True)
class MigrationValidationResult:
    issues: tuple[MigrationIssue, ...] = ()
    plan: PANMigrationPlan | None = None
    renderable_item_keys: frozenset[ItemKey] = frozenset()

    @property
    def counts(self):
        result = {status.value.lower(): 0 for status in PANMigrationStatus}
        for item in _items(self.plan):
            result[item.status.value.lower()] += 1
        return result

    @property
    def has_errors(self):
        return any(issue.status is PANMigrationStatus.UNSUPPORTED for issue in self.issues)


def validate_plan(plan: PANMigrationPlan) -> MigrationValidationResult:
    """Return a non-mutating, transitive renderability assessment for a plan."""
    issues = list(plan.issues)
    families = {
        "addresses": _index(plan.addresses),
        "address_groups": _index(plan.address_groups),
        "services": _index(plan.services),
        "service_groups": _index(plan.service_groups),
        "schedules": _index(plan.schedules),
        "interfaces": _index(plan.interfaces),
        "zones": _index(plan.zones),
        "nat_rules": _index(plan.nat_rules),
        "management_profiles": _index(plan.management_profiles),
    }
    errors: set[ItemKey] = set()
    seen: set[ItemKey] = set()
    issue_keys: set[tuple[ItemKey, str, str]] = set()

    def add(code: str, message: str, item) -> None:
        marker = (_key(item), code, message)
        if marker not in issue_keys:
            issues.append(_issue(code, message, item))
            issue_keys.add(marker)
        errors.add(_key(item))

    interface_assignments = {}
    address_assignments = {}
    for item in (*plan.addresses, *plan.address_groups):
        address_assignments.setdefault((item.target_vsys, item.target_name or item.source_name), []).append(item)
    for owners in address_assignments.values():
        if len(owners) > 1:
            for item in owners:
                add("duplicate_target_address_name", "address and address-group target names must be unique", item)
    service_assignments = {}
    for item in (*plan.services, *plan.service_groups):
        service_assignments.setdefault((item.target_vsys, item.target_name or item.source_name), []).append(item)
    for owners in service_assignments.values():
        if len(owners) > 1:
            for item in owners:
                add("duplicate_target_service_name", "service and service-group target names must be unique", item)
    for item in plan.interfaces:
        if item.target_name:
            interface_assignments.setdefault(item.target_name, []).append(item)
        for member in item.aggregate_members:
            interface_assignments.setdefault(member, []).append(item)
    for name, owners in interface_assignments.items():
        if len({(item.source_vdom, item.source_name) for item in owners}) > 1:
            for item in owners:
                add("TARGET_INTERFACE_ALREADY_ASSIGNED",
                    f"source {item.source_vdom} / {item.source_name} shares target interface {name!r} with "
                    + ", ".join(f"{owner.source_vdom} / {owner.source_name}" for owner in owners if owner is not item), item)

    profile_names = {}
    for item in (*plan.ike_crypto_profiles, *plan.ipsec_crypto_profiles):
        profile_names.setdefault((item.source_object_type, item.target_name), []).append(item)
    for owners in profile_names.values():
        if len(owners) > 1:
            for item in owners:
                add("duplicate_target_crypto_profile", "device-scoped crypto profile names must be unique across VDOMs", item)

    for item in _items(plan):
        key = _key(item)
        if item.source_object_type in {"address", "address_group", "service", "service_group"}:
            name = item.target_name or item.source_name
            if not isinstance(name, str) or not name.strip() or not re.fullmatch(r"[A-Za-z0-9_. -]{1,63}", name):
                add("invalid_target_object_name", "target object name must contain 1 to 63 letters, numbers, spaces, hyphens, periods or underscores", item)
        if item.source_object_type == "zone":
            if issue := zone_name_issue(item.target_name or item.source_name):
                add("invalid_zone_name", issue, item)
        for warning in item.warnings:
            issues.append(MigrationIssue("planned_item_warning", warning, PANMigrationStatus.MANUAL_REVIEW, _ref(item)))
        if item.source_object_type == "security_rule" and item.status is PANMigrationStatus.UNSUPPORTED:
            add("unsupported_security_rule", "security rule source semantics require manual design", item)
        if item.source_object_type == 'security_rule' and item.profile_group and not re.fullmatch(r'[A-Za-z0-9_. -]{1,63}', item.profile_group):
            add('invalid_security_profile_group', 'Invalid target security profile group name', item)
        if item.source_object_type == 'security_rule':
            if not item.applications:
                add('missing_rule_applications', 'Security rule requires explicit application matching', item)
            from .target.profile import valid_target_identity
            if any(not valid_target_identity(name) for name in item.source_users):
                add('invalid_source_user', 'Source-user matching requires explicit target identities', item)
        if item.source_name and key in seen:
            add("duplicate_target_name", "duplicate target name", item)
        seen.add(key)

        if item.source_object_type == 'management_profile':
            if (not re.fullmatch(r'[A-Za-z0-9_.-]{1,31}', item.target_name or '') or item.target_vsys is not None
                    or not item.protocols or set(item.protocols) - {'ping', 'https', 'ssh', 'snmp', 'http', 'telnet'}
                    or not 1 <= len(item.permitted_ips) <= 64):
                add('invalid_management_profile', 'Management profile requires supported protocols and reviewed permitted networks in device scope', item)
            for network in item.permitted_ips:
                try:
                    if not isinstance(network, str) or str(ip_network(network, strict=True)) != network:
                        raise ValueError('Invalid management network')
                except ValueError:
                    add('invalid_management_profile', 'Management permitted network is invalid', item)
        elif item.source_object_type in {'ike_gateway', 'ipsec_tunnel'}:
            add('vpn_manual_completion_required', 'Gateway credentials and tunnel semantics require secure target completion; no executable VPN commands are available', item)
        elif item.source_object_type in {"ike_crypto_profile", "ipsec_crypto_profile"}:
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,31}", item.target_name or ""):
                add("invalid_target_object_name", "crypto profile name must contain 1 to 31 letters, numbers, periods, hyphens or underscores", item)
            if (item.encryption not in {"aes-128-cbc", "aes-256-cbc"} or item.authentication not in {'sha256', 'sha384', 'sha512'}
                    or item.dh_group not in {"group14", "group15", "group16", "group19", "group20", "group21"}
                       | ({"no-pfs"} if item.source_object_type == "ipsec_crypto_profile" else set())
                    or crypto_lifetime(item.lifetime_seconds) is None):
                add("invalid_crypto_profile", "crypto profile algorithms, DH group or lifetime are unsupported", item)
            if not item.target_vsys:
                add("missing_target_vsys", "missing target VSYS mapping", item)
        elif item.source_object_type == "interface":
            if item.management_profile and not re.fullmatch(r'[A-Za-z0-9_.-]{1,31}', item.management_profile):
                add('invalid_management_profile', 'Invalid target management profile name', item)
            if not item.target_name:
                add("missing_target_interface", "interface has no mapped target name", item)
            if item.interface_family not in {"ethernet", "loopback", "aggregate-ethernet", 'tunnel'}:
                add("unsupported_interface_family", "interface has no supported target family", item)
            if item.interface_family == "aggregate-ethernet":
                if not re.fullmatch(r"ae(?:[1-9]|1[0-6])(?:\.[1-9][0-9]{0,3})?", item.target_name or ""):
                    add("invalid_aggregate_interface", "aggregate requires an ae1 through ae16 identifier and optional valid unit", item)
                if not item.parent and (not item.aggregate_members or item.lacp_mode not in {"static", "active", "passive"}):
                    add("missing_aggregate_settings", "aggregate requires explicit members and aggregation mode", item)
            if item.aggregate_members:
                if (item.interface_family != "aggregate-ethernet" or item.parent
                        or len(set(item.aggregate_members)) != len(item.aggregate_members)
                        or any(not re.fullmatch(r"ethernet[0-9]+/[0-9]+", name) for name in item.aggregate_members)):
                    add("invalid_aggregate_members", "aggregate physical members are invalid or duplicated", item)
            if item.interface_family == 'tunnel' and (not re.fullmatch(r'tunnel\.[1-9][0-9]{0,3}', item.target_name or '') or item.parent or item.tag is not None):
                add('invalid_tunnel_interface', 'Tunnel unit requires a valid identifier without a VLAN parent or tag', item)
            if item.interface_family == "loopback":
                if not re.fullmatch(r"loopback\.[1-9][0-9]{0,3}", item.target_name or "") or item.parent or item.tag is not None:
                    add("invalid_loopback_interface", "loopback requires an identifier from 1 to 9999 and no VLAN parent or tag", item)
            if not item.target_vsys:
                add("missing_target_vsys", "missing target VSYS mapping", item)
            if not item.virtual_router:
                add("missing_virtual_router", "missing target virtual-router mapping", item)
            if item.parent and item.tag is None:
                add("missing_interface_tag", "subinterface is missing an explicit VLAN tag", item)
            if not item.parent and item.tag is not None:
                add("unexpected_interface_tag", "physical interface cannot carry a subinterface tag", item)
            try:
                for value in item.ipv4_addresses:
                    if not isinstance(value, str) or "/" not in value:
                        raise ValueError
                    address = IPv4Interface(value)
                    if item.interface_family == "loopback" and address.network.prefixlen != 32:
                        raise ValueError
            except (ValueError, TypeError):
                add("invalid_interface_address", "interface contains an invalid planned IPv4 address", item)
        elif item.source_object_type == "address":
            if not getattr(item, "address_type", None) or not getattr(item, "value", None):
                add("missing_address_value", "address has no supported explicit value", item)
            elif not _valid_address(item.address_type, item.value):
                add("invalid_address_value", "address has an invalid target representation or value", item)
        elif item.source_object_type == "service":
            if not getattr(item, "protocol", None) or not getattr(item, "destination_port", None):
                add("missing_service_value", "service has no supported protocol or destination port", item)
            elif item.protocol not in {"tcp", "udp"}:
                add("invalid_service_protocol", "service protocol must be TCP or UDP", item)
            for field in ("destination_port", "source_port"):
                value = getattr(item, field, None)
                try:
                    valid = isinstance(value, str) and _validate_ports(value, minimum=0)
                except ValueError:
                    valid = False
                if value is not None and not valid:
                    add("invalid_service_port", f"service {field} is not a valid target port expression", item)
        elif item.source_object_type == "schedule":
            schedule_type = getattr(item, "schedule_type", None)
            if (schedule_type == "recurring" and not getattr(item, "weekly", ())) or (
                schedule_type == "one-time" and not getattr(item, "non_recurring", ())
            ) or schedule_type not in {"recurring", "one-time"}:
                add("missing_schedule_value", "schedule has no supported explicit entries", item)
        elif item.source_object_type == "dhcp_server":
            if not item.target_vsys:
                add("missing_target_vsys", "missing target VSYS mapping", item)
            if not getattr(item, "interface", None):
                add("missing_dhcp_interface", "DHCP server has no mapped target interface", item)
            if getattr(item, "mode", None) not in {"enabled", "disabled"}:
                add("unsupported_dhcp_mode", "DHCP server has no supported explicit mode", item)
            lease_type = getattr(item, "lease_type", None)
            lease_timeout = getattr(item, "lease_timeout", None)
            if lease_type not in {None, "unlimited", "timeout"}:
                add("unsupported_dhcp_lease", "DHCP server has an unsupported lease type", item)
            if lease_type == "timeout" and (
                not isinstance(lease_timeout, int) or not 0 <= lease_timeout <= 1_000_000
            ):
                add("invalid_dhcp_lease", "DHCP timeout is outside the PAN-OS supported range", item)
            if lease_type != "timeout" and lease_timeout is not None:
                add("invalid_dhcp_lease", "DHCP lease timeout is present without timeout mode", item)
            if item.gateway and not _valid_ipv4(item.gateway):
                add("invalid_dhcp_gateway", "DHCP gateway is not a valid IPv4 address", item)
            if item.subnet_mask and not _valid_netmask(item.subnet_mask):
                add("invalid_dhcp_netmask", "DHCP subnet mask is not a valid IPv4 netmask", item)
            for value in (item.dns_primary, item.dns_secondary):
                if value and not _valid_ipv4(value):
                    add("invalid_dhcp_dns", "DHCP DNS server is not a valid IPv4 address", item)
            if not item.ip_pools:
                add("missing_dhcp_pool", "DHCP server has no supported explicit IP pool", item)
            for pool in item.ip_pools:
                if not _valid_pool(pool):
                    add("invalid_dhcp_pool", f"DHCP pool {pool!r} is invalid", item)
        elif item.source_object_type == "static_route":
            if item.admin_distance is not None and (
                type(item.admin_distance) is not int or not 10 <= item.admin_distance <= 240
            ):
                add("invalid_route_admin_distance", "route administrative distance is outside PAN-OS range 10-240", item)
            if not getattr(item, "virtual_router", None):
                add("missing_virtual_router", "missing target virtual-router mapping", item)
            if not getattr(item, "destination", None):
                add("missing_route_destination", "route has no explicit destination", item)
            valid_tunnel_none = item.nexthop_type == 'none' and not item.nexthop and any(interface.target_name == item.interface and interface.interface_family == 'tunnel' and interface.target_vsys == item.target_vsys for interface in plan.interfaces)
            if not valid_tunnel_none and (getattr(item, "nexthop_type", None) not in {None, "ip-address", "discard"} or (not item.nexthop and item.nexthop_type != "discard")):
                add("unsupported_route_nexthop", "route has no supported nexthop", item)
            if getattr(item, "interface", None) is None and any("interface mapping" in warning for warning in item.warnings):
                add("missing_route_interface", "missing target interface mapping", item)
        elif item.source_object_type == "nat_rule":
            for value in item.translated_addresses:
                if not (_valid_ipv4(value) or _valid_pool(value)):
                    add("invalid_snat_address", "SNAT requires an explicit IPv4 host or ordered address range", item)
            if item.source_interface_address and not item.to_interface:
                add("missing_nat_interface", "interface-address NAT requires an explicit mapped interface", item)
            if not item.target_vsys:
                add("missing_target_vsys", "missing target VSYS mapping", item)
            if not item.from_zones or not item.to_zones:
                add("missing_nat_zone", "NAT rule is missing a required from or to zone", item)
            if item.source_kind == "source_nat":
                if not item.source_addresses or not item.destination_addresses:
                    add("missing_nat_address", "NAT rule is missing source or destination match", item)
                if not item.service:
                    add("missing_nat_service", "NAT rule has no explicit service match", item)
                if not item.to_interface:
                    add("missing_nat_interface", "NAT rule has no mapped target interface", item)
                if not item.source_translation_type or (
                    not item.source_interface_address and not item.translated_addresses
                ):
                    add("missing_snat_translation", "SNAT translation is missing", item)
        elif item.source_object_type != "static_route" and not item.target_vsys:
            add("missing_target_vsys", "missing target VSYS mapping", item)

    for groups in (plan.address_groups, plan.service_groups):
        by_identity = {(item.target_vsys, item.target_name or item.source_name): item for item in groups}
        graph = {identity: [(item.target_vsys, name) for name in item.members
                            if (item.target_vsys, name) in by_identity]
                 for identity, item in by_identity.items()}
        while True:
            try:
                TopologicalSorter(graph).prepare()
                break
            except CycleError as exc:
                for identity in exc.args[1]:
                    add("circular_group_reference", "group membership contains a circular dependency", by_identity[identity])
                    graph[identity] = ()

    # A base item is eligible only when its own status and required fields are valid.
    renderable = {
        _key(item) for item in _items(plan)
        if item.status is PANMigrationStatus.SUPPORTED and _key(item) not in errors
    }

    def find(families_to_search, name, vsys):
        for family in families_to_search:
            item = families[family].get((vsys, name))
            if item is not None:
                return item
        return None

    def require_reference(owner, name, accepted_families, *, code="missing_reference"):
        if name == "any" or "services" in accepted_families and name in PAN_BUILTIN_SERVICES:
            return
        dependency = find(accepted_families, name, owner.target_vsys)
        if dependency is None and accepted_families == ('zones',) and (owner.target_vsys, name) in plan.target_zone_references:
            return
        if dependency is None and "addresses" in accepted_families and _valid_ipv4_selector(name):
            return
        if dependency is None:
            add(code, f"reference {name!r} is not in the target VSYS", owner)
        elif _key(dependency) not in renderable:
            add("dependency_not_renderable", f"dependency {name!r} is not renderable", owner)

    # Resolve each dependency in the owner's target VSYS. Repeating this pass
    # propagates failures through arbitrarily nested groups and rules.
    predecessors = policy_order_predecessors(plan)
    changed = True
    while changed:
        changed = False
        for group, members, member_families in (
            *((group, group.members, ("addresses", "address_groups")) for group in plan.address_groups),
            *((group, group.members, ("services", "service_groups")) for group in plan.service_groups),
        ):
            if _key(group) not in renderable:
                continue
            before = _key(group) in renderable
            if not members:
                add("missing_group_member", "group has no members", group)
            for member in members:
                if "services" in member_families and member in PAN_BUILTIN_SERVICES:
                    continue
                dependency = find(member_families, member, group.target_vsys)
                if dependency is None:
                    add("missing_group_member", f"group member {member!r} is not planned in this target VSYS", group)
                elif _key(dependency) not in renderable:
                    add("dependency_not_renderable", f"group member {member!r} is not renderable", group)
            if before and _key(group) in errors:
                renderable.remove(_key(group))
                changed = True

        if plan.interfaces:
            for interface in plan.interfaces:
                if _key(interface) not in renderable or not interface.management_profile:
                    continue
                profile = find(('management_profiles',), interface.management_profile, None)
                if profile is not None and _key(profile) not in renderable:
                    add('dependency_not_renderable', 'Generated management profile is not renderable', interface)
                    renderable.remove(_key(interface))
                    changed = True
            for interface in plan.interfaces:
                if _key(interface) not in renderable or not interface.parent:
                    continue
                parent = find(("interfaces",), interface.parent, interface.target_vsys)
                if (parent is not None and _key(parent) not in renderable
                        or parent is None and interface.interface_family == "aggregate-ethernet"):
                    add("dependency_not_renderable", f"parent interface {interface.parent!r} is not renderable", interface)
                    renderable.remove(_key(interface))
                    changed = True
            for zone in plan.zones:
                if _key(zone) not in renderable:
                    continue
                before = _key(zone) in renderable
                if not zone.interfaces:
                    add("missing_zone_interface", "zone has no mapped target interfaces", zone)
                for name in zone.interfaces:
                    require_reference(zone, name, ("interfaces",), code="missing_interface")
                if before and _key(zone) in errors:
                    renderable.remove(_key(zone))
                    changed = True

            for route in plan.static_routes:
                if _key(route) not in renderable or not route.interface:
                    continue
                before = _key(route) in renderable
                require_reference(route, route.interface, ("interfaces",), code="missing_interface")
                if before and _key(route) in errors:
                    renderable.remove(_key(route))
                    changed = True

        for server in plan.dhcp_servers:
            if _key(server) not in renderable:
                continue
            before = _key(server) in renderable
            require_reference(server, server.interface, ("interfaces",), code="missing_interface")
            if before and _key(server) in errors:
                renderable.remove(_key(server))
                changed = True

        for rule in plan.security_rules:
            if _key(rule) not in renderable:
                continue
            before = _key(rule) in renderable
            predecessor = predecessors.get(item_key(rule))
            if predecessor is not None and _key(predecessor) not in renderable:
                add("policy_predecessor_not_renderable",
                    f"Preceding active policy {predecessor.source_vdom} / {predecessor.source_name} "
                    f"(ID {predecessor.source_policy_id}) is not renderable", rule)
            for field, values, accepted in (
                ("from_zones", rule.from_zones, ("zones",)),
                ("to_zones", rule.to_zones, ("zones",)),
                ("sources", rule.sources, ("addresses", "address_groups")),
                ("destinations", rule.destinations, ("addresses", "address_groups")),
                ("services", rule.services, ("services", "service_groups")),
            ):
                if not values:
                    add("missing_rule_field", f"security rule missing {field}", rule)
                for value in values:
                    require_reference(rule, value, accepted)
            if rule.schedule:
                require_reference(rule, rule.schedule, ("schedules",), code="missing_schedule")
            for name in rule.destinations:
                address = find(("addresses",), name, rule.target_vsys)
                if address is not None and address.source_kind == "vip":
                    nat = next((item for item in plan.nat_rules if item.source_kind == 'vip' and item.source_name == address.source_name and item.target_vsys == rule.target_vsys and item.source_vdom == address.source_vdom), None)
                    if nat is None or nat.source_kind != "vip" or nat.source_vdom != address.source_vdom:
                        add("missing_vip_nat", "VIP security match has no corresponding scoped DNAT rule", rule)
                    elif _key(nat) not in renderable:
                        add("dependency_not_renderable", f"VIP DNAT {address.source_name!r} is not renderable", rule)
            if not rule.action:
                add("missing_action", "security rule has no action", rule)
            if before and _key(rule) in errors:
                renderable.remove(_key(rule))
                changed = True

        for rule in plan.nat_rules:
            if _key(rule) not in renderable:
                continue
            before = _key(rule) in renderable
            if rule.translation_interface and plan.interfaces:
                require_reference(rule, rule.translation_interface, ('interfaces',), code='missing_interface')
            if rule.source_kind in {"source_nat", "vip"}:
                for field, values in (("from_zones", rule.from_zones), ("to_zones", rule.to_zones)):
                    if not values:
                        add("missing_nat_zone", f"NAT rule missing {field}", rule)
                    for value in values:
                        require_reference(rule, value, ("zones",))
            if rule.source_kind == "source_nat":
                if not rule.source_addresses or not rule.destination_addresses:
                    add("missing_nat_address", "NAT rule is missing source or destination match", rule)
                for value in (*rule.source_addresses, *rule.destination_addresses):
                    require_reference(rule, value, ("addresses", "address_groups"))
                if not rule.service:
                    add("missing_nat_service", "NAT rule has no explicit service match", rule)
                else:
                    require_reference(rule, rule.service, ("services", "service_groups"))
                if not rule.to_interface:
                    add("missing_nat_interface", "NAT rule has no mapped target interface", rule)
                elif plan.interfaces:
                    require_reference(rule, rule.to_interface, ("interfaces",), code="missing_interface")
            if rule.source_kind == "vip":
                for value in (*rule.source_addresses, *rule.destination_addresses):
                    require_reference(rule, value, ("addresses", "address_groups"))
                if rule.service:
                    require_reference(rule, rule.service, ("services", "service_groups"))
            if rule.source_kind != "source_nat" and rule.source_translation_type and not (rule.source_interface_address or rule.translated_addresses):
                add("missing_snat_translation", "SNAT translation is missing", rule)
            if rule.source_kind != "source_nat" and not rule.source_translation_type and not rule.destination_translated_address:
                add("missing_dnat_translation", "DNAT translated address is missing", rule)
            if before and _key(rule) in errors:
                renderable.remove(_key(rule))
                changed = True

    result = frozenset(renderable)
    return MigrationValidationResult(tuple(issues), plan, result)


def _valid_address(kind, value):
    if not isinstance(value, str):
        return False
    if kind == "ip-netmask":
        return _valid_ipv4_selector(value)
    if kind == "ip-range":
        return _valid_pool(value)
    if kind == "ip-wildcard":
        return _validate_ip_wildcard(value)
    if kind == "fqdn":
        return len(value) <= 253 and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in value.removesuffix(".").split("."))
    return False


def _valid_ipv4(value):
    try:
        IPv4Address(str(value))
        return True
    except (ValueError, TypeError):
        return False


def _valid_ipv4_selector(value):
    try:
        IPv4Network(str(value), strict=False)
        return True
    except (ValueError, TypeError):
        return False


def _valid_netmask(value):
    try:
        IPv4Network(f"0.0.0.0/{value}")
        return True
    except (ValueError, TypeError):
        return False


def _valid_pool(value):
    try:
        start, end = str(value).split("-", 1)
        return IPv4Address(start) <= IPv4Address(end)
    except (ValueError, TypeError):
        return False


def _index(items):
    return {(item.target_vsys, item.target_name or item.source_name): item for item in items
            if item.target_name or item.source_name}


def _key(item) -> ItemKey:
    return target_identity(item)


def _ref(item):
    return MigrationSourceRef(item.source_vdom, item.source_kind, item.source_name, item.source_policy_id)


def _issue(code, message, item):
    return MigrationIssue(code, message, PANMigrationStatus.UNSUPPORTED, _ref(item))


def _items(plan):
    if plan is None:
        return
    for name in ("addresses", "address_groups", "services", "service_groups", "schedules", "interfaces", "zones", "static_routes", "dhcp_servers", "security_rules", "nat_rules", "ike_crypto_profiles", "ipsec_crypto_profiles", 'ike_gateways', 'ipsec_tunnels', 'management_profiles'):
        yield from getattr(plan, name)
