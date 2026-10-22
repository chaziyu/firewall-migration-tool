"""Pair-specific completeness accounting for FortiGate to PAN-OS migration."""

from collections import Counter


# FortiGate source families that are extracted and preserved but are not currently
# represented by PANMigrationPlan or by the recommendation engine. Their presence
# must prevent a rendered subset from being reported as a complete migration.
_SOURCE_ONLY_FAMILIES = (
    ("wildcard_fqdns", "wildcard_fqdn"),
    ("ip_pools6", "ip_pool6"),
    ("vip_groups", "vip_group"),
    ("vips6", "vip6"),
    ("vip_groups6", "vip_group6"),
    ("security_policies", "security_policy"),
    ("protocol_options", "protocol_options"),
    ("per_ip_shapers", "per_ip_shaper"),
    ("session_helpers", "session_helper"),
    ("nac_policies", "nac_policy"),
    ("address6_templates", "address6_template"),
    ("ips_settings", "ips_settings"),
    ("kmip_servers", "kmip_server"),
    ("kerberos_keytabs", "kerberos_keytab"),
    ("router_settings", "router_settings"),
    ("sdn_proxies", "sdn_proxy"),
    ("on_demand_sniffers", "on_demand_sniffer"),
    ("affinity_interrupts", "affinity_interrupt"),
    ("serial_ports", "serial_port"),
    ("firewall_regions", "firewall_region"),
    ("vendor_macs", "vendor_mac"),
    ("ssl_vpn_realms", "ssl_vpn_realm"),
    ("ssl_vpn_clients", "ssl_vpn_client"),
    ("ssl_vpn_user_bookmarks", "ssl_vpn_user_bookmark"),
    ("ssl_vpn_user_group_bookmarks", "ssl_vpn_user_group_bookmark"),
    ("ssl_vpn_host_check_software", "ssl_vpn_host_check_software"),
    ("service_categories", "service_category"),
)


def _identity(item, index):
    vdom = getattr(item, "vdom", None) or "root"
    for field in ("name", "id", "seq_num"):
        value = getattr(item, field, None)
        if value not in (None, ""):
            return vdom, str(value)
    return vdom, str(index)


def build_migration_coverage(source, recommendations=(), *, planned_vpn_sources=(), planned_vip_groups=(),
                             plan=None, options=None):
    """Return migration work that is preserved but not executable yet.

    This is deliberately FortiGate -> PAN-OS specific. It does not create a
    vendor-neutral model and it does not infer target configuration.
    """
    unplanned = []
    if plan is not None:
        unplanned.extend(_unplanned_interfaces(source, plan, options))
    unplanned.extend(_unplanned_ip_pools(source, plan))

    for recommendation in recommendations:
        if recommendation.family == 'VPN' and (recommendation.source_vdom or 'root', recommendation.source_kind, recommendation.source_name) in planned_vpn_sources:
            continue
        unplanned.append({
            "status": "RECOMMENDATION_ONLY",
            "source_vdom": recommendation.source_vdom,
            "source_kind": recommendation.source_kind,
            "source_name": recommendation.source_name,
            "family": recommendation.family,
            "target_object_type": recommendation.target_object_type,
            "readiness": recommendation.readiness.value,
            "reason": f"{recommendation.family} source configuration is represented as review guidance but is not emitted by PANMigrationPlan.",
        })

    for attribute, source_kind in _SOURCE_ONLY_FAMILIES:
        for index, item in enumerate(getattr(source, attribute, ()) or ()):
            vdom, name = _identity(item, index)
            if attribute == 'vip_groups' and (vdom, name) in planned_vip_groups:
                continue
            unplanned.append({
                "status": "SOURCE_ONLY",
                "source_vdom": vdom,
                "source_kind": source_kind,
                "source_name": name,
                "family": attribute,
                "target_object_type": None,
                "readiness": "UNSUPPORTED",
                "reason": "Source configuration is preserved but this migration pair has no executable planner coverage for it.",
            })

    unplanned.sort(key=lambda item: (
        item["status"],
        str(item["source_vdom"]).casefold(),
        str(item["source_kind"]).casefold(),
        str(item["source_name"]).casefold(),
    ))
    counts = Counter(item["status"] for item in unplanned)
    return {
        "complete": not unplanned,
        "unplanned_count": len(unplanned),
        "counts": {
            "RECOMMENDATION_ONLY": counts["RECOMMENDATION_ONLY"],
            "SOURCE_ONLY": counts["SOURCE_ONLY"],
        },
        "unplanned": unplanned,
    }


def _unplanned_ip_pools(source, plan):
    """Track pool definitions through scoped NAT consumers, not names alone.

    Like interfaces, a pool with a corresponding plan is covered even if that
    plan is blocked: its rule status/warnings describe the remaining work.
    Split service rules and combined SNAT/DNAT retain the source policy ID.
    """
    policies = {}
    for policy in getattr(source, 'policies', ()):
        policies.setdefault((policy.vdom or 'root', policy.policy_id), []).append(policy)
    represented = set()
    for rule in getattr(plan, 'nat_rules', ()):
        if (rule.source_policy_id is None or not rule.translated_addresses
                or not rule.source_translation_type or rule.source_interface_address):
            continue
        owners = policies.get((rule.source_vdom or 'root', rule.source_policy_id), ())
        if len(owners) == 1:
            represented.update((owners[0].vdom or 'root', name) for name in owners[0].poolname or ())
    for pool in getattr(source, 'ip_pools', ()):
        vdom = pool.vdom or 'root'
        if (vdom, pool.name) in represented:
            continue
        yield {'status': 'SOURCE_ONLY', 'source_vdom': vdom, 'source_kind': 'ip_pool',
               'source_name': pool.name, 'family': 'ip_pools', 'target_object_type': None,
               'readiness': 'UNSUPPORTED',
               'reason': 'IPv4 IP-pool definition has no corresponding translated-address NAT plan. '
                         'Review its consumers or explicitly retire the definition; no standalone pool commands are emitted.'}


def _unplanned_interfaces(source, plan, options):
    interfaces = {(item.vdom or 'root', item.name): item for item in source.interfaces}
    planned = {(item.source_vdom or 'root', item.source_name): item for item in plan.interfaces}
    represented = set(planned)
    mappings = getattr(options, 'interfaces', {})
    excluded = set(getattr(options, 'conversion_settings', {}).get('excluded_interfaces', ()))
    for identity, source_interface in interfaces.items():
        parent = planned.get(identity)
        if ((source_interface.type or '').casefold() != 'aggregate' or parent is None
                or parent.interface_family != 'aggregate-ethernet'):
            continue
        for member in source_interface.members:
            mapping = mappings.get(identity[0], {}).get(member)
            target = getattr(mapping, 'target_interface', None)
            if target and target in parent.aggregate_members:
                represented.add((identity[0], member))
    for vdom, name in interfaces:
        if (vdom, name) in represented:
            continue
        mapping = mappings.get(vdom, {}).get(name)
        readiness = 'UNSUPPORTED'
        if f'{vdom}/{name}' in excluded:
            reason = 'Source interface is explicitly excluded from conversion; no interface commands are emitted.'
        elif not getattr(mapping, 'target_interface', None):
            readiness = 'PENDING'
            reason = ('Source interface has no approved target placement in this plan. '
                      'Review its interface and zone mappings and source support; no commands are emitted for this record.')
        else:
            reason = 'Source interface is not represented by the current interface plan; review its source support and parent relationships.'
        yield {'status': 'SOURCE_ONLY', 'source_vdom': vdom, 'source_kind': 'interface',
               'source_name': name, 'family': 'interface', 'target_object_type': None,
               'readiness': readiness, 'reason': reason}


__all__ = ["build_migration_coverage"]


def represented_vip_groups(source, plan, satisfied_keys):
    """Only complete flattened groups with satisfied consumer rules count as handled."""
    from .planning.addresses import vip_group_addresses
    from .plan_dependencies import item_key
    result = set()
    for group in getattr(source, 'vip_groups', ()):
        vdom = group.vdom or 'root'
        members, warnings = vip_group_addresses(source, vdom, (group.name,))
        if warnings:
            continue
        consumers = [policy for policy in source.policies if (policy.vdom or 'root') == vdom and group.name in (policy.dstaddr or ())]
        if not consumers:
            continue
        required = [rule for policy in consumers for rule in plan.security_rules
            if rule.source_vdom == vdom and rule.source_policy_id == policy.policy_id and rule.source_name == (policy.name or str(policy.policy_id))]
        if len(required) != len(consumers):
            continue
        complete = True
        for member in members:
            addresses = [item for item in plan.addresses if item.source_kind == 'vip' and item.source_vdom == vdom and item.source_name == member]
            rules = [item for item in plan.nat_rules if item.source_kind == 'vip' and item.source_vdom == vdom and item.source_name == member]
            if len(addresses) != 1 or not rules:
                complete = False
            required.extend((*addresses, *rules))
        if complete and all(item_key(item) in satisfied_keys for item in required):
            result.add((vdom, group.name))
    return result
