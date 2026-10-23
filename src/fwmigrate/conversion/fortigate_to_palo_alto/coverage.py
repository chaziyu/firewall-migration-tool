"""Pair-specific completeness accounting for FortiGate to PAN-OS migration."""

from collections import Counter
import json


# FortiGate source families that are extracted and preserved but are not currently
# represented by PANMigrationPlan or by the recommendation engine. Their presence
# must prevent a rendered subset from being reported as a complete migration.
_SOURCE_ONLY_FAMILIES = (
    ("central_snat", "central_snat"),
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


# Native edit keys differ from descriptive labels. Keep these aligned with the
# FortiGate typed source inventory; singleton sections have no edit key.
_SOURCE_IDENTITY_FIELDS = {
    "central_snat": "policy_id",
    "security_policies": "policy_id",
    "session_helpers": "id",
    "affinity_interrupts": "id",
    "firewall_regions": "id",
    "vendor_macs": "id",
    "ssl_vpn_realms": "url_path",
    "ssl_vpn_user_bookmarks": "owner_name",
    "ssl_vpn_user_group_bookmarks": "owner_name",
    "ips_settings": None,
    "router_settings": None,
}


def _identity(item, index, family):
    # None may mean global or unavailable scope; neither establishes root.
    vdom = getattr(item, "vdom", None)
    field = _SOURCE_IDENTITY_FIELDS.get(family, "name")
    if field is None:
        return vdom, family
    value = getattr(item, field, None)
    if value in (None, ""):
        value = getattr(item, "raw_extra", {}).get(f"unparsed_{field}")
    return vdom, str(value) if value not in (None, "") else f"<unidentified:{index}>"


def build_migration_coverage(source, recommendations=(), *, planned_vpn_sources=(), planned_vip_groups=(),
                             plan=None, options=None, source_inventory=None):
    """Return migration work that is preserved but not executable yet.

    This is deliberately FortiGate -> PAN-OS specific. It does not create a
    vendor-neutral model and it does not infer target configuration.
    """
    unplanned = []
    if plan is not None:
        unplanned.extend(_unplanned_interfaces(source, plan, options))
        unplanned.extend(_unplanned_zones(source, plan, options))
    unplanned.extend(_unplanned_ip_pools(source, plan))
    unplanned.extend(_unmodeled_source_records(source, source_inventory))

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
            vdom, name = _identity(item, index, attribute)
            represented_group = attribute == 'vip_groups' and (vdom, name) in planned_vip_groups
            group_comment = attribute == 'vip_groups' and item.comments is not None
            if represented_group and not group_comment:
                continue
            reason = "Source configuration is preserved but this migration pair has no executable planner coverage for it."
            if group_comment:
                reason = ("VIP-group comment requires manual metadata review; flattened VIP membership and traffic "
                          "commands do not preserve the source group's comment.")
                if not represented_group:
                    reason += " Group membership and consumer coverage also remain unresolved."
            elif attribute == 'session_helpers' and item.name is not None:
                reason = (f"FortiGate system session-helper entry {name!r} (helper type {item.name!r}) is preserved "
                          "but requires manual target application/helper review; no target commands are emitted.")
            unplanned.append({
                "status": "SOURCE_ONLY",
                "source_vdom": vdom,
                "source_kind": source_kind,
                "source_name": name,
                "family": attribute,
                "target_object_type": None,
                "readiness": "UNSUPPORTED",
                "reason": reason,
            })

    unplanned.sort(key=lambda item: (
        item["status"],
        str(item["source_vdom"]).casefold(),
        str(item["source_kind"]).casefold(),
        str(item["source_name"]).casefold(),
    ))
    counts = Counter(item["status"] for item in unplanned)
    return {
        "inventory_available": source_inventory is not None,
        "complete": not unplanned,
        "unplanned_count": len(unplanned),
        "counts": {
            "RECOMMENDATION_ONLY": counts["RECOMMENDATION_ONLY"],
            "SOURCE_ONLY": counts["SOURCE_ONLY"],
        },
        "unplanned": unplanned,
    }


def _unmodeled_source_records(source, inventory):
    """Account for native extraction evidence without exporting its values."""
    if inventory is None:
        return
    from ...vendors.fortigate.extraction.coverage import (
        build_typed_source_identity_index, build_typed_source_inventory,
        extraction_status, find_typed_source_object, supports_path,
    )
    index = build_typed_source_identity_index(build_typed_source_inventory(source))
    for record in inventory:
        status = extraction_status(supports_path(record.source_path),
                                   find_typed_source_object(index, record), record)
        if status not in {'SOURCE_ONLY', 'MODEL_GAP'}:
            continue
        # Encode the complete native identity: repeated leaf names under
        # different sections/parents must remain separate review objects.
        name = json.dumps((record.cli_scope, record.source_path, *record.parent_objects, record.object_name),
                          ensure_ascii=False)
        yield {'status': 'SOURCE_ONLY', 'source_vdom': record.vdom,
               'source_kind': 'source_section', 'source_name': name, 'family': 'source_sections',
               'target_object_type': None, 'readiness': 'UNSUPPORTED',
               'source_scope': record.cli_scope, 'source_path': record.source_path,
               'parent_objects': list(record.parent_objects), 'source_line': record.start_line_number,
               'extraction_status': status,
               'reason': f'Preserved FortiGate section {record.source_path!r} ({record.cli_scope} scope) '
                         'is outside supported migration source coverage. Review or explicitly retire '
                         'this configuration; no target commands are emitted for this record.'}


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


def _unplanned_zones(source, plan, options):
    represented = {(item.source_vdom or 'root', item.source_name) for item in plan.zones
                   if item.source_kind == 'zone'}
    represented.update((ref.source_vdom or 'root', ref.source_name) for item in plan.zones
                       for ref in item.source_contributors if ref.source_kind == 'zone')
    for zone in getattr(source, 'zones', ()):
        vdom = zone.vdom or 'root'
        if (vdom, zone.name) in represented:
            continue
        zone_mappings = getattr(options, 'zones', None)
        mappings = zone_mappings if zone_mappings is not None else getattr(options, 'interfaces', {})
        mapping = mappings.get(vdom, {}).get(zone.name)
        pending = not getattr(mapping, 'target_zone', None)
        yield {'status': 'SOURCE_ONLY', 'source_vdom': vdom, 'source_kind': 'zone',
               'source_name': zone.name, 'family': 'zone', 'target_object_type': None,
               'readiness': 'PENDING' if pending else 'UNSUPPORTED',
               'reason': 'Source zone is not represented by the current plan. Review its target zone '
                         'mapping and member interfaces; no zone commands are emitted for this record.'}


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
    """Return satisfied membership/consumer groups; metadata coverage is separate."""
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
