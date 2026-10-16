"""FortiGate source NAT and deterministic VIP/DNAT planning."""

from typing import Any
from dataclasses import replace
from ipaddress import IPv4Address, IPv4Network

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus, PlannedNATRule
from .policies import ipv6_match_warnings
from .services import service_target
from .addresses import address_references, explicit_all_vdoms
from .vips import vip_policy_consumers, vip_translation, vip_port_translation, vip_service_name


def _service_matches(names, vdom, views):
    """Expand an explicit union into adjacent single-service NAT rules."""
    services = {item.name: item for item in getattr(views, 'services', ()) if (item.vdom or 'root') == vdom}
    groups = {item.name: item for item in getattr(views, 'groups', ()) if (item.vdom or 'root') == vdom}
    def visit(name, seen):
        if name in seen or len(seen) > 64 or name in groups and name in services:
            return None
        if name in groups:
            members = groups[name].members
            if not members:
                return None
            result = []
            for member in members:
                values = visit(member, seen | {name})
                if values is None:
                    return None
                result.extend(values)
                if len(result) > 256:
                    return None
            return result
        if name in services:
            item = services[name]
            return [name] if item.protocol in {'tcp', 'udp'} and item.port is not None else None
        if name == 'DNS':
            return ['FG-DNS-TCP', 'FG-DNS-UDP']
        return [name] if name in {'ALL', 'HTTP', 'HTTPS'} else None
    result = []
    for name in names or ():
        values = visit(name, set())
        if values is None:
            return None
        result.extend(values)
        if len(result) > 256:
            return None
    if 'ALL' in result and 'ALL' not in services and 'ALL' not in groups:
        return ('ALL',)
    return tuple(dict.fromkeys(result)) or None


def _packet_disjoint_test(source, derived=None):
    """Prove disjoint matches; unresolved names and cycles are never disjoint."""
    objects = {}
    for family in ('addresses', 'address_groups', 'vips', 'vip_groups'):
        for item in getattr(source, family, ()):
            objects.setdefault((item.vdom or 'root', item.name), []).append((family, item))

    cache = {}
    def named(vdom, name, seen=()):
        if name in seen or len(seen) >= 64:
            return None
        key = (vdom, name)
        if key not in cache:
            cache[key] = resolve(vdom, name, seen)
        return cache[key]

    def resolve(vdom, name, seen):
        matches = objects.get((vdom, name), ())
        if len(matches) > 1:
            return None
        if matches:
            family, item = matches[0]
            if family == 'address_groups':
                if item.exclude not in {None, 'disable'} or item.exclude_members or not item.members or len(item.members) > 256:
                    return None
                parts = [named(vdom, member, (*seen, name)) for member in item.members]
                if any(part is None for part in parts):
                    return None
                result = tuple(value for part in parts for value in part)
                return result if len(result) <= 256 else None
            if family != 'addresses' or item.address_family != 'ipv4' or item.raw_extra:
                return None
            if item.type not in {None, 'ipmask', 'iprange'}:
                return None
            if item.start_ip and item.end_ip:
                try:
                    start, end = int(IPv4Address(item.start_ip)), int(IPv4Address(item.end_ip))
                    return ((start, end),) if start <= end else None
                except ValueError:
                    return None
            name = '/'.join(item.subnet.split()) if item.subnet else ''
        if name in {'any', 'all'} and not matches:
            name = '0.0.0.0/0'
        try:
            network = IPv4Network(name, strict=False)
            return ((int(network.network_address), int(network.broadcast_address)),)
        except ValueError:
            return None

    def disjoint(first, second, first_names, second_names):
        if not first_names or not second_names:
            return False
        left = [named(first.source_vdom or 'root', name) for name in first_names]
        right = [named(second.source_vdom or 'root', name) for name in second_names]
        return all(part is not None for part in [*left, *right]) and all(
            a_end < b_start or b_end < a_start for group_a in left for group_b in right
            for a_start, a_end in group_a for b_start, b_end in group_b)

    def independent(first, second):
        # FortiGate VIP eligibility precedes policy matching. Consumer policy zones
        # and addresses alone cannot prove that an SNAT flow avoids the VIP.
        pair = [objects.get((rule.source_vdom or 'root', rule.source_name), ()) for rule in (first, second)]
        second_vip = pair[1][0][1] if len(pair[1]) == 1 and pair[1][0][0] == 'vips' else None
        if second_vip is None or vip_translation(second_vip, derived)[2]:
            return False
        if first.source_kind == second.source_kind == 'vip':
            first_vip = pair[0][0][1] if len(pair[0]) == 1 and pair[0][0][0] == 'vips' else None
            if first_vip is None or vip_translation(first_vip, derived)[2]:
                return False
            ports = [vip_port_translation(item) for item in (first_vip, second_vip)]
            if all(ports) and ports[0][:2] != ports[1][:2]:
                return True
            return False
        if first.source_kind != 'source_nat':
            return False
        # Also exclude VIP reverse-SNAT of the mapped server, even for other destinations.
        destination = (second_vip.extip, second_vip.mappedip[0])
        return disjoint(first, second, first.source_addresses, (second_vip.mappedip[0],)) and disjoint(
            first, second, first.destination_addresses, destination)
    return independent


def plan_nat(source: Any, derived: Any, options: Any, *, explicit_all=None):
    if explicit_all is None:
        explicit_all = explicit_all_vdoms(source)
    external_zones = getattr(options, 'conversion_settings', {}).get('vip_external_zones', {})
    identities = {(vip.vdom or 'root', vip.name) for vip in getattr(source, 'vips', ())}
    if any((vdom, name) not in identities for vdom, mappings in external_zones.items() for name in mappings):
        raise ValueError('VIP external zones must select current source VIP identities')
    service_names = {}
    service_views = getattr(derived, "services", None)
    service_groups = {(service.vdom, service.name) for service in getattr(service_views, "groups", ())}
    for service in (*getattr(service_views, "services", ()), *getattr(service_views, "groups", ())):
        service_names.setdefault(service.vdom, set()).add(service.name)
    policies = {(item.vdom or "root", item.policy_id): item for item in getattr(source, "policies", ())}
    zone_names = {(item.vdom or "root", item.name) for item in getattr(source, "zones", ())}
    result = []
    for item in getattr(derived, "nat", ()):
        vdom = item.vdom or "root"
        policy = policies.get((vdom, item.policy_id))
        matches = _service_matches(policy.service, vdom, service_views) if policy else None
        egress_mapping = (
            getattr(options, "interfaces", {}).get(vdom, {}).get(item.egress_interfaces[0])
            if len(item.egress_interfaces) == 1 else None
        )
        warnings = list(item.issues)
        translated = item.translated_addresses[0] if len(item.translated_addresses) == 1 else None
        if len(item.translated_addresses) != 1:
            warnings.append("NAT translation is not deterministic")
        if item.egress_interfaces and len(item.egress_interfaces) != 1:
            warnings.append("NAT has multiple possible egress interfaces")
        if policy is None:
            warnings.append("source NAT policy could not be resolved")
        elif getattr(item, "policy_disabled", False) or str(getattr(policy, "status", "")).strip().lower() in {
            "disable", "disabled", "no", "0"
        }:
            warnings.append("source firewall policy is explicitly disabled; automated NAT activation is unsafe")
        elif not policy.service:
            warnings.append("source NAT policy has no explicit service match")
        elif len(policy.service) > 1:
            warnings.append("source NAT policy has multiple services; service-group semantics are not verified")
        if policy is not None:
            warnings.extend(ipv6_match_warnings(policy))
            warnings.extend(_nat_policy_warnings(policy, service_groups))
            for field, names in (("source", policy.srcintf or ()), ("destination", item.egress_interfaces)):
                if not names or len(_policy_zones(policy, names, options, zone_names)) != len(names):
                    warnings.append(f"NAT {field} zone mapping is incomplete")
            if not policy.srcaddr or not policy.dstaddr:
                warnings.append("source NAT policy is missing explicit address match")
        if item.egress_interfaces and (egress_mapping is None or not getattr(egress_mapping, "target_interface", None)):
            warnings.append("missing mapped target interface for NAT egress")
        if item.translation_type == "ip_pool" and (
            len(getattr(item, "pool_types", ())) != len(getattr(item, "pool_names", ()))
            or not item.pool_types
            or any((pool_type or "").lower() != "overload" for pool_type in item.pool_types)
        ):
            warnings.append("source IP-pool type is not explicitly verified as overload")
        source_translation_type = None
        translated_addresses = ()
        source_interface_address = False
        if translated and item.translation_type == "ip_pool":
            source_translation_type, translated_addresses = "dynamic-ip-and-port", (translated,)
        elif item.translation_type == "interface_address":
            source_translation_type, source_interface_address = "dynamic-ip-and-port", True
        if not source_translation_type:
            warnings.append("unsafe source NAT was not rendered")
        if matches:
            warnings = [warning for warning in warnings if warning not in {
                'source NAT policy has multiple services; service-group semantics are not verified',
                'NAT service-group matching has no verified PAN-OS service mapping'}]
        result.append(PlannedNATRule(
            source_vdom=item.vdom, source_kind="source_nat", source_object_type="nat_rule",
            source_name=item.policy_name or str(item.policy_id), source_policy_id=item.policy_id,
            target_vsys=getattr(getattr(options, "vdoms", {}).get(item.vdom), "vsys", None), target_name=item.policy_name or str(item.policy_id),
            status=PANMigrationStatus.SUPPORTED if not warnings else PANMigrationStatus.MANUAL_REVIEW,
            warnings=tuple(warnings), source_translation_type=source_translation_type,
            translated_addresses=translated_addresses, source_interface_address=source_interface_address,
            from_zones=_policy_zones(policy, policy.srcintf or (), options, zone_names) if policy else (),
            to_zones=_policy_zones(policy, item.egress_interfaces, options, zone_names),
            source_addresses=address_references(source, vdom, policy.srcaddr or (), explicit_all=explicit_all) if policy else (),
            destination_addresses=address_references(source, vdom, policy.dstaddr or (), explicit_all=explicit_all) if policy else (),
            service=(service_target(matches[0], service_names.get(vdom, ()), getattr(options, "service_names", {}).get(vdom, {})) if matches and len(matches) == 1 else
                     service_target(policy.service[0], service_names.get(vdom, ()), getattr(options, "service_names", {}).get(vdom, {})) if policy and policy.service and len(policy.service) == 1 else None),
            to_interface=getattr(egress_mapping, "target_interface", None),
        ))
        if matches and len(matches) > 1 and not warnings:
            original = result.pop()
            result.extend(replace(original, target_name=f'{original.target_name}-svc-{number}',
                service=service_target(name, service_names.get(vdom, ()), getattr(options, 'service_names', {}).get(vdom, {})))
                for number, name in enumerate(matches, 1))
    vip_consumers = vip_policy_consumers(source, derived)
    for vip in getattr(source, "vips", ()):
        vdom = vip.vdom or "root"
        consumers = vip_consumers.get((vdom, vip.name), ())
        referencing = [policy for policy, _ in consumers]
        ext, mapped, warnings = vip_translation(vip, derived)
        port_translation = vip_port_translation(vip)
        warnings.extend(warning for _, issues in consumers for warning in issues)
        if not referencing:
            warnings.append("VIP has no referencing firewall policy for NAT source zone")
        from_contexts = []
        to_contexts = []
        match_contexts = []
        for policy in referencing:
            warnings.extend(ipv6_match_warnings(policy))
            matches = _service_matches(policy.service, vdom, service_views)
            policy_warnings = _nat_policy_warnings(policy, service_groups)
            warnings.extend(warning for warning in policy_warnings if not matches or warning != 'NAT service-group matching has no verified PAN-OS service mapping')
            if port_translation:
                if policy.service != ['ALL'] or 'ALL' in service_names.get(vdom, ()):
                    warnings.append('VIP port translation currently requires an explicit built-in ALL policy service; other post-translation service matches require review')
                matches = (vip_service_name(vip),)
            if policy.status not in {None, "enable"}:
                warnings.append("VIP referencing policy is not explicitly supported as active")
            if not policy.srcaddr or not matches:
                warnings.append("VIP referencing policy requires explicit addresses and supported service matches")
            else:
                match_contexts.append((address_references(source, vdom, policy.srcaddr, explicit_all=explicit_all),
                    tuple(service_target(name, service_names.get(vdom, ()),
                                   getattr(options, "service_names", {}).get(vdom, {})) for name in matches)))
            names = policy.srcintf or ()
            zones = _policy_zones(policy, names, options, zone_names)
            if not names or len(zones) != len(names):
                warnings.append("VIP referencing policy has unresolved source zone")
            else:
                from_contexts.append(tuple(sorted(set(zones))))
            post_zones = _policy_zones(policy, policy.dstintf or (), options, zone_names)
            if not policy.dstintf or len(post_zones) != len(policy.dstintf) or "any" in post_zones or len(set(post_zones)) != 1:
                warnings.append("VIP referencing policy has unresolved post-NAT destination zone")
            else:
                to_contexts.append(tuple(sorted(set(post_zones))))
        if len(set(to_contexts)) > 1:
            warnings.append("VIP referencing policies have conflicting post-NAT destination zones")
        variants = []
        seen_variants = set()
        if not warnings and len(from_contexts) == len(match_contexts) == len(referencing):
            for zones, (addresses, services) in zip(from_contexts, match_contexts):
                for service in services:
                    variant = (zones, addresses, service)
                    if variant not in seen_variants:
                        seen_variants.add(variant)
                        variants.append(variant)
                    if len(variants) > 256:
                        break
                if len(variants) > 256:
                    break
        if len(variants) > 256:
            warnings.append('VIP consumer expansion exceeds 256 rule variants')
        from_zones = from_contexts[0] if from_contexts and len(from_contexts) == len(referencing) and len(set(from_contexts)) == 1 else ()
        external_zone = (_target_zone(options, vdom, vip.extintf, ())
                         if vip.extintf and vip.extintf != "any" else None)
        choice = external_zones.get(vdom, {}).get(vip.name)
        if choice and external_zone and choice != external_zone:
            raise ValueError(f'VIP {vdom}/{vip.name}: destination-zone choice conflicts with the mapped external interface')
        external_zone = external_zone or choice
        if not external_zone:
            warnings.append("VIP external interface has no mapped original-packet destination zone")
        result.append(PlannedNATRule(
            source_vdom=vip.vdom, source_kind="vip", source_object_type="nat_rule", source_name=vip.name,
            target_vsys=getattr(getattr(options, "vdoms", {}).get(vip.vdom), "vsys", None), target_name=vip.name,
            status=PANMigrationStatus.SUPPORTED if not warnings else PANMigrationStatus.MANUAL_REVIEW,
            warnings=tuple(warnings), destination_translated_address=(mapped if mapped and not warnings else None),
            destination_translated_port=port_translation[2] if port_translation else None,
            destination_addresses=((ext,) if ext else ()),
            source_addresses=match_contexts[0][0] if match_contexts else (),
            from_zones=from_zones, to_zones=(external_zone,) if external_zone else (),
            service=match_contexts[0][1][0] if match_contexts else None,
        ))
        if variants and not warnings:
            original = result.pop()
            result.extend(replace(original, target_name=original.target_name if len(variants) == 1 else f'{original.target_name}-match-{number}',
                from_zones=zones, source_addresses=addresses, service=service)
                for number, (zones, addresses, service) in enumerate(variants, 1))
    result = _combine_single_policy_nat(source, result)
    # FortiGate can apply SNAT and VIP translation together; PAN-OS stops at one NAT rule.
    independent = _packet_disjoint_test(source, derived)
    mixed = set()
    for first_index, first in enumerate(result):
        if first.source_kind != 'source_nat':
            continue
        for second_index, second in enumerate(result):
            if second.source_kind == 'vip' and first.target_vsys == second.target_vsys and not independent(first, second):
                mixed.update((first_index, second_index))
    external_matches = {}
    for rule in result:
        if rule.source_kind == "vip":
            external_matches.setdefault((rule.target_vsys, rule.destination_addresses), []).append(rule)
    for index, rule in enumerate(result):
        warning = None
        if index in mixed:
            warning = "SNAT/DNAT precedence and combined translation require manual design"
        elif rule.source_kind == "vip" and any(
                (other.source_vdom, other.source_name) != (rule.source_vdom, rule.source_name)
                and not independent(rule, other)
                for other in external_matches[(rule.target_vsys, rule.destination_addresses)]):
            warning = "overlapping VIP external addresses require explicit NAT precedence"
        if warning:
            result[index] = replace(rule, status=PANMigrationStatus.MANUAL_REVIEW, warnings=(*rule.warnings, warning))
    return tuple(result)


def _combine_single_policy_nat(source, rules):
    # shortcut: only an isolated one-policy pool-SNAT/static-VIP flow; expand after packet partitioning is verified.
    if len(rules) != 2 or len(source.policies) != 1:
        return rules
    snats = [rule for rule in rules if rule.source_kind == 'source_nat']
    dnats = [rule for rule in rules if rule.source_kind == 'vip']
    if len(snats) != 1 or len(dnats) != 1:
        return rules
    snat, dnat = snats[0], dnats[0]
    policy = source.policies[0]
    if (snat.status is not PANMigrationStatus.SUPPORTED or dnat.status is not PANMigrationStatus.SUPPORTED
            or snat.source_vdom != dnat.source_vdom or snat.target_vsys != dnat.target_vsys
            or policy.dstaddr != [dnat.source_name] or policy.policy_id != snat.source_policy_id
            or snat.source_interface_address or not snat.translated_addresses
            or snat.service != 'any' or dnat.service != 'any' or dnat.destination_translated_port
            or snat.from_zones != dnat.from_zones or snat.source_addresses != dnat.source_addresses):
        return rules
    # Exclude mapped-server sources so VIP reverse-SNAT cannot supersede this pool translation.
    if len(policy.srcaddr or ()) != 1:
        return rules
    addresses = [item for item in source.addresses if item.name == policy.srcaddr[0]
        and (item.vdom or 'root') == (policy.vdom or 'root')]
    if (len(addresses) != 1 or addresses[0].type not in {None, 'ipmask'} or addresses[0].raw_extra
            or addresses[0].address_family != 'ipv4' or not addresses[0].subnet):
        return rules
    try:
        clients = IPv4Network('/'.join(addresses[0].subnet.split()), strict=True)
        if IPv4Address(dnat.destination_translated_address) in clients:
            return rules
    except ValueError:
        return rules
    return [replace(dnat, source_policy_id=policy.policy_id, target_name=f'{dnat.target_name}-snat-{policy.policy_id}',
        source_translation_type=snat.source_translation_type, translated_addresses=snat.translated_addresses,
        translation_interface=snat.to_interface)]


def _nat_policy_warnings(policy, service_groups):
    warnings = []
    if getattr(policy, "status", None) not in {None, "enable", "disable", "disabled", "no", "0"}:
        warnings.append("NAT policy state is unsupported")
    if getattr(policy, "poolname", None) and getattr(policy, "ippool", None) not in {None, "enable"}:
        warnings.append("NAT IP-pool references conflict with the explicit pool activation setting")
    if any(((policy.vdom or "root"), name) in service_groups for name in policy.service or ()):
        warnings.append("NAT service-group matching has no verified PAN-OS service mapping")
    for field in ("srcaddr_negate", "dstaddr_negate", "srcaddr6_negate", "dstaddr6_negate", "service_negate"):
        if getattr(policy, field, None) not in {None, "disable", "no", "0"}:
            warnings.append(f"NAT cannot preserve {field}")
    if getattr(policy, "users", None) or getattr(policy, "groups", None):
        warnings.append("NAT user/group matching is unsupported")
    if any(getattr(policy, field, None) not in {None, "disable"}
           for field in ("internet_service", "internet_service_src")) or any(
        getattr(policy, field, None) for field in (
            "internet_service_name", "internet_service_group", "internet_service_custom",
            "internet_service_src_name", "internet_service_src_group", "internet_service_src_custom",
        )
    ):
        warnings.append("NAT Internet Service matching is unsupported")
    if getattr(policy, "schedule", None) != "always":
        warnings.append("NAT requires an explicit always schedule; scheduled matching is unsupported")
    if getattr(policy, "action", None) != "accept" or getattr(policy, "vpntunnel", None):
        warnings.append("NAT requires an explicit supported accept action")
    for key in getattr(policy, "raw_extra", {}):
        if key not in {"uuid", "global-label", "label"}:
            warnings.append(f"unclassified NAT policy setting {key!r} requires manual review")
    return warnings


def _target_zone(options, vdom, name, zone_names):
    zones = getattr(options, "zones", None)
    mappings = ((zones or {}) if (vdom, name) in zone_names and zones is not None
                else getattr(options, "interfaces", {})).get(vdom, {})
    mapping = mappings.get(name)
    return getattr(mapping, "target_zone", None)


def _policy_zones(policy, names, options, zone_names=()):
    if policy is None:
        return ()
    if "any" in names:
        return ("any",) if len(names) == 1 else ()
    vdom = getattr(policy, "vdom", None) or "root"
    return tuple(zone for name in names if (zone := _target_zone(options, vdom, name, zone_names)))
