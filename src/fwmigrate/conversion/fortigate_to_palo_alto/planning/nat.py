"""FortiGate source NAT and deterministic VIP/DNAT planning."""

from typing import Any
from dataclasses import replace

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus, PlannedNATRule
from .policies import ipv6_match_warnings
from .services import service_target
from .addresses import address_references
from .vips import vip_policy_consumers, vip_translation


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


def plan_nat(source: Any, derived: Any, options: Any):
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
            source_addresses=address_references(source, vdom, policy.srcaddr or ()) if policy else (),
            destination_addresses=address_references(source, vdom, policy.dstaddr or ()) if policy else (),
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
        ext, mapped, warnings = vip_translation(vip)
        warnings.extend(warning for _, issues in consumers for warning in issues)
        if not referencing:
            warnings.append("VIP has no referencing firewall policy for NAT source zone")
        from_contexts = []
        to_contexts = []
        match_contexts = []
        for policy in referencing:
            warnings.extend(ipv6_match_warnings(policy))
            warnings.extend(_nat_policy_warnings(policy, service_groups))
            if policy.status not in {None, "enable"}:
                warnings.append("VIP referencing policy is not explicitly supported as active")
            if not policy.srcaddr or len(policy.service or ()) != 1:
                warnings.append("VIP referencing policy requires explicit addresses and one service")
            else:
                match_contexts.append((address_references(source, vdom, policy.srcaddr),
                    service_target(policy.service[0], service_names.get(vdom, ()),
                                   getattr(options, "service_names", {}).get(vdom, {}))))
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
        if len(set(from_contexts)) > 1:
            warnings.append("VIP referencing policies have conflicting source zones")
        if len(set(to_contexts)) > 1:
            warnings.append("VIP referencing policies have conflicting post-NAT destination zones")
        if len(set(match_contexts)) > 1:
            warnings.append("VIP referencing policies have conflicting address/service matches")
        from_zones = from_contexts[0] if from_contexts and len(from_contexts) == len(referencing) and len(set(from_contexts)) == 1 else ()
        external_zone = (_target_zone(options, vdom, vip.extintf, ())
                         if vip.extintf and vip.extintf != "any" else None)
        if not external_zone:
            warnings.append("VIP external interface has no mapped original-packet destination zone")
        result.append(PlannedNATRule(
            source_vdom=vip.vdom, source_kind="vip", source_object_type="nat_rule", source_name=vip.name,
            target_vsys=getattr(getattr(options, "vdoms", {}).get(vip.vdom), "vsys", None), target_name=vip.name,
            status=PANMigrationStatus.SUPPORTED if not warnings else PANMigrationStatus.MANUAL_REVIEW,
            warnings=tuple(warnings), destination_translated_address=(mapped if mapped and not warnings else None),
            destination_addresses=((ext,) if ext else ()),
            source_addresses=match_contexts[0][0] if match_contexts else (),
            from_zones=from_zones, to_zones=(external_zone,) if external_zone else (),
            service=match_contexts[0][1] if match_contexts else None,
        ))
    # FortiGate can apply SNAT and VIP translation together; PAN-OS stops at one NAT rule.
    mixed_scopes = {rule.target_vsys for rule in result if rule.source_kind == "source_nat"} & {
        rule.target_vsys for rule in result if rule.source_kind == "vip"}
    external_matches = {}
    for rule in result:
        if rule.source_kind == "vip":
            external_matches.setdefault((rule.target_vsys, rule.destination_addresses), []).append(rule)
    for index, rule in enumerate(result):
        warning = None
        if rule.target_vsys in mixed_scopes:
            warning = "SNAT/DNAT precedence and combined translation require manual design"
        elif rule.source_kind == "vip" and len(external_matches[(rule.target_vsys, rule.destination_addresses)]) > 1:
            warning = "overlapping VIP external addresses require explicit NAT precedence"
        if warning:
            result[index] = replace(rule, status=PANMigrationStatus.MANUAL_REVIEW, warnings=(*rule.warnings, warning))
    return tuple(result)


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
