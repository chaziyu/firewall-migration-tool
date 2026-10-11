"""FortiGate source NAT and deterministic VIP/DNAT planning."""

from typing import Any

from fwmigrate.conversion.fortigate_to_palo_alto.models import PANMigrationStatus, PlannedNATRule
from .policies import ipv6_match_warnings


def plan_nat(source: Any, derived: Any, options: Any):
    policies = {(item.vdom or "root", item.policy_id): item for item in getattr(source, "policies", ())}
    zone_names = {(item.vdom or "root", item.name) for item in getattr(source, "zones", ())}
    result = []
    for item in getattr(derived, "nat", ()):
        vdom = item.vdom or "root"
        policy = policies.get((vdom, item.policy_id))
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
        elif not policy.service:
            warnings.append("source NAT policy has no explicit service match")
        elif len(policy.service) > 1:
            warnings.append("source NAT policy has multiple services; service-group semantics are not verified")
        if policy is not None:
            warnings.extend(ipv6_match_warnings(policy))
            for field, names in (("source", policy.srcintf or ()), ("destination", item.egress_interfaces)):
                if not names or len(_policy_zones(policy, names, options, zone_names)) != len(names):
                    warnings.append(f"NAT {field} zone mapping is incomplete")
            if not policy.srcaddr or not policy.dstaddr:
                warnings.append("source NAT policy is missing explicit address match")
        if item.egress_interfaces and (egress_mapping is None or not getattr(egress_mapping, "target_interface", None)):
            warnings.append("missing mapped target interface for NAT egress")
        source_translation_type = None
        translated_addresses = ()
        source_interface_address = False
        if translated and item.translation_type == "ip_pool":
            source_translation_type, translated_addresses = "dynamic-ip-and-port", (translated,)
        elif item.translation_type == "interface":
            source_translation_type, source_interface_address = "dynamic-ip-and-port", True
        if not source_translation_type:
            warnings.append("unsafe source NAT was not rendered")
        result.append(PlannedNATRule(
            source_vdom=item.vdom, source_kind="source_nat", source_object_type="nat_rule",
            source_name=item.policy_name or str(item.policy_id), source_policy_id=item.policy_id,
            target_vsys=getattr(getattr(options, "vdoms", {}).get(item.vdom), "vsys", None), target_name=item.policy_name or str(item.policy_id),
            status=PANMigrationStatus.SUPPORTED if not warnings else PANMigrationStatus.MANUAL_REVIEW,
            warnings=tuple(warnings), source_translation_type=source_translation_type,
            translated_addresses=translated_addresses, source_interface_address=source_interface_address,
            from_zones=_policy_zones(policy, policy.srcintf or (), options, zone_names) if policy else (),
            to_zones=_policy_zones(policy, item.egress_interfaces, options, zone_names),
            source_addresses=tuple(policy.srcaddr or ()) if policy else (),
            destination_addresses=tuple(policy.dstaddr or ()) if policy else (),
            service=(policy.service[0] if policy and policy.service and len(policy.service) == 1 else None),
            to_interface=getattr(egress_mapping, "target_interface", None),
        ))
    for vip in getattr(source, "vips", ()):
        vdom = vip.vdom or "root"
        referencing = [policy for policy in getattr(source, "policies", ())
                       if (policy.vdom or "root") == vdom and vip.name in (policy.dstaddr or ())]
        ext = vip.extip or (vip.extaddr[0] if len(vip.extaddr) == 1 else None)
        mapped = vip.mapped_addr or (vip.mappedip[0] if len(vip.mappedip) == 1 else None)
        warnings = []
        if not ext or not mapped or len(vip.extaddr) > 1 or len(vip.mappedip) > 1:
            warnings.append("VIP requires one external and one mapped address")
        if vip.realservers or vip.ldb_method or vip.service or getattr(vip, "type", None) not in (None, "static-nat"):
            warnings.append("VIP type or load-balancing/service semantics are unsupported")
        if getattr(vip, "portforward", None) not in (None, "disable", "no", "0") or any(
            getattr(vip, field, None) for field in ("protocol", "extport", "mappedport")
        ):
            warnings.append("VIP port-forwarding semantics are unsupported")
        if not referencing:
            warnings.append("VIP has no referencing firewall policy for NAT source zone")
        from_contexts = []
        for policy in referencing:
            warnings.extend(ipv6_match_warnings(policy))
            names = policy.srcintf or ()
            zones = _policy_zones(policy, names, options, zone_names)
            if not names or len(zones) != len(names):
                warnings.append("VIP referencing policy has unresolved source zone")
            else:
                from_contexts.append(tuple(sorted(set(zones))))
        if len(set(from_contexts)) > 1:
            warnings.append("VIP referencing policies have conflicting source zones")
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
            from_zones=from_zones, to_zones=(external_zone,) if external_zone else (),
            service=None,
        ))
    return tuple(result)


def _target_zone(options, vdom, name, zone_names):
    zones = getattr(options, "zones", None)
    mappings = ((zones or {}) if (vdom, name) in zone_names and zones is not None
                else getattr(options, "interfaces", {})).get(vdom, {})
    mapping = mappings.get(name)
    return getattr(mapping, "target_zone", None)


def _policy_zones(policy, names, options, zone_names=()):
    if policy is None:
        return ()
    vdom = getattr(policy, "vdom", None) or "root"
    return tuple(zone for name in names if (zone := _target_zone(options, vdom, name, zone_names)))
