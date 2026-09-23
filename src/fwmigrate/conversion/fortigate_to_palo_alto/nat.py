"""FortiGate source NAT and deterministic VIP/DNAT planning."""

from typing import Any

from .models import PANMigrationStatus, PlannedNATRule


def plan_nat(source: Any, derived: Any, options: Any):
    policies = {item.policy_id: item for item in getattr(source, "policies", ())}
    result = []
    for item in getattr(derived, "nat", ()):
        policy = policies.get(item.policy_id)
        warnings = list(item.issues)
        translated = item.translated_addresses[0] if len(item.translated_addresses) == 1 else None
        if len(item.translated_addresses) != 1:
            warnings.append("NAT translation is not deterministic")
        if item.egress_interfaces and len(item.egress_interfaces) != 1:
            warnings.append("NAT has multiple possible egress interfaces")
        source_translation_type = None
        translated_addresses = ()
        source_interface_address = False
        if translated and item.translation_type == "ip_pool":
            source_translation_type, translated_addresses = "dynamic-ip-and-port", (translated,)
        elif not warnings and item.translation_type == "interface":
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
            from_zones=_policy_zones(policy, policy.srcintf if policy else (), options),
            to_zones=_policy_zones(policy, item.egress_interfaces, options),
            source_addresses=tuple(policy.srcaddr if policy else ()),
            destination_addresses=tuple(policy.dstaddr if policy else ()),
            service=(policy.service[0] if policy and policy.service else None),
            to_interface=(item.egress_interfaces[0] if item.egress_interfaces else None),
        ))
    for vip in getattr(source, "vips", ()):
        ext = vip.extip or (vip.extaddr[0] if len(vip.extaddr) == 1 else None)
        mapped = vip.mapped_addr or (vip.mappedip[0] if len(vip.mappedip) == 1 else None)
        warnings = []
        if not ext or not mapped or len(vip.extaddr) > 1 or len(vip.mappedip) > 1:
            warnings.append("VIP requires one external and one mapped address")
        if vip.realservers or vip.ldb_method or vip.service or getattr(vip, "type", None) not in (None, "static-nat"):
            warnings.append("VIP type or load-balancing/service semantics are unsupported")
        result.append(PlannedNATRule(
            source_vdom=vip.vdom, source_kind="vip", source_object_type="nat_rule", source_name=vip.name,
            target_vsys=getattr(getattr(options, "vdoms", {}).get(vip.vdom), "vsys", None), target_name=vip.name,
            status=PANMigrationStatus.SUPPORTED if not warnings else PANMigrationStatus.MANUAL_REVIEW,
            warnings=tuple(warnings), destination_translated_address=(mapped if mapped and not warnings else None),
            destination_addresses=((ext,) if ext else ()),
            service=(vip.service[0] if vip.service else None),
        ))
    return tuple(result)


def _policy_zones(policy, names, options):
    if policy is None:
        return ()
    return tuple(
        getattr(options, "interfaces", {}).get(name).target_zone
        for name in names
        if getattr(options, "interfaces", {}).get(name)
        and getattr(options, "interfaces", {}).get(name).target_zone
    )
